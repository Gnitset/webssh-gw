"use strict";

// ---------- terminal ----------
const termEl = document.getElementById("term");
const scrollback = parseInt(termEl.dataset.scrollback, 10) || 1000;
const term = new Terminal({
  cursorBlink: true,
  fontFamily: "monospace",
  fontSize: 14,
  theme: { background: "#000000" },
  scrollback,
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(termEl);
fit.fit();

// Ctrl/Cmd+C copies when there's a selection, same as most terminal apps
// (otherwise it falls through to xterm.js's default of sending SIGINT).
// Ctrl/Cmd+V always pastes from the clipboard instead of sending xterm's
// usual "literal next character" control code for that key.
term.attachCustomKeyEventHandler((e) => {
  if (e.type !== "keydown" || !(e.ctrlKey || e.metaKey)) return true;
  if (e.key === "c" && term.hasSelection()) {
    navigator.clipboard.writeText(term.getSelection());
    return false;
  }
  if (e.key === "v") {
    navigator.clipboard.readText().then((text) => {
      if (connected && window.goSSHWrite) window.goSSHWrite(text);
    });
    return false;
  }
  return true;
});

let connected = false;
let rfb = null;
const vncEl = document.getElementById("vnc");

// Go (wasm) calls these:
window.termWrite = (u8) => term.write(u8);
window.sshClosed = () => {
  connected = false;
  setStatus("disconnected");
  toggle(false);
  term.writeln("\r\n\x1b[33m*** session closed ***\x1b[0m");
  focusHost();
};

// The WebSocket to the gateway dropped (proxy idle-kill, tab was frozen,
// network blip, ...) and a reconnect is in progress. The SSH session
// itself is still alive server-side; this is purely a transport stall,
// so the UI stays in the "connected" state rather than tearing down.
window.sshReconnecting = () => setStatus("reconnecting…");
window.sshReconnected = () => setStatus("reconnected");

// Unlike sshReconnecting, this means the gateway could not be resumed at
// all (its grace period lapsed, or too much happened while disconnected
// to replay) — the SSH session is genuinely gone, same as sshClosed, but
// worth saying why rather than leaving the terminal silently unresponsive.
window.sshGaveUp = (reason) => {
  connected = false;
  setStatus("disconnected: " + reason);
  toggle(false);
  term.writeln("\r\n\x1b[31m*** session lost: " + reason + " ***\x1b[0m");
  focusHost();
};

// known_hosts (trust-on-first-use), per host:port, stored in localStorage.
window.hostKeyConfirm = (host, port, keyType, fpr) => {
  const k = `hk:${host}:${port}`;
  const saved = localStorage.getItem(k);
  if (saved === fpr) return true;
  if (saved && saved !== fpr) {
    return window.confirm(
      `WARNING: host key for ${host}:${port} CHANGED.\n` +
      `stored: ${saved}\nnew:    ${keyType} ${fpr}\n\n` +
      `This can mean a man-in-the-middle. Accept and replace?`
    ) && (localStorage.setItem(k, fpr), true);
  }
  const ok = window.confirm(
    `New host ${host}:${port}\nkey type: ${keyType}\nSHA256: ${fpr}\n\nTrust and remember this key?`
  );
  if (ok) localStorage.setItem(k, fpr);
  return ok;
};

// ---------- UI ----------
const $ = (id) => document.getElementById(id);
const defaultSshPort = $("port").value;
const defaultVncPort = "5900";
function setStatus(s) { $("status").textContent = s; }
function toggle(on) {
  connected = on;
  $("connect").disabled = on;
  $("disconnect").disabled = !on;
  ["protocol", "host", "port", "user", "authType", "password", "passphrase", "key"].forEach((id) => $(id).disabled = on);
}

function isVnc() { return $("protocol").value === "vnc"; }

function syncAuthFields() {
  const vnc = isVnc();
  $("authType").style.display = vnc ? "none" : "inline-block";
  const key = !vnc && $("authType").value === "key";
  $("key").style.display = key ? "block" : "none";
  $("passphrase").style.display = key ? "inline-block" : "none";
  $("password").style.display = (vnc || !key) ? "inline-block" : "none";
}

$("authType").addEventListener("change", syncAuthFields);

$("protocol").addEventListener("change", () => {
  const vnc = isVnc();
  termEl.style.display = vnc ? "none" : "block";
  vncEl.style.display = vnc ? "block" : "none";
  // Swap the port field's value between the two protocols' conventional
  // defaults, but only if it still holds a default rather than something
  // the user actually typed in.
  const current = $("port").value.trim();
  if (current === "" || current === defaultSshPort || current === defaultVncPort) {
    $("port").value = vnc ? defaultVncPort : defaultSshPort;
  }
  syncAuthFields();
});

async function doConnect() {
  // Mirror whatever path prefix this page was actually loaded under (e.g.
  // "/ssh" if mounted at example.com/ssh instead of its own subdomain),
  // rather than assuming the app owns the domain root.
  const base = location.pathname.replace(/\/[^/]*$/, "");
  const wsBase = (location.protocol === "https:" ? "wss" : "ws") + "://" + location.host + base + "/ws";
  fit.fit();
  const cfg = {
    host: $("host").value.trim(),
    port: $("port").value.trim() || "22",
    user: $("user").value.trim(),
    authType: $("authType").value,
    password: $("password").value,
    key: $("key").value,
    passphrase: $("passphrase").value,
    wsBase,
    cols: term.cols,
    rows: term.rows,
  };
  // Clear sensitive fields as soon as they're handed off, so they don't
  // linger in the DOM any longer than necessary.
  $("password").value = "";
  $("passphrase").value = "";
  if (!cfg.host || !cfg.user) { setStatus("host and user required"); return; }
  setStatus("connecting…");
  toggle(true);
  try {
    await window.goSSHConnect(cfg);
    setStatus("connected to " + cfg.host);
    term.focus();
  } catch (err) {
    setStatus("error: " + err);
    toggle(false);
    term.writeln("\r\n\x1b[31m" + err + "\x1b[0m");
    focusHost();
  }
}

// VNC connects straight from the browser's native WebSocket into noVNC's
// RFB class — unlike SSH, there's no crypto the browser can't already do
// natively, so no wasm bridge is needed for this protocol.
function doVncConnect() {
  const base = location.pathname.replace(/\/[^/]*$/, "");
  const wsBase = (location.protocol === "https:" ? "wss" : "ws") + "://" + location.host + base + "/ws";
  const host = $("host").value.trim();
  const port = $("port").value.trim() || defaultVncPort;
  const credentials = { username: $("user").value.trim(), password: $("password").value };
  // Clear as soon as it's handed off, so it doesn't linger in the DOM.
  $("password").value = "";
  const url = `${wsBase}?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`;
  setStatus("connecting…");
  toggle(true);
  // A failed security negotiation fires both "securityfailure" (with the
  // actual reason, e.g. a bad password) and then "disconnect" right after
  // as the connection tears down — remember the former so the latter's
  // generic message doesn't overwrite it.
  let failureReason = null;
  rfb = new RFB(vncEl, url, { credentials });
  rfb.scaleViewport = true;
  rfb.addEventListener("connect", () => {
    setStatus("connected to " + host);
    rfb.focus();
    // noVNC deliberately shows no cursor at all (sets cursor:none on its
    // internal canvas, in its own constructor, well before this point)
    // until the server sends a real cursor-shape update — some servers,
    // macOS Screen Sharing included, don't send one proactively and only
    // do once the shape actually changes, which can take a while. Set a
    // plain default cursor as a placeholder; noVNC's own update, whenever
    // it arrives, overwrites this the same way it would've overwritten
    // "none", so this doesn't fight it once the real cursor shows up.
    const canvas = vncEl.querySelector("canvas");
    if (canvas) canvas.style.cursor = "default";
  });
  // The remote proactively telling us its clipboard changed (e.g. the user
  // copied something on the remote desktop) — mirror it into the local
  // clipboard, the same direction Ctrl/Cmd+V below pushes.
  rfb.addEventListener("clipboard", (e) => {
    if (e.detail && typeof e.detail.text === "string") {
      navigator.clipboard.writeText(e.detail.text).catch(() => {});
    }
  });
  rfb.addEventListener("disconnect", (e) => {
    rfb = null;
    toggle(false);
    if (failureReason) {
      setStatus("auth failed: " + failureReason);
    } else {
      setStatus((e.detail && e.detail.clean) ? "disconnected" : "disconnected: connection lost");
    }
    focusHost();
  });
  rfb.addEventListener("securityfailure", (e) => {
    failureReason = (e.detail && e.detail.reason) || "unknown reason";
  });
  rfb.addEventListener("credentialsrequired", () => {
    setStatus("credentials required");
  });
}

// noVNC forwards raw keystrokes to the remote by default, which for a
// literal Ctrl/Cmd+V would just trigger a paste from the REMOTE's own
// clipboard — not what's on the local one. Intercepted in the capture
// phase on vncEl (the div RFB renders its canvas into), so this runs
// before RFB's own keydown handler ever sees the event: push the local
// clipboard to the remote first via the RFB clipboard protocol, then
// synthesize the paste keystroke ourselves so it arrives after the
// clipboard update it depends on, not racing it.
const VNC_XK_CONTROL_L = 0xffe3;
const VNC_XK_SUPER_L = 0xffeb; // what noVNC itself maps the Meta/Cmd key to
const VNC_XK_V = 0x0076;
vncEl.addEventListener("keydown", (e) => {
  if (!rfb || e.key.toLowerCase() !== "v" || !(e.ctrlKey || e.metaKey)) return;
  e.preventDefault();
  e.stopPropagation();
  const modKeysym = e.metaKey ? VNC_XK_SUPER_L : VNC_XK_CONTROL_L;
  const modCode = e.metaKey ? "MetaLeft" : "ControlLeft";
  navigator.clipboard.readText().then((text) => {
    rfb.clipboardPasteFrom(text);
    rfb.sendKey(modKeysym, modCode, true);
    rfb.sendKey(VNC_XK_V, "KeyV", true);
    rfb.sendKey(VNC_XK_V, "KeyV", false);
    rfb.sendKey(modKeysym, modCode, false);
  }).catch(() => {});
}, true);

// Enter in host/port/user attempts a connect; if password auth needs a
// password that isn't typed yet, this instead focuses the password field
// (a "prompt") rather than connecting — a second Enter there confirms.
function tryConnect() {
  if (connected) return;
  const vnc = isVnc();
  if (!vnc && !wasmReady) { setStatus("still loading…"); return; }
  if (!$("host").value.trim()) { $("host").focus(); return; }
  if ((vnc || $("authType").value === "password") && !$("password").value) {
    setStatus("enter password, then press enter");
    $("password").focus();
    return;
  }
  if (vnc) doVncConnect(); else doConnect();
}

function focusHost() {
  $("host").focus();
  $("host").select();
}

$("connect").addEventListener("click", tryConnect);

["host", "port", "user", "password", "passphrase"].forEach((id) => {
  $(id).addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); tryConnect(); }
  });
});

$("disconnect").addEventListener("click", () => {
  if (rfb) rfb.disconnect();
  else if (window.goSSHClose) window.goSSHClose();
});

focusHost();

term.onData((d) => { if (connected && window.goSSHWrite) window.goSSHWrite(d); });

function syncTerminalSize() {
  if (isVnc()) return;
  fit.fit();
  if (connected && window.goSSHResize) window.goSSHResize(term.cols, term.rows);
}

window.addEventListener("resize", syncTerminalSize);

// Prompt before closing/navigating away while a session is live — e.g. a
// Ctrl+W pressed outside fullscreen (where Keyboard Lock isn't active)
// would otherwise drop the connection with no warning at all. Browsers
// show their own generic text here regardless of what's set below.
window.addEventListener("beforeunload", (e) => {
  if (!connected) return;
  e.preventDefault();
  e.returnValue = "";
});

// Browsers reserve shortcuts like Ctrl+W/Ctrl+T and never deliver their
// keydown to the page, no matter what a handler does — that's enforced
// above the DOM, not something preventDefault() can override. The
// Keyboard Lock API is the one sanctioned way around it, and only while
// the page is in fullscreen. Once the keydown actually reaches xterm.js,
// its own key handling already turns Ctrl+<letter> into the right control
// byte, so no extra handling is needed here beyond getting the event
// delivered at all.
$("fullscreen").addEventListener("click", async () => {
  if (document.fullscreenElement) {
    await document.exitFullscreen();
    return;
  }
  try {
    await document.documentElement.requestFullscreen();
    if (navigator.keyboard && navigator.keyboard.lock) {
      await navigator.keyboard.lock();
    }
  } catch (err) {
    setStatus("fullscreen failed: " + err);
  }
});

document.addEventListener("fullscreenchange", () => {
  const inFullscreen = !!document.fullscreenElement;
  $("fullscreen").textContent = inFullscreen ? "exit fullscreen" : "fullscreen";
  if (!inFullscreen && navigator.keyboard && navigator.keyboard.unlock) {
    navigator.keyboard.unlock();
  }
  syncTerminalSize();
});

// ---------- wasm boot ----------
let wasmReady = false;
window.goReady = () => { wasmReady = true; setStatus("ready"); };

(async () => {
  setStatus("loading…");
  const go = new Go();
  const res = await WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject);
  go.run(res.instance); // resolves goReady via main()
})();
