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
let rdpSession = null;
const vncEl = document.getElementById("vnc");
const rdpEl = document.getElementById("rdp");
const rdpCanvas = document.getElementById("rdpCanvas");

// JS KeyboardEvent.code -> PC/AT Set 1 scancode (what RDP's keyboard input
// PDU wants). Extended keys (the right-hand modifiers, arrows, the nav
// cluster, numpad enter/divide) are encoded as 0xE000 | code, since
// DeviceEvent.keyPressed() takes a single number with no separate
// "extended" flag. Covers everyday typing and navigation, not an
// exhaustive 104-key table (numpad digits, media keys, etc. are missing).
const RDP_SCANCODES = {
  Escape: 0x01, Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
  Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0A, Digit0: 0x0B,
  Minus: 0x0C, Equal: 0x0D, Backspace: 0x0E, Tab: 0x0F,
  KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12, KeyR: 0x13, KeyT: 0x14, KeyY: 0x15, KeyU: 0x16,
  KeyI: 0x17, KeyO: 0x18, KeyP: 0x19, BracketLeft: 0x1A, BracketRight: 0x1B,
  Enter: 0x1C, ControlLeft: 0x1D,
  KeyA: 0x1E, KeyS: 0x1F, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22, KeyH: 0x23, KeyJ: 0x24,
  KeyK: 0x25, KeyL: 0x26, Semicolon: 0x27, Quote: 0x28, Backquote: 0x29,
  ShiftLeft: 0x2A, Backslash: 0x2B,
  KeyZ: 0x2C, KeyX: 0x2D, KeyC: 0x2E, KeyV: 0x2F, KeyB: 0x30, KeyN: 0x31, KeyM: 0x32,
  Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
  AltLeft: 0x38, Space: 0x39, CapsLock: 0x3A,
  F1: 0x3B, F2: 0x3C, F3: 0x3D, F4: 0x3E, F5: 0x3F, F6: 0x40, F7: 0x41, F8: 0x42,
  F9: 0x43, F10: 0x44, F11: 0x57, F12: 0x58,
  NumpadEnter: 0xE01C, ControlRight: 0xE01D, AltRight: 0xE038,
  Insert: 0xE052, Delete: 0xE053, Home: 0xE047, End: 0xE04F,
  PageUp: 0xE049, PageDown: 0xE051,
  ArrowUp: 0xE048, ArrowDown: 0xE050, ArrowLeft: 0xE04B, ArrowRight: 0xE04D,
  MetaLeft: 0xE05B, MetaRight: 0xE05C, ContextMenu: 0xE05D, NumpadDivide: 0xE035,
};

function rdpCanvasPos(e) {
  const rect = rdpCanvas.getBoundingClientRect();
  const scaleX = rdpCanvas.width / rect.width;
  const scaleY = rdpCanvas.height / rect.height;
  return {
    x: Math.round((e.clientX - rect.left) * scaleX),
    y: Math.round((e.clientY - rect.top) * scaleY),
  };
}

// Resetting width (even to its current value) clears the canvas's drawing
// buffer regardless of whether IronRDP's renderCanvas() got a 2D or WebGL
// context from it — clearRect only works for the former, and this project
// has no way to know which it uses internally.
function clearRdpCanvas() {
  rdpCanvas.width = rdpCanvas.width;
}

function rdpApply(event) {
  if (!rdpSession) return;
  const t = new IronRDP.InputTransaction();
  t.addEvent(event);
  rdpSession.applyInputs(t);
}

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
const defaultPorts = { ssh: defaultSshPort, vnc: "5900", rdp: "3389" };
function setStatus(s) { $("status").textContent = s; }
function toggle(on) {
  connected = on;
  $("connect").disabled = on;
  $("disconnect").disabled = !on;
  ["protocol", "host", "port", "user", "authType", "password", "passphrase", "key"].forEach((id) => $(id).disabled = on);
}

function proto() { return $("protocol").value; }

function syncAuthFields() {
  const keyCapable = proto() === "ssh";
  $("authType").style.display = keyCapable ? "inline-block" : "none";
  const key = keyCapable && $("authType").value === "key";
  $("key").style.display = key ? "block" : "none";
  $("passphrase").style.display = key ? "inline-block" : "none";
  $("password").style.display = (!keyCapable || !key) ? "inline-block" : "none";
}

$("authType").addEventListener("change", syncAuthFields);

$("protocol").addEventListener("change", () => {
  const p = proto();
  termEl.style.display = p === "ssh" ? "block" : "none";
  vncEl.style.display = p === "vnc" ? "block" : "none";
  rdpEl.style.display = p === "rdp" ? "block" : "none";
  // Swap the port field's value between protocols' conventional defaults,
  // but only if it still holds a default rather than something the user
  // actually typed in.
  const current = $("port").value.trim();
  if (Object.values(defaultPorts).includes(current) || current === "") {
    $("port").value = defaultPorts[p];
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
  const port = $("port").value.trim() || defaultPorts.vnc;
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

// RDP's CLIPRDR channel only has the client push local clipboard content
// once, in response to forceClipboardUpdateCallback right after the channel
// comes up — there's no OS-level event for "clipboard changed outside the
// browser", so content copied elsewhere while this tab was unfocused would
// otherwise never reach the remote. Re-push on every focus regain, which is
// the same heuristic real RDP/Citrix clients use.
function pushLocalClipboardToRdp() {
  if (!rdpSession) return;
  navigator.clipboard.readText().then((text) => {
    const data = new IronRDP.ClipboardData();
    data.addText("text/plain", text);
    rdpSession.onClipboardPaste(data);
  }).catch(() => {});
}
window.addEventListener("focus", pushLocalClipboardToRdp);

// RDP, like VNC, needs no wasm bridge — but unlike VNC/SSH, the gateway
// itself has to speak a little RDP (see server/rdp.go) because a browser
// can't open the raw TLS connection to the target that RDP needs; the
// IronRDP wasm client talks to the gateway over /rdp via that RDCleanPath
// handshake, then it's a plain byte relay same as the others.
function doRdpConnect() {
  const base = location.pathname.replace(/\/[^/]*$/, "");
  const wsBase = (location.protocol === "https:" ? "wss" : "ws") + "://" + location.host + base + "/rdp";
  const host = $("host").value.trim();
  const port = $("port").value.trim() || defaultPorts.rdp;
  const user = $("user").value.trim();
  const password = $("password").value;
  $("password").value = "";

  const container = rdpEl.getBoundingClientRect();
  const width = Math.max(320, Math.round(container.width)) || 1024;
  const height = Math.max(240, Math.round(container.height)) || 768;

  setStatus("connecting…");
  toggle(true);

  const builder = new IronRDP.SessionBuilder()
    .proxyAddress(wsBase)
    .destination(`${host}:${port}`)
    .username(user)
    .password(password)
    // Required by the builder, but unused by our gateway: access is
    // already gated by the cookie on the WebSocket upgrade, same as
    // /ws and /resume, so there's no separate protocol-level credential
    // to supply here.
    .authToken("")
    // Also required by the builder; we don't customize the cursor icon.
    .setCursorStyleCallback(() => {})
    .setCursorStyleCallbackContext(null)
    // Unlike VNC's clipboardPasteFrom() push model, RDP's CLIPRDR channel
    // is pull-based: once the channel comes up, this fires once so the
    // client can push whatever's currently on the local clipboard; the
    // remote caches it and serves it from that cache on an actual paste,
    // so there's no need to intercept Ctrl+V here -- it already reaches
    // the remote as an ordinary keystroke via RDP_SCANCODES. Later changes
    // (e.g. made outside the browser) are caught by the focus-regain push
    // above instead, since CLIPRDR itself has no "re-push now" callback.
    .forceClipboardUpdateCallback(pushLocalClipboardToRdp)
    // The remote's clipboard changed (e.g. the user copied something on
    // the remote desktop) -- mirror it into the local clipboard, the same
    // direction the focus-regain push above goes the other way. Fires with
    // a single ClipboardData argument; take the first text item.
    .remoteClipboardChangedCallback((data) => {
      const item = data.items().find((i) => i.mimeType().startsWith("text/"));
      if (item) navigator.clipboard.writeText(item.value()).catch(() => {});
    })
    .desktopSize(new IronRDP.DesktopSize(width, height))
    .renderCanvas(rdpCanvas);

  builder.connect().then((session) => {
    rdpSession = session;
    const size = session.desktopSize();
    rdpCanvas.width = size.width;
    rdpCanvas.height = size.height;
    setStatus("connected to " + host);
    rdpCanvas.focus();
    session.run().then((info) => {
      rdpSession = null;
      toggle(false);
      clearRdpCanvas();
      setStatus("disconnected: " + info.reason());
      focusHost();
    });
  }).catch((err) => {
    rdpSession = null;
    toggle(false);
    setStatus("error: " + rdpErrorMessage(err));
    focusHost();
  });
}

// IronRDP's connect() rejects with a wasm-bound error object, not a plain
// Error — it has no useful default string/JSON form (just an internal
// pointer), so pull the message out via its own accessor methods instead.
function rdpErrorMessage(err) {
  if (err && typeof err.backtrace === "function") {
    try { return err.backtrace(); } catch (e) { /* fall through */ }
  }
  return String(err);
}

rdpCanvas.addEventListener("mousemove", (e) => {
  const p = rdpCanvasPos(e);
  rdpApply(IronRDP.DeviceEvent.mouseMove(p.x, p.y));
});
rdpCanvas.addEventListener("mousedown", (e) => { e.preventDefault(); rdpCanvas.focus(); rdpApply(IronRDP.DeviceEvent.mouseButtonPressed(e.button)); });
rdpCanvas.addEventListener("mouseup", (e) => { e.preventDefault(); rdpApply(IronRDP.DeviceEvent.mouseButtonReleased(e.button)); });
rdpCanvas.addEventListener("contextmenu", (e) => e.preventDefault());
rdpCanvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  if (e.deltaY) rdpApply(IronRDP.DeviceEvent.wheelRotations(true, -e.deltaY, 0));
  if (e.deltaX) rdpApply(IronRDP.DeviceEvent.wheelRotations(false, -e.deltaX, 0));
}, { passive: false });
rdpCanvas.addEventListener("keydown", (e) => {
  if (!rdpSession) return;
  e.preventDefault();
  const code = RDP_SCANCODES[e.code];
  if (code !== undefined) {
    rdpApply(IronRDP.DeviceEvent.keyPressed(code));
  } else if (e.key.length === 1) {
    rdpApply(IronRDP.DeviceEvent.unicodePressed(e.key));
  }
});
rdpCanvas.addEventListener("keyup", (e) => {
  if (!rdpSession) return;
  e.preventDefault();
  const code = RDP_SCANCODES[e.code];
  if (code !== undefined) {
    rdpApply(IronRDP.DeviceEvent.keyReleased(code));
  } else if (e.key.length === 1) {
    rdpApply(IronRDP.DeviceEvent.unicodeReleased(e.key));
  }
});

// Enter in host/port/user attempts a connect; if password auth needs a
// password that isn't typed yet, this instead focuses the password field
// (a "prompt") rather than connecting — a second Enter there confirms.
function tryConnect() {
  if (connected) return;
  const p = proto();
  if (p === "ssh" && !wasmReady) { setStatus("still loading…"); return; }
  if (!$("host").value.trim()) { $("host").focus(); return; }
  if ((p !== "ssh" || $("authType").value === "password") && !$("password").value) {
    setStatus("enter password, then press enter");
    $("password").focus();
    return;
  }
  if (p === "vnc") doVncConnect();
  else if (p === "rdp") doRdpConnect();
  else doConnect();
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
  else if (rdpSession) rdpSession.shutdown();
  else if (window.goSSHClose) window.goSSHClose();
});

focusHost();

term.onData((d) => { if (connected && window.goSSHWrite) window.goSSHWrite(d); });

function syncTerminalSize() {
  if (proto() !== "ssh") return;
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
