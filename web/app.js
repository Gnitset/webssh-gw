"use strict";

// ---------- terminal ----------
const term = new Terminal({
  cursorBlink: true,
  fontFamily: "monospace",
  fontSize: 14,
  theme: { background: "#000000" },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById("term"));
fit.fit();

let connected = false;

// Go (wasm) calls these:
window.termWrite = (u8) => term.write(u8);
window.sshClosed = () => {
  connected = false;
  setStatus("disconnected");
  toggle(false);
  term.writeln("\r\n\x1b[33m*** session closed ***\x1b[0m");
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
function setStatus(s) { $("status").textContent = s; }
function toggle(on) {
  connected = on;
  $("connect").disabled = on;
  $("disconnect").disabled = !on;
  ["host", "port", "user", "authType", "password", "passphrase", "key"].forEach((id) => $(id).disabled = on);
}

$("authType").addEventListener("change", (e) => {
  const key = e.target.value === "key";
  $("key").style.display = key ? "block" : "none";
  $("passphrase").style.display = key ? "inline-block" : "none";
  $("password").style.display = key ? "none" : "inline-block";
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

// Enter in host/port/user attempts a connect; if password auth needs a
// password that isn't typed yet, this instead focuses the password field
// (a "prompt") rather than connecting — a second Enter there confirms.
function tryConnect() {
  if (connected) return;
  if (!wasmReady) { setStatus("still loading…"); return; }
  if (!$("host").value.trim()) { $("host").focus(); return; }
  if ($("authType").value === "password" && !$("password").value) {
    setStatus("enter password, then press enter");
    $("password").focus();
    return;
  }
  doConnect();
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
  if (window.goSSHClose) window.goSSHClose();
});

focusHost();

term.onData((d) => { if (connected && window.goSSHWrite) window.goSSHWrite(d); });

function syncTerminalSize() {
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
