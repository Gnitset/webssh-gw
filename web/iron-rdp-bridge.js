// Same purpose as novnc-bridge.js: app.js is a classic script, so this
// module does the ES module import and wasm init, then hands the RDP
// backend to it via a global.
import { Backend, init } from "./iron-remote-desktop-rdp.js";
await init("warn");
window.IronRDP = Backend;
