// app.js is a classic script (not a module), so this tiny module shim does
// the ES module import of noVNC's core and hands the RFB class to it via a
// global. Module scripts run after the document is parsed but before
// DOMContentLoaded, well before a user can click "connect", so there's no
// race with app.js reading window.RFB later.
import RFB from "./novnc/core/rfb.js";
window.RFB = RFB;
