// Writes a one-page client setup sheet for this server.
// Fill in the two values below, then run: node scripts/client-setup-pdf.mjs
import { createWriteStream } from "node:fs";
import PDFDocument from "pdfkit";

const DOMAIN = "rd.example.com";
const PUBLIC_KEY = "PASTE_YOUR_PUBLIC_KEY_HERE";

const OUTPUT = "rustdesk-client-setup.pdf";

if (DOMAIN === "rd.example.com" || PUBLIC_KEY.startsWith("PASTE_")) {
  console.error("Edit DOMAIN and PUBLIC_KEY at the top of this script first.");
  process.exit(1);
}

const API = `https://${DOMAIN}`;
const configString = Buffer.from(
  JSON.stringify({ host: DOMAIN, relay: "", api: API, key: PUBLIC_KEY }),
)
  .toString("base64url")
  .split("")
  .reverse()
  .join("");

const doc = new PDFDocument({ size: "LETTER", margin: 54 });
doc.pipe(createWriteStream(OUTPUT));

const heading = (text) => doc.moveDown(0.8).font("Helvetica-Bold").fontSize(13).text(text).moveDown(0.3);
const para = (text) => doc.font("Helvetica").fontSize(10.5).text(text).moveDown(0.3);
const field = (label, value, font = "Helvetica") =>
  doc
    .font("Helvetica-Bold").fontSize(10.5).text(`${label}:  `, { continued: true })
    .font(font).text(value);
const code = (text) => doc.font("Courier").fontSize(9).text(text, { lineBreak: true }).moveDown(0.3);

doc.font("Helvetica-Bold").fontSize(18).text("RustDesk client setup");
doc.font("Helvetica").fontSize(10.5).text(`Server: ${DOMAIN}`);
para("Apply these settings on every device: the computers you connect to and the ones you connect from.");

heading("Settings");
field("ID Server", DOMAIN);
field("Relay Server", "(leave empty)");
field("API Server", API);
field("Key", PUBLIC_KEY, "Courier");
field("Use WebSocket", "On");

heading("Desktop (Windows, macOS, Linux)");
para("1. Open Settings > Network and click Unlock network settings.");
para("2. Click ID/Relay Server, enter the settings above, and click OK.");
para("3. On the same Network page, turn on Use WebSocket.");

heading("Android and iOS");
para("1. Open Settings > ID/Relay Server and enter the settings above.");
para("2. In Settings, turn on Use WebSocket.");

heading("Faster setup: import");
para(
  "Copy this text, open the ID/Relay Server dialog, and click the import (clipboard) icon. " +
    "Use WebSocket still has to be turned on separately. It is one line: " +
    "if the copy picks up a line break, remove it before importing.",
);
code(configString);

heading("Check that it works");
para("1. The bottom of the RustDesk window shows Ready.");
para("2. During a session, hover the shield icon in the toolbar. It should say Relayed and encrypted connection.");

heading("If something is wrong");
field("Never shows Ready", "Use WebSocket is off, API Server is not https://, or the ID Server is mistyped.");
field("Key mismatch", "The Key is empty or wrong on the device you are connecting from.");
field("Remote desktop is offline", "The other device is not set up this way, or RustDesk is not running on it.");

doc.end();
console.log(`Wrote ${OUTPUT}`);
