// Generates a server key pair in the same format hbbs uses (id_ed25519 / id_ed25519.pub).
import { generateKeyPairSync } from "node:crypto";

const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
const seed = Buffer.from(jwk.d, "base64url");
const pk = Buffer.from(jwk.x, "base64url");

console.log("PRIVATE_KEY (keep secret; store with `npx wrangler secret put PRIVATE_KEY`):");
console.log(Buffer.concat([seed, pk]).toString("base64"));
console.log();
console.log("Public key (the `Key` field in every RustDesk client):");
console.log(pk.toString("base64"));
