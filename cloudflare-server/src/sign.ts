import { Msg } from "./pb";

export interface Signer {
  publicKeyB64: string;
  // libsodium crypto_sign "combined" format: 64-byte signature followed by the message,
  // which is what the client's sign::verify expects.
  sign(message: Uint8Array): Promise<Uint8Array>;
  signIdPk(id: string, pk: Uint8Array): Promise<Uint8Array>;
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function b64encode(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function b64url(b: Uint8Array): string {
  return b64encode(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// `secretKeyB64` is the content of hbbs's `id_ed25519` file: base64 of the 64-byte libsodium
// secret key (32-byte seed followed by the 32-byte public key). Reusing an existing hbbs key
// keeps already-configured clients working.
export async function loadSigner(secretKeyB64: string): Promise<Signer> {
  let sk: Uint8Array;
  try {
    sk = b64decode(secretKeyB64);
  } catch {
    throw new Error("PRIVATE_KEY is not valid base64");
  }
  if (sk.length !== 64) {
    throw new Error(`PRIVATE_KEY must decode to 64 bytes (seed + public key), got ${sk.length}`);
  }
  const seed = sk.slice(0, 32);
  const pk = sk.slice(32);
  const mismatch = "PRIVATE_KEY's public half does not match its seed";
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", d: b64url(seed), x: b64url(pk) },
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  } catch {
    // Some runtimes check the pair on import, others only through the probe below.
    throw new Error(mismatch);
  }
  const verifyKey = await crypto.subtle.importKey("raw", pk, { name: "Ed25519" }, false, [
    "verify",
  ]);
  const probe = new Uint8Array([1, 2, 3]);
  const probeSig = await crypto.subtle.sign("Ed25519", key, probe);
  if (!(await crypto.subtle.verify("Ed25519", verifyKey, probeSig, probe))) {
    throw new Error(mismatch);
  }

  const sign = async (message: Uint8Array): Promise<Uint8Array> => {
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key, message));
    const out = new Uint8Array(sig.length + message.length);
    out.set(sig);
    out.set(message, sig.length);
    return out;
  };
  return {
    publicKeyB64: b64encode(pk),
    sign,
    // IdPk { id = 1, pk = 2 } from rendezvous.proto, as hbbs signs it
    signIdPk: (id, peerPk) => sign(new Msg().setStr(1, id).setBytes(2, peerPk).encode()),
  };
}

export function publicKeyFromSecret(secretKeyB64: string): string {
  return b64encode(b64decode(secretKeyB64).slice(32, 64));
}
