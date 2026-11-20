import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { demangle, formatIp, mangle, parseIp } from "../src/addr";
import { Msg, RM, unwrap, wrap } from "../src/pb";
import { relayObjectName } from "../src/relay-name";
import { loadSigner, publicKeyFromSecret } from "../src/sign";
import { RendezvousMessage, IdPk } from "./proto";

// Produced by the client's own AddrMangle (libs/hbb_common/src/lib.rs) with a fixed clock.
const MANGLE_VECTORS = [
  { addr: "203.0.113.7", port: 54321, tm: 1763650000123456n, hex: "71ca81ec878717ee699601" },
  { addr: "1.2.3.4", port: 1, tm: 0n, hex: "01000000000002040608" },
  { addr: "255.255.255.255", port: 65535, tm: 4294967295n, hex: "fefffffffffffdffffff03" },
  { addr: "10.0.0.1", port: 40000, tm: 1700000000000000n, hex: "40dc00803c3014803c32" },
  { addr: "2001:db8::1", port: 443, tm: 1n, hex: "20010db8000000000000000000000001bb01" },
  { addr: "::ffff:198.51.100.9", port: 5000, tm: 99999999n, hex: "87f4fec1eb0b8a29b41e" },
];

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("AddrMangle", () => {
  for (const v of MANGLE_VECTORS) {
    it(`matches the client for ${v.addr}:${v.port}`, () => {
      const ip = parseIp(v.addr)!;
      expect(hex(mangle({ ip, port: v.port }, v.tm))).toBe(v.hex);
      const back = demangle(Buffer.from(v.hex, "hex"))!;
      expect(formatIp(back.ip)).toBe(formatIp(ip));
      expect(back.port).toBe(v.port);
    });
  }
});

describe("protobuf codec", () => {
  it("decodes what the real proto encodes, keeping unknown fields on re-encode", () => {
    const original = RendezvousMessage.encode(
      RendezvousMessage.create({
        request_relay: {
          id: "123456789",
          uuid: "6f1c4a8e-1111-4222-8333-944445555666",
          relay_server: "rd.example.com",
          secure: true,
          conn_type: 2,
          token: "t",
          control_permissions: { permissions: 12345 },
          switch_code: "sc",
        },
      }),
    ).finish();
    const parsed = unwrap(original)!;
    expect(parsed.kind).toBe(RM.RequestRelay);
    expect(parsed.body.str(1)).toBe("123456789");
    expect(parsed.body.bool(5)).toBe(true);
    parsed.body.setBytes(3, Uint8Array.from([1, 2, 3]));
    const decoded = RendezvousMessage.toObject(
      RendezvousMessage.decode(wrap(parsed.kind, parsed.body)),
      { oneofs: true, longs: Number },
    );
    expect(decoded.union).toBe("request_relay");
    expect(decoded.request_relay).toMatchObject({
      id: "123456789",
      relay_server: "rd.example.com",
      secure: true,
      conn_type: 2,
      control_permissions: { permissions: 12345 },
      switch_code: "sc",
    });
    expect(hex(decoded.request_relay.socket_addr)).toBe("010203");
  });

  it("encodes negative int32 and empty oneof bodies the way the real proto reads them", () => {
    const bytes = wrap(RM.RegisterPkResponse, new Msg().setInt(1, 0).setInt(2, -5));
    const decoded = RendezvousMessage.toObject(RendezvousMessage.decode(bytes), {
      oneofs: true,
      defaults: true,
    });
    expect(decoded.union).toBe("register_pk_response");
    expect(decoded.register_pk_response).toMatchObject({ result: 0, keep_alive: -5 });
    expect(RendezvousMessage.decode(wrap(RM.TestNatResponse, new Msg())).test_nat_response).toBeTruthy();
  });

  it("rejects truncated input", () => {
    expect(() => unwrap(Uint8Array.from([0x92, 0x01, 0x05, 0x0a]))).toThrow();
  });
});

describe("signer", () => {
  it("signs IdPk in libsodium's combined format, verifiable with the server public key", async () => {
    const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
    const seed = Buffer.from(jwk.d!, "base64url");
    const pk = Buffer.from(jwk.x!, "base64url");
    const secret = Buffer.concat([seed, pk]).toString("base64");
    const signer = await loadSigner(secret);
    expect(signer.publicKeyB64).toBe(pk.toString("base64"));
    expect(publicKeyFromSecret(secret)).toBe(pk.toString("base64"));

    const peerPk = new Uint8Array(32).fill(7);
    const signed = await signer.signIdPk("123456789", peerPk);
    const sig = signed.subarray(0, 64);
    const body = signed.subarray(64);
    const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x! }, format: "jwk" });
    expect(verify(null, body, pub, sig)).toBe(true);
    const idpk = IdPk.decode(body);
    expect(idpk.id).toBe("123456789");
    expect(hex(idpk.pk)).toBe(hex(peerPk));
  });

  it("refuses a key whose halves do not belong together", async () => {
    const a = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
    const b = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
    const mixed = Buffer.concat([
      Buffer.from(a.d!, "base64url"),
      Buffer.from(b.x!, "base64url"),
    ]).toString("base64");
    await expect(loadSigner(mixed)).rejects.toThrow(/does not match/);
  });
});

describe("relayObjectName", () => {
  it("gives each templated session host its own object and everything else the hub", () => {
    const t = "{token}.relay.example.com";
    expect(relayObjectName("0123456789ab.relay.example.com", t)).toBe("session:0123456789ab");
    expect(relayObjectName("rd.example.com", t)).toBe("hub");
    expect(relayObjectName("evil.relay.example.com", t)).toBe("hub");
    expect(relayObjectName("0123456789ab.relay.example.com", undefined)).toBe("hub");
  });
});
