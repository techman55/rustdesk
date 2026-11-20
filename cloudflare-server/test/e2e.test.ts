import { createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { demangle, formatIp } from "../src/addr";
import { newKey, Peer, startServer, type Server, type ServerKey } from "./harness";
import { IdPk } from "./proto";

const VERSION = "1.4.4";

function devicePk(): Buffer {
  return randomBytes(32);
}

async function registerDevice(
  server: Server,
  id: string,
  uuid: Buffer,
  pk: Buffer,
): Promise<{ peer: Peer; res: any }> {
  const peer = await Peer.connect(`${server.ws}/ws/id`);
  peer.send({ register_pk: { id, uuid, pk } });
  const res = await peer.next();
  expect(res.union).toBe("register_pk_response");
  return { peer, res: res.register_pk_response };
}

function verifySignedIdPk(signed: Uint8Array, key: ServerKey) {
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
  const sig = signed.subarray(0, 64);
  const body = signed.subarray(64);
  expect(verify(null, body, pub, sig)).toBe(true);
  return IdPk.decode(body);
}

describe("rendezvous + relay over WebSocket", () => {
  let server: Server;
  const key = newKey();

  beforeAll(async () => {
    server = await startServer({ PRIVATE_KEY: key.secret, HEARTBEAT_SECONDS: "1" });
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("registers a device, then keeps it alive with heartbeats it must echo", async () => {
    const { peer, res } = await registerDevice(server, "100000001", randomBytes(16), devicePk());
    expect(res.result).toBe(0);
    expect(res.keep_alive).toBe(2);
    const hb = await peer.frame(4000, false);
    expect(hb.length).toBe(0);
    peer.sendRaw(Buffer.alloc(0));
    peer.close();
  });

  it("drops a device that stops answering heartbeats, so it shows offline", async () => {
    const id = "100000010";
    const { peer } = await registerDevice(server, id, randomBytes(16), devicePk());
    expect((await peer.waitClosed(8000)).code).toBe(1001);
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id, licence_key: key.publicKey, version: VERSION } });
    expect((await ctl.next()).punch_hole_response.failure).toBe(2); // OFFLINE
    ctl.close();
  });

  it("binds an id to the first machine uuid that registers it", async () => {
    const uuid = randomBytes(16);
    const first = await registerDevice(server, "100000002", uuid, devicePk());
    expect(first.res.result).toBe(0);
    const thief = await registerDevice(server, "100000002", randomBytes(16), devicePk());
    expect(thief.res.result).toBe(2); // UUID_MISMATCH
    first.peer.close();
    thief.peer.close();
  });

  it("answers punch-hole requests for bad keys, unknown ids and offline devices", async () => {
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id: "100000003", licence_key: "wrong", version: VERSION } });
    let r = await ctl.next();
    expect(r.punch_hole_response.failure).toBe(3); // LICENSE_MISMATCH

    ctl.send({ punch_hole_request: { id: "999999999", licence_key: key.publicKey, version: VERSION } });
    r = await ctl.next();
    expect(r.punch_hole_response.socket_addr.length).toBe(0);
    expect(r.punch_hole_response.failure).toBe(0); // ID_NOT_EXIST

    const dev = await registerDevice(server, "100000003", randomBytes(16), devicePk());
    dev.peer.close();
    await dev.peer.waitClosed();
    await new Promise((r) => setTimeout(r, 200));
    ctl.send({ punch_hole_request: { id: "100000003", licence_key: key.publicKey, version: VERSION } });
    r = await ctl.next();
    expect(r.punch_hole_response.failure).toBe(2); // OFFLINE
    ctl.close();
  });

  it("brokers a relayed session with a server-signed peer key, then relays both ways", async () => {
    const id = "100000004";
    const pk = devicePk();
    const dev = await registerDevice(server, id, randomBytes(16), pk);

    // Controller: PunchHoleRequest, as Client::_start_inner sends it in WebSocket mode.
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({
      punch_hole_request: {
        id,
        licence_key: key.publicKey,
        nat_type: 1,
        conn_type: 0,
        version: VERSION,
        force_relay: true,
      },
    });

    // Controlled side gets a PunchHole and answers on a fresh connection with a
    // RelayResponse, as RendezvousMediator::create_relay does.
    const ph = (await dev.peer.next()).punch_hole;
    expect(ph.force_relay).toBe(true);
    expect(ph.relay_server).toBe("127.0.0.1");
    const ctlAddr = demangle(ph.socket_addr)!;
    expect(formatIp(ctlAddr.ip)).toBe("127.0.0.1");

    const uuid = randomUUID();
    const answer = await Peer.connect(`${server.ws}/ws/id`);
    answer.send({
      relay_response: {
        socket_addr: ph.socket_addr,
        uuid,
        relay_server: ph.relay_server,
        id,
        version: VERSION,
      },
    });

    const rr = (await ctl.next()).relay_response;
    expect(rr.uuid).toBe(uuid);
    expect(rr.relay_server).toBe("127.0.0.1");
    expect(rr.socket_addr.length).toBe(0);
    const idpk = verifySignedIdPk(rr.pk, key);
    expect(idpk.id).toBe(id);
    expect(Buffer.from(idpk.pk).equals(pk)).toBe(true);

    // Relay: the controlled side connects first and speaks before the controller arrives.
    const relayDev = await Peer.connect(`${server.ws}/ws/relay`);
    relayDev.send({ request_relay: { licence_key: key.publicKey, uuid } });
    relayDev.sendRaw(Buffer.from("signed-id-from-controlled"));
    await new Promise((r) => setTimeout(r, 300));
    const relayCtl = await Peer.connect(`${server.ws}/ws/relay`);
    relayCtl.send({ request_relay: { licence_key: key.publicKey, uuid, id } });

    expect((await relayCtl.frame()).toString()).toBe("signed-id-from-controlled");
    relayCtl.sendRaw(Buffer.from("public-key-from-controller"));
    expect((await relayDev.frame()).toString()).toBe("public-key-from-controller");
    const big = randomBytes(3 << 20);
    relayDev.sendRaw(big);
    expect((await relayCtl.frame(10_000)).equals(big)).toBe(true);

    relayDev.close();
    await relayCtl.waitClosed();
    for (const p of [dev.peer, ctl, answer]) p.close();
  });

  it("forwards a controller's RequestRelay and routes the acknowledgement back", async () => {
    const id = "100000005";
    const dev = await registerDevice(server, id, randomBytes(16), devicePk());
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    const uuid = randomUUID();
    ctl.send({ request_relay: { id, uuid, relay_server: "127.0.0.1", secure: true } });

    const rq = (await dev.peer.next()).request_relay;
    expect(rq.uuid).toBe(uuid);
    expect(rq.secure).toBe(true);
    expect(rq.socket_addr.length).toBeGreaterThan(0);

    const ack = await Peer.connect(`${server.ws}/ws/id`);
    ack.send({ relay_response: { socket_addr: rq.socket_addr, version: VERSION } });
    const rr = (await ctl.next()).relay_response;
    expect(rr.refuse_reason).toBe("");

    ctl.send({ request_relay: { id: "100000999", uuid: randomUUID() } });
    expect((await ctl.next()).relay_response.refuse_reason).toBe("Remote desktop is offline");
    for (const p of [dev.peer, ctl, ack]) p.close();
  });

  it("does not sign a key for an id the controller never asked for", async () => {
    const id = "100000006";
    const dev = await registerDevice(server, id, randomBytes(16), devicePk());
    const other = await registerDevice(server, "100000007", randomBytes(16), devicePk());
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id, licence_key: key.publicKey, version: VERSION } });
    const ph = (await dev.peer.next()).punch_hole;

    const forged = await Peer.connect(`${server.ws}/ws/id`);
    forged.send({
      relay_response: {
        socket_addr: ph.socket_addr,
        uuid: randomUUID(),
        relay_server: "attacker.example",
        id: "100000007",
        version: VERSION,
      },
    });
    await ctl.expectNothing(500);
    for (const p of [dev.peer, other.peer, ctl, forged]) p.close();
  });

  it("closes relay connections that lack the server key", async () => {
    const relay = await Peer.connect(`${server.ws}/ws/relay`);
    relay.send({ request_relay: { licence_key: "wrong", uuid: randomUUID() } });
    expect((await relay.waitClosed()).code).toBe(1008);
  });

  it("reports which ids are online", async () => {
    const dev = await registerDevice(server, "100000008", randomBytes(16), devicePk());
    const q = await Peer.connect(`${server.ws}/ws/id`);
    q.send({ online_request: { id: "200000000", peers: ["100000008", "nobody-here", "100000008"] } });
    const states = (await q.next()).online_response.states;
    expect([...states]).toEqual([0b10100000]);
    dev.peer.close();
    q.close();
  });

  it("changes a device id for the machine that owns it", async () => {
    const uuid = randomBytes(16);
    const dev = await registerDevice(server, "100000009", uuid, devicePk());
    await registerDevice(server, "takenid1", randomBytes(16), devicePk());
    const change = async (old_id: string, id: string, u: Buffer) => {
      const p = await Peer.connect(`${server.ws}/ws/id`);
      p.send({ register_pk: { old_id, id, uuid: u } });
      const r = (await p.next()).register_pk_response.result;
      p.close();
      return r;
    };
    expect(await change("100000009", "1bad", uuid)).toBe(5); // INVALID_ID_FORMAT
    expect(await change("100000009", "takenid1", uuid)).toBe(3); // ID_EXISTS
    expect(await change("100000009", "newname1", randomBytes(16))).toBe(2); // not the owner
    expect(await change("100000009", "newname1", uuid)).toBe(0);
    const again = await registerDevice(server, "newname1", uuid, devicePk());
    expect(again.res.result).toBe(0);
    dev.peer.close();
    again.peer.close();
  });

  it("serves only the API the client needs", async () => {
    const hb = await fetch(`${server.http}/api/heartbeat`, { method: "POST", body: "{}" });
    expect(await hb.json()).toEqual({});
    expect((await fetch(`${server.http}/api/sysinfo`, { method: "POST" })).status).toBe(404);
    expect((await fetch(`${server.http}/ws/id`)).status).toBe(426);
  });
});

describe("per-session relay hosts", () => {
  let server: Server;
  const key = newKey();

  beforeAll(async () => {
    server = await startServer({
      PRIVATE_KEY: key.secret,
      RELAY_HOST_TEMPLATE: "{token}.relay.example.com",
    });
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("hands out a fresh relay host per session and pairs peers on it", async () => {
    const id = "300000001";
    const dev = await registerDevice(server, id, randomBytes(16), devicePk());
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id, licence_key: key.publicKey, version: VERSION } });
    const relayHost = (await dev.peer.next()).punch_hole.relay_server as string;
    expect(relayHost).toMatch(/^[0-9a-f]{12}\.relay\.example\.com$/);

    const uuid = randomUUID();
    const host = { Host: relayHost };
    const a = await Peer.connect(`${server.ws}/ws/relay`, host);
    a.send({ request_relay: { licence_key: key.publicKey, uuid } });
    // Same uuid on the shared hub must not pair with the session's own relay object.
    const hub = await Peer.connect(`${server.ws}/ws/relay`);
    hub.send({ request_relay: { licence_key: key.publicKey, uuid } });
    const b = await Peer.connect(`${server.ws}/ws/relay`, host);
    b.send({ request_relay: { licence_key: key.publicKey, uuid } });

    a.sendRaw(Buffer.from("over the session relay"));
    expect((await b.frame()).toString()).toBe("over the session relay");
    await hub.expectNothing(300);
    for (const p of [dev.peer, ctl, a, b, hub]) p.close();
  });
});
