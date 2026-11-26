import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server as HttpServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newKey, Peer, startServer, type Server } from "./harness";

interface Push {
  title: string;
  message: string;
  priority: string;
  url: string;
}

const VERSION = "1.4.4";

describe("connection alerts and admin actions", () => {
  const key = newKey();
  let server: Server;
  let pushover: HttpServer;
  const pushes: Push[] = [];
  const devices: Record<string, { peer: Peer; uuid: string }> = {};
  let conn = 100;

  beforeAll(async () => {
    pushover = createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const f = new URLSearchParams(body);
        pushes.push({
          title: f.get("title")!,
          message: f.get("message")!,
          priority: f.get("priority")!,
          url: f.get("url")!,
        });
        res.end('{"status":1}');
      });
    });
    await new Promise<void>((r) => pushover.listen(0, "127.0.0.1", r));
    const port = (pushover.address() as { port: number }).port;
    server = await startServer({
      PRIVATE_KEY: key.secret,
      PUSHOVER_APP_TOKEN: "app",
      PUSHOVER_USER_KEY: "user",
      PUSHOVER_API_URL: `http://127.0.0.1:${port}/1/messages.json`,
    });
    for (const id of ["700000001", "700000002"]) {
      const uuid = randomBytes(16);
      const peer = await Peer.connect(`${server.ws}/ws/id`);
      peer.send({ register_pk: { id, uuid, pk: randomBytes(32) } });
      expect((await peer.next()).register_pk_response.result).toBe(0);
      devices[id] = { peer, uuid: uuid.toString("base64") };
    }
  });
  afterAll(async () => {
    Object.values(devices).forEach((d) => d.peer.close());
    await server?.stop();
    pushover?.close();
  });

  const post = (path: string, body: unknown) =>
    fetch(`${server.http}${path}`, { method: "POST", body: JSON.stringify(body) });

  // What the controlled device posts to its API server for one incoming connection.
  const report = (device: string, connId: number, fields: Record<string, unknown>) =>
    post("/api/audit/conn", {
      id: device,
      uuid: devices[device].uuid,
      conn_id: connId,
      nonce: randomBytes(8).toString("hex"),
      ...fields,
    });

  async function request(device: string): Promise<any> {
    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id: device, licence_key: key.publicKey, version: VERSION } });
    try {
      // A refusal comes straight back; otherwise the device is asked to connect.
      const refused = await ctl.next(1000).then((m) => m.punch_hole_response, () => undefined);
      if (refused) return { refused };
      return { ph: (await devices[device].peer.next(2000)).punch_hole };
    } finally {
      ctl.close();
    }
  }

  async function session(device: string, peer = "800000001", name = "jack"): Promise<number> {
    await request(device);
    const id = ++conn;
    await report(device, id, { action: "new", ip: "127.0.0.1" });
    await report(device, id, { peer: [peer, name], type: 0, primary_auth: 3 });
    return id;
  }

  async function nextPush(): Promise<Push> {
    for (let i = 0; i < 50 && !pushes.length; i++) await new Promise((r) => setTimeout(r, 100));
    const p = pushes.shift();
    if (!p) throw new Error("no notification");
    return p;
  }

  async function noPush(): Promise<void> {
    await new Promise((r) => setTimeout(r, 500));
    expect(pushes.map((p) => p.title)).toEqual([]);
  }

  async function act(link: string, action: string): Promise<void> {
    const u = new URL(link);
    const r = await fetch(`${u.origin}${u.pathname}`, {
      method: "POST",
      body: new URLSearchParams({ k: u.searchParams.get("k")!, action }),
      redirect: "manual",
    });
    expect(r.status).toBe(303);
  }

  const heartbeat = (device: string, conns: number[], uuid = devices[device].uuid) =>
    post("/api/heartbeat", { id: device, uuid, conns }).then((r) => r.json());

  let link: string;

  it("alerts when a session logs in, linking to a details page", async () => {
    await post("/api/sysinfo", {
      id: "700000001",
      uuid: devices["700000001"].uuid,
      hostname: "office-pc",
      username: "alex",
      os: "macOS 26",
    });
    await session("700000001");
    const p = await nextPush();
    expect(p.title).toBe("RustDesk: remote desktop session started");
    expect(p.message).toContain("jack (800000001) → office-pc (700000001)");
    expect(p.message).toContain("127.0.0.1");
    expect(p.priority).toBe("0");
    link = p.url;

    const page = await (await fetch(link)).text();
    for (const text of ["800000001", "office-pc", "alex", "127.0.0.1", "permanent password", VERSION]) {
      expect(page).toContain(text);
    }
    const u = new URL(link);
    expect((await fetch(`${u.origin}${u.pathname}?k=wrong`)).status).toBe(404);
  });

  it("alerts at high priority on an attempt that never logs in", async () => {
    await request("700000002");
    const id = ++conn;
    // Anything but an empty body makes the device retry the report and hold back the next.
    for (const r of [
      await report("700000002", id, { action: "new", ip: "127.0.0.1" }),
      await report("700000002", id, { action: "close" }),
    ]) {
      expect(r.status).toBe(200);
      expect(await r.text()).toBe("");
    }
    const p = await nextPush();
    expect(p.title).toBe("RustDesk: login attempt failed");
    expect(p.priority).toBe("1");
  });

  it("stays quiet for a trusted pair until the trust is undone", async () => {
    await act(link, "trust");
    expect(await (await fetch(link)).text()).toContain("Untrust");
    await session("700000001");
    // A failed attempt from the address the trusted client logs in from is quiet too.
    const id = ++conn;
    await report("700000001", id, { action: "new", ip: "127.0.0.1" });
    await report("700000001", id, { action: "close" });
    await noPush();

    await act(link, "untrust");
    await session("700000001");
    expect((await nextPush()).title).toBe("RustDesk: remote desktop session started");
  });

  it("ends a session through the device's heartbeat, which forged heartbeats cannot cancel", async () => {
    const id = await session("700000001", "800000002", "eve");
    const p = await nextPush();
    await act(p.url, "end");
    expect(await heartbeat("700000001", [id], randomBytes(16).toString("base64"))).toEqual({});
    expect(await heartbeat("700000001", [id, 5])).toEqual({ disconnect: [id] });
    expect(await heartbeat("700000001", [id])).toEqual({ disconnect: [id] });
    await report("700000001", id, { action: "close" });
    expect(await heartbeat("700000001", [])).toEqual({});
    expect(await (await fetch(p.url)).text()).toContain("The session has ended.");
  });

  it("blocks a client ID right after it logs in, until unblocked", async () => {
    await session("700000002", "800000003", "mallory");
    const first = await nextPush();
    await act(first.url, "block_id");

    const id = await session("700000002", "800000003", "mallory");
    const p = await nextPush();
    expect(p.title).toBe("RustDesk: blocked client disconnected");
    expect(await heartbeat("700000002", [id])).toEqual({ disconnect: [id] });

    await act(first.url, "unblock_id");
    const again = await session("700000002", "800000003", "mallory");
    expect((await nextPush()).title).toBe("RustDesk: remote desktop session started");
    expect(await heartbeat("700000002", [again])).toEqual({});
  });

  it("cuts a blocked client's relayed session as soon as it logs in", async () => {
    const device = "700000002";
    await session(device, "800000009", "intruder");
    const first = await nextPush();
    await act(first.url, "block_id");

    const ctl = await Peer.connect(`${server.ws}/ws/id`);
    ctl.send({ punch_hole_request: { id: device, licence_key: key.publicKey, version: VERSION } });
    const ph = (await devices[device].peer.next()).punch_hole;
    const uuid = randomUUID();
    const answer = await Peer.connect(`${server.ws}/ws/id`);
    answer.send({
      relay_response: { socket_addr: ph.socket_addr, uuid, relay_server: ph.relay_server, id: device, version: VERSION },
    });
    await ctl.next();
    const a = await Peer.connect(`${server.ws}/ws/relay`);
    a.send({ request_relay: { licence_key: key.publicKey, uuid } });
    const b = await Peer.connect(`${server.ws}/ws/relay`);
    b.send({ request_relay: { licence_key: key.publicKey, uuid } });
    a.sendRaw(Buffer.from("screen"));
    await b.frame();

    const id = ++conn;
    await report(device, id, { action: "new", ip: "127.0.0.1" });
    await report(device, id, { peer: ["800000009", "intruder"], type: 0 });
    await a.waitClosed(3000);
    await b.waitClosed(3000);
    expect((await nextPush()).title).toBe("RustDesk: blocked client disconnected");

    // Its client reconnecting does not repeat the alert.
    await session(device, "800000009", "intruder");
    await noPush();
    await act(first.url, "unblock_id");
    for (const p of [ctl, answer]) p.close();
  });

  it("pauses new connections to one device without affecting others", async () => {
    await act(link, "pause");
    expect((await request("700000001")).refused.other_failure).toBe(
      "Connections to this device are paused by the administrator",
    );
    expect((await request("700000002")).ph).toBeTruthy();
    expect(await (await fetch(link)).text()).toContain("Resume");
    await act(link, "unpause");
    expect((await request("700000001")).ph).toBeTruthy();
  });

  it("turns the whole relay off and back on", async () => {
    await act(link, "relay_off");
    await expect(Peer.connect(`${server.ws}/ws/relay`)).rejects.toThrow(/403/);
    expect((await request("700000002")).refused.other_failure).toBe(
      "The relay is turned off by the administrator",
    );
    expect(await heartbeat("700000002", [42])).toEqual({ disconnect: [42] });
    expect((await fetch(link)).status).toBe(200);

    await act(link, "relay_on");
    (await Peer.connect(`${server.ws}/ws/relay`)).close();
    expect((await request("700000002")).ph).toBeTruthy();
  });

  it("blocks a client IP address and unblocks it", async () => {
    await act(link, "block_ip");
    expect((await request("700000002")).refused.other_failure).toBe("Connection refused by the server");
    await expect(Peer.connect(`${server.ws}/ws/relay`)).rejects.toThrow(/403/);
    await act(link, "unblock_ip");
    expect((await request("700000002")).ph).toBeTruthy();
  });

  it("ignores reports that do not come from the registered machine", async () => {
    const r = await post("/api/audit/conn", {
      id: "700000001",
      uuid: randomBytes(16).toString("base64"),
      conn_id: 1,
      action: "new",
      ip: "198.51.100.7",
    });
    expect(r.status).toBe(403);
    await noPush();
  });
});
