import { DurableObject } from "cloudflare:workers";
import { addrKey, demangle, formatIp, mangle, parseIp, type SockAddr } from "./addr";
import { requireKey, sendableCloseCode, type Env } from "./env";
import { Msg, PbError, PunchFailure, RegisterPkResult, RM, unwrap, wrap } from "./pb";
import { loadSigner, type Signer } from "./sign";

// Per-connection state, kept in the WebSocket attachment so it survives hibernation.
interface Att {
  ip: string;
  // A unique stand-in for the client's source port: Cloudflare does not expose the real one,
  // and (ip, port) is what peers echo back to route a RelayResponse.
  port: number;
  host: string;
  t: number;
  id?: string; // set once this socket registered as a device
  reg?: number;
  want?: string; // the peer this controller connection asked for
}

interface PeerRow {
  uuid: Uint8Array;
  pk: Uint8Array;
  ip: string;
}

// hbbs bounds rendezvous messages at 64 KiB; an online query for ~5000 ids is the largest.
const MAX_MESSAGE = 64 * 1024;
const MAX_ONLINE_QUERY = 5000;
const NON_DEVICE_IDLE_MS = 5 * 60_000;
const DEFAULT_HEARTBEAT_SECONDS = 40;
const REG_WINDOW_MS = 6_000;
const MAX_ID_LEN = 253;
const CUSTOM_ID = /^[a-zA-Z][\w-]{5,15}$/;
const RELAY_UUID = /^[A-Za-z0-9_-]{1,128}$/;

let signerCache: { key: string; signer: Promise<Signer> } | undefined;

function attachment(ws: WebSocket): Att | undefined {
  return (ws.deserializeAttachment() as Att | null) ?? undefined;
}

function keyOf(a: Att): string {
  return `${a.ip}|${a.port}`;
}

function sockAddr(a: Att): SockAddr {
  return { ip: parseIp(a.ip) ?? new Uint8Array(4), port: a.port };
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function toBuffer(u: Uint8Array): ArrayBuffer {
  return u.slice().buffer;
}

function close(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    // already closed
  }
}

function send(ws: WebSocket, kind: number, body: Msg): void {
  try {
    ws.send(wrap(kind, body));
  } catch {
    // the socket closed under us; its close handler cleans up
  }
}

export class Registry extends DurableObject<Env> {
  private byAddr = new Map<string, WebSocket>();
  private devices = new Map<string, WebSocket>();
  private lastSeen = new Map<WebSocket, number>();
  private regRate = new Map<string, { n: number; t: number }>();
  private alarmSet = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS peers (
      id TEXT PRIMARY KEY,
      uuid BLOB NOT NULL,
      pk BLOB NOT NULL,
      ip TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )`);
    const now = Date.now();
    for (const ws of ctx.getWebSockets()) {
      const a = attachment(ws);
      if (!a) continue;
      this.byAddr.set(keyOf(a), ws);
      this.lastSeen.set(ws, now);
      if (a.id) this.bindDevice(a.id, ws, a.reg ?? 0);
    }
  }

  async fetch(request: Request): Promise<Response> {
    const ip = formatIp(
      parseIp(request.headers.get("CF-Connecting-IP") ?? "") ?? new Uint8Array([127, 0, 0, 1]),
    );
    const port = this.allocPort(ip);
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    const a: Att = { ip, port, host: new URL(request.url).hostname, t: Date.now() };
    server.serializeAttachment(a);
    this.byAddr.set(keyOf(a), server);
    this.lastSeen.set(server, a.t);
    await this.ensureAlarm();
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
    const a = attachment(ws);
    if (!a) return;
    this.lastSeen.set(ws, Date.now());
    if (typeof message === "string" || message.byteLength === 0) return; // heartbeat echo
    if (message.byteLength > MAX_MESSAGE) {
      close(ws, 1009, "message too large");
      return;
    }
    try {
      const parsed = unwrap(new Uint8Array(message));
      if (!parsed) return;
      const { kind, body } = parsed;
      switch (kind) {
        case RM.RegisterPk:
          return this.onRegisterPk(ws, a, body);
        case RM.PunchHoleRequest:
          return await this.onPunchHoleRequest(ws, a, body);
        case RM.RequestRelay:
          return this.onRequestRelay(ws, a, body);
        case RM.RelayResponse:
          return await this.onRelayResponse(body);
        case RM.OnlineRequest:
          return this.onOnlineRequest(ws, body);
        case RM.TestNatRequest:
          return send(ws, RM.TestNatResponse, new Msg().setInt(1, a.port));
      }
    } catch (e) {
      if (!(e instanceof PbError)) throw e;
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    this.forget(ws);
    close(ws, sendableCloseCode(code), reason);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.forget(ws);
  }

  // Devices only answer heartbeats the server sends: the client drops its rendezvous
  // connection after 1.5x keep_alive of silence, and WebSocket pings do not count.
  async alarm(): Promise<void> {
    const now = Date.now();
    const hb = this.heartbeatMs();
    const empty = new ArrayBuffer(0);
    let open = 0;
    for (const ws of this.ctx.getWebSockets()) {
      const a = attachment(ws);
      if (!a) continue;
      if (a.id) {
        if (now - (this.lastSeen.get(ws) ?? now) > 3 * hb) {
          this.forget(ws);
          close(ws, 1001, "heartbeat timeout");
          continue;
        }
        try {
          ws.send(empty);
        } catch {
          this.forget(ws);
          continue;
        }
      } else if (now - a.t > NON_DEVICE_IDLE_MS) {
        this.forget(ws);
        close(ws, 1000, "idle");
        continue;
      }
      open++;
    }
    this.alarmSet = open > 0;
    if (this.alarmSet) await this.ctx.storage.setAlarm(now + hb);
  }

  private heartbeatMs(): number {
    const s = Number(this.env.HEARTBEAT_SECONDS);
    return (Number.isFinite(s) && s > 0 ? s : DEFAULT_HEARTBEAT_SECONDS) * 1000;
  }

  private async ensureAlarm(): Promise<void> {
    if (this.alarmSet) return;
    if ((await this.ctx.storage.getAlarm()) === null) {
      await this.ctx.storage.setAlarm(Date.now() + this.heartbeatMs());
    }
    this.alarmSet = true;
  }

  private signer(): Promise<Signer> {
    if (signerCache?.key !== this.env.PRIVATE_KEY) {
      signerCache = { key: this.env.PRIVATE_KEY, signer: loadSigner(this.env.PRIVATE_KEY) };
    }
    return signerCache.signer;
  }

  private allocPort(ip: string): number {
    for (;;) {
      const port = 1024 + Math.floor(Math.random() * (65536 - 1024));
      if (!this.byAddr.has(`${ip}|${port}`)) return port;
    }
  }

  private bindDevice(id: string, ws: WebSocket, reg: number): void {
    const cur = this.devices.get(id);
    if (cur && cur !== ws && (attachment(cur)?.reg ?? 0) > reg) return;
    this.devices.set(id, ws);
  }

  private forget(ws: WebSocket): void {
    this.lastSeen.delete(ws);
    const a = attachment(ws);
    if (!a) return;
    if (this.byAddr.get(keyOf(a)) === ws) this.byAddr.delete(keyOf(a));
    if (a.id && this.devices.get(a.id) === ws) this.devices.delete(a.id);
  }

  private peerRow(id: string): PeerRow | undefined {
    const r = this.ctx.storage.sql
      .exec<{ uuid: ArrayBuffer; pk: ArrayBuffer; ip: string }>(
        "SELECT uuid, pk, ip FROM peers WHERE id = ?",
        id,
      )
      .toArray()[0];
    return r && { uuid: new Uint8Array(r.uuid), pk: new Uint8Array(r.pk), ip: r.ip };
  }

  private registerTooFrequent(id: string): boolean {
    const now = Date.now();
    if (this.regRate.size > 10_000) {
      for (const [k, v] of this.regRate) if (now - v.t > REG_WINDOW_MS) this.regRate.delete(k);
    }
    const r = this.regRate.get(id);
    if (!r || now - r.t > REG_WINDOW_MS) {
      this.regRate.set(id, { n: 1, t: now });
      return false;
    }
    if (r.n > 2) return true;
    r.n++;
    r.t = now;
    return false;
  }

  // Mirrors hbbs: the first device to register an id owns it (bound to its machine uuid), and
  // a known uuid may not swap its key from a new address. That binding is what stops anyone
  // from getting this server to sign their own key for someone else's id.
  private onRegisterPk(ws: WebSocket, a: Att, m: Msg): void {
    const id = m.str(1);
    const uuid = m.bytes(2);
    const pk = m.bytes(3);
    const oldId = m.str(4);
    const reply = (result: number, keepAlive = 0) =>
      send(ws, RM.RegisterPkResponse, new Msg().setInt(1, result).setInt(2, keepAlive));

    if (oldId) return this.changeId(oldId, id, uuid, reply);
    if (!uuid.length || uuid.length > 256 || pk.length !== 32) return;
    if (id.length < 6 || id.length > MAX_ID_LEN) return reply(RegisterPkResult.UUID_MISMATCH);
    if (this.registerTooFrequent(id)) return reply(RegisterPkResult.TOO_FREQUENT);

    const now = Date.now();
    const row = this.peerRow(id);
    if (!row) {
      this.ctx.storage.sql.exec(
        "INSERT INTO peers (id, uuid, pk, ip, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        id,
        toBuffer(uuid),
        toBuffer(pk),
        a.ip,
        now,
        now,
      );
    } else if (!equal(row.uuid, uuid) || (row.ip !== a.ip && !equal(row.pk, pk))) {
      return reply(RegisterPkResult.UUID_MISMATCH);
    } else if (row.ip !== a.ip || !equal(row.pk, pk)) {
      this.ctx.storage.sql.exec(
        "UPDATE peers SET pk = ?, ip = ?, updated_at = ? WHERE id = ?",
        toBuffer(pk),
        a.ip,
        now,
        id,
      );
    }

    a.id = id;
    a.reg = now;
    ws.serializeAttachment(a);
    this.bindDevice(id, ws, now);
    reply(RegisterPkResult.OK, Math.ceil((2 * this.heartbeatMs()) / 1000));
  }

  private changeId(
    oldId: string,
    newId: string,
    uuid: Uint8Array,
    reply: (result: number) => void,
  ): void {
    if (!CUSTOM_ID.test(newId)) return reply(RegisterPkResult.INVALID_ID_FORMAT);
    if (!uuid.length) return;
    if (this.registerTooFrequent(`change:${oldId}`)) return reply(RegisterPkResult.TOO_FREQUENT);
    const oldRow = this.peerRow(oldId);
    if (oldRow && !equal(oldRow.uuid, uuid)) return reply(RegisterPkResult.UUID_MISMATCH);
    const newRow = this.peerRow(newId);
    if (newRow && !equal(newRow.uuid, uuid)) return reply(RegisterPkResult.ID_EXISTS);
    if (oldRow && oldId !== newId) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("DELETE FROM peers WHERE id = ?", newId);
        this.ctx.storage.sql.exec(
          "UPDATE peers SET id = ?, updated_at = ? WHERE id = ?",
          newId,
          Date.now(),
          oldId,
        );
      });
    }
    reply(RegisterPkResult.OK);
  }

  private relayServer(host: string): string {
    const template = this.env.RELAY_HOST_TEMPLATE?.trim();
    if (template) {
      const token = Array.from(crypto.getRandomValues(new Uint8Array(6)), (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("");
      return template.replace("{token}", token);
    }
    return this.env.RELAY_SERVER?.trim() || host;
  }

  private async onPunchHoleRequest(ws: WebSocket, a: Att, m: Msg): Promise<void> {
    const id = m.str(1);
    const fail = (failure: number) =>
      send(ws, RM.PunchHoleResponse, new Msg().setInt(3, failure));
    if (requireKey(this.env)) {
      const signer = await this.signer();
      if (m.str(3).trim() !== signer.publicKeyB64) return fail(PunchFailure.LICENSE_MISMATCH);
    }
    const target = this.devices.get(id);
    if (!target) {
      return fail(this.peerRow(id) ? PunchFailure.OFFLINE : PunchFailure.ID_NOT_EXIST);
    }
    a.want = id;
    ws.serializeAttachment(a);
    // In WebSocket mode the controlled side always answers through a relay, with a
    // RelayResponse that onRelayResponse routes back here.
    const ph = new Msg()
      .setBytes(1, mangle(sockAddr(a)))
      .setStr(2, this.relayServer(a.host))
      .setInt(3, m.int32(2))
      .setInt(5, m.bool(8))
      .setStr(10, m.str(12));
    send(target, RM.PunchHole, ph);
  }

  private onRequestRelay(ws: WebSocket, a: Att, m: Msg): void {
    if (!RELAY_UUID.test(m.str(2))) return;
    const id = m.str(1);
    const target = this.devices.get(id);
    if (!target) {
      send(ws, RM.RelayResponse, new Msg().setStr(6, "Remote desktop is offline"));
      return;
    }
    a.want = id;
    ws.serializeAttachment(a);
    m.setBytes(3, mangle(sockAddr(a)));
    send(target, RM.RequestRelay, m);
  }

  private async onRelayResponse(m: Msg): Promise<void> {
    const uuid = m.str(2);
    if (!(uuid === "" && m.str(3) === "") && !RELAY_UUID.test(uuid)) return;
    const to = demangle(m.bytes(1));
    const controller = to && this.byAddr.get(addrKey(to));
    if (!controller) return;
    const ca = attachment(controller);
    m.delete(1);
    if (m.has(4)) {
      const id = m.str(4);
      if (ca?.want !== id) return;
      const row = this.peerRow(id);
      const pk =
        row && m.str(7) ? await (await this.signer()).signIdPk(id, row.pk) : new Uint8Array(0);
      m.delete(4).setBytes(5, pk, true);
    }
    send(controller, RM.RelayResponse, m);
  }

  private onOnlineRequest(ws: WebSocket, m: Msg): void {
    const peers = m.strs(2).slice(0, MAX_ONLINE_QUERY);
    const states = new Uint8Array(Math.ceil(peers.length / 8));
    peers.forEach((p, i) => {
      if (this.devices.has(p)) states[i >> 3] |= 1 << (7 - (i & 7));
    });
    send(ws, RM.OnlineResponse, new Msg().setBytes(1, states));
  }
}
