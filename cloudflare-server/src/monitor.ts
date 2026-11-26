// Connection monitoring: devices report each incoming connection to their API server
// (/api/audit/conn: opened, logged in, closed; /api/audit/alarm: repeated failures). This
// turns those reports into Pushover alerts with a details page, and holds the admin's
// decisions (trusted pairs, blocks, pauses) that the rendezvous and relay paths enforce.

import { formatIp, parseIp } from "./addr";
import { renderEvent, renderMessage, type EventView, type Side } from "./admin";
import type { Env } from "./env";
import { pushoverConfigured, sendPushover, type Notice } from "./notify";
import { relayObjectName } from "./relay-name";
import { b64decode } from "./sign";

export interface Geo {
  country?: string;
  region?: string;
  city?: string;
  asn?: number;
  org?: string;
}

type Row = Record<string, SqlStorageValue>;

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const BLOCK_MS = DAY;
// The device reports a connection right after the relay is set up; this pairs that report
// with the request this server brokered (and saw the client's address and location for).
const MATCH_WINDOW_MS = 2 * MINUTE;
const PENDING_AFTER_MS = 3 * MINUTE;
// A device lists a connection in its heartbeats from the moment it opens, so a disconnect
// request older than this whose connection is no longer listed is done.
const DISCONNECT_GRACE_MS = MINUTE;
// If the device has not dropped the connection by then, close the relay as well.
const RELAY_FALLBACK_MS = 15_000;
const MAX_BODY = 64 * 1024;
const MAX_NOTIFY_ATTEMPTS = 5;
const RATE_WINDOW_MS = 10 * MINUTE;
const RATE_MAX = 20;
const DEFAULT_RETENTION_DAYS = 90;
// One "blocked client" alert per client and device in this window, however often it retries.
const BLOCKED_ALERT_WINDOW_MS = 10 * MINUTE;

// The device retries an audit post, and holds back its later ones, unless the answer is a
// 2xx with an empty body (post_audit_async in src/server/connection.rs).
const delivered = () => new Response(null, { status: 200 });

function log(event: string, fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ event, ...fields }));
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS device_info (
    id TEXT PRIMARY KEY, ip TEXT, geo TEXT, online_since INTEGER, last_heartbeat INTEGER,
    hostname TEXT, username TEXT, os TEXT, version TEXT, sysinfo_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS requests (
    at INTEGER NOT NULL, target TEXT NOT NULL, ip TEXT NOT NULL, geo TEXT, version TEXT,
    relay_host TEXT, uuid TEXT)`,
  `CREATE INDEX IF NOT EXISTS requests_target ON requests (target, ip, at)`,
  `CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, token TEXT NOT NULL, origin TEXT NOT NULL,
    device_id TEXT NOT NULL, conn_id INTEGER NOT NULL, ip TEXT, geo TEXT,
    client_version TEXT, relay_host TEXT, relay_uuid TEXT,
    peer_id TEXT, peer_name TEXT, conn_type INTEGER, primary_auth INTEGER, two_factor INTEGER,
    alarm INTEGER, opened_at INTEGER NOT NULL, authorized_at INTEGER, closed_at INTEGER,
    end_requested_at INTEGER, ended_reason TEXT,
    notify_kind TEXT, notified_at INTEGER, notify_attempts INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS events_conn ON events (device_id, conn_id, opened_at)`,
  `CREATE INDEX IF NOT EXISTS events_opened ON events (opened_at)`,
  `CREATE TABLE IF NOT EXISTS trusted (
    peer_id TEXT NOT NULL, device_id TEXT NOT NULL, at INTEGER NOT NULL,
    PRIMARY KEY (peer_id, device_id))`,
  `CREATE TABLE IF NOT EXISTS blocked_ids (peer_id TEXT PRIMARY KEY, at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY, at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS paused (device_id TEXT PRIMARY KEY, until INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS flags (name TEXT PRIMARY KEY, until INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS disconnects (
    device_id TEXT NOT NULL, conn_id INTEGER NOT NULL, at INTEGER NOT NULL,
    relay_closed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_id, conn_id))`,
  `CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, at INTEGER NOT NULL)`,
];

export const ACTIONS = [
  "trust",
  "untrust",
  "end",
  "block_id",
  "unblock_id",
  "block_ip",
  "unblock_ip",
  "pause",
  "unpause",
  "relay_off",
  "relay_on",
] as const;
type Action = (typeof ACTIONS)[number];

export function normIp(s: unknown): string {
  const b = typeof s === "string" ? parseIp(s) : undefined;
  return b ? formatIp(b) : "";
}

export function parseGeo(s: unknown): Geo | undefined {
  if (typeof s !== "string" || !s) return undefined;
  try {
    const g = JSON.parse(s);
    return g && typeof g === "object" ? (g as Geo) : undefined;
  } catch {
    return undefined;
  }
}

function str(v: unknown, max = 128): string | null {
  return typeof v === "string" && v ? v.slice(0, max) : null;
}

function int(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) ? v : null;
}

function randomHex(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

function sameSecret(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const SECURITY_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  // The page URL carries the access token.
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
};

export class Monitor {
  constructor(
    private sql: SqlStorage,
    private env: Env,
    private isOnline: (id: string) => boolean,
  ) {
    for (const s of SCHEMA) sql.exec(s);
  }

  // ---- hooks for the rendezvous and relay paths ----

  denyReason(target: string, ip: string, now = Date.now()): string | undefined {
    if (this.relayOffUntil(now)) return "The relay is turned off by the administrator";
    if (ip && this.one("SELECT 1 FROM blocked_ips WHERE ip = ?", ip)) {
      return "Connection refused by the server";
    }
    if (this.one("SELECT 1 FROM paused WHERE device_id = ? AND until > ?", target, now)) {
      return "Connections to this device are paused by the administrator";
    }
    return undefined;
  }

  relayAllowed(ip: string): boolean {
    return !this.relayOffUntil(Date.now()) && !(ip && this.one("SELECT 1 FROM blocked_ips WHERE ip = ?", ip));
  }

  recordRequest(r: {
    target: string;
    ip: string;
    geo?: string;
    version?: string;
    relayHost?: string;
    uuid?: string;
  }): void {
    this.sql.exec(
      "INSERT INTO requests (at, target, ip, geo, version, relay_host, uuid) VALUES (?, ?, ?, ?, ?, ?, ?)",
      Date.now(),
      r.target,
      r.ip,
      r.geo ?? null,
      r.version || null,
      r.relayHost || null,
      r.uuid || null,
    );
  }

  deviceOnline(id: string, ip: string, geo: string | undefined): void {
    this.sql.exec(
      `INSERT INTO device_info (id, ip, geo, online_since) VALUES (?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET ip = excluded.ip, geo = excluded.geo,
         online_since = excluded.online_since`,
      id,
      ip,
      geo ?? null,
      Date.now(),
    );
  }

  // ---- HTTP: the client API and the admin page ----

  async http(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const admin = url.pathname.match(/^\/admin\/e\/([0-9a-f]{32})$/);
    if (admin) return this.admin(request, url, admin[1]);
    if (request.method !== "POST") return new Response("Not found", { status: 404 });

    let body: Record<string, unknown>;
    try {
      const text = await request.text();
      if (text.length > MAX_BODY) throw new Error();
      body = JSON.parse(text);
      if (!body || typeof body !== "object") throw new Error();
    } catch {
      return new Response("Bad request", { status: 400 });
    }
    switch (url.pathname) {
      case "/api/heartbeat":
        return Response.json(await this.heartbeat(body));
      case "/api/sysinfo":
        this.sysinfo(body);
        // Anything but SYSINFO_UPDATED: that answer turns on the client's Pro features.
        return new Response("OK");
      case "/api/audit/conn":
        return this.auditConn(body, url.origin);
      case "/api/audit/alarm":
        return this.auditAlarm(body, url.origin);
      default:
        return new Response("Not found", { status: 404 });
    }
  }

  // ---- periodic work, run from the registry's alarm ----

  async tick(now = Date.now()): Promise<void> {
    for (const e of this.all(
      `SELECT * FROM events WHERE authorized_at IS NULL AND closed_at IS NULL
       AND notify_kind IS NULL AND opened_at < ?`,
      now - PENDING_AFTER_MS,
    )) {
      this.want(e, "pending");
    }
    for (const d of this.all(
      "SELECT device_id, conn_id FROM disconnects WHERE relay_closed = 0 AND at < ?",
      now - RELAY_FALLBACK_MS,
    )) {
      await this.closeEventRelay(String(d.device_id), Number(d.conn_id));
    }
    this.sql.exec("DELETE FROM disconnects WHERE at < ?", now - DAY);
    this.sql.exec("DELETE FROM requests WHERE at < ?", now - 10 * MINUTE);
    this.sql.exec("DELETE FROM nonces WHERE at < ?", now - 10 * MINUTE);
    this.sql.exec("DELETE FROM paused WHERE until < ?", now);
    this.sql.exec("DELETE FROM flags WHERE until < ?", now);
    const days = Number(this.env.EVENT_RETENTION_DAYS);
    const keep = (Number.isFinite(days) && days > 0 ? days : DEFAULT_RETENTION_DAYS) * DAY;
    this.sql.exec("DELETE FROM events WHERE opened_at < ?", now - keep);
    await this.sendPending();
  }

  // When a requested end becomes overdue and the relay should be closed as well.
  nextDue(): number | undefined {
    const r = this.one("SELECT MIN(at) AS at FROM disconnects WHERE relay_closed = 0");
    return r?.at === null || r?.at === undefined ? undefined : Number(r.at) + RELAY_FALLBACK_MS + 1000;
  }

  hasPendingWork(now = Date.now()): boolean {
    return !!this.one(
      `SELECT 1 FROM events WHERE (closed_at IS NULL AND authorized_at IS NULL
         AND notify_kind IS NULL AND opened_at > ?)
       OR (notify_kind IS NOT NULL AND notified_at IS NULL AND notify_attempts < ?)
       UNION SELECT 1 FROM disconnects`,
      now - DAY,
      MAX_NOTIFY_ATTEMPTS,
    );
  }

  // ---- device reports ----

  private deviceOk(id: unknown, uuid: unknown): id is string {
    if (typeof id !== "string" || typeof uuid !== "string") return false;
    const row = this.one("SELECT uuid FROM peers WHERE id = ?", id);
    if (!row) return false;
    try {
      const b = b64decode(uuid.replace(/-/g, "+").replace(/_/g, "/"));
      return equalBytes(b, new Uint8Array(row.uuid as ArrayBuffer));
    } catch {
      return false;
    }
  }

  // The client posts each record until it gets an answer, tagging it with a nonce.
  private firstTime(nonce: unknown): boolean {
    if (typeof nonce !== "string" || !nonce) return true;
    if (this.one("SELECT 1 FROM nonces WHERE nonce = ?", nonce.slice(0, 64))) return false;
    this.sql.exec("INSERT INTO nonces (nonce, at) VALUES (?, ?)", nonce.slice(0, 64), Date.now());
    return true;
  }

  private async heartbeat(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = body.id;
    if (!this.deviceOk(id, body.uuid)) return {};
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO device_info (id, last_heartbeat) VALUES (?, ?)
       ON CONFLICT (id) DO UPDATE SET last_heartbeat = excluded.last_heartbeat`,
      id,
      now,
    );
    const conns = Array.isArray(body.conns)
      ? body.conns.filter((c): c is number => Number.isInteger(c))
      : [];
    if (this.relayOffUntil(now)) return conns.length ? { disconnect: conns } : {};

    const disconnect: number[] = [];
    for (const d of this.all(
      "SELECT conn_id, at, relay_closed FROM disconnects WHERE device_id = ?",
      id,
    )) {
      const connId = Number(d.conn_id);
      if (conns.includes(connId)) {
        disconnect.push(connId);
        if (!d.relay_closed && now - Number(d.at) > RELAY_FALLBACK_MS) {
          await this.closeEventRelay(id, connId);
        }
      } else if (now - Number(d.at) > DISCONNECT_GRACE_MS) {
        this.sql.exec("DELETE FROM disconnects WHERE device_id = ? AND conn_id = ?", id, connId);
      }
    }
    if (disconnect.length) log("disconnect_sent", { device: id, conns, disconnect });
    return disconnect.length ? { disconnect } : {};
  }

  private sysinfo(body: Record<string, unknown>): void {
    if (!this.deviceOk(body.id, body.uuid)) return;
    this.sql.exec(
      `INSERT INTO device_info (id, hostname, username, os, version, sysinfo_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET hostname = excluded.hostname, username = excluded.username,
         os = excluded.os, version = excluded.version, sysinfo_at = excluded.sysinfo_at`,
      body.id,
      str(body.hostname),
      str(body.username),
      str(body.os, 256),
      str(body.version, 32),
      Date.now(),
    );
  }

  private async auditConn(body: Record<string, unknown>, origin: string): Promise<Response> {
    const device = body.id;
    if (!this.deviceOk(device, body.uuid)) return new Response("Forbidden", { status: 403 });
    const connId = int(body.conn_id);
    if (connId === null) return new Response("Bad request", { status: 400 });
    if (!this.firstTime(body.nonce)) return delivered();
    const now = Date.now();

    log("audit_conn", {
      device,
      conn: connId,
      action: body.action ?? (Array.isArray(body.peer) ? "login" : "other"),
      peer: Array.isArray(body.peer) ? body.peer[0] : undefined,
    });
    if (body.action === "new") {
      this.openEvent(device, connId, normIp(body.ip), origin, now);
    } else if (body.action === "close") {
      const e = this.findEvent(device, connId, now);
      if (e) {
        this.sql.exec("UPDATE events SET closed_at = ? WHERE id = ?", now, e.id);
        this.sql.exec("DELETE FROM disconnects WHERE device_id = ? AND conn_id = ?", device, connId);
        if (e.authorized_at === null) this.want({ ...e, closed_at: now }, "failed");
      }
    } else if (Array.isArray(body.peer)) {
      // A successful login: `peer` is [client id, client name] from the login request.
      const peerId = str(body.peer[0], 64);
      const e = this.findEvent(device, connId, now) ?? this.openEvent(device, connId, "", origin, now);
      this.sql.exec(
        `UPDATE events SET peer_id = ?, peer_name = ?, conn_type = ?, primary_auth = ?,
           two_factor = ?, authorized_at = ? WHERE id = ?`,
        peerId,
        str(body.peer[1]),
        int(body.type),
        int(body.primary_auth),
        int(body.two_factor),
        now,
        e.id,
      );
      const ev = this.event(String(e.id))!;
      if (peerId && this.one("SELECT 1 FROM blocked_ids WHERE peer_id = ?", peerId)) {
        this.requestEnd(ev, "The client's ID is blocked");
        await this.closeEventRelay(device, connId);
        const alerted = this.one(
          `SELECT 1 FROM events WHERE peer_id = ? AND device_id = ? AND notify_kind = 'blocked'
           AND notified_at > ?`,
          peerId,
          device,
          now - BLOCKED_ALERT_WINDOW_MS,
        );
        if (!alerted) this.want(ev, "blocked");
      } else if (!(peerId && this.isTrusted(peerId, device))) {
        this.want(ev, "started");
      }
    }
    await this.sendPending();
    return delivered();
  }

  private async auditAlarm(body: Record<string, unknown>, origin: string): Promise<Response> {
    const device = body.id;
    if (!this.deviceOk(device, body.uuid)) return new Response("Forbidden", { status: 403 });
    const connId = int(body.conn_id);
    const typ = int(body.typ);
    if (connId === null || typ === null) return new Response("Bad request", { status: 400 });
    if (!this.firstTime(body.nonce)) return delivered();
    let info: Record<string, unknown> = {};
    try {
      info = typeof body.info === "string" ? JSON.parse(body.info) : {};
    } catch {
      // keep what the event already has
    }
    const now = Date.now();
    const e =
      this.findEvent(device, connId, now) ??
      this.openEvent(device, connId, normIp(info.ip), origin, now);
    this.sql.exec(
      `UPDATE events SET alarm = ?, peer_id = COALESCE(peer_id, ?),
         peer_name = COALESCE(peer_name, ?) WHERE id = ?`,
      typ,
      str(info.id, 64),
      str(info.name),
      e.id,
    );
    this.want(this.event(String(e.id))!, "alarm");
    await this.sendPending();
    return delivered();
  }

  private openEvent(device: string, connId: number, ip: string, origin: string, now: number): Row {
    const req = ip
      ? this.one(
          `SELECT geo, version FROM requests WHERE target = ? AND ip = ? AND at > ?
           AND version IS NOT NULL ORDER BY at DESC LIMIT 1`,
          device,
          ip,
          now - MATCH_WINDOW_MS,
        )
      : undefined;
    const relay = ip
      ? this.one(
          `SELECT geo, relay_host, uuid FROM requests WHERE target = ? AND ip = ? AND at > ?
           AND uuid IS NOT NULL ORDER BY at DESC LIMIT 1`,
          device,
          ip,
          now - MATCH_WINDOW_MS,
        )
      : undefined;
    const id = randomHex(16);
    this.sql.exec(
      `INSERT INTO events (id, token, origin, device_id, conn_id, ip, geo, client_version,
         relay_host, relay_uuid, opened_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      randomHex(24),
      origin,
      device,
      connId,
      ip || null,
      req?.geo ?? relay?.geo ?? null,
      req?.version ?? null,
      relay?.relay_host ?? null,
      relay?.uuid ?? null,
      now,
    );
    const e = this.event(id)!;
    if (ip && this.one("SELECT 1 FROM blocked_ips WHERE ip = ?", ip)) {
      this.requestEnd(e, "The client's IP address is blocked");
    }
    return e;
  }

  private findEvent(device: string, connId: number, now: number): Row | undefined {
    return this.one(
      `SELECT * FROM events WHERE device_id = ? AND conn_id = ? AND opened_at > ?
       ORDER BY opened_at DESC LIMIT 1`,
      device,
      connId,
      now - DAY,
    );
  }

  private event(id: string): Row | undefined {
    return this.one("SELECT * FROM events WHERE id = ?", id);
  }

  private isTrusted(peerId: string, device: string): boolean {
    return !!this.one("SELECT 1 FROM trusted WHERE peer_id = ? AND device_id = ?", peerId, device);
  }

  // A failed attempt rarely carries the client's ID, so it counts as trusted when it comes
  // from an address a trusted client of this device is known to use.
  private trustedAttempt(e: Row): boolean {
    const device = String(e.device_id);
    if (e.peer_id) return this.isTrusted(String(e.peer_id), device);
    if (!e.ip) return false;
    return !!this.one(
      `SELECT 1 FROM trusted t WHERE t.device_id = ? AND (
         EXISTS (SELECT 1 FROM device_info d WHERE d.id = t.peer_id AND d.ip = ?)
         OR EXISTS (SELECT 1 FROM events e WHERE e.device_id = t.device_id
           AND e.peer_id = t.peer_id AND e.ip = ? AND e.authorized_at IS NOT NULL))`,
      device,
      e.ip,
      e.ip,
    );
  }

  // One alert per connection, except that a login (or a blocked login) is always reported
  // even if an earlier "still not logged in" alert went out.
  private want(e: Row, kind: "started" | "blocked" | "failed" | "pending" | "alarm"): void {
    const login = kind === "started" || kind === "blocked";
    const prev = e.notify_kind as string | null;
    if (prev && (!login || prev === "started" || prev === "blocked" || prev === "suppressed")) {
      return;
    }
    if (!login && this.trustedAttempt(e)) {
      this.sql.exec("UPDATE events SET notify_kind = 'trusted', notified_at = ? WHERE id = ?", Date.now(), e.id);
      return;
    }
    const recent = this.one(
      "SELECT COUNT(*) AS n FROM events WHERE device_id = ? AND notified_at > ? AND notify_kind != 'trusted'",
      e.device_id,
      Date.now() - RATE_WINDOW_MS,
    );
    if (Number(recent?.n ?? 0) >= RATE_MAX) {
      this.sql.exec("UPDATE events SET notify_kind = 'suppressed', notified_at = ? WHERE id = ?", Date.now(), e.id);
      return;
    }
    this.sql.exec(
      "UPDATE events SET notify_kind = ?, notified_at = NULL, notify_attempts = 0 WHERE id = ?",
      kind,
      e.id,
    );
  }

  private async sendPending(): Promise<void> {
    if (!pushoverConfigured(this.env)) return;
    const rows = this.all(
      `SELECT * FROM events WHERE notify_kind IN ('started', 'blocked', 'failed', 'pending', 'alarm')
       AND notified_at IS NULL AND notify_attempts < ? ORDER BY opened_at LIMIT 10`,
      MAX_NOTIFY_ATTEMPTS,
    );
    for (const e of rows) {
      // Claimed before the request goes out: other events may run while it is in flight.
      this.sql.exec(
        "UPDATE events SET notified_at = 0, notify_attempts = notify_attempts + 1 WHERE id = ?",
        e.id,
      );
      const started = Date.now();
      const ok = await sendPushover(this.env, this.notice(e));
      log("pushover", { kind: e.notify_kind, device: e.device_id, ok, ms: Date.now() - started });
      this.sql.exec("UPDATE events SET notified_at = ? WHERE id = ?", ok ? Date.now() : null, e.id);
    }
  }

  private notice(e: Row): Notice {
    const v = this.view(e);
    const { title, message, priority } = renderMessage(v);
    return {
      title,
      message,
      priority,
      url: `${e.origin}/admin/e/${e.id}?k=${e.token}`,
      urlTitle: "Details and actions",
    };
  }

  // ---- ending sessions ----

  private requestEnd(e: Row, reason: string): void {
    if (e.closed_at !== null) return;
    this.sql.exec(
      "INSERT OR IGNORE INTO disconnects (device_id, conn_id, at) VALUES (?, ?, ?)",
      e.device_id,
      e.conn_id,
      Date.now(),
    );
    this.sql.exec(
      "UPDATE events SET end_requested_at = COALESCE(end_requested_at, ?), ended_reason = COALESCE(ended_reason, ?) WHERE id = ?",
      Date.now(),
      reason,
      e.id,
    );
  }

  private async closeEventRelay(device: string, connId: number): Promise<void> {
    this.sql.exec(
      "UPDATE disconnects SET relay_closed = 1 WHERE device_id = ? AND conn_id = ?",
      device,
      connId,
    );
    const e = this.findEvent(device, connId, Date.now());
    if (e?.relay_uuid) {
      await this.closeRelay(e.relay_host as string | null, String(e.relay_uuid));
    } else {
      log("relay_close_skipped", { device, conn: connId, reason: "session relay unknown" });
    }
  }

  private async closeRelay(host: string | null, uuid: string | null): Promise<void> {
    const name = host ? relayObjectName(host, this.env.RELAY_HOST_TEMPLATE) : "hub";
    const stub = this.env.RELAY.get(this.env.RELAY.idFromName(name));
    try {
      const closed = uuid ? await stub.closeSession(uuid) : await stub.closeAll();
      log("relay_closed", { relay: name, uuid, sockets: closed });
    } catch (e) {
      log("relay_close_failed", { relay: name, uuid, error: String(e) });
    }
  }

  private async closeAllRelays(now: number): Promise<void> {
    const names = new Set(["hub"]);
    for (const r of this.all(
      "SELECT DISTINCT relay_host FROM events WHERE relay_host IS NOT NULL AND opened_at > ?",
      now - DAY,
    )) {
      names.add(relayObjectName(String(r.relay_host), this.env.RELAY_HOST_TEMPLATE));
    }
    for (const name of names) {
      try {
        await this.env.RELAY.get(this.env.RELAY.idFromName(name)).closeAll();
      } catch {
        // as above
      }
    }
  }

  private relayOffUntil(now: number): number | undefined {
    const r = this.one("SELECT until FROM flags WHERE name = 'relay_off' AND until > ?", now);
    return r ? Number(r.until) : undefined;
  }

  // ---- admin page ----

  private async admin(request: Request, url: URL, id: string): Promise<Response> {
    const e = this.event(id);
    const k = request.method === "POST" ? null : url.searchParams.get("k");
    if (request.method === "POST") {
      const form = await request.formData().catch(() => undefined);
      const token = form?.get("k");
      const action = form?.get("action");
      if (!e || typeof token !== "string" || !sameSecret(token, String(e.token))) {
        return new Response("Not found", { status: 404 });
      }
      if (typeof action === "string" && (ACTIONS as readonly string[]).includes(action)) {
        await this.act(e, action as Action);
      }
      const back = new URL(`/admin/e/${id}`, url.origin);
      back.searchParams.set("k", token);
      if (typeof action === "string") back.searchParams.set("done", action);
      return new Response(null, { status: 303, headers: { Location: back.pathname + back.search } });
    }
    if (request.method !== "GET" || !e || !k || !sameSecret(k, String(e.token))) {
      return new Response("Not found", { status: 404 });
    }
    const view = this.view(e);
    view.done = url.searchParams.get("done") ?? undefined;
    return new Response(renderEvent(view), { headers: SECURITY_HEADERS });
  }

  private async act(e: Row, action: Action): Promise<void> {
    const now = Date.now();
    const peer = e.peer_id as string | null;
    const ip = e.ip as string | null;
    switch (action) {
      case "trust":
        if (peer) {
          this.sql.exec(
            "INSERT OR IGNORE INTO trusted (peer_id, device_id, at) VALUES (?, ?, ?)",
            peer,
            e.device_id,
            now,
          );
        }
        break;
      case "untrust":
        if (peer) this.sql.exec("DELETE FROM trusted WHERE peer_id = ? AND device_id = ?", peer, e.device_id);
        break;
      case "end":
        this.requestEnd(e, "Ended by you");
        break;
      case "block_id":
        if (peer) {
          this.sql.exec("INSERT OR IGNORE INTO blocked_ids (peer_id, at) VALUES (?, ?)", peer, now);
          this.requestEnd(e, "The client's ID is blocked");
          if (e.closed_at === null) await this.closeEventRelay(String(e.device_id), Number(e.conn_id));
        }
        break;
      case "unblock_id":
        if (peer) this.sql.exec("DELETE FROM blocked_ids WHERE peer_id = ?", peer);
        break;
      case "block_ip":
        if (ip) {
          this.sql.exec("INSERT OR IGNORE INTO blocked_ips (ip, at) VALUES (?, ?)", ip, now);
          this.requestEnd(e, "The client's IP address is blocked");
          if (e.closed_at === null) await this.closeEventRelay(String(e.device_id), Number(e.conn_id));
        }
        break;
      case "unblock_ip":
        if (ip) this.sql.exec("DELETE FROM blocked_ips WHERE ip = ?", ip);
        break;
      case "pause":
        this.sql.exec(
          "INSERT OR REPLACE INTO paused (device_id, until) VALUES (?, ?)",
          e.device_id,
          now + BLOCK_MS,
        );
        break;
      case "unpause":
        this.sql.exec("DELETE FROM paused WHERE device_id = ?", e.device_id);
        break;
      case "relay_off":
        this.sql.exec(
          "INSERT OR REPLACE INTO flags (name, until) VALUES ('relay_off', ?)",
          now + BLOCK_MS,
        );
        await this.closeAllRelays(now);
        break;
      case "relay_on":
        this.sql.exec("DELETE FROM flags WHERE name = 'relay_off'");
        break;
    }
  }

  private side(id: string | null, ip?: string | null, geo?: Geo): Side {
    const s: Side = { id: id ?? undefined, ip: ip ?? undefined, geo, registered: false };
    if (!id) return s;
    const p = this.one("SELECT created_at, updated_at FROM peers WHERE id = ?", id);
    const d = this.one("SELECT * FROM device_info WHERE id = ?", id);
    if (p) {
      s.registered = true;
      s.registeredAt = Number(p.created_at);
      s.keyChangedAt = Number(p.updated_at);
      s.online = this.isOnline(id);
    }
    if (d) {
      s.hostname = (d.hostname as string | null) ?? undefined;
      s.username = (d.username as string | null) ?? undefined;
      s.os = (d.os as string | null) ?? undefined;
      s.version = (d.version as string | null) ?? undefined;
      s.onlineSince = (d.online_since as number | null) ?? undefined;
      s.lastHeartbeat = (d.last_heartbeat as number | null) ?? undefined;
      if (!s.ip) s.ip = (d.ip as string | null) ?? undefined;
      if (!s.geo) s.geo = parseGeo(d.geo);
    }
    return s;
  }

  private view(e: Row): EventView {
    const now = Date.now();
    const peer = e.peer_id as string | null;
    const ip = e.ip as string | null;
    const device = String(e.device_id);
    const client = this.side(peer, ip, parseGeo(e.geo));
    client.name = (e.peer_name as string | null) ?? undefined;
    client.clientVersion = (e.client_version as string | null) ?? undefined;
    if (!peer && ip) {
      client.likely = this.all(
        "SELECT id FROM device_info WHERE ip = ? AND id != ? LIMIT 5",
        ip,
        device,
      ).map((r) => String(r.id));
    }
    const paused = this.one("SELECT until FROM paused WHERE device_id = ? AND until > ?", device, now);
    return {
      id: String(e.id),
      token: String(e.token),
      now,
      device: this.side(device),
      client,
      connType: (e.conn_type as number | null) ?? undefined,
      primaryAuth: (e.primary_auth as number | null) ?? undefined,
      twoFactor: (e.two_factor as number | null) ?? undefined,
      alarm: (e.alarm as number | null) ?? undefined,
      openedAt: Number(e.opened_at),
      authorizedAt: (e.authorized_at as number | null) ?? undefined,
      closedAt: (e.closed_at as number | null) ?? undefined,
      endRequestedAt: (e.end_requested_at as number | null) ?? undefined,
      endedReason: (e.ended_reason as string | null) ?? undefined,
      relayHost: (e.relay_host as string | null) ?? undefined,
      notifyKind: (e.notify_kind as string | null) ?? undefined,
      trusted: !!peer && this.isTrusted(peer, device),
      blockedId: !!peer && !!this.one("SELECT 1 FROM blocked_ids WHERE peer_id = ?", peer),
      blockedIp: !!ip && !!this.one("SELECT 1 FROM blocked_ips WHERE ip = ?", ip),
      pausedUntil: paused ? Number(paused.until) : undefined,
      relayOffUntil: this.relayOffUntil(now),
    };
  }

  // ---- SQL helpers ----

  private all(query: string, ...args: SqlStorageValue[]): Row[] {
    return this.sql.exec(query, ...args).toArray() as Row[];
  }

  private one(query: string, ...args: SqlStorageValue[]): Row | undefined {
    return this.all(query, ...args)[0];
  }
}
