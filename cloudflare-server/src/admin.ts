import type { Geo } from "./monitor";

export interface Side {
  id?: string;
  name?: string;
  hostname?: string;
  username?: string;
  os?: string;
  version?: string;
  clientVersion?: string;
  ip?: string;
  geo?: Geo;
  registered: boolean;
  registeredAt?: number;
  keyChangedAt?: number;
  onlineSince?: number;
  lastHeartbeat?: number;
  online?: boolean;
  likely?: string[];
}

export interface EventView {
  id: string;
  token: string;
  now: number;
  device: Side;
  client: Side;
  connType?: number;
  primaryAuth?: number;
  twoFactor?: number;
  alarm?: number;
  openedAt: number;
  authorizedAt?: number;
  closedAt?: number;
  endRequestedAt?: number;
  endedReason?: string;
  relayHost?: string;
  notifyKind?: string;
  trusted: boolean;
  blockedId: boolean;
  blockedIp: boolean;
  pausedUntil?: number;
  relayOffUntil?: number;
  // kind is the alert this event sent; source is "id:<client id>" or "ip:<address>"
  silence?: { kind: string; source: string; until?: number; available: boolean };
  done?: string;
}

// Values the controlled client reports (src/server/connection.rs).
const CONN_TYPES: Record<number, string> = {
  0: "Remote desktop",
  1: "File transfer",
  2: "Port forward",
  3: "Camera",
  4: "Terminal",
};
const PRIMARY_AUTH: Record<number, string> = {
  1: "accepted on screen",
  2: "one-time password",
  3: "permanent password",
  4: "switch sides",
};
const ALERT_NAMES: Record<string, string> = {
  started: "session started",
  blocked: "blocked client disconnected",
  failed: "login attempt failed",
  pending: "login attempt in progress",
  alarm: "security alert",
};
const TWO_FACTOR: Record<number, string> = { 1: "2FA code", 2: "trusted device" };
const ALARMS: Record<number, string> = {
  0: "blocked by the device's IP whitelist",
  1: "more than 30 wrong passwords",
  2: "more than 6 wrong passwords in a minute",
  6: "too many wrong passwords from this network",
  7: "repeated failed terminal logins",
  8: "too many concurrent terminal logins",
  9: "tried to use a feature it was not granted",
  10: "blocked by the device's ID whitelist",
};

function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function place(geo?: Geo): string {
  if (!geo) return "";
  return [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
}

function network(geo?: Geo): string {
  if (!geo?.org && !geo?.asn) return "";
  return [geo.org, geo.asn ? `AS${geo.asn}` : ""].filter(Boolean).join(" ");
}

function label(s: Side): string {
  const name = s.name || s.hostname;
  if (s.id && name) return `${name} (${s.id})`;
  return s.id || name || "unknown";
}

function from(s: Side): string {
  return [place(s.geo), s.ip, network(s.geo)].filter(Boolean).join(" · ") || "unknown location";
}

function auth(v: EventView): string {
  const parts = [v.primaryAuth ? PRIMARY_AUTH[v.primaryAuth] : "", v.twoFactor ? TWO_FACTOR[v.twoFactor] : ""];
  return parts.filter(Boolean).join(" + ");
}

function typeName(v: EventView): string {
  return v.connType !== undefined ? (CONN_TYPES[v.connType] ?? "Unknown") : "Connection";
}

export function renderMessage(v: EventView): { title: string; message: string; priority: 0 | 1 } {
  const target = label(v.device);
  switch (v.notifyKind) {
    case "started":
      return {
        title: `RustDesk: ${typeName(v).toLowerCase()} session started`,
        message: `${label(v.client)} → ${target}\nFrom ${from(v.client)}${auth(v) ? `\nLogin: ${auth(v)}` : ""}`,
        priority: 0,
      };
    case "blocked":
      return {
        title: "RustDesk: blocked client disconnected",
        message: `${label(v.client)} → ${target}\nFrom ${from(v.client)}\nIts ID is blocked; the session is being ended.`,
        priority: 1,
      };
    case "alarm":
      return {
        title: "RustDesk: security alert",
        message: `${label(v.client)} → ${target}\nFrom ${from(v.client)}\n${capital(ALARMS[v.alarm ?? -1] ?? "security alarm")}.`,
        priority: 1,
      };
    case "pending":
      return {
        title: "RustDesk: login attempt in progress",
        message: `Connection to ${target}\nFrom ${from(v.client)}\nNot logged in after 3 minutes.`,
        priority: 1,
      };
    default:
      return {
        title: "RustDesk: login attempt failed",
        message: `Connection to ${target}\nFrom ${from(v.client)}\nNever logged in (wrong password, rejected, or cancelled).`,
        priority: 1,
      };
  }
}

function capital(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function when(t: number | undefined, now: number): string {
  if (!t) return "";
  const s = Math.round((now - t) / 1000);
  const rel =
    s < 0
      ? `in ${until(-s)}`
      : s < 60
        ? `${s} s ago`
        : s < 3600
          ? `${Math.round(s / 60)} min ago`
          : s < 172800
            ? `${Math.round(s / 3600)} h ago`
            : `${Math.round(s / 86400)} days ago`;
  return `${new Date(t).toISOString().slice(0, 16).replace("T", " ")} UTC (${rel})`;
}

function until(s: number): string {
  return s < 3600 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`;
}

function rows(items: [string, unknown][]): string {
  return items
    .filter(([, v]) => v !== undefined && v !== "" && v !== null)
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`)
    .join("");
}

function sideRows(s: Side, now: number, extra: [string, unknown][] = []): string {
  return rows([
    ["ID", s.id ?? "unknown (it never logged in)"],
    ["Name", s.name],
    ["Computer name", s.hostname],
    ["User", s.username],
    ["OS", s.os],
    ["RustDesk version", s.clientVersion ?? s.version],
    ["IP address", s.ip],
    ["Location", place(s.geo)],
    ["Network", network(s.geo)],
    ...extra,
    ["Registered here", s.registered ? when(s.registeredAt, now) : s.id ? "no" : undefined],
    ["Key or address last changed", s.registered && s.keyChangedAt !== s.registeredAt ? when(s.keyChangedAt, now) : undefined],
    ["Online now", s.registered ? (s.online ? "yes" : "no") : undefined],
    ["Connected to this server since", s.online ? when(s.onlineSince, now) : undefined],
    ["Last check-in", when(s.lastHeartbeat, now)],
  ]);
}

function button(v: EventView, action: string, text: string): string {
  return `<form method="post"><input type="hidden" name="k" value="${esc(v.token)}"><input type="hidden" name="action" value="${esc(action)}"><button>${esc(text)}</button></form>`;
}

function action(title: string, state: string, control: string): string {
  return `<div class="action"><div><b>${esc(title)}</b><br><span>${esc(state)}</span></div>${control}</div>`;
}

const DONE: Record<string, string> = {
  trust: "Pair trusted.",
  untrust: "Pair no longer trusted.",
  end: "Asked the device to end the session.",
  block_id: "Client ID blocked.",
  unblock_id: "Client ID unblocked.",
  block_ip: "Client IP address blocked.",
  unblock_ip: "Client IP address unblocked.",
  pause: "New connections to this device paused for 24 hours.",
  unpause: "Connections to this device resumed.",
  relay_off: "Relay turned off for 24 hours.",
  relay_on: "Relay turned back on.",
  silence: "These alerts are silenced for 24 hours.",
  unsilence: "These alerts are back on.",
};

function silenceAction(v: EventView): string {
  const s = v.silence;
  if (!s || (!s.available && !s.until)) return "";
  const [type, value] = [s.source.slice(0, 2) === "id" ? "ID" : "IP", s.source.slice(3)];
  return action(
    `Silence "${ALERT_NAMES[s.kind] ?? s.kind}" alerts from ${type} ${value}`,
    s.until
      ? `Silenced until ${when(s.until, v.now)}. Attempts are still recorded, and blocks stay in force.`
      : "For 24 hours. Attempts are still recorded, and blocks stay in force.",
    button(v, s.until ? "unsilence" : "silence", s.until ? "Unsilence" : "Silence 24 h"),
  );
}

export function renderEvent(v: EventView): string {
  const now = v.now;
  const status = v.closedAt
    ? v.authorizedAt
      ? "Ended"
      : "Ended without logging in"
    : v.authorizedAt
      ? "Logged in"
      : "Connected, not logged in";
  const ended = !!v.closedAt;
  const c = v.client;
  const likely = c.likely?.length ? `possibly ${c.likely.join(", ")} (same IP address)` : undefined;

  const actions = [
    action(
      "Trust this pair",
      !c.id
        ? "Unavailable: the client's ID is only known after it logs in."
        : v.trusted
          ? `No alerts for ${c.id} connecting to ${v.device.id}.`
          : `Stop alerts for ${c.id} connecting to ${v.device.id}.`,
      c.id ? button(v, v.trusted ? "untrust" : "trust", v.trusted ? "Untrust" : "Trust") : "",
    ),
    action(
      "End this session",
      ended
        ? "The session has ended."
        : v.endRequestedAt
          ? `Ending (${v.endedReason ?? "requested"}). The device drops it within seconds.`
          : "The device closes it within a few seconds; the client is told not to retry.",
      ended || v.endRequestedAt ? "" : button(v, "end", "End session"),
    ),
    action(
      "Block this client's ID",
      !c.id
        ? "Unavailable: the client's ID is only known after it logs in."
        : v.blockedId
          ? `${c.id} is blocked: any session it starts is ended right after it logs in.`
          : `End this session and any future session from ${c.id}, right after it logs in.`,
      c.id ? button(v, v.blockedId ? "unblock_id" : "block_id", v.blockedId ? "Unblock ID" : "Block ID") : "",
    ),
    action(
      "Block this client's IP address",
      !c.ip
        ? "Unavailable: the address is unknown."
        : v.blockedIp
          ? `${c.ip} is blocked from starting connections.`
          : `End this session and refuse new connections from ${c.ip}.`,
      c.ip ? button(v, v.blockedIp ? "unblock_ip" : "block_ip", v.blockedIp ? "Unblock IP" : "Block IP") : "",
    ),
    silenceAction(v),
    action(
      `Pause new connections to ${label(v.device)}`,
      v.pausedUntil
        ? `Paused until ${when(v.pausedUntil, now)}. Other devices are not affected.`
        : "For 24 hours. Sessions already open continue; other devices are not affected.",
      button(v, v.pausedUntil ? "unpause" : "pause", v.pausedUntil ? "Resume" : "Pause 24 h"),
    ),
    action(
      "Turn off the whole relay",
      v.relayOffUntil
        ? `Off until ${when(v.relayOffUntil, now)}. No remote sessions can run, including yours.`
        : "For 24 hours: ends every session and refuses new ones, including yours. This page keeps working.",
      button(v, v.relayOffUntil ? "relay_on" : "relay_off", v.relayOffUntil ? "Turn relay on" : "Turn off 24 h"),
    ),
  ].join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RustDesk connection</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#111;background:#fff;max-width:720px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:4px 8px 4px 0;border-bottom:1px solid #ddd}
th{width:40%;font-weight:bold}td{word-break:break-word}
.done{background:#eef6ee;border:1px solid #9c9;padding:8px;margin:12px 0}
.action{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #ddd}
.action span{color:#444;font-size:14px}button{font:inherit;padding:6px 12px;white-space:nowrap;cursor:pointer}
</style></head><body>
<h1>RustDesk connection</h1>
<div>${esc(status)} · ${esc(typeName(v))}</div>
${v.done && DONE[v.done] ? `<div class="done">${esc(DONE[v.done])}</div>` : ""}
<h2>Connecting client</h2>
<table>${sideRows(c, now, [["Probably", likely]])}</table>
<h2>Device being accessed</h2>
<table>${sideRows(v.device, now)}</table>
<h2>Session</h2>
<table>${rows([
    ["Type", typeName(v)],
    ["Login", auth(v) || (v.authorizedAt ? "yes" : "not logged in")],
    ["Alarm", v.alarm !== undefined ? ALARMS[v.alarm] ?? `type ${v.alarm}` : undefined],
    ["Connected", when(v.openedAt, now)],
    ["Logged in", when(v.authorizedAt, now)],
    ["Ended", when(v.closedAt, now)],
    ["End requested", v.endRequestedAt ? `${when(v.endRequestedAt, now)}: ${v.endedReason ?? ""}` : undefined],
    ["Relay", v.relayHost],
  ])}</table>
<h2>Actions</h2>
${actions}
</body></html>`;
}
