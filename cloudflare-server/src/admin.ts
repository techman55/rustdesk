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

function iso(t: number, seconds = false): string {
  return new Date(t).toISOString().slice(0, seconds ? 19 : 16).replace("T", " ") + "Z";
}

function ago(t: number, now: number): string {
  const s = Math.round((now - t) / 1000);
  if (s < 0) return `in ${until(-s)}`;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function when(t: number | undefined, now: number): string {
  return t ? `${iso(t)} (${ago(t, now)})` : "";
}

function until(s: number): string {
  return s < 3600 ? `${Math.round(s / 60)}m` : `${Math.round(s / 3600)}h`;
}

// A table cell: plain text, or [text, css class] for colored values.
type Cell = string | [string, string] | undefined | null;

function cell(v: Cell): string {
  if (Array.isArray(v)) return `<span class="${v[1]}">${esc(v[0])}</span>`;
  return esc(v);
}

function table(items: [string, Cell][]): string {
  const body = items
    .filter(([, v]) => v !== undefined && v !== "" && v !== null)
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${cell(v)}</td></tr>`)
    .join("");
  return `<table>${body}</table>`;
}

const bool = (b: boolean): Cell => (b ? ["true", "ok"] : ["false", "muted"]);

function sideTable(s: Side, now: number, extra: [string, Cell][] = []): string {
  return table([
    ["id", s.id ?? ["null  // known only after login", "muted"]],
    ["name", s.name],
    ["hostname", s.hostname],
    ["user", s.username],
    ["os", s.os],
    ["version", s.clientVersion ?? s.version],
    ["ip", s.ip],
    ["location", place(s.geo)],
    ["network", network(s.geo)],
    ...extra,
    ["registered", s.registered ? when(s.registeredAt, now) : s.id ? ["false  // not a device on this server", "muted"] : undefined],
    ["key_changed", s.registered && s.keyChangedAt !== s.registeredAt ? when(s.keyChangedAt, now) : undefined],
    ["online", s.registered ? bool(!!s.online) : undefined],
    ["online_since", s.online ? when(s.onlineSince, now) : undefined],
    ["last_checkin", when(s.lastHeartbeat, now)],
  ]);
}

function panel(name: string, comment: string, body: string): string {
  return `<section class="panel"><h2>${esc(name)}<small>// ${esc(comment)}</small></h2>${body}</section>`;
}

function button(v: EventView, action: string, text: string, tone: "danger" | "plain" = "plain"): string {
  return `<form method="post"><input type="hidden" name="k" value="${esc(v.token)}"><input type="hidden" name="action" value="${esc(action)}"><button class="${tone}">${esc(text)}</button></form>`;
}

// One action, shown as the command it amounts to, what it does or did, and its state.
function action(cmd: string, note: string, control: string, state?: [string, string]): string {
  const chip = state ? `<span class="chip ${state[1]}">${esc(state[0])}</span>` : "";
  const tokens = cmd.split(" ").map((t) => `<span class="tok">${esc(t)}</span>`).join(" ");
  return `<div class="cmd"><div class="desc"><div class="name"><span class="prompt">$</span> ${tokens}</div><div class="note">${esc(note)}</div></div><div class="ctl">${chip}${control}</div></div>`;
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
  const [type, value] = [s.source.slice(0, 2) === "id" ? "id" : "ip", s.source.slice(3)];
  return action(
    `silence --alert ${s.kind} --${type} ${value} --for 24h`,
    `"${ALERT_NAMES[s.kind] ?? s.kind}" alerts. ` +
      (s.until
        ? `Silenced until ${when(s.until, v.now)}. Attempts are still recorded, and blocks stay in force.`
        : "For 24 hours. Attempts are still recorded, and blocks stay in force."),
    button(v, s.until ? "unsilence" : "silence", s.until ? "Unsilence" : "Silence 24 h"),
    s.until ? ["silenced", "warn"] : undefined,
  );
}

function status(v: EventView): [string, string] {
  if (v.notifyKind === "blocked") return ["blocked", "bad"];
  if (v.closedAt) return v.authorizedAt ? ["ended", "muted"] : ["failed", "bad"];
  if (v.endRequestedAt) return ["ending", "warn"];
  if (v.authorizedAt) return ["live", "ok"];
  return ["not logged in", "warn"];
}

function timeline(v: EventView): string {
  const steps: [number | undefined, string, string, string][] = [
    [v.openedAt, "connected", v.client.ip ?? "", "info"],
    [v.authorizedAt, "logged_in", auth(v) || (v.client.id ?? ""), "ok"],
    [v.endRequestedAt, "end_requested", v.endedReason ?? "", "warn"],
    [v.closedAt, v.authorizedAt ? "closed" : "closed_no_login", "", v.authorizedAt ? "muted" : "bad"],
  ];
  const lines = steps
    .filter((s): s is [number, string, string, string] => !!s[0])
    .sort((a, b) => a[0] - b[0])
    .map(
      ([t, what, detail, tone]) =>
        `<li><time>${esc(iso(t, true))}</time><span class="${tone}">${esc(what)}</span><span class="muted">${esc(detail)}</span></li>`,
    )
    .join("");
  return `<ol class="log">${lines}</ol>`;
}

export function renderEvent(v: EventView): string {
  const now = v.now;
  const ended = !!v.closedAt;
  const c = v.client;
  const [statusText, statusTone] = status(v);
  const likely: Cell = c.likely?.length ? [`${c.likely.join(", ")}  // same ip, unconfirmed`, "warn"] : undefined;
  const idNeeded = "Unavailable: the client's ID is only known after it logs in.";

  const actions = [
    action(
      `trust --client ${c.id ?? "?"} --device ${v.device.id}`,
      !c.id
        ? idNeeded
        : v.trusted
          ? `No alerts for ${c.id} connecting to ${v.device.id}.`
          : `Stop alerts for ${c.id} connecting to ${v.device.id}.`,
      c.id ? button(v, v.trusted ? "untrust" : "trust", v.trusted ? "Untrust" : "Trust") : "",
      !c.id ? ["n/a", "muted"] : v.trusted ? ["trusted", "ok"] : undefined,
    ),
    action(
      `end-session --conn ${v.id.slice(0, 8)}`,
      ended
        ? "The session has ended."
        : v.endRequestedAt
          ? `Ending (${v.endedReason ?? "requested"}). The device drops it within seconds.`
          : "The device closes it within a few seconds; the client is told not to retry.",
      ended || v.endRequestedAt ? "" : button(v, "end", "End session", "danger"),
      ended ? ["ended", "muted"] : v.endRequestedAt ? ["ending", "warn"] : undefined,
    ),
    action(
      `block --id ${c.id ?? "?"}`,
      !c.id
        ? idNeeded
        : v.blockedId
          ? `${c.id} is blocked: any session it starts is ended right after it logs in.`
          : `End this session and any future session from ${c.id}, right after it logs in.`,
      c.id
        ? button(v, v.blockedId ? "unblock_id" : "block_id", v.blockedId ? "Unblock ID" : "Block ID", v.blockedId ? "plain" : "danger")
        : "",
      !c.id ? ["n/a", "muted"] : v.blockedId ? ["blocked", "bad"] : undefined,
    ),
    action(
      `block --ip ${c.ip ?? "?"}`,
      !c.ip
        ? "Unavailable: the address is unknown."
        : v.blockedIp
          ? `${c.ip} is blocked from starting connections.`
          : `End this session and refuse new connections from ${c.ip}.`,
      c.ip
        ? button(v, v.blockedIp ? "unblock_ip" : "block_ip", v.blockedIp ? "Unblock IP" : "Block IP", v.blockedIp ? "plain" : "danger")
        : "",
      !c.ip ? ["n/a", "muted"] : v.blockedIp ? ["blocked", "bad"] : undefined,
    ),
    silenceAction(v),
    action(
      `pause --device ${v.device.id} --for 24h`,
      v.pausedUntil
        ? `Paused until ${when(v.pausedUntil, now)}. Other devices are not affected.`
        : `New connections to ${label(v.device)}, for 24 hours. Sessions already open continue; other devices are not affected.`,
      button(v, v.pausedUntil ? "unpause" : "pause", v.pausedUntil ? "Resume" : "Pause 24 h"),
      v.pausedUntil ? ["paused", "warn"] : undefined,
    ),
    action(
      "relay --off --for 24h",
      v.relayOffUntil
        ? `Off until ${when(v.relayOffUntil, now)}. No remote sessions can run, including yours.`
        : "Turns off the whole relay for 24 hours: ends every session and refuses new ones, including yours. This page keeps working.",
      button(v, v.relayOffUntil ? "relay_on" : "relay_off", v.relayOffUntil ? "Turn relay on" : "Turn off 24 h", v.relayOffUntil ? "plain" : "danger"),
      v.relayOffUntil ? ["relay off", "bad"] : undefined,
    ),
  ].join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${esc(statusText)} · ${esc(label(c))} → ${esc(label(v.device))}</title>
<style>
:root{--bg:#f6f8fa;--panel:#fff;--fg:#1f2328;--muted:#6e7781;--line:#d0d7de;--soft:#eaeef2;--head:#f6f8fa;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;--info:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#010409;--panel:#0d1117;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;--soft:#21262d;--head:#161b22;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--info:#58a6ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.55 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
.wrap{max-width:980px;margin:0 auto;padding:20px 16px 40px}
.crumbs{color:var(--muted)}.crumbs b{color:var(--fg);font-weight:600}
h1{font-size:17px;font-weight:600;margin:10px 0 6px;display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.route{color:var(--muted);word-break:break-word}.route code{color:var(--fg);font:inherit}
.pill,.chip{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:0 9px;font-size:12px;line-height:20px;white-space:nowrap}
.pill:before{content:"\\25CF  ";}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info{color:var(--info)}.muted{color:var(--muted)}
.done{margin:14px 0 0;border:1px solid var(--line);border-left:3px solid var(--ok);background:var(--panel);padding:7px 12px}
.done:before{content:"\\2713  ok  ";color:var(--ok);font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px;align-items:start}
@media (max-width:760px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:16px}
.grid .panel{margin-top:0}
h2{margin:0;padding:8px 12px;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;background:var(--head);border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:baseline}
h2 small{text-transform:none;letter-spacing:0;font-weight:400;color:var(--muted)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:5px 12px;border-top:1px solid var(--soft)}
tr:first-child th,tr:first-child td{border-top:0}
th{width:34%;color:var(--muted);font-weight:400;white-space:nowrap}
td{word-break:break-word}
.log{list-style:none;margin:0;padding:8px 12px}
.log li{display:grid;grid-template-columns:auto auto 1fr;gap:14px;padding:2px 0}
.log time{color:var(--muted)}
@media (max-width:560px){.log li{grid-template-columns:auto 1fr;gap:2px 12px;padding:4px 0}.log time{grid-column:1/-1}}
.tok{white-space:nowrap}
.cmd{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:10px 12px;border-top:1px solid var(--soft)}
.cmd:first-of-type{border-top:0}
.name{font-weight:600}.prompt{color:var(--muted);font-weight:400}
.note{color:var(--muted);margin-top:2px}
.ctl{display:flex;align-items:center;gap:8px;flex-shrink:0}
form{margin:0}
button{font:inherit;font-size:12px;color:var(--fg);background:var(--head);border:1px solid var(--line);border-radius:6px;padding:5px 12px;cursor:pointer;white-space:nowrap}
button:hover{border-color:var(--muted)}
button.danger{color:var(--bad)}button.danger:hover{border-color:var(--bad)}
@media (max-width:560px){.cmd{flex-direction:column;align-items:flex-start}}
footer{margin-top:18px;color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<div class="crumbs">rustdesk / events / <b>${esc(v.id.slice(0, 8))}</b></div>
<h1><span class="pill ${statusTone}">${esc(statusText)}</span>${esc(typeName(v).toLowerCase())}</h1>
<div class="route"><code>${esc(label(c))}</code> ──▶ <code>${esc(label(v.device))}</code></div>
${v.done && DONE[v.done] ? `<div class="done">${esc(DONE[v.done])}</div>` : ""}
<div class="grid">
${panel("client", "connecting side", sideTable(c, now, [["probably", likely]]))}
${panel("device", "being accessed", sideTable(v.device, now))}
</div>
<div class="grid">
${panel("session", "what was opened", table([
    ["type", typeName(v)],
    ["login", auth(v) || (v.authorizedAt ? "yes" : ["none", "warn"])],
    ["alarm", v.alarm !== undefined ? [ALARMS[v.alarm] ?? `type ${v.alarm}`, "bad"] : undefined],
    ["relay", v.relayHost],
    ["event_id", v.id],
  ]))}
${panel("timeline", "utc", timeline(v))}
</div>
${panel("actions", "each one can be undone here", actions)}
<footer>rendered ${esc(iso(now, true))} · keep this link private: it grants these actions</footer>
</div></body></html>`;
}
