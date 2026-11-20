# RustDesk server on Cloudflare Workers

A RustDesk rendezvous (ID) server and relay server that run on Cloudflare Workers and
Durable Objects. Nothing to host or patch: unmodified RustDesk clients connect to it over
WebSocket, and sessions stay **end-to-end encrypted** between the two peers.

```
                    wss://rd.example.com/ws/id                   ┌──────────────────────┐
 controlled device ─────────────────────────────┐                │ Registry (1 Durable  │
 (holds it open)                                ├──── Worker ───▶│ Object): id → key,   │
 controlling client ────────────────────────────┘                │ signs {id, key},     │
                    wss://rd.example.com/ws/relay                │ brokers sessions     │
 both peers ────────────────────────────────────────── Worker ─▶ Relay Durable Object: │
                                                                 │ pairs by session id, │
                                                                 │ forwards bytes       │
                                                                 └──────────────────────┘
```

## How end-to-end encryption works here

RustDesk encrypts sessions between the two peers; servers only forward ciphertext. What the
server contributes is trust: each device registers its public key, and the server signs
`{id, public key}` with its own Ed25519 key. The connecting client checks that signature
against the server key configured in its **Key** field, then runs the key exchange with the
peer. A server that cannot sign (like the
[server demo](https://github.com/rustdesk/rustdesk-server-demo)) leaves clients falling back to
an **unencrypted** session. This server signs, so sessions are encrypted.

The first device to register an ID owns it (bound to that machine's uuid), exactly as `hbbs`
does. That binding is what stops someone else from registering your ID with their own key
and getting it signed.

The server sees metadata (IDs, IP addresses, when sessions happen, how much data), never
session content.

## Deploy

You need a Cloudflare account and a domain on Cloudflare. The Workers Free plan works for
light use; see [Cost](#cost).

1. Install dependencies:

   ```bash
   npm ci
   ```

2. Create the server key. Either generate a new one:

   ```bash
   npm run genkey
   ```

   or reuse an existing `hbbs` key (`id_ed25519`), so clients already set up for that server
   keep working. Store the secret half:

   ```bash
   npx wrangler secret put PRIVATE_KEY
   ```

3. In `wrangler.jsonc`, uncomment `routes` and set your hostname (for example
   `rd.example.com`).

4. Deploy:

   ```bash
   npx wrangler deploy
   ```

## Configure the clients

Every device, both the ones you control and the ones you connect from, needs:

| Setting (Settings → Network) | Value |
| --- | --- |
| ID server | `rd.example.com` |
| Relay server | leave empty (or `rd.example.com`) |
| API server | `https://rd.example.com` |
| Key | the public key from step 2 |
| Use WebSocket | on |

The API server entry is what makes the client use `wss://` instead of `ws://`. Devices that
are not in WebSocket mode cannot reach this server at all: Workers accept HTTP and WebSocket
only, not RustDesk's raw TCP/UDP ports.

For a custom client build, set the same options: `custom-rendezvous-server`, `api-server`,
`key` and `allow-websocket=Y` (plus `relay-server` if you want it fixed).

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `PRIVATE_KEY` (secret) | required | base64 of the 64-byte Ed25519 secret key, `hbbs` format |
| `REQUIRE_KEY` | `true` | refuse clients and relay connections without the matching Key. `false` lets anyone who knows your hostname use your server |
| `RELAY_SERVER` | host the client used | relay address handed to peers in hub mode |
| `RELAY_HOST_TEMPLATE` | unset | e.g. `{token}.relay.example.com`; see below |
| `HEARTBEAT_SECONDS` | `40` | how often idle devices are pinged; clients drop the connection after 3 missed pings |

### Scaling the relay

By default every session goes through one shared relay Durable Object (the hub). A Durable
Object is single-threaded, so the hub handles a handful of concurrent sessions (roughly 5–10
desktop streams).

For more, set `RELAY_HOST_TEMPLATE`. The server then gives every session its own hostname, so
its own relay Durable Object, placed near the first peer to connect:

1. Add a proxied wildcard DNS record, for example `*.relay.example.com`, and a matching
   Worker route `*.relay.example.com/*`. A two-level wildcard needs an Advanced Certificate;
   a one-level template such as `{token}.example.com` is covered by Universal SSL.
2. Set `"RELAY_HOST_TEMPLATE": "{token}.relay.example.com"` and deploy.
3. Leave the **Relay server** field empty on clients. The controlled device uses its own
   Relay server setting over the one the server offers, so a set value sends every session to
   the hub.

## Known limits

- **Every session is relayed.** WebSocket mode has no peer-to-peer path, so all traffic flows
  through Cloudflare, and latency depends on where the relay Durable Object sits.
- **Deploying drops live sessions** and device connections. Clients reconnect on their own.
- **No RustDesk Server Pro features:** accounts, address book sync, device groups, strategies,
  audit logs. The API answers the client's heartbeat and nothing else, so the client keeps
  those features hidden.
- **No bandwidth limits or IP blocking** (hbbs's IP blocker is not ported). With
  `REQUIRE_KEY` on, only holders of the Key can open sessions, but anyone can register an ID,
  as with hbbs.
- **No backpressure on the relay.** A peer that reads much slower than the other sends can
  make the relay object buffer until Cloudflare resets it. RustDesk's own frame pacing keeps
  this rare.
- LAN discovery, UDP hole punching and WebRTC trickle-ICE messages are not handled; none of
  them is used in WebSocket mode.

## Cost

Workers have no egress charges. Durable Objects bill compute time and messages:

- Idle devices cost almost nothing. The registry hibernates between heartbeats.
- An active relayed session keeps its relay object awake, roughly **$0.006–0.01 per
  session-hour** on the Paid plan (128 MB × wall time, plus incoming messages at 20:1).
- Each device posts `/api/heartbeat` every 15 seconds while idle (every 3 seconds while it is
  being controlled): about 5,800 Worker requests a day per idle device. On the Free plan
  (100,000 requests a day) that alone caps you at about 15 devices.

Check current pricing before relying on these numbers.

## Development

```bash
npm run typecheck
npm test
```

The tests start the Worker in local `workerd` and play both peers against it. They encode
messages with the client's own `libs/hbb_common/protos/rendezvous.proto`, so check out the
`libs/hbb_common` submodule first.
