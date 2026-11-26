import { DurableObject } from "cloudflare:workers";
import { requireKey, sendableCloseCode, type Env } from "./env";
import { PbError, RM, unwrap } from "./pb";
import { publicKeyFromSecret } from "./sign";

// Same contract as hbbr: the first message on a relay connection is a RequestRelay carrying
// the session uuid (and the server key); two connections with the same uuid are paired and
// everything after that is forwarded untouched. The relay never sends anything itself.

interface Att {
  t: number;
  uuid?: string;
  paired?: boolean;
}

interface Waiter {
  ws: WebSocket;
  early: (ArrayBuffer | string)[];
  size: number;
  timer: ReturnType<typeof setTimeout>;
}

const PAIR_TIMEOUT_MS = 30_000;
// The controlled side sends its signed handshake as soon as it connects, often before the
// controller arrives; that is a few hundred bytes, so this is generous.
const MAX_EARLY_BYTES = 4 << 20;
const MAX_REQUEST = 64 * 1024;
const RELAY_UUID = /^[A-Za-z0-9_-]{1,128}$/;

function attachment(ws: WebSocket): Att | undefined {
  return (ws.deserializeAttachment() as Att | null) ?? undefined;
}

function size(m: ArrayBuffer | string): number {
  return typeof m === "string" ? m.length : m.byteLength;
}

function close(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    // already closed
  }
}

export class Relay extends DurableObject<Env> {
  private peers = new Map<WebSocket, WebSocket>();
  private waiting = new Map<string, Waiter>();
  // Unidentified connections; the pending timer also keeps the object in memory, so state
  // that is not in an attachment cannot be lost to hibernation before pairing.
  private firstMessage = new Map<WebSocket, ReturnType<typeof setTimeout>>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    const byUuid = new Map<string, WebSocket[]>();
    for (const ws of ctx.getWebSockets()) {
      const a = attachment(ws);
      if (a?.uuid && a.paired) {
        byUuid.set(a.uuid, [...(byUuid.get(a.uuid) ?? []), ws]);
      } else {
        close(ws, 1011, "relay restarted");
      }
    }
    for (const [, pair] of byUuid) {
      if (pair.length === 2) {
        this.peers.set(pair[0], pair[1]);
        this.peers.set(pair[1], pair[0]);
      } else {
        pair.forEach((ws) => close(ws, 1011, "relay restarted"));
      }
    }
  }

  async fetch(): Promise<Response> {
    const [client, server] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ t: Date.now() } satisfies Att);
    this.firstMessage.set(
      server,
      setTimeout(() => {
        this.firstMessage.delete(server);
        close(server, 1008, "no relay request");
      }, PAIR_TIMEOUT_MS),
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string): Promise<void> {
    const peer = this.peers.get(ws);
    if (peer) {
      try {
        peer.send(message);
      } catch {
        this.teardown(ws, 1011, "peer gone");
      }
      return;
    }
    const a = attachment(ws);
    if (!a?.uuid) return this.onRequest(ws, message);
    const w = this.waiting.get(a.uuid);
    if (w?.ws !== ws) return this.teardown(ws, 1011, "not paired");
    w.size += size(message);
    if (w.size > MAX_EARLY_BYTES) return this.teardown(ws, 1009, "too much data before pairing");
    w.early.push(message);
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    this.teardown(ws, sendableCloseCode(code), reason || "peer closed");
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    this.teardown(ws, 1011, "peer error");
  }

  closeSession(uuid: string): void {
    for (const ws of this.ctx.getWebSockets()) {
      if (attachment(ws)?.uuid === uuid) this.teardown(ws, 1000, "ended by the administrator");
    }
  }

  closeAll(): void {
    for (const ws of this.ctx.getWebSockets()) this.teardown(ws, 1000, "relay turned off");
  }

  private onRequest(ws: WebSocket, message: ArrayBuffer | string): void {
    clearTimeout(this.firstMessage.get(ws) ?? null);
    this.firstMessage.delete(ws);
    let uuid: string;
    let key: string;
    try {
      if (typeof message === "string" || message.byteLength > MAX_REQUEST) throw new PbError("");
      const parsed = unwrap(new Uint8Array(message));
      if (parsed?.kind !== RM.RequestRelay) throw new PbError("");
      uuid = parsed.body.str(2);
      key = parsed.body.str(6);
    } catch (e) {
      if (!(e instanceof PbError)) throw e;
      return close(ws, 1008, "expected RequestRelay");
    }
    if (!RELAY_UUID.test(uuid)) return close(ws, 1008, "invalid uuid");
    if (requireKey(this.env) && key.trim() !== publicKeyFromSecret(this.env.PRIVATE_KEY)) {
      return close(ws, 1008, "key mismatch");
    }

    const w = this.waiting.get(uuid);
    if (!w) {
      ws.serializeAttachment({ t: Date.now(), uuid, paired: false } satisfies Att);
      this.waiting.set(uuid, {
        ws,
        early: [],
        size: 0,
        timer: setTimeout(() => this.teardown(ws, 1000, "pair timeout"), PAIR_TIMEOUT_MS),
      });
      return;
    }
    clearTimeout(w.timer);
    this.waiting.delete(uuid);
    ws.serializeAttachment({ t: Date.now(), uuid, paired: true } satisfies Att);
    w.ws.serializeAttachment({ t: Date.now(), uuid, paired: true } satisfies Att);
    this.peers.set(ws, w.ws);
    this.peers.set(w.ws, ws);
    try {
      for (const m of w.early) ws.send(m);
    } catch {
      this.teardown(ws, 1011, "peer gone");
    }
  }

  private teardown(ws: WebSocket, code: number, reason: string): void {
    clearTimeout(this.firstMessage.get(ws) ?? null);
    this.firstMessage.delete(ws);
    const a = attachment(ws);
    const w = a?.uuid ? this.waiting.get(a.uuid) : undefined;
    if (w?.ws === ws) {
      clearTimeout(w.timer);
      this.waiting.delete(a!.uuid!);
    }
    const peer = this.peers.get(ws);
    this.peers.delete(ws);
    if (peer) {
      this.peers.delete(peer);
      close(peer, code, reason);
    }
    close(ws, code, reason);
  }
}
