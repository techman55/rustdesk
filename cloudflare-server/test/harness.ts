import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { RendezvousMessage } from "./proto";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

export interface ServerKey {
  secret: string;
  publicKey: string;
  x: string; // base64url, for node:crypto
}

export function newKey(): ServerKey {
  const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
  const seed = Buffer.from(jwk.d!, "base64url");
  const pk = Buffer.from(jwk.x!, "base64url");
  return {
    secret: Buffer.concat([seed, pk]).toString("base64"),
    publicKey: pk.toString("base64"),
    x: jwk.x!,
  };
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

export interface Server {
  http: string;
  ws: string;
  stop(): Promise<void>;
}

export async function startServer(vars: Record<string, string>): Promise<Server> {
  const port = await freePort();
  const persist = mkdtempSync(join(tmpdir(), "rd-cf-"));
  const args = [
    "wrangler",
    "dev",
    "--ip",
    "127.0.0.1",
    "--port",
    String(port),
    "--persist-to",
    persist,
    "--show-interactive-dev-session=false",
    "--log-level",
    "warn",
  ];
  for (const [k, v] of Object.entries(vars)) args.push("--var", `${k}:${v}`);
  // Outbound requests from the Worker go to local test servers, never through a proxy.
  const env = { ...process.env };
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete env[k];
  const child: ChildProcess = spawn("npx", args, { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout!.on("data", (d) => (output += d));
  child.stderr!.on("data", (d) => (output += d));
  const http = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 90_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error(`wrangler dev exited:\n${output}`);
    try {
      await fetch(`${http}/`);
      break;
    } catch {
      // not listening yet
    }
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      throw new Error(`wrangler dev did not start:\n${output}`);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return {
    http,
    ws: `ws://127.0.0.1:${port}`,
    stop: async () => {
      child.kill("SIGTERM");
      await new Promise((r) => setTimeout(r, 300));
      if (child.exitCode === null) child.kill("SIGKILL");
      rmSync(persist, { recursive: true, force: true });
    },
  };
}

export type Decoded = { union: string; [k: string]: any };

// One WebSocket, as a RustDesk client would hold it: binary protobuf frames, plus the
// empty frames the server uses as heartbeats.
export class Peer {
  readonly ws: WebSocket;
  private frames: Buffer[] = [];
  private waiters: (() => void)[] = [];
  closed?: { code: number; reason: string };
  readonly open: Promise<void>;

  constructor(url: string, headers?: Record<string, string>) {
    this.ws = new WebSocket(url, { headers });
    this.open = new Promise((resolve, reject) => {
      this.ws.once("open", () => resolve());
      this.ws.once("error", reject);
    });
    this.ws.on("message", (data: Buffer) => {
      this.frames.push(data);
      this.wake();
    });
    this.ws.on("close", (code, reason) => {
      this.closed = { code, reason: reason.toString() };
      this.wake();
    });
  }

  static async connect(url: string, headers?: Record<string, string>): Promise<Peer> {
    const p = new Peer(url, headers);
    await p.open;
    return p;
  }

  private wake() {
    const w = this.waiters;
    this.waiters = [];
    w.forEach((f) => f());
  }

  send(msg: Record<string, unknown>): void {
    this.ws.send(RendezvousMessage.encode(RendezvousMessage.create(msg)).finish());
  }

  sendRaw(data: Buffer | string): void {
    this.ws.send(data);
  }

  async frame(timeoutMs = 5000, skipEmpty = true): Promise<Buffer> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      while (this.frames.length) {
        const f = this.frames.shift()!;
        if (!(skipEmpty && f.length === 0)) return f;
      }
      if (this.closed) throw new Error(`socket closed: ${this.closed.code} ${this.closed.reason}`);
      const left = deadline - Date.now();
      if (left <= 0) throw new Error("timed out waiting for a frame");
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.waiters.push(() => {
          clearTimeout(t);
          resolve();
        });
      });
    }
  }

  async next(timeoutMs?: number): Promise<Decoded> {
    const f = await this.frame(timeoutMs);
    return RendezvousMessage.toObject(RendezvousMessage.decode(f), {
      oneofs: true,
      defaults: true,
      longs: Number,
    }) as Decoded;
  }

  async expectNothing(ms: number): Promise<void> {
    await new Promise((r) => setTimeout(r, ms));
    const real = this.frames.filter((f) => f.length > 0);
    if (real.length) throw new Error(`unexpected frame(s): ${real.length}`);
  }

  async waitClosed(timeoutMs = 5000): Promise<{ code: number; reason: string }> {
    const deadline = Date.now() + timeoutMs;
    while (!this.closed) {
      if (Date.now() > deadline) throw new Error("socket did not close");
      await new Promise((r) => setTimeout(r, 50));
    }
    return this.closed;
  }

  close(): void {
    this.ws.close();
  }
}
