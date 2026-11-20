import type { Registry } from "./registry";
import type { Relay } from "./relay";

export interface Env {
  REGISTRY: DurableObjectNamespace<Registry>;
  RELAY: DurableObjectNamespace<Relay>;
  // Secret: base64 of the 64-byte Ed25519 secret key (hbbs `id_ed25519` format).
  PRIVATE_KEY: string;
  // "false" lets clients without the matching Key use this server (hbbs without -k).
  REQUIRE_KEY?: string;
  // Relay address handed to peers in hub mode. Defaults to the host the client connected to.
  RELAY_SERVER?: string;
  // e.g. "{token}.relay.example.com": every session gets its own host, so its own relay
  // Durable Object. Needs a wildcard DNS record and route for that pattern.
  RELAY_HOST_TEMPLATE?: string;
  HEARTBEAT_SECONDS?: string;
}

export function requireKey(env: Env): boolean {
  return (env.REQUIRE_KEY ?? "true").trim().toLowerCase() !== "false";
}

// Codes a peer may report but an endpoint may not send (RFC 6455 7.4.1).
export function sendableCloseCode(code: number): number {
  return code >= 1000 && code < 5000 && ![1004, 1005, 1006, 1015].includes(code) ? code : 1000;
}
