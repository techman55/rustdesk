import type { Env } from "./env";
import { relayObjectName } from "./relay-name";

export { Registry } from "./registry";
export { Relay } from "./relay";

const API_PATHS = new Set(["/api/heartbeat", "/api/sysinfo", "/api/audit/conn", "/api/audit/alarm"]);

// Cloudflare's view of where the client is, for connection alerts. Rebuilt from request.cf
// on every request, so a client cannot supply its own.
function withGeo(request: Request): Request {
  const headers = new Headers(request.headers);
  headers.delete("X-RD-Geo");
  const cf = request.cf as Record<string, unknown> | undefined;
  if (cf) {
    headers.set(
      "X-RD-Geo",
      JSON.stringify({
        country: cf.country,
        region: cf.region,
        city: cf.city,
        asn: cf.asn,
        org: cf.asOrganization,
      }),
    );
  }
  return new Request(request, { headers });
}

// With `allow-websocket` on, a client set up for host H reaches the rendezvous server at
// wss://H/ws/id and a relay server at wss://H/ws/relay (hbb_common::websocket::check_ws).
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const registry = () => env.REGISTRY.get(env.REGISTRY.idFromName("registry"));
    switch (url.pathname) {
      case "/ws/id":
      case "/ws/relay": {
        if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
          return new Response("Expected a WebSocket upgrade", { status: 426 });
        }
        if (!env.PRIVATE_KEY) {
          return new Response("PRIVATE_KEY is not configured", { status: 500 });
        }
        if (url.pathname === "/ws/id") return registry().fetch(withGeo(request));
        if (!(await registry().relayAllowed(request.headers.get("CF-Connecting-IP") ?? ""))) {
          return new Response("Relay unavailable", { status: 403 });
        }
        const name = relayObjectName(url.hostname, env.RELAY_HOST_TEMPLATE);
        return env.RELAY.get(env.RELAY.idFromName(name)).fetch(request);
      }
      default:
        // The client polls this API once an https api-server is set (which is what makes it
        // use wss://), and reports connections to it.
        if (API_PATHS.has(url.pathname) || url.pathname.startsWith("/admin/")) {
          return registry().fetch(withGeo(request));
        }
        return new Response("Not found", { status: 404 });
    }
  },
} satisfies ExportedHandler<Env>;
