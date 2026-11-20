import type { Env } from "./env";
import { relayObjectName } from "./relay-name";

export { Registry } from "./registry";
export { Relay } from "./relay";

// With `allow-websocket` on, a client set up for host H reaches the rendezvous server at
// wss://H/ws/id and a relay server at wss://H/ws/relay (hbb_common::websocket::check_ws).
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    switch (url.pathname) {
      case "/ws/id":
      case "/ws/relay": {
        if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
          return new Response("Expected a WebSocket upgrade", { status: 426 });
        }
        if (!env.PRIVATE_KEY) {
          return new Response("PRIVATE_KEY is not configured", { status: 500 });
        }
        if (url.pathname === "/ws/id") {
          return env.REGISTRY.get(env.REGISTRY.idFromName("registry")).fetch(request);
        }
        const name = relayObjectName(url.hostname, env.RELAY_HOST_TEMPLATE);
        return env.RELAY.get(env.RELAY.idFromName(name)).fetch(request);
      }
      // Setting an https api-server is what makes the client use wss://. The client then
      // polls this API; answering the heartbeat (and nothing else) keeps it from enabling
      // RustDesk Server Pro features this server does not have.
      case "/api/heartbeat":
        return Response.json({});
      default:
        return new Response("Not found", { status: 404 });
    }
  },
} satisfies ExportedHandler<Env>;
