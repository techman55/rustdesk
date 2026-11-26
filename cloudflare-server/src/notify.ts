import type { Env } from "./env";

export interface Notice {
  title: string;
  message: string;
  url: string;
  urlTitle: string;
  priority: 0 | 1;
}

const PUSHOVER_URL = "https://api.pushover.net/1/messages.json";

export function pushoverConfigured(env: Env): boolean {
  return !!(env.PUSHOVER_APP_TOKEN && env.PUSHOVER_USER_KEY);
}

export async function sendPushover(env: Env, n: Notice): Promise<boolean> {
  const body = new URLSearchParams({
    token: env.PUSHOVER_APP_TOKEN ?? "",
    user: env.PUSHOVER_USER_KEY ?? "",
    title: n.title.slice(0, 250),
    message: n.message.slice(0, 1024),
    url: n.url.slice(0, 512),
    url_title: n.urlTitle.slice(0, 100),
    priority: String(n.priority),
  });
  try {
    const r = await fetch(env.PUSHOVER_API_URL || PUSHOVER_URL, {
      method: "POST",
      body,
      signal: AbortSignal.timeout(10_000),
    });
    return r.ok;
  } catch {
    return false;
  }
}
