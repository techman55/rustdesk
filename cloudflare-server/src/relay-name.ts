// Which relay Durable Object a /ws/relay connection belongs to.
export function relayObjectName(hostname: string, template: string | undefined): string {
  template = template?.trim().toLowerCase();
  if (template?.includes("{token}")) {
    const [prefix, suffix] = template.split("{token}", 2);
    const host = hostname.toLowerCase();
    if (host.startsWith(prefix) && host.endsWith(suffix)) {
      const token = host.slice(prefix.length, host.length - suffix.length);
      if (/^[0-9a-f]{12}$/.test(token)) return `session:${token}`;
    }
  }
  return "hub";
}
