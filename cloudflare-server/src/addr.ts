// Port of hbb_common::AddrMangle (libs/hbb_common/src/lib.rs). Peers decode the controller's
// address from it and echo the exact bytes back in RelayResponse, which is how this server
// routes the answer to the right controller connection.

export interface SockAddr {
  ip: Uint8Array; // 4 bytes (IPv4, including v4-mapped IPv6) or 16 bytes
  port: number;
}

export function parseIp(s: string): Uint8Array | undefined {
  s = s.trim();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const v4 = parseIpv4(s);
  if (v4) return v4;
  const v6 = parseIpv6(s);
  if (!v6) return undefined;
  const mapped = v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff;
  return mapped ? v6.slice(12) : v6;
}

function parseIpv4(s: string): Uint8Array | undefined {
  const parts = s.split(".");
  if (parts.length !== 4) return undefined;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return undefined;
    const n = Number(parts[i]);
    if (n > 255) return undefined;
    out[i] = n;
  }
  return out;
}

function parseIpv6(s: string): Uint8Array | undefined {
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  const halves = s.split("::");
  if (halves.length > 2) return undefined;
  const groups = (part: string): number[] | undefined => {
    if (part === "") return [];
    const out: number[] = [];
    const items = part.split(":");
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (i === items.length - 1 && it.includes(".")) {
        const v4 = parseIpv4(it);
        if (!v4) return undefined;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(it)) return undefined;
        out.push(parseInt(it, 16));
      }
    }
    return out;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return undefined;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : fill !== 0) return undefined;
  const all = [...head, ...new Array(halves.length === 2 ? fill : 0).fill(0), ...tail];
  const out = new Uint8Array(16);
  all.forEach((g, i) => {
    out[i * 2] = g >> 8;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

export function formatIp(ip: Uint8Array): string {
  if (ip.length === 4) return ip.join(".");
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(((ip[i] << 8) | ip[i + 1]).toString(16));
  return g.join(":");
}

export function addrKey(a: SockAddr): string {
  return `${formatIp(a.ip)}|${a.port}`;
}

export function mangle(a: SockAddr, nowMicros: bigint = BigInt(Date.now()) * 1000n): Uint8Array {
  if (a.ip.length === 16) {
    const out = new Uint8Array(18);
    out.set(a.ip);
    out[16] = a.port & 0xff;
    out[17] = a.port >> 8;
    return out;
  }
  const tm = BigInt.asUintN(32, nowMicros);
  const ip = BigInt(a.ip[0] | (a.ip[1] << 8) | (a.ip[2] << 16)) + (BigInt(a.ip[3]) << 24n);
  const port = BigInt(a.port);
  const v = ((ip + tm) << 49n) | (tm << 17n) | (port + (tm & 0xffffn));
  const bytes = new Uint8Array(16);
  let x = v;
  for (let i = 0; i < 16; i++) {
    bytes[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  let n = 16;
  while (n > 0 && bytes[n - 1] === 0) n--;
  return bytes.slice(0, n);
}

export function demangle(b: Uint8Array): SockAddr | undefined {
  if (b.length > 16) {
    if (b.length !== 18) return undefined;
    return { ip: b.slice(0, 16), port: b[16] | (b[17] << 8) };
  }
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  const tm = (n >> 17n) & 0xffffffffn;
  const ipNum = BigInt.asUintN(32, (n >> 49n) - tm);
  const port = Number(BigInt.asUintN(16, (n & 0xffffffn) - (tm & 0xffffn)));
  const ip = new Uint8Array(4);
  for (let i = 0; i < 4; i++) ip[i] = Number((ipNum >> BigInt(8 * i)) & 0xffn);
  return { ip, port };
}
