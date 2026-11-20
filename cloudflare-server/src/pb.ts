// Minimal protobuf wire codec. Messages are kept as an ordered field list so a forwarded
// message keeps every field this server does not know about (new client versions add fields
// to PunchHole, RequestRelay, RelayResponse, ... and peers must still receive them).

export const VARINT = 0;
export const I64 = 1;
export const LEN = 2;
export const I32 = 5;

interface Field {
  no: number;
  wt: number;
  // bigint for VARINT, raw bytes for LEN / I64 / I32
  v: bigint | Uint8Array;
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export class PbError extends Error {}

function readVarint(buf: Uint8Array, pos: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (let i = 0; i < 10; i++) {
    if (pos >= buf.length) throw new PbError("truncated varint");
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [BigInt.asUintN(64, result), pos];
    shift += 7n;
  }
  throw new PbError("varint too long");
}

function writeVarint(out: number[], v: bigint): void {
  v = BigInt.asUintN(64, v);
  while (v >= 0x80n) {
    out.push(Number(v & 0x7fn) | 0x80);
    v >>= 7n;
  }
  out.push(Number(v));
}

export class Msg {
  fields: Field[] = [];

  static decode(buf: Uint8Array): Msg {
    const m = new Msg();
    let pos = 0;
    while (pos < buf.length) {
      let tag: bigint;
      [tag, pos] = readVarint(buf, pos);
      const no = Number(tag >> 3n);
      const wt = Number(tag & 7n);
      if (no < 1 || no > 536870911) throw new PbError("bad field number");
      switch (wt) {
        case VARINT: {
          let v: bigint;
          [v, pos] = readVarint(buf, pos);
          m.fields.push({ no, wt, v });
          break;
        }
        case LEN: {
          let len: bigint;
          [len, pos] = readVarint(buf, pos);
          const end = pos + Number(len);
          if (len > BigInt(buf.length) || end > buf.length) throw new PbError("truncated field");
          m.fields.push({ no, wt, v: buf.slice(pos, end) });
          pos = end;
          break;
        }
        case I64:
        case I32: {
          const end = pos + (wt === I64 ? 8 : 4);
          if (end > buf.length) throw new PbError("truncated fixed field");
          m.fields.push({ no, wt, v: buf.slice(pos, end) });
          pos = end;
          break;
        }
        default:
          throw new PbError(`unsupported wire type ${wt}`);
      }
    }
    return m;
  }

  encode(): Uint8Array {
    const out: number[] = [];
    const chunks: Uint8Array[] = [];
    let size = 0;
    const flush = () => {
      if (out.length) {
        chunks.push(Uint8Array.from(out));
        size += out.length;
        out.length = 0;
      }
    };
    for (const f of this.fields) {
      writeVarint(out, (BigInt(f.no) << 3n) | BigInt(f.wt));
      if (f.wt === VARINT) {
        writeVarint(out, f.v as bigint);
      } else {
        const b = f.v as Uint8Array;
        if (f.wt === LEN) writeVarint(out, BigInt(b.length));
        flush();
        chunks.push(b);
        size += b.length;
      }
    }
    flush();
    const res = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) {
      res.set(c, off);
      off += c.length;
    }
    return res;
  }

  // proto3: the last occurrence of a scalar field wins
  private last(no: number, wt: number): Field | undefined {
    for (let i = this.fields.length - 1; i >= 0; i--) {
      const f = this.fields[i];
      if (f.no === no && f.wt === wt) return f;
    }
    return undefined;
  }

  has(no: number): boolean {
    return this.fields.some((f) => f.no === no);
  }

  bytes(no: number): Uint8Array {
    return (this.last(no, LEN)?.v as Uint8Array | undefined) ?? new Uint8Array(0);
  }

  str(no: number): string {
    const b = this.bytes(no);
    try {
      return dec.decode(b);
    } catch {
      throw new PbError(`field ${no} is not valid UTF-8`);
    }
  }

  strs(no: number): string[] {
    return this.fields
      .filter((f) => f.no === no && f.wt === LEN)
      .map((f) => dec.decode(f.v as Uint8Array));
  }

  int32(no: number): number {
    const f = this.last(no, VARINT);
    return f ? Number(BigInt.asIntN(32, f.v as bigint)) : 0;
  }

  uint32(no: number): number {
    const f = this.last(no, VARINT);
    return f ? Number(BigInt.asUintN(32, f.v as bigint)) : 0;
  }

  bool(no: number): boolean {
    const f = this.last(no, VARINT);
    return f ? (f.v as bigint) !== 0n : false;
  }

  msg(no: number): Msg | undefined {
    const f = this.last(no, LEN);
    return f ? Msg.decode(f.v as Uint8Array) : undefined;
  }

  delete(no: number): this {
    this.fields = this.fields.filter((f) => f.no !== no);
    return this;
  }

  // Setters drop proto3 default values, as a proto3 encoder would; `keep` forces the field
  // out, which a oneof member needs to be seen as set.
  setBytes(no: number, v: Uint8Array, keep = false): this {
    this.delete(no);
    if (v.length || keep) this.fields.push({ no, wt: LEN, v });
    return this;
  }

  setStr(no: number, v: string, keep = false): this {
    return this.setBytes(no, enc.encode(v), keep);
  }

  addStr(no: number, v: string): this {
    this.fields.push({ no, wt: LEN, v: enc.encode(v) });
    return this;
  }

  setInt(no: number, v: number | boolean, keep = false): this {
    this.delete(no);
    const n = typeof v === "boolean" ? (v ? 1n : 0n) : BigInt(Math.trunc(v));
    if (n !== 0n || keep) this.fields.push({ no, wt: VARINT, v: BigInt.asUintN(64, n) });
    return this;
  }

  setMsg(no: number, m: Msg): this {
    return this.setBytes(no, m.encode(), true);
  }
}

// RendezvousMessage oneof members (libs/hbb_common/protos/rendezvous.proto)
export const RM = {
  RegisterPeer: 6,
  RegisterPeerResponse: 7,
  PunchHoleRequest: 8,
  PunchHole: 9,
  PunchHoleSent: 10,
  PunchHoleResponse: 11,
  FetchLocalAddr: 12,
  LocalAddr: 13,
  ConfigUpdate: 14,
  RegisterPk: 15,
  RegisterPkResponse: 16,
  SoftwareUpdate: 17,
  RequestRelay: 18,
  RelayResponse: 19,
  TestNatRequest: 20,
  TestNatResponse: 21,
  PeerDiscovery: 22,
  OnlineRequest: 23,
  OnlineResponse: 24,
  KeyExchange: 25,
  HealthCheck: 26,
  IceCandidate: 29,
} as const;

export const RegisterPkResult = {
  OK: 0,
  UUID_MISMATCH: 2,
  ID_EXISTS: 3,
  TOO_FREQUENT: 4,
  INVALID_ID_FORMAT: 5,
  NOT_SUPPORT: 6,
  SERVER_ERROR: 7,
  NOT_DEPLOYED: 8,
} as const;

export const PunchFailure = {
  ID_NOT_EXIST: 0,
  OFFLINE: 2,
  LICENSE_MISMATCH: 3,
  LICENSE_OVERUSE: 4,
} as const;

export function unwrap(buf: Uint8Array): { kind: number; body: Msg } | undefined {
  const outer = Msg.decode(buf);
  for (let i = outer.fields.length - 1; i >= 0; i--) {
    const f = outer.fields[i];
    if (f.wt === LEN) return { kind: f.no, body: Msg.decode(f.v as Uint8Array) };
  }
  return undefined;
}

export function wrap(kind: number, body: Msg): Uint8Array {
  return new Msg().setMsg(kind, body).encode();
}
