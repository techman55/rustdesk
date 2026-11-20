import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";

// The client's own protocol definition, so tests do not trust this server's codec.
const PROTO = fileURLToPath(
  new URL("../../libs/hbb_common/protos/rendezvous.proto", import.meta.url),
);

const root = new protobuf.Root().loadSync(PROTO, { keepCase: true });
export const RendezvousMessage = root.lookupType("hbb.RendezvousMessage");
export const IdPk = root.lookupType("hbb.IdPk") as protobuf.Type & {
  decode(b: Uint8Array): { id: string; pk: Uint8Array };
};
