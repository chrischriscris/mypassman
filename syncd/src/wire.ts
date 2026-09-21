//! Wire-format readers for the mypassman vault objects the server must
//! inspect. Trust lives in the format: the server verifies signatures but
//! never sees plaintext.
//!
//! TLV field: tag(u8) || len(u32 LE) || value
//! Manifest file: owner_sig(64) || tlv body
//! Op frame:    seq(8 LE) || nonce(24) || device_sig(64) || ct_len(4 LE) || ct

export const VAULT_ID_LEN = 16;
export const DEVICE_ID_LEN = 16;
export const SIG_LEN = 64;
export const NONCE_LEN = 24;
export const OP_HEADER_LEN = 8 + NONCE_LEN + SIG_LEN + 4;

const OPSIG_CONTEXT = "mypassman/v1/opsig";

export class WireError extends Error {
  constructor(msg: string, readonly status = 400) {
    super(msg);
  }
}

export const hex = (b: Uint8Array) =>
  [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string) => {
  if (!/^[0-9a-f]+$/i.test(s) || s.length % 2) throw new WireError("bad hex");
  return Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)));
};
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));

export async function sha256Hex(b: Uint8Array | string): Promise<string> {
  const data = typeof b === "string" ? new TextEncoder().encode(b) : b;
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource)));
}

/** Iterate TLV fields. Rejects truncated input — strict, not canonical-order-checked. */
export function* readTlv(buf: Uint8Array): Generator<[number, Uint8Array]> {
  let pos = 0;
  while (pos < buf.length) {
    if (pos + 5 > buf.length) throw new WireError("tlv: truncated header");
    const tag = buf[pos]!;
    const len = new DataView(buf.buffer, buf.byteOffset + pos + 1, 4).getUint32(0, true);
    pos += 5;
    if (pos + len > buf.length) throw new WireError("tlv: truncated value");
    yield [tag, buf.subarray(pos, pos + len)];
    pos += len;
  }
}

const u32v = (v: Uint8Array) => new DataView(v.buffer, v.byteOffset, 4).getUint32(0, true);
const u64v = (v: Uint8Array) => new DataView(v.buffer, v.byteOffset, 8).getBigUint64(0, true);

export interface DeviceEntry {
  id: Uint8Array; // 16
  vk: Uint8Array; // 32
  name: string;
  active: boolean;
}

export interface ManifestInfo {
  vaultId: Uint8Array;
  keyEpoch: number;
  snapshotEpoch: bigint;
  ownerVk: Uint8Array;
  devices: DeviceEntry[];
}

// manifest tags
const T_VAULT_ID = 0x01,
  T_KEY_EPOCH = 0x06,
  T_SNAPSHOT_EPOCH = 0x07,
  T_DEVICE = 0x08,
  T_OWNER_VK = 0x0a;
// device entry tags
const D_ID = 0x01,
  D_VK = 0x02,
  D_NAME = 0x03,
  D_STATUS = 0x04;

function parseDevice(buf: Uint8Array): DeviceEntry {
  let id: Uint8Array | undefined, vk: Uint8Array | undefined;
  let name = "", active = true;
  for (const [t, v] of readTlv(buf)) {
    switch (t) {
      case D_ID: id = v; break;
      case D_VK: vk = v; break;
      case D_NAME: name = new TextDecoder().decode(v); break;
      case D_STATUS: active = v[0] === 1; break;
    }
  }
  if (!id || id.length !== DEVICE_ID_LEN) throw new WireError("device: bad id");
  if (!vk || vk.length !== 32) throw new WireError("device: bad vk");
  return { id, vk, name, active };
}

/** Parse manifest bytes (does NOT verify the signature — see verifyManifest). */
export function parseManifest(file: Uint8Array): ManifestInfo {
  if (file.length < SIG_LEN + 5) throw new WireError("manifest: short");
  const body = file.subarray(SIG_LEN);
  let vaultId: Uint8Array | undefined, ownerVk: Uint8Array | undefined;
  let keyEpoch = 0, snapshotEpoch = 0n;
  const devices: DeviceEntry[] = [];
  for (const [t, v] of readTlv(body)) {
    switch (t) {
      case T_VAULT_ID: vaultId = v; break;
      case T_KEY_EPOCH: keyEpoch = u32v(v); break;
      case T_SNAPSHOT_EPOCH: snapshotEpoch = u64v(v); break;
      case T_DEVICE: devices.push(parseDevice(v)); break;
      case T_OWNER_VK: ownerVk = v; break;
    }
  }
  if (!vaultId || vaultId.length !== VAULT_ID_LEN) throw new WireError("manifest: bad vault_id");
  if (!ownerVk || ownerVk.length !== 32) throw new WireError("manifest: bad owner_vk");
  return { vaultId, ownerVk, keyEpoch, snapshotEpoch, devices };
}

async function ed25519Verify(vk: Uint8Array, sig: Uint8Array, data: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", vk as BufferSource, "Ed25519", false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, sig as BufferSource, data as BufferSource);
}

export function verifyManifest(file: Uint8Array, info: ManifestInfo): Promise<boolean> {
  return ed25519Verify(info.ownerVk, file.subarray(0, SIG_LEN), file.subarray(SIG_LEN));
}

export interface OpFrame {
  seq: bigint;
  nonce: Uint8Array;
  sig: Uint8Array;
  ct: Uint8Array;
  raw: Uint8Array;
}

/** Split a concatenated op stream into frames. */
export function parseOpFrames(buf: Uint8Array): OpFrame[] {
  const out: OpFrame[] = [];
  let pos = 0;
  while (pos < buf.length) {
    if (pos + OP_HEADER_LEN > buf.length) throw new WireError("op: truncated header");
    const dv = new DataView(buf.buffer, buf.byteOffset + pos);
    const seq = dv.getBigUint64(0, true);
    const nonce = buf.subarray(pos + 8, pos + 8 + NONCE_LEN);
    const sig = buf.subarray(pos + 32, pos + 32 + SIG_LEN);
    const ctLen = dv.getUint32(96, true);
    if (ctLen > 1 << 20) throw new WireError("op: oversize ct");
    const end = pos + OP_HEADER_LEN + ctLen;
    if (end > buf.length) throw new WireError("op: truncated ct");
    out.push({ seq, nonce, sig, ct: buf.subarray(pos + OP_HEADER_LEN, end), raw: buf.subarray(pos, end) });
    pos = end;
  }
  return out;
}

const OPSIG_PREFIX = new TextEncoder().encode(OPSIG_CONTEXT);

/** op_sig_preimage: "mypassman/v1/opsig" || seq(8 LE) || nonce(24) || ct */
export function opSigVerify(vk: Uint8Array, op: OpFrame): Promise<boolean> {
  const pre = new Uint8Array(OPSIG_PREFIX.length + 8 + NONCE_LEN + op.ct.length);
  pre.set(OPSIG_PREFIX);
  new DataView(pre.buffer, OPSIG_PREFIX.length).setBigUint64(0, op.seq, true);
  pre.set(op.nonce, OPSIG_PREFIX.length + 8);
  pre.set(op.ct, OPSIG_PREFIX.length + 8 + NONCE_LEN);
  return ed25519Verify(vk, op.sig, pre);
}

/** Human-typeable invite code: 8 chars, no confusables, XXXX-XXXX. */
export function newCode(): string {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const r = crypto.getRandomValues(new Uint8Array(8));
  const s = [...r].map((b) => A[b % A.length]).join("");
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

/** Opaque API token. */
export function newToken(): string {
  const r = crypto.getRandomValues(new Uint8Array(24));
  return "mpm_" + btoa(String.fromCharCode(...r)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
