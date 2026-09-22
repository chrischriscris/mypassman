// Shared builders for the relay contract suite — TLV encoding, signed
// manifests, device-signed op frames. Used by contract.test.mjs and the
// fixture generator.

export const cat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const b = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { b.set(p, o); o += p.length; }
  return b;
};
export const tlv = (tag, v) => {
  const b = new Uint8Array(5 + v.length);
  b[0] = tag;
  new DataView(b.buffer).setUint32(1, v.length, true);
  b.set(v, 5);
  return b;
};
export const u8 = (n) => Uint8Array.of(n);
export const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
export const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
export const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
export const rand = (n) => {
  const b = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(b.subarray(o, Math.min(o + 65536, n)));
  return b;
};
export const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => Uint8Array.from(s.match(/../g).map((x) => parseInt(x, 16)));

export async function newEd25519() {
  const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const vk = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { kp, vk };
}
export const sign = async (sk, b) =>
  new Uint8Array(await crypto.subtle.sign("Ed25519", sk, b));
export const sha256hex = async (b) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));

export const deviceTlv = (id, vk, name, active = true, extra = []) =>
  cat(
    tlv(0x01, id),
    tlv(0x02, vk),
    tlv(0x03, new TextEncoder().encode(name)),
    tlv(0x04, u8(active ? 1 : 2)),
    tlv(0x05, u64(0)),
    ...extra,
  );

export const slotTlv = (type = 1) =>
  cat(tlv(0x01, u8(type)), tlv(0x02, rand(32)), tlv(0x03, u32(19456)), tlv(0x04, u32(2)), tlv(0x05, u32(1)), tlv(0x06, rand(72)));

/** Canonical manifest body → owner-signed file bytes (sig || body). */
export async function manifestFile({
  vaultId,
  owner,
  devices = [],
  slots = [slotTlv()],
  formatV = 1,
  minReader = 1,
  keyEpoch = 1,
  snapshotEpoch = 1,
  purged = 0,
  kdf = cat(u32(19456), u32(2), u32(1), rand(32)),
}) {
  const body = cat(
    tlv(0x01, vaultId),
    tlv(0x02, u16(formatV)),
    tlv(0x03, u16(minReader)),
    tlv(0x04, kdf),
    ...slots.map((s) => tlv(0x05, s)),
    tlv(0x06, u32(keyEpoch)),
    tlv(0x07, u64(snapshotEpoch)),
    ...devices.map((d) => tlv(0x08, d)),
    tlv(0x09, u64(purged)),
    tlv(0x0a, owner.vk),
  );
  return cat(await sign(owner.kp.privateKey, body), body);
}

const OPSIG_PREFIX = new TextEncoder().encode("mypassman/v1/opsig");

/** One op frame: seq(8) || nonce(24) || device_sig(64) || ct_len(4) || ct.
 *  The relay verifies the device signature over the blind ciphertext —
 *  random ct is fine. */
export async function opFrame(devSk, seq, ctLen = 64) {
  const s = u64(seq);
  const nonce = rand(24);
  const ct = rand(ctLen);
  const pre = cat(OPSIG_PREFIX, s, nonce, ct);
  const sig = await sign(devSk, pre);
  return cat(s, nonce, sig, u32(ct.length), ct);
}

/** `n` consecutive frames from seq `start`, concatenated. */
export async function opBatch(devSk, start, n, ctLen = 64) {
  const frames = [];
  for (let i = 0; i < n; i++) frames.push(await opFrame(devSk, start + i, ctLen));
  return cat(...frames);
}

const OP_HDR = 8 + 24 + 64 + 4;

/** Split a concatenated op stream into raw frames (structure only). */
export function parseFrames(buf) {
  const out = [];
  let pos = 0;
  while (pos < buf.length) {
    if (pos + OP_HDR > buf.length) throw new Error("op: truncated header");
    const seq = new DataView(buf.buffer, buf.byteOffset + pos, 8).getBigUint64(0, true);
    const ctLen = new DataView(buf.buffer, buf.byteOffset + pos + 96, 4).getUint32(0, true);
    const end = pos + OP_HDR + ctLen;
    if (end > buf.length) throw new Error("op: truncated ct");
    out.push({ seq: Number(seq), raw: buf.subarray(pos, end) });
    pos = end;
  }
  return out;
}
