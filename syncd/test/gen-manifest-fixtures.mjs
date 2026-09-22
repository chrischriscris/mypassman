// Generates fixtures/manifest/cases.tsv — signed manifest bytes plus
// malformed mutations, consumed by BOTH parsers:
//   Rust:   crates/core/tests/manifest_fixtures.rs (Manifest::from_file)
//   Worker: syncd/test/manifest-fixtures.test.mjs (parseManifest+verify)
// Regenerate:  node test/gen-manifest-fixtures.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const out = join(dirname(fileURLToPath(import.meta.url)), "../../fixtures/manifest/cases.tsv");

const cat = (...parts) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const b = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { b.set(p, o); o += p.length; }
  return b;
};
const tlv = (tag, v) => {
  const b = new Uint8Array(5 + v.length);
  b[0] = tag;
  new DataView(b.buffer).setUint32(1, v.length, true);
  b.set(v, 5);
  return b;
};
const u8 = (n) => Uint8Array.of(n);
const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

const key = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const ownerVk = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
const vaultId = rand(16);
const devId = rand(16), devVk = rand(32);

const device = (over = {}) =>
  cat(
    tlv(0x01, over.id ?? devId),
    tlv(0x02, over.vk ?? devVk),
    tlv(0x03, new TextEncoder().encode(over.name ?? "laptop")),
    tlv(0x04, u8(over.status ?? 1)),
    ...(over.enrolled !== null ? [tlv(0x05, u64(over.enrolled ?? 0))] : []),
    ...(over.extra ?? []),
  );
const slot = (over = {}) =>
  cat(
    ...(over.type !== null ? [tlv(0x01, u8(over.type ?? 1))] : []),
    tlv(0x02, over.salt ?? rand(32)),
    tlv(0x03, u32(19456)),
    tlv(0x04, u32(2)),
    tlv(0x05, u32(1)),
    ...(over.blob !== null ? [tlv(0x06, over.blob ?? rand(72))] : []),
    ...(over.extra ?? []),
  );

// canonical field order: vault_id, format_v, min_reader, kdf, wrap_slot*,
// key_epoch, snapshot_epoch, device*, purged_before, owner_vk, [unknown]
const kdf = cat(u32(19456), u32(2), u32(1), rand(32));
const baseBody = (mut = {}) =>
  cat(
    ...(mut.dropVaultId ? [] : [tlv(0x01, mut.vaultId ?? vaultId)]),
    tlv(0x02, u16(mut.formatV ?? 1)),
    tlv(0x03, u16(mut.minReader ?? 1)),
    tlv(0x04, mut.kdf ?? kdf),
    ...(mut.slots ?? [slot()]).map((s) => tlv(0x05, s)),
    tlv(0x06, u32(mut.keyEpoch ?? 1)),
    tlv(0x07, u64(mut.snapshotEpoch ?? 1)),
    ...(mut.devices ?? [device()]).map((d) => tlv(0x08, d)),
    tlv(0x09, mut.purged ?? u64(0)),
    ...(mut.dropOwnerVk ? [] : [tlv(0x0a, mut.ownerVk ?? ownerVk)]),
    ...(mut.tail ?? []),
  );

const sign = async (body) => cat(new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, body)), body);
const cases = [];
const ok = async (name, body) => cases.push([name, "ok", hex(await sign(body))]);
const err = async (name, body) => cases.push([name, "err", hex(await sign(body))]);
// raw file bytes (no re-sign) — for sig corruption / truncation cases
const errRaw = (name, bytes) => cases.push([name, "err", hex(bytes)]);

await ok("valid", baseBody());
await ok("valid-two-devices", baseBody({ devices: [device(), device({ id: rand(16), name: "phone" })] }));
await ok("valid-two-slots", baseBody({ slots: [slot(), slot({ type: 2 })] }));
await ok("valid-unknown-field", baseBody({ tail: [tlv(0x7f, rand(9))] }));
await ok(
  "valid-unknown-device-field",
  baseBody({ devices: [device({ extra: [tlv(0x7f, rand(4))] })] }),
);
await ok(
  "valid-revoked-device",
  baseBody({ devices: [device({ status: 2, extra: [tlv(0x06, u64(7))] })] }),
);

await err(
  "err-dup-vault-id",
  cat(tlv(0x01, vaultId), tlv(0x01, vaultId), tlv(0x02, u16(1)), tlv(0x03, u16(1)), tlv(0x06, u32(1)), tlv(0x0a, ownerVk)),
);
await err(
  "err-out-of-order",
  cat(tlv(0x01, vaultId), tlv(0x0a, ownerVk), tlv(0x06, u32(1))),
);
await err(
  "err-dup-singleton",
  cat(tlv(0x01, vaultId), tlv(0x02, u16(1)), tlv(0x02, u16(1)), tlv(0x0a, ownerVk)),
);
await err(
  "err-nonconsecutive-repeatable",
  cat(
    tlv(0x01, vaultId), tlv(0x02, u16(1)), tlv(0x03, u16(1)), tlv(0x06, u32(1)),
    tlv(0x08, device()), tlv(0x09, u64(0)), tlv(0x08, device({ id: rand(16) })),
    tlv(0x0a, ownerVk),
  ),
);
await err("err-short-vault-id", baseBody({ vaultId: rand(8) }));
await err("err-key-epoch-badlen", cat(tlv(0x01, vaultId), tlv(0x02, u16(1)), tlv(0x06, u16(1)), tlv(0x0a, ownerVk)));
await err("err-kdf-badlen", baseBody({ kdf: rand(5) }));
await err(
  "err-snapshot-epoch-badlen",
  cat(tlv(0x01, vaultId), tlv(0x07, u32(1)), tlv(0x0a, ownerVk)),
);
await err("err-purged-badlen", baseBody({ purged: u32(0) }));
await err("err-owner-vk-badlen", baseBody({ ownerVk: rand(16) }));
await err("err-slot-no-type", baseBody({ slots: [slot({ type: null })] }));
await err("err-slot-bad-type", baseBody({ slots: [slot({ type: 9 })] }));
await err(
  "err-slot-out-of-order",
  baseBody({
    slots: [cat(tlv(0x06, rand(72)), tlv(0x01, u8(1)))],
  }),
);
await err(
  "err-slot-dup-type",
  baseBody({ slots: [cat(tlv(0x01, u8(1)), tlv(0x01, u8(1)), tlv(0x06, rand(72)))] }),
);
await err("err-slot-salt-badlen", baseBody({ slots: [slot({ salt: rand(16) })] }));
await err(
  "err-device-no-vk",
  baseBody({ devices: [cat(tlv(0x01, devId), tlv(0x03, new TextEncoder().encode("x")))] }),
);
await err("err-device-short-id", baseBody({ devices: [device({ id: rand(8) })] }));
await err("err-device-short-vk", baseBody({ devices: [device({ vk: rand(16) })] }));
await err(
  "err-device-status-badlen",
  baseBody({ devices: [cat(tlv(0x01, devId), tlv(0x02, devVk), tlv(0x04, new Uint8Array(0)))] }),
);
await err(
  "err-device-enrolled-badlen",
  baseBody({ devices: [cat(tlv(0x01, devId), tlv(0x02, devVk), tlv(0x05, u32(0)))] }),
);
await err("err-format-v-too-new", baseBody({ formatV: 2 }));
await err("err-min-reader-too-new", baseBody({ minReader: 2 }));
await err("err-missing-vault-id", baseBody({ dropVaultId: true }));
await err("err-missing-owner-vk", baseBody({ dropOwnerVk: true }));

// sig-level corruption + truncation: no re-sign
const good = await sign(baseBody());
const badSig = good.slice(); badSig[0] ^= 0xff;
errRaw("err-bad-sig", badSig);
errRaw("err-truncated-header", cat(good, Uint8Array.of(1, 2, 3)));
const truncVal = good.slice();
new DataView(truncVal.buffer).setUint32(64 + 5 + 1, 0xffff, true); // format_v len inflated
errRaw("err-truncated-value", truncVal);
errRaw("err-short-file", good.subarray(0, 66));
errRaw("err-empty", new Uint8Array(0));

writeFileSync(out, cases.map((c) => c.join("\t")).join("\n") + "\n");
console.log(`wrote ${cases.length} cases → ${out}`);
