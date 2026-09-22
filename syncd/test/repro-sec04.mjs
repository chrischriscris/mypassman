// SEC-04 reproduction: two concurrent POST enroll/finish calls redeeming
// the same invite+device. If the mint-then-burn sequence interleaves,
// both succeed → duplicate token sets for one invite.
// Requires: wrangler dev --local on :8797 with SETUP_KEY=test-setup.
// Run: node test/repro-sec04.mjs
const concat = (...ps) => {
  const o = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of ps) {
    o.set(p, i);
    i += p.length;
  }
  return o;
};
const tlv = (tag, v) => {
  const h = new Uint8Array(5);
  h[0] = tag;
  new DataView(h.buffer).setUint32(1, v.length, true);
  return concat(h, v);
};
const u32le = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const u64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};

async function ed25519() {
  const kp = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const vk = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { kp, vk };
}
const sign = (sk, b) => crypto.subtle.sign("Ed25519", sk, b).then((s) => new Uint8Array(s));

function deviceTlv(id, vk, name, active) {
  return concat(
    tlv(0x01, id),
    tlv(0x02, vk),
    tlv(0x03, new TextEncoder().encode(name)),
    tlv(0x04, new Uint8Array([active ? 1 : 0])),
  );
}

async function manifestFile(owner, vaultId, keyEpoch, snapEpoch, devices) {
  const body = concat(
    tlv(0x01, vaultId),
    tlv(0x06, u32le(keyEpoch)),
    tlv(0x07, u64le(snapEpoch)),
    ...devices.map((d) => tlv(0x08, d)),
    tlv(0x0a, owner.vk),
  );
  return concat(new Uint8Array(await sign(owner.kp.privateKey, body)), body);
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (b) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", b)));

const BASE = process.env.RELAY_URL ?? "http://127.0.0.1:8797";
const SETUP = process.env.SETUP_KEY ?? "test-setup";
const health = await fetch(`${BASE}/health`);
if (!health.ok) throw new Error("worker not up");

let wins = 0;
const ROUNDS = 12;
for (let round = 0; round < ROUNDS; round++) {
  // fresh vault per round — an invite is single-use by design
  const vaultId = crypto.getRandomValues(new Uint8Array(16));
  const vid = hex(vaultId);
  const owner = await ed25519();
  const devA = await ed25519();
  const devAId = crypto.getRandomValues(new Uint8Array(16));
  const newDev = await ed25519();
  const newDevId = crypto.getRandomValues(new Uint8Array(16));

  const m1 = await manifestFile(owner, vaultId, 1, 1, [deviceTlv(devAId, devA.vk, "a", true)]);
  const rb = await fetch(`${BASE}/v/${vid}/bootstrap`, {
    method: "POST",
    headers: { "x-setup-key": SETUP },
    body: m1,
  });
  if (!rb.ok) throw new Error(`bootstrap: ${rb.status} ${await rb.text()}`);
  const { token: admin } = await rb.json();

  // invite → join → approve (manifest CAS adds the device)
  const { code } = await (
    await fetch(`${BASE}/v/${vid}/enroll/invite`, {
      method: "POST",
      headers: { authorization: `Bearer ${admin}` },
    })
  ).json();
  const rj = await fetch(`${BASE}/v/${vid}/enroll/join`, {
    method: "POST",
    headers: { authorization: `Bearer ${code}`, "content-type": "application/json" },
    body: JSON.stringify({ device: hex(newDevId), vk: hex(newDev.vk), name: "new" }),
  });
  if (!rj.ok) throw new Error(`join: ${rj.status} ${await rj.text()}`);

  const m2 = await manifestFile(owner, vaultId, 1, 2, [
    deviceTlv(devAId, devA.vk, "a", true),
    deviceTlv(newDevId, newDev.vk, "new", true),
  ]);
  const rp = await fetch(`${BASE}/v/${vid}/manifest`, {
    method: "PUT",
    headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest: hex(m2), base_hash: await sha256(m1) }),
  });
  if (!rp.ok) throw new Error(`approve: ${rp.status} ${await rp.text()}`);

  // K concurrent finishes on the same invite+device
  const K = 4;
  const rs = await Promise.all(
    Array.from({ length: K }, () =>
      fetch(`${BASE}/v/${vid}/enroll/finish`, {
        method: "POST",
        headers: { authorization: `Bearer ${code}`, "content-type": "application/json" },
        body: JSON.stringify({ device: hex(newDevId) }),
      }),
    ),
  );
  const ok = rs.filter((r) => r.ok).length;
  if (ok > 1) {
    wins++;
    const toks = await Promise.all(rs.filter((r) => r.ok).map((r) => r.json()));
    const uniq = new Set(toks.map((t) => t.write));
    console.log(`round ${round}: ${ok}/${K} redeemed — distinct write tokens: ${uniq.size}`);
  } else if (ok === 0) {
    console.log(`round ${round}: none succeeded: ${rs.map((r) => r.status)}`);
    const e = await rs[0].text();
    console.log(`  first error: ${e}`);
    process.exit(2);
  }
}
console.log(`rounds with double redemption: ${wins}/${ROUNDS}`);
if (wins > 0) {
  console.log("REPRODUCED: one invite redeemed multiple times");
  process.exit(1);
}
console.log("NOT REPRODUCED");
