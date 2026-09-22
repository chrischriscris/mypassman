// SEC-01 reproduction: two concurrent PUT /manifest requests sharing the
// same base_hash. If putManifest's check→write interleaves across awaits,
// both succeed (one silently lost). Run: node test/repro-sec01.mjs



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

// manifest file = owner_sig(64) || body
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

const vaultId = crypto.getRandomValues(new Uint8Array(16));
const vid = hex(vaultId);
const owner = await ed25519();
const devA = await ed25519();
const devAId = crypto.getRandomValues(new Uint8Array(16));

// bootstrap: manifest with devA
const m1 = await manifestFile(owner, vaultId, 1, 1, [deviceTlv(devAId, devA.vk, "a", true)]);
const r = await fetch(`${BASE}/v/${vid}/bootstrap`, {
  method: "POST",
  headers: { "x-setup-key": SETUP },
  body: m1,
});
if (!r.ok) throw new Error(`bootstrap: ${r.status} ${await r.text()}`);
const { token: admin } = await r.json();

// pad device names toward the 64 KiB cap so hashing/verify hold the race
// window open longer
const pad = "x".repeat(48 * 1024);

const put = (m, baseHash) =>
  fetch(`${BASE}/v/${vid}/manifest`, {
    method: "PUT",
    headers: { authorization: `Bearer ${admin}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest: hex(m), base_hash: baseHash }),
  });

// hammer the race window: N rounds of K concurrent CAS writes sharing
// the same base hash. Any round where >1 succeeds = a silently lost
// update.
let wins = 0;
let curHash = await sha256(m1);
let curEpoch = 1;
const ROUNDS = 12;
const K = 4;
for (let round = 0; round < ROUNDS; round++) {
  const batch = await Promise.all(
    Array.from({ length: K }, async () => {
      const d = await ed25519();
      return manifestFile(owner, vaultId, 1, ++curEpoch, [
        deviceTlv(devAId, devA.vk, "a", true),
        deviceTlv(crypto.getRandomValues(new Uint8Array(16)), d.vk, pad, true),
      ]);
    }),
  );
  const bh = curHash;
  const rs = await Promise.all(batch.map((m) => put(m, bh)));
  const ok = rs.filter((r) => r.ok).length;
  if (ok > 1) {
    wins++;
    console.log(`round ${round}: ${ok}/${K} SUCCEEDED — lost update`);
  } else if (ok === 0) {
    console.log(`round ${round}: all failed ${rs.map((r) => r.status)}`);
    process.exit(2);
  }
  // whatever is actually stored is next round's base (covers both the
  // clean-winner and lost-update cases)
  const cur = await (await fetch(`${BASE}/v/${vid}/manifest`, {
    headers: { authorization: `Bearer ${admin}` },
  })).json();
  curHash = await sha256(Uint8Array.from(cur.manifest.match(/../g).map((x) => parseInt(x, 16))));
}
console.log(`rounds with lost update: ${wins}/${ROUNDS}`);
if (wins > 0) {
  console.log("REPRODUCED: concurrent CAS writes both succeeded");
  process.exit(1);
}
console.log(`NOT REPRODUCED in ${ROUNDS} rounds`);
