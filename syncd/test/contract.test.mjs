// TEST-01: relay contract suite — runs against BOTH relay implementations
// over identical HTTP requests:
//   Worker:      node test/run-contract.mjs worker   (wrangler dev)
//   Rust relay:  node test/run-contract.mjs rust     (mpm-syncd)
// Requires BASE_URL + SETUP_KEY in env (the runner sets them).
import test from "node:test";
import assert from "node:assert/strict";
import {
  cat, deviceTlv, hex, manifestFile, newEd25519, opBatch, opFrame, parseFrames,
  rand, sha256hex, slotTlv, unhex,
} from "./kit.mjs";

const BASE = process.env.BASE_URL;
const SETUP = process.env.SETUP_KEY ?? "test-setup";
assert.ok(BASE, "BASE_URL required");

// A fresh vault per run — relays accumulate state, so every run picks a
// new vault_id rather than needing a reset.
const owner = await newEd25519();
const devA = await newEd25519(); // registered device (ops signer)
const vaultId = rand(16);
const V = hex(vaultId);
const devAHex = hex(rand(16));

let manifestBytes = await manifestFile({
  vaultId,
  owner,
  devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")],
});
let admin; // bootstrap token

const req = async (path, { method = "GET", token, body, headers = {}, vault = V, duplex } = {}) => {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  const r = await fetch(`${BASE}/v/${vault}/${path}`, { method, headers: h, body, duplex });
  const buf = await r.arrayBuffer();
  let json = null;
  try { json = JSON.parse(new TextDecoder().decode(buf)); } catch { /* octet-stream */ }
  return { status: r.status, json, buf: new Uint8Array(buf), headers: r.headers };
};

const jpost = (path, obj, token) =>
  req(path, { method: "POST", token, body: JSON.stringify(obj), headers: { "content-type": "application/json" } });

// ── bootstrap ────────────────────────────────────────────────────────

test("bootstrap: no/wrong setup key → 401", async () => {
  assert.equal((await req("bootstrap", { method: "POST", body: manifestBytes.buffer })).status, 401);
  assert.equal(
    (await req("bootstrap", { method: "POST", body: manifestBytes.buffer, headers: { "x-setup-key": "nope" } })).status,
    401,
  );
});

test("bootstrap: valid → admin token", async () => {
  const r = await req("bootstrap", { method: "POST", body: manifestBytes.buffer, headers: { "x-setup-key": SETUP } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  admin = r.json.token;
  assert.ok(admin.startsWith("mpm_"));
});

test("bootstrap: second attempt → 409; wrong-vault manifest → 400", async () => {
  const r = await req("bootstrap", { method: "POST", body: manifestBytes.buffer, headers: { "x-setup-key": SETUP } });
  assert.equal(r.status, 409);
  // a manifest whose vault_id doesn't match the path is refused — needs a
  // FRESH path (an existing vault 409s on "already exists" first)
  const otherVid = rand(16);
  const other = await manifestFile({ vaultId: otherVid, owner });
  const r2 = await req("bootstrap", {
    method: "POST", body: other.buffer,
    headers: { "x-setup-key": SETUP },
    vault: hex(rand(16)),
  });
  assert.equal(r2.status, 400);
});

// ── auth ─────────────────────────────────────────────────────────────

test("auth: no token → 401; garbage → 401; read token can't admin → 403", async () => {
  assert.equal((await req("manifest")).status, 401);
  assert.equal((await req("manifest", { token: "mpm_garbage" })).status, 401);
  const rtok = (await jpost("tokens", { scope: "read" }, admin)).json.token;
  assert.equal((await jpost("tokens", { scope: "read" }, rtok)).status, 403);
});

// ── manifest CAS ─────────────────────────────────────────────────────

test("manifest: get roundtrip; put wrong base → 409; put right → 200", async () => {
  const g = await req("manifest", { token: admin });
  assert.equal(g.status, 200);
  assert.equal(g.json.manifest, hex(manifestBytes));

  const bumped = await manifestFile({
    vaultId, owner, snapshotEpoch: 2,
    devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")],
  });
  const bad = await req("manifest", {
    method: "PUT", token: admin,
    body: JSON.stringify({ manifest: hex(bumped), base_hash: "00".repeat(32) }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(bad.status, 409);
  const good = await req("manifest", {
    method: "PUT", token: admin,
    body: JSON.stringify({ manifest: hex(bumped), base_hash: await sha256hex(manifestBytes) }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(good.status, 200);
  assert.equal(good.json.snapshot_epoch, 2);
  manifestBytes = bumped;
});

test("manifest: concurrent same-base puts — exactly one wins", async () => {
  const base = await sha256hex(manifestBytes);
  const m3 = await manifestFile({ vaultId, owner, snapshotEpoch: 3, devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")] });
  const m4 = await manifestFile({ vaultId, owner, snapshotEpoch: 4, devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")] });
  const results = await Promise.all([
    req("manifest", { method: "PUT", token: admin, body: JSON.stringify({ manifest: hex(m3), base_hash: base }), headers: { "content-type": "application/json" } }),
    req("manifest", { method: "PUT", token: admin, body: JSON.stringify({ manifest: hex(m4), base_hash: base }), headers: { "content-type": "application/json" } }),
  ]);
  const codes = results.map((r) => r.status).sort();
  assert.deepEqual(codes, [200, 409], `expected one winner, got ${codes}`);
  manifestBytes = results[0].status === 200 ? m3 : m4;
});

test("manifest: epoch regression → 409; owner mismatch → 400; bad sig → 400", async () => {
  const base = await sha256hex(manifestBytes);
  const put = (bytes) =>
    req("manifest", { method: "PUT", token: admin, body: JSON.stringify({ manifest: hex(bytes), base_hash: base }), headers: { "content-type": "application/json" } });

  const older = await manifestFile({ vaultId, owner, snapshotEpoch: 1, devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")] });
  assert.equal((await put(older)).status, 409);

  const stranger = await newEd25519();
  const foreign = await manifestFile({ vaultId, owner: stranger, snapshotEpoch: 9, devices: [deviceTlv(unhex(devAHex), devA.vk, "dev-a")] });
  assert.equal((await put(foreign)).status, 400);

  const corrupt = manifestBytes.slice();
  corrupt[10] ^= 0xff;
  assert.equal((await put(corrupt)).status, 400);
});

// ── ops push/pull ────────────────────────────────────────────────────

let writeTok;

test("ops: unauth → 401; read scope → 403; unknown device → 403", async () => {
  writeTok = (await jpost("tokens", { scope: "write", device: devAHex }, admin)).json.token;
  const body = await opBatch(devA.kp.privateKey, 1, 1);
  assert.equal((await req(`ops?device=${devAHex}`, { method: "POST", body: body.buffer })).status, 401);
  const rtok = (await jpost("tokens", { scope: "read" }, admin)).json.token;
  assert.equal((await req(`ops?device=${devAHex}`, { method: "POST", token: rtok, body: body.buffer })).status, 403);
  const devB = hex(rand(16));
  assert.equal(
    (await req(`ops?device=${devB}`, { method: "POST", token: writeTok, body: body.buffer })).status,
    403, // token bound to devA can't write devB — also not in registry
  );
});

test("ops: push → head; idempotent replay; equivocation → 409; gap → 409", async () => {
  const batch = await opBatch(devA.kp.privateKey, 1, 3);
  const r = await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: batch.buffer });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.head, 3);

  // same bytes, same seqs → idempotent, head unchanged
  const again = await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: batch.buffer });
  assert.equal(again.status, 200);
  assert.equal(again.json.head, 3);

  // same seq, different bytes → equivocation
  const evil = await opFrame(devA.kp.privateKey, 2, 32);
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: evil.buffer })).status,
    409,
  );

  // seq 5 while head is 3 → gap
  const gap = await opFrame(devA.kp.privateKey, 5, 32);
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: gap.buffer })).status,
    409,
  );
});

test("ops: bad device signature → 403; malformed frame → 400", async () => {
  const stranger = await newEd25519();
  const forged = await opFrame(stranger.kp.privateKey, 4, 32); // wrong signer
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: forged.buffer })).status,
    403,
  );
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: rand(50).buffer })).status,
    400,
  );
});

const FRAME_HDR = 8 + 24 + 64 + 4; // seq || nonce || sig || ct_len

test("ops: 257 frames → 413; oversized body → 413", async () => {
  const tooMany = await opBatch(devA.kp.privateKey, 4, 257, 8);
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: tooMany.buffer })).status,
    413,
  );
  const huge = await opFrame(devA.kp.privateKey, 4, (1 << 20) - 50); // ~1MiB body incl header
  assert.equal(
    (await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: huge.buffer })).status,
    413,
  );
  // a streamed (chunked, no Content-Length) body must hit the same cap
  const over = rand((1 << 20) + 1);
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(over.subarray(0, 600_000));
      c.enqueue(over.subarray(600_000));
      c.close();
    },
  });
  assert.equal(
    (await req(`ops?device=${devAHex}`, {
      method: "POST", token: writeTok, body: stream, duplex: "half",
    })).status,
    413,
  );
  // malformed json → 400, not 500
  assert.equal(
    (await req("tokens", {
      method: "POST", token: admin,
      headers: { "content-type": "application/json" },
      body: "{nope",
    })).status,
    400,
  );
});

test("tokens: expired rows don't eat the 64-token cap", async () => {
  // mint MAX_TOKENS-worth of already-expired tokens; every mint purges
  // expired rows before the cap check, so none of these may 429 —
  // without the purge the table fills and mint ~#62 deadlocks the vault
  for (let i = 0; i < 64; i++) {
    const r = await jpost("tokens", { scope: "read", ttl_s: -1 }, admin);
    assert.equal(r.status, 200, `mint ${i}: ${JSON.stringify(r.json)}`);
  }
  // and a live token still mints
  assert.equal((await jpost("tokens", { scope: "read" }, admin)).status, 200);
});

// ── pagination / partial sync ────────────────────────────────────────

test("ops pagination: count cap + since resume (partial sync)", async () => {
  // devA already has head=3; push 300 more → 303 total
  const ctLen = 8;
  const frameLen = FRAME_HDR + ctLen;
  const more = await opBatch(devA.kp.privateKey, 4, 300, ctLen);
  // push in ≤256-frame chunks — the client's contract too
  for (let off = 0; off < 300; off += 256) {
    // subarray is a VIEW — pass the Uint8Array itself, never `.buffer`
    // (which would post the whole 300-frame backing store)
    const slice = more.subarray(off * frameLen, Math.min((off + 256) * frameLen, more.length));
    const r = await req(`ops?device=${devAHex}`, { method: "POST", token: writeTok, body: slice });
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }

  // page 1: exactly 256 frames, more=1, head reports true tip
  // (the first 3 ops are 164B frames — count frames, not bytes)
  const p1 = await req(`ops?device=${devAHex}&since=0&limit=256`, { token: writeTok });
  assert.equal(p1.status, 200);
  assert.equal(p1.headers.get("x-more"), "1");
  assert.equal(p1.headers.get("x-head"), "303");
  const f1 = parseFrames(p1.buf);
  assert.equal(f1.length, 256);
  assert.equal(f1[0].seq, 1);
  assert.equal(f1.at(-1).seq, 256);

  // page 2 resumes at seq 257 — partial sync completes
  const p2 = await req(`ops?device=${devAHex}&since=256&limit=256`, { token: writeTok });
  assert.equal(p2.headers.get("x-more"), "0");
  const f2 = parseFrames(p2.buf);
  assert.equal(f2.length, 47);
  assert.equal(f2[0].seq, 257);
  assert.equal(f2.at(-1).seq, 303);
});

test("ops pagination: byte bound caps the page under the count", async () => {
  // two ~700KiB frames can't share a 1MiB page
  const devBig = await newEd25519();
  const devBigHex = hex(rand(16));
  // register devBig — owner-signed manifest bump
  const cur = await sha256hex(manifestBytes);
  const bumped = await manifestFile({
    vaultId, owner, snapshotEpoch: 10,
    devices: [
      deviceTlv(unhex(devAHex), devA.vk, "dev-a"),
      deviceTlv(unhex(devBigHex), devBig.vk, "dev-big"),
    ],
  });
  const put = await req("manifest", {
    method: "PUT", token: admin,
    body: JSON.stringify({ manifest: hex(bumped), base_hash: cur }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  manifestBytes = bumped;
  const bigTok = (await jpost("tokens", { scope: "write", device: devBigHex }, admin)).json.token;
  const ctLen = 700 * 1024;
  const flen = FRAME_HDR + ctLen;
  const two = await opBatch(devBig.kp.privateKey, 1, 2, ctLen);
  // each frame > half of 1MiB but each fits a single push body
  for (const off of [0, 1]) {
    const one = two.subarray(off * flen, (off + 1) * flen);
    const r = await req(`ops?device=${devBigHex}`, { method: "POST", token: bigTok, body: one });
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }
  const p1 = await req(`ops?device=${devBigHex}&since=0&limit=256`, { token: bigTok });
  assert.equal(p1.headers.get("x-more"), "1");
  assert.equal(p1.buf.length, flen, "one frame per byte-bound page");
  const p2 = await req(`ops?device=${devBigHex}&since=1&limit=256`, { token: bigTok });
  assert.equal(p2.headers.get("x-more"), "0");
  assert.equal(p2.buf.length, flen);
});

// ── enrollment ───────────────────────────────────────────────────────

test("enrollment: invite → join → pending → approve → finish → working tokens", async () => {
  const invite = (await jpost("enroll/invite", {}, admin)).json;
  assert.ok(invite.code);
  const devC = await newEd25519();
  const devCHex = hex(rand(16));

  // finish before approval → 409
  assert.equal(
    (await jpost("enroll/finish", { device: devCHex }, invite.code)).status,
    409,
  );

  // join under the invite code
  const join = await jpost(
    "enroll/join",
    { device: devCHex, vk: hex(devC.vk), name: "dev-c" },
    invite.code,
  );
  assert.equal(join.status, 200, JSON.stringify(join.json));
  assert.equal(join.json.manifest, hex(manifestBytes));

  // one invite binds to one device: a different device under the same
  // code is refused, but a same-device retry is fine
  assert.equal(
    (await jpost(
      "enroll/join",
      { device: hex(rand(16)), vk: hex((await newEd25519()).vk), name: "sneaky" },
      invite.code,
    )).status,
    409,
  );
  const retry = await jpost(
    "enroll/join",
    { device: devCHex, vk: hex(devC.vk), name: "dev-c" },
    invite.code,
  );
  assert.equal(retry.status, 200, JSON.stringify(retry.json));

  // pending lists it
  const pending = await req("enroll/pending", { token: admin });
  assert.ok(pending.json.some((p) => p.device === devCHex));

  // owner approves: push manifest with devC active
  const cur = await sha256hex(manifestBytes);
  const approved = await manifestFile({
    vaultId, owner, snapshotEpoch: 11,
    devices: [
      deviceTlv(unhex(devAHex), devA.vk, "dev-a"),
      deviceTlv(unhex(devCHex), devC.vk, "dev-c"),
    ],
  });
  // devBig was dropped from the registry — that's a revocation for it
  const put = await req("manifest", {
    method: "PUT", token: admin,
    body: JSON.stringify({ manifest: hex(approved), base_hash: cur }),
    headers: { "content-type": "application/json" },
  });
  assert.equal(put.status, 200);
  manifestBytes = approved;

  // finish mints device-bound tokens
  const fin = await jpost("enroll/finish", { device: devCHex }, invite.code);
  assert.equal(fin.status, 200, JSON.stringify(fin.json));
  assert.ok(fin.json.read && fin.json.write);

  // invite is burned — a second finish must not mint again
  assert.notEqual((await jpost("enroll/finish", { device: devCHex }, invite.code)).status, 200);

  // the minted tokens work
  const st = await req("state", { token: fin.json.read });
  assert.equal(st.status, 200);
  assert.equal(st.json.snapshot_epoch, 11);
});

test("enrollment: bad invite → 401; control-char name → 400", async () => {
  const d = await newEd25519();
  const r = await jpost("enroll/join", { device: hex(rand(16)), vk: hex(d.vk), name: "x" }, "AAAA-BBBB");
  assert.equal(r.status, 401);

  // a name with escape bytes is refused — it would land on the owner's
  // terminal via `pair pending`
  const inv = (await jpost("enroll/invite", {}, admin)).json;
  const bad = await jpost(
    "enroll/join",
    { device: hex(rand(16)), vk: hex(d.vk), name: "evil]8;;https://x" },
    inv.code,
  );
  assert.equal(bad.status, 400);
  const newline = await jpost(
    "enroll/join",
    { device: hex(rand(16)), vk: hex(d.vk), name: "a\nb" },
    inv.code,
  );
  assert.equal(newline.status, 400);
});

// ── revoke + state ───────────────────────────────────────────────────

test("revoke: device tokens die; state heads reflect pushes", async () => {
  const doomed = await jpost("tokens", { scope: "write", device: devAHex }, admin);
  const dt = doomed.json.token;
  assert.equal((await req("state", { token: dt })).status, 200);
  const rv = await jpost("revoke", { device: devAHex }, admin);
  assert.equal(rv.status, 200);
  assert.ok(rv.json.removed >= 1);
  assert.equal((await req("state", { token: dt })).status, 401);

  const st = await req("state", { token: admin });
  assert.equal(st.status, 200);
  const headA = st.json.heads.find((h) => h.device === devAHex);
  assert.equal(headA.head, 303);
});
