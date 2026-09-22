//! VaultSync — one Durable Object per vault. The transaction story §8
//! requires lives here: op append + seq continuity + manifest CAS all run
//! inside SQLite transactions on the single-threaded DO, so there is no
//! coordinator to build. Storage IS the durable copy for the wire; clients
//! still keep local retention authoritative (syncd is never the only copy).

import { DurableObject } from "cloudflare:workers";
import {
  b64,
  hex,
  newCode,
  newToken,
  opSigVerify,
  parseManifest,
  parseOpFrames,
  sha256Hex,
  unhex,
  verifyManifest,
  WireError,
  type ManifestInfo,
  type OpFrame,
} from "./wire";

export interface Env {
  SETUP_KEY: string;
}

type Scope = "read" | "write" | "admin" | "enroll";

// ── bounds (§8: bound everything before buffering) ──────────────────
const MAX_BODY = 1 << 20; // 1 MiB request bodies
const MAX_OPS_BATCH = 256;
const PAGE_MAX = 256;
// Aggregate byte budget for one GET /ops page — mirrors the push cap.
const PAGE_MAX_BYTES = 1 << 20;
const MAX_TOKENS = 64;
const MAX_PENDING = 16;
const MAX_INVITES = 8;
const INVITE_TTL_S = 15 * 60;
const MAX_SNAPSHOTS = 8;

interface TokenRow extends Record<string, SqlStorageValue> {
  hash: string;
  scope: string;
  device: string | null;
  created: number;
  expires: number | null;
}

interface PendingRow extends Record<string, SqlStorageValue> {
  device: string;
  vk: ArrayBuffer;
  name: string;
  created: number;
}

const http = (status: number, msg: string) => new WireError(`${status} ${msg}`, status);

export class VaultSync extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      const sql = ctx.storage.sql;
      sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)`);
      sql.exec(
        `CREATE TABLE IF NOT EXISTS ops (
           device TEXT NOT NULL, seq INTEGER NOT NULL, body BLOB NOT NULL,
           PRIMARY KEY (device, seq)
         ) STRICT`,
      );
      sql.exec(
        `CREATE TABLE IF NOT EXISTS tokens (
           hash TEXT PRIMARY KEY, scope TEXT NOT NULL, device TEXT,
           created INTEGER NOT NULL, expires INTEGER
         ) STRICT`,
      );
      sql.exec(
        `CREATE TABLE IF NOT EXISTS invites (
           hash TEXT PRIMARY KEY, created INTEGER NOT NULL, expires INTEGER NOT NULL
         ) STRICT`,
      );
      sql.exec(
        `CREATE TABLE IF NOT EXISTS pending (
           device TEXT PRIMARY KEY, vk BLOB NOT NULL, name TEXT NOT NULL,
           created INTEGER NOT NULL
         ) STRICT`,
      );
      sql.exec(
        `CREATE TABLE IF NOT EXISTS snapshots (
           epoch INTEGER PRIMARY KEY, body BLOB NOT NULL
         ) STRICT`,
      );
    });
  }

  // ── storage helpers ────────────────────────────────────────────────

  private get sql() {
    return this.ctx.storage.sql;
  }

  private manifestBytes(): ArrayBuffer | null {
    const r = this.sql.exec(`SELECT v FROM meta WHERE k = 'manifest'`).toArray();
    return (r[0]?.v as ArrayBuffer) ?? null;
  }

  private manifest(): ManifestInfo | null {
    const b = this.manifestBytes();
    return b ? parseManifest(new Uint8Array(b)) : null;
  }

  private requireManifest(): ManifestInfo {
    const m = this.manifest();
    if (!m) throw http(404, "vault not bootstrapped");
    return m;
  }

  /** Bearer token → scope check. `admin` satisfies every scope. */
  private async authorize(auth: string | null, need: Scope, device?: string): Promise<TokenRow> {
    if (!auth) throw http(401, "missing bearer token");
    const hash = await sha256Hex(auth);
    const row = this.sql
      .exec<TokenRow>(`SELECT * FROM tokens WHERE hash = ?`, hash)
      .toArray()[0];
    if (!row) throw http(401, "bad token");
    if (row.expires !== null && row.expires < nowS()) {
      this.sql.exec(`DELETE FROM tokens WHERE hash = ?`, hash);
      throw http(401, "token expired");
    }
    const ok =
      row.scope === "admin" ||
      row.scope === need ||
      (need === "read" && row.scope === "write"); // a write token can read sync state
    if (!ok) throw http(403, `token lacks ${need} scope`);
    // stored bindings are lowercase — normalize the request's device id
    // or ?device=ABCD… would 403 a legitimately bound token
    if (device !== undefined && row.scope !== "admin" && row.device !== device.toLowerCase()) {
      throw http(403, "token not bound to this device");
    }
    return row;
  }

  /** Invite-code auth for the join/finish endpoints. */
  private async requireInvite(code: string | null): Promise<string> {
    if (!code) throw http(401, "missing enroll code");
    const hash = await sha256Hex(code.toUpperCase());
    const row = this.sql
      .exec<{ hash: string; expires: number }>(
        `SELECT hash, expires FROM invites WHERE hash = ?`,
        hash,
      )
      .toArray()[0];
    if (!row) throw http(401, "bad code");
    if (row.expires < nowS()) {
      this.sql.exec(`DELETE FROM invites WHERE hash = ?`, hash);
      throw http(401, "code expired");
    }
    return hash;
  }

  private async mintToken(scope: Scope, device: string | null, ttlS: number | null): Promise<string> {
    const count = this.sql.exec(`SELECT count(*) AS n FROM tokens`).one().n as number;
    if (count >= MAX_TOKENS) throw http(429, "token cap reached");
    const token = `${newToken()}_${scope[0]}`;
    this.sql.exec(
      `INSERT INTO tokens (hash, scope, device, created, expires) VALUES (?,?,?,?,?)`,
      await sha256Hex(token),
      scope,
      device,
      nowS(),
      ttlS === null ? null : nowS() + ttlS,
    );
    return token;
  }

  private static bytes(v: unknown): Uint8Array {
    return v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v as ArrayBufferLike);
  }

  // ── RPC surface ────────────────────────────────────────────────────

  /** First manifest write. Worker already authenticated via SETUP_KEY.
   *  `vaultId` is the DO's name — the manifest's embedded vault_id must
   *  match it so a bootstrap can't land under the wrong vault. */
  async bootstrap(vaultId: string, manifest: ArrayBuffer): Promise<{ token: string }> {
    if (manifest.byteLength > 64 * 1024) throw http(413, "manifest too large");
    if (this.manifestBytes()) throw http(409, "vault already exists");
    const info = parseManifest(new Uint8Array(manifest));
    if (!(await verifyManifest(new Uint8Array(manifest), info))) {
      throw http(400, "manifest self-signature invalid");
    }
    if (hex(info.vaultId) !== vaultId.toLowerCase()) {
      throw http(400, "manifest vault_id does not match the path");
    }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(`INSERT INTO meta (k, v) VALUES ('manifest', ?)`, manifest);
    });
    return { token: await this.mintToken("admin", null, null) };
  }

  async getManifest(auth: string | null): Promise<{ manifest: ArrayBuffer; snapshot_epoch: number }> {
    await this.authorize(auth, "read");
    const b = this.manifestBytes();
    if (!b) throw http(404, "vault not bootstrapped");
    const m = parseManifest(new Uint8Array(b));
    return { manifest: b, snapshot_epoch: Number(m.snapshotEpoch) };
  }

  /** Compare-and-swap on the sha256 of the stored manifest — serializes
   *  device adds/revokes regardless of epoch movement. Epochs may never
   *  decrease (rollback defense). */
  async putManifest(
    auth: string | null,
    manifest: ArrayBuffer,
    baseHash: string,
  ): Promise<{ snapshot_epoch: number }> {
    await this.authorize(auth, "admin");
    if (manifest.byteLength > 64 * 1024) throw http(413, "manifest too large");
    const stored = this.manifestBytes();
    if (!stored) throw http(404, "vault not bootstrapped");
    const storedHash = await sha256Hex(new Uint8Array(stored));
    if (storedHash !== baseHash.toLowerCase()) throw http(409, "manifest changed — re-pull");
    const info = parseManifest(new Uint8Array(manifest));
    const cur = this.requireManifest();
    if (hex(info.vaultId) !== hex(cur.vaultId)) throw http(400, "vault_id mismatch");
    // the self-signature proves nothing without pinning — an admin token
    // holder could otherwise push a manifest signed by *their* key
    if (hex(info.ownerVk) !== hex(cur.ownerVk)) {
      throw http(400, "owner key mismatch — owner keys do not rotate");
    }
    if (!(await verifyManifest(new Uint8Array(manifest), info))) {
      throw http(400, "manifest signature invalid");
    }
    if (info.keyEpoch < cur.keyEpoch || info.snapshotEpoch < cur.snapshotEpoch) {
      throw http(409, "epoch regression — refusing older manifest");
    }
    this.sql.exec(`UPDATE meta SET v = ? WHERE k = 'manifest'`, manifest);
    return { snapshot_epoch: Number(info.snapshotEpoch) };
  }

  /** Cheap sync probe: manifest epoch + per-device seq heads. */
  async state(auth: string | null): Promise<{
    snapshot_epoch: number;
    heads: { device: string; head: number }[];
  }> {
    await this.authorize(auth, "read");
    const m = this.requireManifest();
    const heads = this.sql
      .exec<{ device: string; head: number }>(
        `SELECT device, max(seq) AS head FROM ops GROUP BY device`,
      )
      .toArray();
    return { snapshot_epoch: Number(m.snapshotEpoch), heads };
  }

  /** Raw concatenated op frames — the client appends them to its local
   *  log verbatim, no decoding round-trip. */
  async getOps(
    auth: string | null,
    device: string,
    since: number,
    limit: number,
  ): Promise<{ frames: ArrayBuffer; head: number; more: boolean }> {
    await this.authorize(auth, "read");
    if (!/^[0-9a-f]{32}$/i.test(device)) throw http(400, "bad device id");
    const lim = Math.min(Math.max(limit | 0, 1), PAGE_MAX);
    const rows = this.sql
      .exec<{ seq: number; body: ArrayBuffer }>(
        `SELECT seq, body FROM ops WHERE device = ? AND seq > ? ORDER BY seq LIMIT ?`,
        device.toLowerCase(),
        since,
        lim + 1, // one extra row = "more" flag without a second query
      )
      .toArray();
    // Bound the page by BOTH count and bytes: the lim+1 probe row flags
    // truncation; a frame that would overflow the byte budget defers to
    // the next page (more=1), keeping the seq cursor correct.
    const page: Array<{ seq: number; body: ArrayBuffer }> = [];
    let total = 0;
    let more = false;
    for (const [i, r] of rows.entries()) {
      if (i === lim) {
        more = true;
        break;
      }
      if (page.length > 0 && total + r.body.byteLength > PAGE_MAX_BYTES) {
        more = true;
        break;
      }
      page.push(r);
      total += r.body.byteLength;
    }
    const frames = new Uint8Array(total);
    let off = 0;
    for (const r of page) {
      frames.set(VaultSync.bytes(r.body), off);
      off += r.body.byteLength;
    }
    const head =
      (this.sql
        .exec<{ h: number | null }>(`SELECT max(seq) AS h FROM ops WHERE device = ?`, device.toLowerCase())
        .toArray()[0]?.h ?? 0);
    return { frames: frames.buffer, head, more };
  }

  /** Append a batch of op frames for one device. Every op's ed25519 sig is
   *  verified against the manifest's device registry — a write token can
   *  only extend *its* device's chain. seq ≤ head with identical bytes is
   *  an idempotent replay; different bytes = equivocation → 409. */
  async appendOps(auth: string | null, device: string, body: ArrayBuffer): Promise<{ head: number }> {
    const tok = await this.authorize(auth, "write", device);
    void tok;
    if (!/^[0-9a-f]{32}$/i.test(device)) throw http(400, "bad device id");
    if (body.byteLength === 0 || body.byteLength > MAX_BODY) throw http(413, "bad body size");
    const dev = device.toLowerCase();
    const frames = parseOpFrames(new Uint8Array(body));
    if (frames.length > MAX_OPS_BATCH) throw http(413, "too many ops in batch");
    const m = this.requireManifest();
    const entry = m.devices.find((d) => hex(d.id) === dev);
    if (!entry) throw http(403, "device not in registry");
    if (!entry.active) throw http(403, "device revoked");
    // sig verification is async — finish it BEFORE opening the txn
    for (const f of frames) {
      if (!(await opSigVerify(entry.vk, f))) {
        throw http(403, `op ${f.seq}: bad device signature`);
      }
    }
    let head = 0;
    this.ctx.storage.transactionSync(() => {
      const h = this.sql
        .exec<{ h: number | null }>(`SELECT max(seq) AS h FROM ops WHERE device = ?`, dev)
        .toArray()[0];
      head = h?.h ?? 0;
      for (const f of frames) {
        const seq = Number(f.seq);
        if (seq <= head) {
          const cur = this.sql
            .exec<{ body: ArrayBuffer }>(`SELECT body FROM ops WHERE device = ? AND seq = ?`, dev, seq)
            .toArray()[0];
          if (!cur || !eqBytes(VaultSync.bytes(cur.body), f.raw)) {
            throw http(409, `op ${seq}: equivocation — different bytes at an existing seq`);
          }
          continue; // idempotent re-push
        }
        if (seq !== head + 1) throw http(409, `op ${seq}: gap — expected ${head + 1}`);
        this.sql.exec(`INSERT INTO ops (device, seq, body) VALUES (?,?,?)`, dev, seq, f.raw.slice().buffer);
        head = seq;
      }
    });
    return { head };
  }

  // ── snapshots (immutable objects; compaction lands with M3-proper) ──

  async getSnapshot(auth: string | null, epoch: number | null): Promise<ArrayBuffer | null> {
    await this.authorize(auth, "read");
    const row = epoch === null
      ? this.sql.exec<{ body: ArrayBuffer }>(`SELECT body FROM snapshots ORDER BY epoch DESC LIMIT 1`).toArray()[0]
      : this.sql.exec<{ body: ArrayBuffer }>(`SELECT body FROM snapshots WHERE epoch = ?`, epoch).toArray()[0];
    return row?.body ?? null;
  }

  async putSnapshot(auth: string | null, epoch: number, body: ArrayBuffer): Promise<{ epoch: number }> {
    await this.authorize(auth, "write");
    if (body.byteLength === 0 || body.byteLength > MAX_BODY) throw http(413, "bad snapshot size");
    const existing = this.sql
      .exec<{ body: ArrayBuffer }>(`SELECT body FROM snapshots WHERE epoch = ?`, epoch)
      .toArray()[0];
    if (existing) {
      if (!eqBytes(VaultSync.bytes(existing.body), new Uint8Array(body))) {
        throw http(409, "snapshot epoch exists with different bytes");
      }
      return { epoch };
    }
    const count = this.sql.exec(`SELECT count(*) AS n FROM snapshots`).one().n as number;
    if (count >= MAX_SNAPSHOTS) throw http(429, "snapshot cap — compact first");
    this.sql.exec(`INSERT INTO snapshots (epoch, body) VALUES (?,?)`, epoch, body);
    return { epoch };
  }

  // ── tokens ─────────────────────────────────────────────────────────

  async mintScopedToken(
    auth: string | null,
    scope: Scope,
    device: string | null,
    ttlS: number | null,
  ): Promise<{ token: string }> {
    await this.authorize(auth, "admin");
    if (!["read", "write", "admin"].includes(scope)) throw http(400, "bad scope");
    if (device !== null) {
      if (!/^[0-9a-f]{32}$/i.test(device)) throw http(400, "bad device id");
      device = device.toLowerCase();
    }
    return { token: await this.mintToken(scope, device, ttlS) };
  }

  /** Revocation companion: drop every token bound to a device. The real
   *  revocation is the manifest registry update the client pushes after. */
  async revokeDevice(auth: string | null, device: string): Promise<{ removed: number }> {
    await this.authorize(auth, "admin");
    const r = this.sql.exec(`DELETE FROM tokens WHERE device = ?`, device.toLowerCase());
    this.sql.exec(`DELETE FROM pending WHERE device = ?`, device.toLowerCase());
    return { removed: r.rowsWritten };
  }

  // ── enrollment ─────────────────────────────────────────────────────

  /** Admin mints a short-lived invite code; the human carries it to the
   *  new device (typed or QR). Hash-stored, single-join + single-finish. */
  async enrollInvite(auth: string | null): Promise<{ code: string; ttl_s: number }> {
    await this.authorize(auth, "admin");
    this.sql.exec(`DELETE FROM invites WHERE expires < ?`, nowS());
    const count = this.sql.exec(`SELECT count(*) AS n FROM invites`).one().n as number;
    if (count >= MAX_INVITES) throw http(429, "too many live invites");
    const code = newCode();
    this.sql.exec(
      `INSERT INTO invites (hash, created, expires) VALUES (?,?,?)`,
      await sha256Hex(code),
      nowS(),
      nowS() + INVITE_TTL_S,
    );
    return { code, ttl_s: INVITE_TTL_S };
  }

  /** New device submits its pubkey under the invite code — and gets the
   *  manifest back: the code IS its read capability until finish mints
   *  real tokens (it needs the manifest to attempt a password unlock). */
  async enrollJoin(
    code: string | null,
    deviceId: string,
    vk: string,
    name: string,
  ): Promise<{ manifest: ArrayBuffer; snapshot_epoch: number }> {
    await this.requireInvite(code);
    if (!/^[0-9a-f]{32}$/i.test(deviceId)) throw http(400, "bad device id");
    const vkb = unhex(vk);
    if (vkb.length !== 32) throw http(400, "bad vk");
    if (!name || name.length > 64) throw http(400, "bad device name");
    const dev = deviceId.toLowerCase();
    this.sql.exec(`DELETE FROM pending WHERE created < ?`, nowS() - INVITE_TTL_S);
    // A retry may refresh the row, but a DIFFERENT vk for the same device
    // id means squatting — an invite must never overwrite another joiner's
    // key under a name the owner might recognize.
    const existing = this.sql
      .exec<{ vk: ArrayBuffer }>(`SELECT vk FROM pending WHERE device = ?`, dev)
      .one();
    if (existing && hex(VaultSync.bytes(existing.vk)) !== vk.toLowerCase())
      throw http(409, "device id already pending under a different key — decline it first");
    if (!existing) {
      const count = this.sql.exec(`SELECT count(*) AS n FROM pending`).one().n as number;
      if (count >= MAX_PENDING) throw http(429, "too many pending devices");
    }
    this.sql.exec(
      `INSERT OR REPLACE INTO pending (device, vk, name, created) VALUES (?,?,?,?)`,
      dev,
      vkb.slice().buffer,
      name,
      nowS(),
    );
    const b = this.manifestBytes();
    if (!b) throw http(404, "vault not bootstrapped");
    const m = parseManifest(new Uint8Array(b));
    return { manifest: b, snapshot_epoch: Number(m.snapshotEpoch) };
  }

  async enrollPending(auth: string | null): Promise<
    { device: string; vk: string; name: string; created: number }[]
  > {
    await this.authorize(auth, "admin");
    return this.sql
      .exec<PendingRow>(`SELECT * FROM pending ORDER BY created`)
      .toArray()
      .map((r) => ({ device: r.device, vk: hex(VaultSync.bytes(r.vk)), name: r.name, created: r.created }));
  }

  async enrollDecline(auth: string | null, deviceId: string): Promise<{ ok: true }> {
    await this.authorize(auth, "admin");
    this.sql.exec(`DELETE FROM pending WHERE device = ?`, deviceId.toLowerCase());
    return { ok: true };
  }

  /** The code → tokens exchange. Approval is NOT a server flag — it's the
   *  device appearing in the owner-signed manifest — AND the code only
   *  redeems for the device that joined under it: finish requires a
   *  pending row whose vk matches the approved registry vk. Without that
   *  check an invite holder could mint tokens bound to any already-active
   *  device. The new device gets read + write tokens bound to its id; the
   *  invite is burned. */
  async enrollFinish(
    code: string | null,
    deviceId: string,
  ): Promise<{ read: string; write: string; manifest: ArrayBuffer; snapshot_epoch: number }> {
    const hash = await this.requireInvite(code);
    const dev = deviceId.toLowerCase();
    const m = this.requireManifest();
    const entry = m.devices.find((d) => hex(d.id) === dev);
    if (!entry || !entry.active) {
      throw http(409, "not approved yet — the enrolled device must sign you into the manifest");
    }
    const pend = this.sql
      .exec<{ vk: ArrayBuffer }>(`SELECT vk FROM pending WHERE device = ?`, dev)
      .toArray()[0];
    if (!pend) {
      throw http(409, "no pending join for this device — re-run pair join under a fresh invite");
    }
    if (hex(VaultSync.bytes(pend.vk)) !== hex(entry.vk)) {
      throw http(409, "pending key does not match the approved registry key");
    }
    const read = await this.mintToken("read", dev, null);
    const write = await this.mintToken("write", dev, null);
    this.sql.exec(`DELETE FROM invites WHERE hash = ?`, hash);
    this.sql.exec(`DELETE FROM pending WHERE device = ?`, dev);
    const b = this.manifestBytes()!;
    return { read, write, manifest: b, snapshot_epoch: Number(m.snapshotEpoch) };
  }
}

// ── helpers ──────────────────────────────────────────────────────────

const nowS = () => Math.floor(Date.now() / 1000);

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
