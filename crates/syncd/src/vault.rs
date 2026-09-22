//! Per-vault SQLite store — one file per vault (`<data_dir>/<vault_id>.db`),
//! mirroring the per-vault-Durable-Object isolation of the Cloudflare
//! backend. Same schema, same semantics: sig-verify before the transaction,
//! seq continuity + equivocation checks inside it. The router holds a
//! per-vault lock so handlers serialize exactly like the single-threaded DO.

use mpm_core::Manifest;
use rand_core::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

pub const MAX_MANIFEST: usize = 64 * 1024;
pub const MAX_BODY: usize = 1 << 20;
pub const MAX_OPS_BATCH: usize = 256;
pub const PAGE_MAX: u64 = 256;
/// Aggregate byte budget for one GET /ops page — mirrors the push cap so
/// a page can never exceed what a single write batch may carry.
pub const PAGE_MAX_BYTES: usize = 1 << 20;
pub const MAX_TOKENS: i64 = 64;
pub const MAX_PENDING: i64 = 16;
pub const MAX_INVITES: i64 = 8;
pub const INVITE_TTL_S: i64 = 15 * 60;
pub const MAX_SNAPSHOTS: i64 = 8;

/// Errors carry an HTTP status — the router maps them straight through.
pub struct Ve(pub u16, pub String);
pub fn ve<T>(status: u16, msg: impl Into<String>) -> Result<T, Ve> {
    Err(Ve(status, msg.into()))
}
type VResult<T> = Result<T, Ve>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Read,
    Write,
    Admin,
}
impl Scope {
    fn from_str(s: &str) -> Option<Scope> {
        Some(match s {
            "read" => Scope::Read,
            "write" => Scope::Write,
            "admin" => Scope::Admin,
            _ => return None,
        })
    }
    fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Admin => "admin",
        }
    }
}

fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn valid_dev(device: &str) -> bool {
    device.len() == 32 && device.bytes().all(|b| b.is_ascii_hexdigit())
}

pub struct VaultStore {
    conn: Connection,
}

impl VaultStore {
    /// `create` is for bootstrap only — callers pass false for every other
    /// route so a request for a nonexistent vault can't mint a db file.
    /// New db files are chmod 0600: the manifest inside carries wrap slots.
    pub fn open(path: &std::path::Path, create: bool) -> rusqlite::Result<Self> {
        let existed = path.exists();
        let conn = if create {
            Connection::open(path)?
        } else {
            Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?
        };
        #[cfg(unix)]
        if create && !existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000i64)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
             CREATE TABLE IF NOT EXISTS ops (
               device TEXT NOT NULL, seq INTEGER NOT NULL, body BLOB NOT NULL,
               PRIMARY KEY (device, seq)) STRICT;
             CREATE TABLE IF NOT EXISTS tokens (
               hash TEXT PRIMARY KEY, scope TEXT NOT NULL, device TEXT,
               created INTEGER NOT NULL, expires INTEGER) STRICT;
             CREATE TABLE IF NOT EXISTS invites (
               hash TEXT PRIMARY KEY, created INTEGER NOT NULL,
               expires INTEGER NOT NULL) STRICT;
             CREATE TABLE IF NOT EXISTS pending (
               device TEXT PRIMARY KEY, vk BLOB NOT NULL, name TEXT NOT NULL,
               created INTEGER NOT NULL) STRICT;
             CREATE TABLE IF NOT EXISTS snapshots (
               epoch INTEGER PRIMARY KEY, body BLOB NOT NULL) STRICT;",
        )?;
        Ok(Self { conn })
    }

    // ── auth ──────────────────────────────────────────────────────────

    /// Bearer token → scope check. `admin` satisfies every scope; `write`
    /// satisfies `read`. Device-bound non-admin tokens act only for their
    /// device; an unbound non-admin token fails any device-scoped call.
    fn authorize(&self, bearer: Option<&str>, need: Scope, device: Option<&str>) -> VResult<()> {
        let token = bearer.ok_or(Ve(401, "missing bearer token".into()))?;
        let hash = sha256_hex(token.as_bytes());
        let row = self
            .conn
            .query_row(
                "SELECT scope, device, expires FROM tokens WHERE hash = ?1",
                params![hash],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| Ve(500, "db".into()))?
            .ok_or(Ve(401, "bad token".into()))?;
        let (scope_s, dev, expires) = row;
        if let Some(e) = expires {
            if e < now_s() {
                self.conn
                    .execute("DELETE FROM tokens WHERE hash = ?1", params![hash])
                    .ok();
                return ve(401, "token expired");
            }
        }
        let scope = Scope::from_str(&scope_s).ok_or(Ve(500, "bad scope row".into()))?;
        let ok = scope == Scope::Admin
            || scope == need
            || (need == Scope::Read && scope == Scope::Write);
        if !ok {
            return ve(403, "insufficient scope");
        }
        if let Some(req) = device {
            // stored bindings are lowercase — normalize the request's id
            // or `?device=ABCD…` would 403 a legitimately bound token
            if scope != Scope::Admin && dev.as_deref() != Some(req.to_ascii_lowercase().as_str()) {
                return ve(403, "token not bound to this device");
            }
        }
        Ok(())
    }

    /// Invite-code auth for the join/finish endpoints — codes travel as
    /// the bearer token. Check-only; `enroll_finish` burns the invite.
    fn require_invite(&self, code: Option<&str>) -> VResult<String> {
        let code = code.ok_or(Ve(401, "missing enroll code".into()))?;
        let hash = sha256_hex(code.to_uppercase().as_bytes());
        let expires: Option<i64> = self
            .conn
            .query_row(
                "SELECT expires FROM invites WHERE hash = ?1",
                params![hash],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Ve(500, "db".into()))?;
        let Some(e) = expires else {
            return ve(401, "bad code");
        };
        if e < now_s() {
            self.conn
                .execute("DELETE FROM invites WHERE hash = ?1", params![hash])
                .ok();
            return ve(401, "code expired");
        }
        Ok(hash)
    }

    fn mint_token(
        &self,
        scope: Scope,
        device: Option<&str>,
        ttl_s: Option<i64>,
    ) -> VResult<String> {
        Self::mint_token_on(&self.conn, scope, device, ttl_s)
    }

    fn mint_token_on(
        conn: &Connection,
        scope: Scope,
        device: Option<&str>,
        ttl_s: Option<i64>,
    ) -> VResult<String> {
        let count: i64 = conn
            .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))
            .map_err(|_| Ve(500, "db".into()))?;
        if count >= MAX_TOKENS {
            return ve(429, "token cap reached");
        }
        let token = format!("{}_{}", new_token(), scope.as_str().as_bytes()[0] as char);
        let expires = ttl_s.map(|t| now_s().saturating_add(t));
        conn.execute(
            "INSERT INTO tokens (hash, scope, device, created, expires) VALUES (?1,?2,?3,?4,?5)",
            params![
                sha256_hex(token.as_bytes()),
                scope.as_str(),
                device,
                now_s(),
                expires
            ],
        )
        .map_err(|_| Ve(500, "db".into()))?;
        Ok(token)
    }

    // ── bootstrap / manifest ──────────────────────────────────────────

    /// First manifest write. Router already authenticated via setup key.
    /// `vault_id` is the path id — the manifest's embedded vault_id must
    /// match it so a bootstrap can't land under the wrong vault.
    pub fn bootstrap(&self, vault_id: &str, manifest: &[u8]) -> VResult<String> {
        if manifest.len() > MAX_MANIFEST {
            return ve(413, "manifest too large");
        }
        if self.manifest_bytes()?.is_some() {
            return ve(409, "vault already exists");
        }
        // from_file parses AND verifies the owner self-signature
        let m = Manifest::from_file(manifest)
            .map_err(|_| ve_err(400, "manifest self-signature invalid"))?;
        if hex(&m.vault_id) != vault_id.to_ascii_lowercase() {
            return ve(400, "manifest vault_id does not match the path");
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| Ve(500, "db".into()))?;
        tx.execute(
            "INSERT INTO meta (k, v) VALUES ('manifest', ?1)",
            params![manifest],
        )
        .map_err(|_| Ve(500, "db".into()))?;
        let token = Self::mint_token_on(&tx, Scope::Admin, None, None)?;
        tx.commit().map_err(|_| Ve(500, "db".into()))?;
        Ok(token)
    }

    fn manifest_bytes(&self) -> VResult<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = 'manifest'", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map_err(|_| Ve(500, "db".into()))
    }

    fn require_manifest(&self) -> VResult<(Vec<u8>, Manifest)> {
        let bytes = self
            .manifest_bytes()?
            .ok_or(Ve(404, "vault not bootstrapped".into()))?;
        let m =
            Manifest::from_file(&bytes).map_err(|_| Ve(500, "stored manifest corrupt".into()))?;
        Ok((bytes, m))
    }

    pub fn get_manifest(&self, bearer: Option<&str>) -> VResult<(Vec<u8>, u64)> {
        self.authorize(bearer, Scope::Read, None)?;
        let (bytes, m) = self.require_manifest()?;
        Ok((bytes, m.snapshot_epoch))
    }

    /// Compare-and-swap on the sha256 of the stored manifest — serializes
    /// device adds/revokes regardless of epoch movement. Epochs may never
    /// decrease (rollback defense) and vault_id is pinned at bootstrap.
    pub fn put_manifest(&self, bearer: Option<&str>, body: &[u8], base_hash: &str) -> VResult<u64> {
        self.authorize(bearer, Scope::Admin, None)?;
        if body.len() > MAX_MANIFEST {
            return ve(413, "manifest too large");
        }
        let (stored, cur) = self.require_manifest()?;
        if sha256_hex(&stored) != base_hash.to_ascii_lowercase() {
            return ve(409, "manifest changed — re-pull");
        }
        let m = Manifest::from_file(body).map_err(|_| ve_err(400, "manifest signature invalid"))?;
        if m.vault_id != cur.vault_id {
            return ve(400, "vault_id mismatch");
        }
        // the self-signature proves nothing without pinning — an admin token
        // holder could otherwise push a manifest signed by *their* key
        if m.owner_vk != cur.owner_vk {
            return ve(400, "owner key mismatch — owner keys do not rotate");
        }
        if m.key_epoch < cur.key_epoch || m.snapshot_epoch < cur.snapshot_epoch {
            return ve(409, "epoch regression — refusing older manifest");
        }
        self.conn
            .execute("UPDATE meta SET v = ?1 WHERE k = 'manifest'", params![body])
            .map_err(|_| Ve(500, "db".into()))?;
        Ok(m.snapshot_epoch)
    }

    /// Cheap sync probe: manifest epoch + per-device seq heads.
    pub fn state(&self, bearer: Option<&str>) -> VResult<(u64, Vec<(String, u64)>)> {
        self.authorize(bearer, Scope::Read, None)?;
        let (_, m) = self.require_manifest()?;
        let mut stmt = self
            .conn
            .prepare("SELECT device, max(seq) FROM ops GROUP BY device")
            .map_err(|_| Ve(500, "db".into()))?;
        let heads = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|_| Ve(500, "db".into()))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Ve(500, "db".into()))?;
        Ok((m.snapshot_epoch, heads))
    }

    /// Raw concatenated op frames — the client appends them to its local
    /// log verbatim, no decoding round-trip. `head` is the device's true
    /// head (global max seq), even when the page is partial.
    pub fn get_ops(
        &self,
        bearer: Option<&str>,
        device: &str,
        since: u64,
        limit: u64,
    ) -> VResult<(Vec<u8>, u64, bool)> {
        self.authorize(bearer, Scope::Read, None)?;
        if !valid_dev(device) {
            return ve(400, "bad device id");
        }
        let dev = device.to_ascii_lowercase();
        let lim = limit.clamp(1, PAGE_MAX);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, body FROM ops WHERE device = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
            )
            .map_err(|_| Ve(500, "db".into()))?;
        let rows = stmt
            .query_map(params![dev, since as i64, (lim + 1) as i64], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|_| Ve(500, "db".into()))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Ve(500, "db".into()))?;
        // Bound the page by BOTH count and bytes: the lim+1 probe row
        // flags truncation, and a frame that would overflow the byte
        // budget is deferred to the next page (more=1) so the cursor
        // stays correct. A single stored frame always fits — ingest
        // capped bodies at 1 MiB — but an empty `out` is never blocked.
        let mut more = false;
        let mut out = Vec::new();
        for (i, (_, body)) in rows.iter().enumerate() {
            if i as u64 == lim {
                more = true;
                break;
            }
            if !out.is_empty() && out.len() + body.len() > PAGE_MAX_BYTES {
                more = true;
                break;
            }
            out.extend_from_slice(body);
        }
        let head: u64 = self
            .conn
            .query_row(
                "SELECT max(seq) FROM ops WHERE device = ?1",
                params![dev],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(|_| Ve(500, "db".into()))?
            .unwrap_or(0) as u64;
        Ok((out, head, more))
    }

    /// Append a batch of op frames for one device. Every op's ed25519 sig
    /// is verified against the manifest's device registry — a write token
    /// can only extend *its* device's chain. seq ≤ head with identical
    /// bytes is an idempotent replay; different bytes = equivocation → 409.
    pub fn append_ops(&self, bearer: Option<&str>, device: &str, body: &[u8]) -> VResult<u64> {
        self.authorize(bearer, Scope::Write, Some(device))?;
        if !valid_dev(device) {
            return ve(400, "bad device id");
        }
        if body.is_empty() || body.len() > MAX_BODY {
            return ve(413, "bad body size");
        }
        let dev = device.to_ascii_lowercase();
        let (_, m) = self.require_manifest()?;
        let entry = m
            .devices
            .iter()
            .find(|d| hex(&d.id) == dev)
            .ok_or(Ve(403, "device not in registry".into()))?;
        if !entry.active {
            return ve(403, "device revoked");
        }

        // decode all frames first (cheap), cap the batch BEFORE paying
        // for signature verification — matches the TS backend's order
        let mut frames: Vec<(mpm_core::Op, &[u8])> = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            let (op, n) = mpm_core::Op::decode(rest).map_err(|e| Ve(400, format!("op: {e}")))?;
            frames.push((op, &rest[..n]));
            if frames.len() > MAX_OPS_BATCH {
                return ve(413, "too many ops in batch");
            }
            rest = &rest[n..];
        }
        for (op, _) in &frames {
            let pre = mpm_core::aad::op_sig_preimage(op.seq, &op.nonce, &op.ct);
            let sig = ed25519_dalek::Signature::from_bytes(&op.sig);
            if mpm_crypto::keys::verify(&entry.vk, &pre, &sig).is_err() {
                return ve(403, format!("op {}: bad device signature", op.seq));
            }
        }

        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| Ve(500, "db".into()))?;
        let mut head: u64 = tx
            .query_row(
                "SELECT max(seq) FROM ops WHERE device = ?1",
                params![dev],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(|_| Ve(500, "db".into()))?
            .unwrap_or(0) as u64;
        for (op, raw) in &frames {
            let seq = op.seq;
            if seq <= head {
                let cur: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT body FROM ops WHERE device = ?1 AND seq = ?2",
                        params![dev, seq as i64],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|_| Ve(500, "db".into()))?;
                match cur {
                    Some(b) if b == *raw => continue, // idempotent re-push
                    _ => {
                        return ve(
                            409,
                            format!("op {seq}: equivocation — different bytes at an existing seq"),
                        )
                    }
                }
            }
            if seq != head + 1 {
                return ve(409, format!("op {seq}: gap — expected {}", head + 1));
            }
            tx.execute(
                "INSERT INTO ops (device, seq, body) VALUES (?1,?2,?3)",
                params![dev, seq as i64, *raw],
            )
            .map_err(|_| Ve(500, "db".into()))?;
            head = seq;
        }
        tx.commit().map_err(|_| Ve(500, "db".into()))?;
        Ok(head)
    }

    // ── snapshots (immutable objects; compaction lands with M3-proper) ──

    pub fn get_snapshot(&self, bearer: Option<&str>, epoch: Option<u64>) -> VResult<Vec<u8>> {
        self.authorize(bearer, Scope::Read, None)?;
        let row = match epoch {
            Some(e) => self.conn.query_row(
                "SELECT body FROM snapshots WHERE epoch = ?1",
                params![e as i64],
                |r| r.get::<_, Vec<u8>>(0),
            ),
            None => self.conn.query_row(
                "SELECT body FROM snapshots ORDER BY epoch DESC LIMIT 1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            ),
        }
        .optional()
        .map_err(|_| Ve(500, "db".into()))?;
        row.ok_or(Ve(404, "no snapshot".into()))
    }

    pub fn put_snapshot(&self, bearer: Option<&str>, epoch: u64, body: &[u8]) -> VResult<()> {
        self.authorize(bearer, Scope::Write, None)?;
        if body.is_empty() || body.len() > MAX_BODY {
            return ve(413, "bad snapshot size");
        }
        let cur: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT body FROM snapshots WHERE epoch = ?1",
                params![epoch as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Ve(500, "db".into()))?;
        if let Some(b) = cur {
            return if b == body {
                Ok(())
            } else {
                ve(409, "snapshot epoch exists with different bytes")
            };
        }
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM snapshots", [], |r| r.get(0))
            .map_err(|_| Ve(500, "db".into()))?;
        if count >= MAX_SNAPSHOTS {
            return ve(429, "snapshot cap — compact first");
        }
        self.conn
            .execute(
                "INSERT INTO snapshots (epoch, body) VALUES (?1,?2)",
                params![epoch as i64, body],
            )
            .map_err(|_| Ve(500, "db".into()))?;
        Ok(())
    }

    // ── tokens ─────────────────────────────────────────────────────────

    pub fn mint_scoped_token(
        &self,
        bearer: Option<&str>,
        scope: &str,
        device: Option<&str>,
        ttl_s: Option<i64>,
    ) -> VResult<String> {
        self.authorize(bearer, Scope::Admin, None)?;
        let scope = Scope::from_str(scope).ok_or(Ve(400, "bad scope".into()))?;
        let device = match device {
            Some(d) => {
                if !valid_dev(d) {
                    return ve(400, "bad device id");
                }
                Some(d.to_ascii_lowercase())
            }
            None => None,
        };
        self.mint_token(scope, device.as_deref(), ttl_s)
    }

    /// Revocation companion: drop every token bound to a device. The real
    /// revocation is the manifest registry update the client pushes after.
    pub fn revoke_device(&self, bearer: Option<&str>, device: &str) -> VResult<usize> {
        self.authorize(bearer, Scope::Admin, None)?;
        let dev = device.to_ascii_lowercase();
        let n = self
            .conn
            .execute("DELETE FROM tokens WHERE device = ?1", params![dev])
            .map_err(|_| Ve(500, "db".into()))?;
        self.conn
            .execute("DELETE FROM pending WHERE device = ?1", params![dev])
            .ok();
        Ok(n)
    }

    // ── enrollment ─────────────────────────────────────────────────────

    /// Admin mints a short-lived invite code; the human carries it to the
    /// new device (typed or QR). Hash-stored; burned at finish.
    pub fn enroll_invite(&self, bearer: Option<&str>) -> VResult<(String, i64)> {
        self.authorize(bearer, Scope::Admin, None)?;
        self.conn
            .execute("DELETE FROM invites WHERE expires < ?1", params![now_s()])
            .map_err(|_| Ve(500, "db".into()))?;
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM invites", [], |r| r.get(0))
            .map_err(|_| Ve(500, "db".into()))?;
        if count >= MAX_INVITES {
            return ve(429, "too many live invites");
        }
        let code = new_code();
        self.conn
            .execute(
                "INSERT INTO invites (hash, created, expires) VALUES (?1,?2,?3)",
                params![sha256_hex(code.as_bytes()), now_s(), now_s() + INVITE_TTL_S],
            )
            .map_err(|_| Ve(500, "db".into()))?;
        Ok((code, INVITE_TTL_S))
    }

    /// New device submits its pubkey under the invite code — and gets the
    /// manifest back: the code IS its read capability until finish mints
    /// real tokens (it needs the manifest to attempt a password unlock).
    pub fn enroll_join(
        &self,
        code: Option<&str>,
        device_id: &str,
        vk_hex: &str,
        name: &str,
    ) -> VResult<(Vec<u8>, u64)> {
        self.require_invite(code)?;
        if !valid_dev(device_id) {
            return ve(400, "bad device id");
        }
        let vk = unhex(vk_hex).map_err(|_| Ve(400, "bad vk".into()))?;
        if vk.len() != 32 {
            return ve(400, "bad vk");
        }
        if name.is_empty() || name.chars().count() > 64 {
            return ve(400, "bad device name");
        }
        let dev = device_id.to_ascii_lowercase();
        self.conn
            .execute(
                "DELETE FROM pending WHERE created < ?1",
                params![now_s() - INVITE_TTL_S],
            )
            .map_err(|_| Ve(500, "db".into()))?;
        // A pending row may be refreshed by a retry, but a DIFFERENT vk
        // for the same device id means someone is squatting it — never
        // let one invite overwrite another joiner's key under a name the
        // owner might recognize.
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT vk FROM pending WHERE device = ?1",
                params![dev],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Ve(500, "db".into()))?;
        if let Some(old) = &existing {
            if *old != vk {
                return ve(
                    409,
                    "device id already pending under a different key — decline it first",
                );
            }
        }
        let count: i64 = self
            .conn
            .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))
            .map_err(|_| Ve(500, "db".into()))?;
        if count >= MAX_PENDING && existing.is_none() {
            return ve(429, "too many pending devices");
        }
        self.conn
            .execute(
                "INSERT INTO pending (device, vk, name, created) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(device) DO UPDATE SET name=excluded.name, created=excluded.created",
                params![dev, vk, name, now_s()],
            )
            .map_err(|_| Ve(500, "db".into()))?;
        let (bytes, m) = self.require_manifest()?;
        Ok((bytes, m.snapshot_epoch))
    }

    pub fn enroll_pending(
        &self,
        bearer: Option<&str>,
    ) -> VResult<Vec<(String, String, String, i64)>> {
        self.authorize(bearer, Scope::Admin, None)?;
        let mut stmt = self
            .conn
            .prepare("SELECT device, vk, name, created FROM pending ORDER BY created")
            .map_err(|_| Ve(500, "db".into()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    hex(&r.get::<_, Vec<u8>>(1)?),
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|_| Ve(500, "db".into()))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Ve(500, "db".into()))?;
        Ok(rows)
    }

    pub fn enroll_decline(&self, bearer: Option<&str>, device_id: &str) -> VResult<()> {
        self.authorize(bearer, Scope::Admin, None)?;
        self.conn
            .execute(
                "DELETE FROM pending WHERE device = ?1",
                params![device_id.to_ascii_lowercase()],
            )
            .map_err(|_| Ve(500, "db".into()))?;
        Ok(())
    }

    /// The code → tokens exchange. Approval is NOT a server flag — it's
    /// the device appearing active in the owner-signed manifest. The new
    /// device gets read + write tokens bound to its id; the invite burns.
    pub fn enroll_finish(
        &self,
        code: Option<&str>,
        device_id: &str,
    ) -> VResult<(String, String, Vec<u8>, u64)> {
        let hash = self.require_invite(code)?;
        let dev = device_id.to_ascii_lowercase();
        let (bytes, m) = self.require_manifest()?;
        let entry = m.devices.iter().find(|d| hex(&d.id) == dev);
        match entry {
            Some(e) if e.active => {}
            _ => {
                return ve(
                    409,
                    "not approved yet — the enrolled device must sign you into the manifest",
                )
            }
        }
        // the code redeems only for the device that joined under it: a
        // pending row must exist and its vk must be the one the owner
        // signed into the registry. Otherwise an invite holder could mint
        // tokens bound to any already-active device.
        let entry_vk = entry.unwrap().vk;
        let pending_vk: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT vk FROM pending WHERE device = ?1",
                params![dev],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Ve(500, "db".into()))?;
        match pending_vk {
            Some(vk) if vk == entry_vk => {}
            Some(_) => return ve(409, "pending key does not match the approved registry key"),
            None => {
                return ve(
                    409,
                    "no pending join for this device — re-run pair join under a fresh invite",
                )
            }
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|_| Ve(500, "db".into()))?;
        let read = Self::mint_token_on(&tx, Scope::Read, Some(&dev), None)?;
        let write = Self::mint_token_on(&tx, Scope::Write, Some(&dev), None)?;
        // burns must commit with the mints — a failed invite delete that
        // still committed tokens would leave the code replayable
        tx.execute("DELETE FROM invites WHERE hash = ?1", params![hash])
            .map_err(|_| Ve(500, "db".into()))?;
        tx.execute("DELETE FROM pending WHERE device = ?1", params![dev])
            .map_err(|_| Ve(500, "db".into()))?;
        tx.commit().map_err(|_| Ve(500, "db".into()))?;
        Ok((read, write, bytes, m.snapshot_epoch))
    }
}

fn ve_err(status: u16, msg: impl Into<String>) -> Ve {
    Ve(status, msg.into())
}

// ── helpers ──────────────────────────────────────────────────────────

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}
pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(b))
}
fn new_token() -> String {
    let mut r = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut r);
    "mpm_".to_string() + &hex(&r)
}
/// Human-typeable invite code: 8 chars, no confusables, XXXX-XXXX.
fn new_code() -> String {
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut r = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut r);
    let s: String = r
        .iter()
        .map(|b| A[(*b as usize) % A.len()] as char)
        .collect();
    format!("{}-{}", &s[..4], &s[4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpm_crypto::keys::{DeviceKey, KeyBundle};

    fn tmpdir() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "mpm-syncd-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Bootstrapped store + enrolled device + write token for it.
    fn boot() -> (VaultStore, String, String, DeviceKey) {
        let dir = tmpdir();
        let bundle = KeyBundle::generate();
        let dev = DeviceKey::generate();
        let mut m = Manifest::new(
            mpm_crypto::kdf::KdfParams::default(),
            [0u8; 32],
            bundle.owner_verifying_key(),
        );
        m.devices.push(mpm_core::DeviceEntry {
            id: dev.id,
            vk: dev.verifying_key(),
            name: "t".into(),
            active: true,
            enrolled_at: 0,
            revoked_seq: None,
            extra: Vec::new(),
        });
        let manifest = m.to_file(&bundle.owner_signing_key());
        let vault_id = hex(&m.vault_id);
        let store = VaultStore::open(&dir.join("v.db"), true).unwrap();
        let admin = store.bootstrap(&vault_id, &manifest).unwrap();
        let dev_hex = hex(&dev.id);
        let wtok = store
            .mint_scoped_token(Some(&admin), "write", Some(&dev_hex), None)
            .unwrap();
        (store, wtok, dev_hex, dev)
    }

    /// Signed frame with a padded ciphertext — the relay only needs the
    /// signature valid and seq continuity; contents are opaque to it.
    fn frame(dev: &DeviceKey, seq: u64, ct_len: usize) -> mpm_core::Op {
        let ct = vec![0xAB; ct_len];
        let pre = mpm_core::aad::op_sig_preimage(seq, &[0u8; 24], &ct);
        mpm_core::Op {
            seq,
            nonce: [0u8; 24],
            sig: dev.sign(&pre).to_bytes(),
            ct,
        }
    }

    fn push(store: &VaultStore, tok: &str, dev_hex: &str, frames: &[mpm_core::Op]) {
        let mut body = Vec::new();
        for f in frames {
            body.extend_from_slice(&f.encode());
        }
        store.append_ops(Some(tok), dev_hex, &body).unwrap();
    }

    /// PERF-01: a GET page is bounded by aggregate bytes, not just frame
    /// count — the frame that would overflow defers to the next page.
    #[test]
    fn get_ops_page_bounded_by_bytes() {
        let (store, tok, dev_hex, dev) = boot();
        // five ~400 KiB frames, one push each (push cap is 1 MiB)
        for seq in 1..=5u64 {
            push(&store, &tok, &dev_hex, &[frame(&dev, seq, 400 * 1024)]);
        }
        let mut since = 0u64;
        let mut pages = 0;
        loop {
            let (body, head, more) = store.get_ops(Some(&tok), &dev_hex, since, 256).unwrap();
            assert!(body.len() <= PAGE_MAX_BYTES, "page over byte budget");
            assert_eq!(head, 5);
            pages += 1;
            // two ~400 KiB frames fit under the cap; the third defers
            let mut seqs = Vec::new();
            let mut rest = &body[..];
            while !rest.is_empty() {
                let (op, n) = mpm_core::Op::decode(rest).unwrap();
                seqs.push(op.seq);
                rest = &rest[n..];
            }
            assert_eq!(seqs, vec![since + 1, since + 2][..seqs.len().min(2)]);
            assert!(seqs.len() <= 2);
            since = *seqs.last().unwrap();
            if !more {
                break;
            }
        }
        assert_eq!(since, 5);
        assert_eq!(pages, 3); // 2 + 2 + 1
                              // past the tail: empty page, no more
        let (body, _, more) = store.get_ops(Some(&tok), &dev_hex, since, 256).unwrap();
        assert!(body.is_empty() && !more);
    }

    /// Count cap still binds: 300 small frames page at 256 then 44.
    #[test]
    fn get_ops_page_bounded_by_count() {
        let (store, tok, dev_hex, dev) = boot();
        let mut batch = Vec::new();
        for seq in 1..=256u64 {
            batch.push(frame(&dev, seq, 64));
        }
        push(&store, &tok, &dev_hex, &batch);
        let mut batch2 = Vec::new();
        for seq in 257..=300u64 {
            batch2.push(frame(&dev, seq, 64));
        }
        push(&store, &tok, &dev_hex, &batch2);

        let (p1, head, more1) = store.get_ops(Some(&tok), &dev_hex, 0, 256).unwrap();
        assert!(more1 && head == 300);
        assert_eq!(p1.len(), 256 * (mpm_core::op::OP_HEADER_LEN + 64));
        let (p2, _, more2) = store.get_ops(Some(&tok), &dev_hex, 256, 256).unwrap();
        assert!(!more2);
        assert_eq!(p2.len(), 44 * (mpm_core::op::OP_HEADER_LEN + 64));
    }

    /// Boundary: a frame that lands exactly on the byte budget is kept;
    /// the one after it defers. `more` follows the cursor, not the cap.
    #[test]
    fn get_ops_byte_boundary_exact() {
        let (store, tok, dev_hex, dev) = boot();
        // f1+f2 = exactly PAGE_MAX_BYTES; f3 overflows → page 1 = f1+f2
        let f1 = frame(&dev, 1, PAGE_MAX_BYTES / 2 - mpm_core::op::OP_HEADER_LEN);
        let f2 = frame(&dev, 2, PAGE_MAX_BYTES / 2 - mpm_core::op::OP_HEADER_LEN);
        let f3 = frame(&dev, 3, 64);
        // each push body must stay ≤ MAX_BODY — f1+f2 is exactly the cap
        push(&store, &tok, &dev_hex, &[f1, f2]);
        push(&store, &tok, &dev_hex, &[f3]);
        let (p1, _, more1) = store.get_ops(Some(&tok), &dev_hex, 0, 256).unwrap();
        assert_eq!(p1.len(), PAGE_MAX_BYTES);
        assert!(more1);
        let (p2, _, more2) = store.get_ops(Some(&tok), &dev_hex, 2, 256).unwrap();
        assert!(!more2 && !p2.is_empty());
    }
}
