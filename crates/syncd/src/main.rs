//! mpm-syncd — mypassman sync relay, single-binary self-hosted edition.
//!
//! Same wire protocol as the Cloudflare Worker backend (syncd/): every
//! route is /v/<vault_id>/<route>, auth is bearer-token scoped, vaults are
//! isolated one-SQLite-file-per-vault under --data. The server verifies
//! signatures but never sees plaintext — all state and policy live in the
//! per-vault store (vault.rs), which mirrors VaultSync's semantics.
//!
//!   MPM_SETUP_KEY=… mpm-syncd --data /var/lib/mpm --bind 127.0.0.1:8787

mod vault;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use vault::{unhex, VaultStore, Ve};

struct AppState {
    dir: PathBuf,
    setup_key: Option<String>,
    /// One lock per vault id — DO-style serialization of vault requests.
    /// Weak refs so per-vault mutexes don't pin memory forever; dead
    /// entries are pruned once the map grows past 4096.
    locks: Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}

fn sha256_raw(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let d = sha2::Sha256::digest(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Constant-time equality for fixed-size digests — no early exit.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

struct ApiErr(Ve);
impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.0 .0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(json!({ "error": self.0 .1 })),
        )
            .into_response()
    }
}
type R<T> = Result<T, ApiErr>;
impl From<Ve> for ApiErr {
    fn from(e: Ve) -> Self {
        ApiErr(e)
    }
}
fn err<T>(status: u16, msg: impl Into<String>) -> R<T> {
    Err(ApiErr(Ve(status, msg.into())))
}

fn bearer(h: &HeaderMap) -> Option<String> {
    let v = h.get(header::AUTHORIZATION)?.to_str().ok()?;
    (v.len() >= 7 && v[..7].eq_ignore_ascii_case("bearer ")).then(|| v[7..].trim().to_string())
}

impl AppState {
    /// Validate the vault id, serialize all work for that vault, and run
    /// the (blocking) store call on the blocking pool. `create` is for
    /// bootstrap only — every other route 404s on a vault file that
    /// doesn't exist, so unauthenticated requests can't mint databases
    /// or grow the lock map.
    async fn with_vault<T>(
        &self,
        vault_id: &str,
        create: bool,
        f: impl FnOnce(&VaultStore) -> Result<T, Ve> + Send + 'static,
    ) -> R<T>
    where
        T: Send + 'static,
    {
        if vault_id.len() != 32 || !vault_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return err(404, "not found");
        }
        let id = vault_id.to_ascii_lowercase();
        let path = self.dir.join(format!("{id}.db"));
        if !create && !path.exists() {
            return err(404, "not found");
        }
        let lock = {
            let mut m = self.locks.lock().unwrap();
            if m.len() > 4096 {
                m.retain(|_, w| w.strong_count() > 0);
            }
            match m.get(&id).and_then(|w| w.upgrade()) {
                Some(l) => l,
                None => {
                    let l = Arc::new(tokio::sync::Mutex::new(()));
                    m.insert(id.clone(), Arc::downgrade(&l));
                    l
                }
            }
        };
        let _g = lock.lock().await;
        tokio::task::spawn_blocking(move || {
            let store =
                VaultStore::open(&path, create).map_err(|_| Ve(500, "store open".into()))?;
            f(&store)
        })
        .await
        .map_err(|_| ApiErr(Ve(500, "task".into())))?
        .map_err(ApiErr)
    }
}

fn jstr<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or(ApiErr(Ve(400, format!("missing field {k}"))))
}

#[tokio::main]
async fn main() {
    let mut dir =
        PathBuf::from(std::env::var("MPM_SYNC_DATA").unwrap_or_else(|_| "syncd-data".into()));
    let mut bind = std::env::var("MPM_SYNC_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data" if i + 1 < args.len() => {
                dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--bind" if i + 1 < args.len() => {
                bind = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "mpm-syncd — mypassman sync relay\n\n\
                     usage: mpm-syncd [--data DIR] [--bind ADDR]\n\n\
                     env:  MPM_SETUP_KEY   vault-bootstrap key (required to bootstrap vaults)\n\
                     \x20     MPM_SYNC_DATA   data dir (default ./syncd-data)\n\
                     \x20     MPM_SYNC_BIND   listen addr (default 127.0.0.1:8787)\n"
                );
                return;
            }
            other => {
                eprintln!("unknown arg: {other} (try --help)");
                std::process::exit(2);
            }
        }
    }
    std::fs::create_dir_all(&dir).expect("create data dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let setup_key = std::env::var("MPM_SETUP_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    if setup_key.is_none() {
        eprintln!("warning: MPM_SETUP_KEY unset — vault bootstrap disabled");
    }
    let dir_disp = dir.display().to_string();
    let state = Arc::new(AppState {
        dir,
        setup_key,
        locks: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v/{vault}/bootstrap", post(bootstrap))
        .route("/v/{vault}/manifest", get(get_manifest).put(put_manifest))
        .route("/v/{vault}/state", get(vault_state))
        .route("/v/{vault}/ops", get(get_ops).post(post_ops))
        .route("/v/{vault}/snapshot", get(get_snapshot).put(put_snapshot))
        .route("/v/{vault}/tokens", post(mint_token))
        .route("/v/{vault}/revoke", post(revoke))
        .route("/v/{vault}/enroll/invite", post(enroll_invite))
        .route("/v/{vault}/enroll/join", post(enroll_join))
        .route("/v/{vault}/enroll/pending", get(enroll_pending))
        .route("/v/{vault}/enroll/decline", post(enroll_decline))
        .route("/v/{vault}/enroll/finish", post(enroll_finish))
        .layer(axum::extract::DefaultBodyLimit::max(vault::MAX_BODY))
        .with_state(state);

    let addr: SocketAddr = bind.parse().expect("bad --bind addr");
    eprintln!("mpm-syncd listening on http://{addr} (data: {dir_disp})");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

// ── bootstrap ─────────────────────────────────────────────────────────

async fn bootstrap(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let ok = s.setup_key.as_deref().is_some_and(|k| {
        h.get("x-setup-key")
            .and_then(|v| v.to_str().ok())
            // digest + xor-fold: the setup key is a long-lived shared
            // secret — don't hand a timing oracle to the network
            .is_some_and(|v| ct_eq(&sha256_raw(v.as_bytes()), &sha256_raw(k.as_bytes())))
    });
    if !ok {
        return err(401, "bad setup key");
    }
    let id = vault.clone();
    let token = s
        .with_vault(&vault, true, move |st| st.bootstrap(&id, &body))
        .await?;
    Ok(Json(json!({ "token": token })))
}

// ── manifest / state ──────────────────────────────────────────────────

async fn get_manifest(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let (bytes, epoch) = s
        .with_vault(&vault, false, move |st| st.get_manifest(auth.as_deref()))
        .await?;
    Ok(Json(
        json!({ "manifest": vault::hex(&bytes), "snapshot_epoch": epoch }),
    ))
}

async fn put_manifest(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?;
    let manifest =
        unhex(jstr(&v, "manifest")?).map_err(|_| ApiErr(Ve(400, "bad manifest hex".into())))?;
    let base_hash = jstr(&v, "base_hash")?.to_string();
    let epoch = s
        .with_vault(&vault, false, move |st| {
            st.put_manifest(auth.as_deref(), &manifest, &base_hash)
        })
        .await?;
    Ok(Json(json!({ "snapshot_epoch": epoch })))
}

async fn vault_state(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let (epoch, heads) = s
        .with_vault(&vault, false, move |st| st.state(auth.as_deref()))
        .await?;
    Ok(Json(json!({
        "snapshot_epoch": epoch,
        "heads": heads.iter().map(|(d, h)| json!({"device": d, "head": h})).collect::<Vec<_>>(),
    })))
}

// ── ops ───────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct OpsQ {
    device: Option<String>,
    since: Option<u64>,
    limit: Option<u64>,
}

async fn get_ops(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    Query(q): Query<OpsQ>,
    h: HeaderMap,
) -> R<Response> {
    let auth = bearer(&h);
    let dev = q.device.unwrap_or_default();
    let (frames, head, more) = s
        .with_vault(&vault, false, move |st| {
            st.get_ops(
                auth.as_deref(),
                &dev,
                q.since.unwrap_or(0),
                q.limit.unwrap_or(256),
            )
        })
        .await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::HeaderName::from_static("x-head"), head.to_string()),
            (
                header::HeaderName::from_static("x-more"),
                if more { "1" } else { "0" }.to_string(),
            ),
        ],
        frames,
    )
        .into_response())
}

async fn post_ops(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    Query(q): Query<OpsQ>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let dev = q.device.unwrap_or_default();
    let head = s
        .with_vault(&vault, false, move |st| {
            st.append_ops(auth.as_deref(), &dev, &body)
        })
        .await?;
    Ok(Json(json!({ "head": head })))
}

// ── snapshots ─────────────────────────────────────────────────────────

fn parse_epoch(q: &HashMap<String, String>) -> R<Option<u64>> {
    match q.get("epoch") {
        None => Ok(None),
        Some(e) => e
            .parse::<u64>()
            .map(Some)
            .map_err(|_| ApiErr(Ve(400, "bad epoch".into()))),
    }
}

async fn get_snapshot(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
) -> R<Response> {
    let auth = bearer(&h);
    let epoch = parse_epoch(&q)?;
    match s
        .with_vault(&vault, false, move |st| {
            st.get_snapshot(auth.as_deref(), epoch)
        })
        .await
    {
        Ok(body) => {
            Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
        }
        Err(ApiErr(Ve(404, _))) => err(404, "no snapshot"),
        Err(e) => Err(e),
    }
}

async fn put_snapshot(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let epoch = parse_epoch(&q)?.unwrap_or(0);
    s.with_vault(&vault, false, move |st| {
        st.put_snapshot(auth.as_deref(), epoch, &body)
    })
    .await?;
    Ok(Json(json!({ "epoch": epoch })))
}

// ── tokens / revoke ───────────────────────────────────────────────────

async fn mint_token(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    // empty body mints a default read token; malformed json is a 400
    let v: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?
    };
    let scope = jstr(&v, "scope").unwrap_or("read").to_string();
    let device = v.get("device").and_then(Value::as_str).map(str::to_string);
    let ttl = v.get("ttl_s").and_then(Value::as_i64);
    let token = s
        .with_vault(&vault, false, move |st| {
            st.mint_scoped_token(auth.as_deref(), &scope, device.as_deref(), ttl)
        })
        .await?;
    Ok(Json(json!({ "token": token })))
}

async fn revoke(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?;
    let device = jstr(&v, "device")?.to_string();
    let removed = s
        .with_vault(&vault, false, move |st| {
            st.revoke_device(auth.as_deref(), &device)
        })
        .await?;
    Ok(Json(json!({ "removed": removed })))
}

// ── enrollment ────────────────────────────────────────────────────────

async fn enroll_invite(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let (code, ttl) = s
        .with_vault(&vault, false, move |st| st.enroll_invite(auth.as_deref()))
        .await?;
    Ok(Json(json!({ "code": code, "ttl_s": ttl })))
}

async fn enroll_join(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?;
    let (device, vk, name) = (
        jstr(&v, "device")?.to_string(),
        jstr(&v, "vk")?.to_string(),
        jstr(&v, "name")?.to_string(),
    );
    let (bytes, epoch) = s
        .with_vault(&vault, false, move |st| {
            st.enroll_join(auth.as_deref(), &device, &vk, &name)
        })
        .await?;
    Ok(Json(
        json!({ "manifest": vault::hex(&bytes), "snapshot_epoch": epoch }),
    ))
}

async fn enroll_pending(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let rows = s
        .with_vault(&vault, false, move |st| st.enroll_pending(auth.as_deref()))
        .await?;
    Ok(Json(json!(rows
        .iter()
        .map(|(d, vk, n, c)| json!({"device": d, "vk": vk, "name": n, "created": c}))
        .collect::<Vec<_>>())))
}

async fn enroll_decline(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?;
    let device = jstr(&v, "device")?.to_string();
    s.with_vault(&vault, false, move |st| {
        st.enroll_decline(auth.as_deref(), &device)
    })
    .await?;
    Ok(Json(json!({ "ok": true })))
}

async fn enroll_finish(
    State(s): State<Arc<AppState>>,
    Path(vault): Path<String>,
    h: HeaderMap,
    body: Bytes,
) -> R<Json<Value>> {
    let auth = bearer(&h);
    let v: Value = serde_json::from_slice(&body).map_err(|_| ApiErr(Ve(400, "bad json".into())))?;
    let device = jstr(&v, "device")?.to_string();
    let (read, write, bytes, epoch) = s
        .with_vault(&vault, false, move |st| {
            st.enroll_finish(auth.as_deref(), &device)
        })
        .await?;
    Ok(Json(json!({
        "read": read,
        "write": write,
        "manifest": vault::hex(&bytes),
        "snapshot_epoch": epoch,
    })))
}
