//! mypassman syncd — zero-knowledge sync relay.
//! Routing + auth extraction only; all state and policy live in the
//! per-vault VaultSync Durable Object (the transaction coordinator).

import { sha256Hex, unhex, WireError } from "./wire";
import { VaultSync } from "./vault";

export { VaultSync };

export interface Env {
  VAULT: DurableObjectNamespace<VaultSync>;
  SETUP_KEY: string;
}

const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });

const bearer = (req: Request): string | null => {
  const h = req.headers.get("authorization");
  if (!h?.toLowerCase().startsWith("bearer ")) return null;
  return h.slice(7).trim();
};

const VAULT_RE = /^\/v\/([0-9a-f]{32})\/([a-z/_-]+)$/i;

const MAX_BODY = 1 << 20; // parity with mpm-syncd's DefaultBodyLimit

/** Body budget enforced HERE, at the Worker boundary — the DO cap only
 *  sees bytes already buffered. Content-Length may be absent (chunked)
 *  or a lie, so the stream itself is counted and aborted over budget. */
async function readBody(req: Request): Promise<ArrayBuffer> {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > MAX_BODY) throw new WireError("body too large", 413);
  const chunks: Uint8Array[] = [];
  let n = 0;
  if (req.body) {
    const reader = req.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > MAX_BODY) throw new WireError("body too large", 413);
      chunks.push(value);
    }
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out.buffer;
}

/** Missing/non-string required field → 400 (mpm-syncd's jstr parity). */
const needStr = (v: unknown): string => {
  if (typeof v !== "string") throw new WireError("bad request", 400);
  return v;
};

async function readJson(req: Request): Promise<any> {
  const text = new TextDecoder().decode(await readBody(req));
  if (!text.trim()) return {}; // empty body → defaults (mpm-syncd parity)
  try {
    return JSON.parse(text);
  } catch (e) {
    if (e instanceof WireError) throw e;
    throw new WireError("bad json", 400);
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/health") return json({ ok: true });

    const m = VAULT_RE.exec(url.pathname);
    if (!m) return json({ error: "not found" }, 404);
    const vaultId = m[1]!.toLowerCase();
    const sub = m[2]!;
    const stub = env.VAULT.getByName(vaultId);
    const auth = bearer(req);

    try {
      // ── bootstrap: setup-key only, one shot per vault ──────────────
      if (sub === "bootstrap" && req.method === "POST") {
        // digest-compare: SETUP_KEY is a long-lived shared secret — never
        // compare raw strings (timing oracle on the secret itself)
        const provided = req.headers.get("x-setup-key");
        const ok =
          !!env.SETUP_KEY &&
          !!provided &&
          (await sha256Hex(provided)) === (await sha256Hex(env.SETUP_KEY));
        if (!ok) return json({ error: "bad setup key" }, 401);
        const body = await readBody(req);
        const { token } = await stub.bootstrap(vaultId, body);
        return json({ token });
      }

      switch (`${req.method} ${sub}`) {
        case "GET manifest": {
          const r = await stub.getManifest(auth);
          return json({ manifest: hexenc(r.manifest), snapshot_epoch: r.snapshot_epoch });
        }
        case "PUT manifest": {
          const { manifest, base_hash } = await readJson(req);
          return json(await stub.putManifest(auth, unhex(needStr(manifest)).buffer as ArrayBuffer, needStr(base_hash)));
        }
        case "GET state":
          return json(await stub.state(auth));
        case "GET ops": {
          const q = url.searchParams;
          const r = await stub.getOps(
            auth,
            q.get("device") ?? "",
            Number(q.get("since") ?? 0),
            Number(q.get("limit") ?? 256),
          );
          return new Response(r.frames, {
            headers: {
              "content-type": "application/octet-stream",
              "x-head": String(r.head),
              "x-more": r.more ? "1" : "0",
            },
          });
        }
        case "POST ops": {
          const device = url.searchParams.get("device") ?? "";
          const body = await readBody(req);
          return json(await stub.appendOps(auth, device, body));
        }
        case "GET snapshot": {
          const ep = url.searchParams.get("epoch");
          const body = await stub.getSnapshot(auth, ep === null ? null : Number(ep));
          if (!body) return json({ error: "no snapshot" }, 404);
          return new Response(body, { headers: { "content-type": "application/octet-stream" } });
        }
        case "PUT snapshot": {
          const epoch = Number(url.searchParams.get("epoch") ?? 0);
          const body = await readBody(req);
          return json(await stub.putSnapshot(auth, epoch, body));
        }
        case "POST tokens": {
          const t = await readJson(req);
          return json(await stub.mintScopedToken(
            auth,
            typeof t.scope === "string" ? t.scope : "read",
            typeof t.device === "string" ? t.device : null,
            typeof t.ttl_s === "number" ? t.ttl_s : null,
          ));
        }
        case "POST revoke": {
          const { device } = await readJson(req);
          return json(await stub.revokeDevice(auth, needStr(device)));
        }
        case "POST enroll/invite":
          return json(await stub.enrollInvite(auth));
        case "POST enroll/join": {
          const j = await readJson(req);
          const r = await stub.enrollJoin(auth, needStr(j.device), needStr(j.vk), needStr(j.name));
          return json({ manifest: hexenc(r.manifest), snapshot_epoch: r.snapshot_epoch });
        }
        case "GET enroll/pending":
          return json(await stub.enrollPending(auth));
        case "POST enroll/decline": {
          const { device } = await readJson(req);
          return json(await stub.enrollDecline(auth, needStr(device)));
        }
        case "POST enroll/finish": {
          const { device } = await readJson(req);
          const r = await stub.enrollFinish(auth, needStr(device));
          return json({
            read: r.read,
            write: r.write,
            manifest: hexenc(r.manifest),
            snapshot_epoch: r.snapshot_epoch,
          });
        }
        default:
          return json({ error: "not found" }, 404);
      }
    } catch (e) {
      if (e instanceof WireError) return json({ error: e.message.replace(/^\d+ /, "") }, e.status);
      if (e instanceof Error && /^\d{3} /.test(e.message)) {
        return json({ error: e.message.slice(4) }, Number(e.message.slice(0, 3)));
      }
      console.error("syncd error", e);
      return json({ error: "internal" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;

function hexenc(b: ArrayBuffer): string {
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
