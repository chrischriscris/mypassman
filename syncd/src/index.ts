//! mypassman syncd — zero-knowledge sync relay.
//! Routing + auth extraction only; all state and policy live in the
//! per-vault VaultSync Durable Object (the transaction coordinator).

import { unhex, WireError } from "./wire";
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
        if (!env.SETUP_KEY || req.headers.get("x-setup-key") !== env.SETUP_KEY) {
          return json({ error: "bad setup key" }, 401);
        }
        const body = await req.arrayBuffer();
        const { token } = await stub.bootstrap(body);
        return json({ token });
      }

      switch (`${req.method} ${sub}`) {
        case "GET manifest": {
          const r = await stub.getManifest(auth);
          return json({ manifest: hexenc(r.manifest), snapshot_epoch: r.snapshot_epoch });
        }
        case "PUT manifest": {
          const { manifest, base_hash } = (await req.json()) as { manifest: string; base_hash: string };
          return json(await stub.putManifest(auth, unhex(manifest).buffer as ArrayBuffer, base_hash));
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
          const body = await req.arrayBuffer();
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
          const body = await req.arrayBuffer();
          return json(await stub.putSnapshot(auth, epoch, body));
        }
        case "POST tokens": {
          const t = (await req.json()) as { scope?: "read" | "write" | "admin"; device?: string; ttl_s?: number };
          return json(await stub.mintScopedToken(auth, t.scope ?? "read", t.device ?? null, t.ttl_s ?? null));
        }
        case "POST revoke": {
          const { device } = (await req.json()) as { device: string };
          return json(await stub.revokeDevice(auth, device));
        }
        case "POST enroll/invite":
          return json(await stub.enrollInvite(auth));
        case "POST enroll/join": {
          const j = (await req.json()) as { device: string; vk: string; name: string };
          const r = await stub.enrollJoin(auth, j.device, j.vk, j.name);
          return json({ manifest: hexenc(r.manifest), snapshot_epoch: r.snapshot_epoch });
        }
        case "GET enroll/pending":
          return json(await stub.enrollPending(auth));
        case "POST enroll/decline": {
          const { device } = (await req.json()) as { device: string };
          return json(await stub.enrollDecline(auth, device));
        }
        case "POST enroll/finish": {
          const { device } = (await req.json()) as { device: string };
          const r = await stub.enrollFinish(auth, device);
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
