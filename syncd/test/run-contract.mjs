// TEST-01 runner: spawn the chosen relay, wait for /health, run the
// shared contract suite against it, tear down.
//   node test/run-contract.mjs worker    # wrangler dev (workerd)
//   node test/run-contract.mjs rust      # ../target/debug/mpm-syncd
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const mode = process.argv[2];
if (!["worker", "rust"].includes(mode)) {
  console.error("usage: run-contract.mjs worker|rust");
  process.exit(2);
}
const here = dirname(fileURLToPath(import.meta.url));
const SETUP_KEY = process.env.SETUP_KEY ?? "test-setup";
const port = 8800 + Math.floor(Math.random() * 900);
const BASE_URL = `http://127.0.0.1:${port}`;

let child;
let dataDir;
if (mode === "worker") {
  child = spawn(
    "npx",
    ["wrangler", "dev", "--port", String(port), "--ip", "127.0.0.1", "--inspector-port", "0", "--var", `SETUP_KEY:${SETUP_KEY}`],
    { cwd: join(here, ".."), stdio: ["ignore", "pipe", "pipe"] },
  );
} else {
  dataDir = mkdtempSync(join(tmpdir(), "mpm-syncd-contract-"));
  child = spawn(join(here, "../../target/debug/mpm-syncd"), [], {
    env: {
      ...process.env,
      MPM_SETUP_KEY: SETUP_KEY,
      MPM_SYNC_BIND: `127.0.0.1:${port}`,
      MPM_SYNC_DATA: dataDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

child.stderr.on("data", (d) => process.stderr.write(`[${mode}] ${d}`));
child.on("exit", (c) => {
  console.error(`[${mode}] relay exited early (code ${c})`);
});

const deadline = Date.now() + 90_000;
let up = false;
while (Date.now() < deadline) {
  try {
    const r = await fetch(`${BASE_URL}/health`);
    if (r.ok) { up = true; break; }
  } catch { /* not yet */ }
  await new Promise((r) => setTimeout(r, 250));
}
if (!up) {
  child.kill("SIGKILL");
  console.error(`relay never came up on ${BASE_URL}`);
  process.exit(1);
}
console.error(`relay up: ${mode} @ ${BASE_URL}`);

const t = spawn("node", ["--test", join(here, "contract.test.mjs")], {
  env: { ...process.env, BASE_URL, SETUP_KEY },
  stdio: "inherit",
});
t.on("exit", (code) => {
  child.kill("SIGKILL");
  if (dataDir) rmSync(dataDir, { recursive: true, force: true });
  process.exit(code ?? 1);
});
