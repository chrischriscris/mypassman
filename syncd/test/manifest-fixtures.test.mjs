// PROTO-01: shared manifest fixtures — the Rust side runs the identical
// file through Manifest::from_file (crates/core/tests/manifest_fixtures.rs).
// Accept = parseManifest doesn't throw AND verifyManifest passes.
// Run: node --test test/manifest-fixtures.test.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { parseManifest, verifyManifest, unhex } from "../src/wire.ts";

const cases = join(dirname(fileURLToPath(import.meta.url)), "../../fixtures/manifest/cases.tsv");
const lines = readFileSync(cases, "utf8").split("\n").filter((l) => l.trim());
assert.ok(lines.length >= 30, "fixture file looks truncated");

for (const line of lines) {
  const [name, expect, hexs] = line.split("\t");
  test(name, async () => {
    const file = hexs?.trim() ? unhex(hexs.trim()) : new Uint8Array(0);
    let ok = false;
    try {
      const info = parseManifest(file);
      ok = await verifyManifest(file, info);
    } catch {
      ok = false;
    }
    assert.equal(ok, expect === "ok", `fixture ${name}`);
  });
}
