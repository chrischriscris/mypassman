import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const directory = dirname(fileURLToPath(import.meta.url));
const context = {};
runInNewContext(readFileSync(resolve(directory, "data.js"), "utf8"), context);
const data = context.MPM_ATLAS;
const gitOptions = { cwd: resolve(directory, "../.."), encoding: "utf8", stdio: "pipe" };
assert.equal(execFileSync("git", ["rev-parse", data.archive.ref], gitOptions).trim(), data.archive.revision, "Archive ref differs from recorded snapshot");
const unique = (items) => {
  const ids = items.map((item) => item.id);
  assert.equal(new Set(ids).size, ids.length, "Duplicate IDs");
  for (const id of ids) assert.match(id, /^[a-z][a-z0-9-]*$/);
};
const checkLink = (href) => {
  if (/^https:\/\//.test(href)) return;
  const [path, anchor] = href.split("#");
  const target = resolve(directory, path);
  assert.ok(existsSync(target), `Missing local target: ${href}`);
  if (anchor && path.endsWith(".md")) {
    const headings = [...readFileSync(target, "utf8").matchAll(/^#+ (.+)$/gm)]
      .map((match) => match[1].toLowerCase().replace(/[^\p{L}\p{N}_\s-]/gu, "").replace(/\s/g, "-"));
    assert.ok(headings.includes(anchor), `Missing Markdown heading: ${href}`);
  }
};
assert.equal(data.schemaVersion, 1);
for (const entries of [data.systems, data.decisions, data.scenarios]) unique(entries);
const decisions = new Set(data.decisions.map((item) => item.id));
for (const system of data.systems) {
  assert.ok(["not-started", "in-progress", "implemented", "verified"].includes(system.implementation));
  for (const field of ["purpose", "owns", "boundary", "failure", "next", "done"]) assert.ok(system[field]?.trim(), `${system.id}: missing ${field}`);
  for (const decision of system.decisions) assert.ok(decisions.has(decision), `Unknown decision: ${decision}`);
  for (const item of [...system.sources, ...system.evidence]) {
    checkLink(item.href);
    if (item.archivePath) {
      assert.match(item.archivePath, /^[a-zA-Z0-9_./-]+$/);
      assert.ok(!item.archivePath.split("/").includes(".."));
      execFileSync("git", ["cat-file", "-e", `${data.archive.ref}:${item.archivePath}`], gitOptions);
    }
  }
  if (["implemented", "verified"].includes(system.implementation)) assert.ok(system.evidence.length, `${system.id}: implementation needs evidence`);
  if (system.implementation === "verified") {
    for (const field of ["command", "result", "date", "revision", "limits"]) assert.ok(system.verification?.[field]?.trim(), `${system.id}: verification needs ${field}`);
  }
}
for (const decision of data.decisions) {
  assert.ok(["Chosen", "Proposed", "Open", "Deferred"].includes(decision.status));
  if (decision.status === "Chosen") assert.ok(decision.choice?.trim());
  checkLink(decision.source);
}
for (const scenario of data.scenarios) {
  assert.ok(scenario.steps.length > 1);
  for (const step of scenario.steps) for (const field of ["title", "a", "relay", "b", "note"]) assert.ok(step[field]?.trim(), `${scenario.id}: missing ${field}`);
}
for (const item of data.activity) if (item.href) checkLink(item.href);
for (const path of ["index.html", "styles.css", "app.js", "README.md"]) assert.ok(existsSync(resolve(directory, path)));
console.log(`Atlas checked: ${data.systems.length} systems, ${data.decisions.length} decisions, ${data.scenarios.length} walkthroughs; local targets and evidence requirements valid.`);
