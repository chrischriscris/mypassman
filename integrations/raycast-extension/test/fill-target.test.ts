// node --test test/ — exercises the fail-closed target rules used by fill()
import { test } from "node:test";
import assert from "node:assert/strict";
import { identifyTarget, sameTarget } from "../src/fill-target.ts";

test("lookup failure yields no identifiable target", () => {
  assert.equal(identifyTarget(null), null);
  assert.equal(identifyTarget(undefined), null);
});

test("null bundle id yields no identifiable target", () => {
  assert.equal(identifyTarget({ name: "Safari", bundleId: null }), null);
  assert.equal(identifyTarget({ name: "Safari", bundleId: undefined }), null);
  assert.equal(identifyTarget({ name: "Safari" }), null);
});

test("identified target keeps name and bundle id", () => {
  assert.deepEqual(identifyTarget({ name: "Safari", bundleId: "com.apple.Safari" }), {
    name: "Safari",
    bundleId: "com.apple.Safari",
  });
});

test("same target app passes the post-close check", () => {
  const intended = identifyTarget({ name: "Safari", bundleId: "com.apple.Safari" })!;
  assert.ok(sameTarget(intended, { name: "Safari", bundleId: "com.apple.Safari" }));
});

test("changed bundle id fails closed", () => {
  const intended = identifyTarget({ name: "Safari", bundleId: "com.apple.Safari" })!;
  assert.ok(!sameTarget(intended, { name: "Terminal", bundleId: "com.apple.Terminal" }));
});

test("failed or unidentifiable post-close lookup fails closed", () => {
  const intended = identifyTarget({ name: "Safari", bundleId: "com.apple.Safari" })!;
  assert.ok(!sameTarget(intended, null));
  assert.ok(!sameTarget(intended, undefined));
  assert.ok(!sameTarget(intended, { name: "Terminal" }));
  assert.ok(!sameTarget(intended, { name: "Safari", bundleId: null }));
});
