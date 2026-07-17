import assert from "node:assert/strict";
import test from "node:test";
import { TIERS, tierEntitlements } from "../lib/tiers.js";

test("website entitlements exactly match the Dustonic desktop contract", () => {
  const expected = [
    "id", "name", "safeCleaning", "manualClean", "proRules",
    "scheduledClean", "autoClean", "duplicateFinder", "largeFileFinder",
  ];
  assert.deepEqual(Object.keys(TIERS.free), expected);
  assert.deepEqual(Object.keys(TIERS.pro), expected);
  assert.deepEqual(tierEntitlements("free"), {
    id: "free", name: "Free", safeCleaning: true, manualClean: true,
    proRules: false, scheduledClean: false, autoClean: false,
    duplicateFinder: false, largeFileFinder: false,
  });
  assert.deepEqual(tierEntitlements("pro"), {
    id: "pro", name: "Pro", safeCleaning: true, manualClean: true,
    proRules: true, scheduledClean: true, autoClean: true,
    duplicateFinder: true, largeFileFinder: true,
  });
});
