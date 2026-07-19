// Tests for the promo / discount-code system: store persistence + redemption
// ledger (first-time-only, one-per-account, dedupe), checkout validation, the
// product-id mapping derived from the checkout links, and webhook matching.
// Run with: node --test
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Configure env BEFORE importing modules that read it at load time.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "promo-test-"));
process.env.DATA_DIR = TMP;
// Static checkout links → the product ids are recovered from these (the same
// ids the live "Buy" buttons use), so no extra env vars are needed.
process.env.DODO_CHECKOUT_PRO_MONTHLY =
  "https://checkout.dodopayments.com/buy/pdt_proMonth01";
process.env.DODO_CHECKOUT_PRO_ANNUAL =
  "https://checkout.dodopayments.com/buy/pdt_proAnnual01";

const store = await import("../lib/store.js");
const promos = await import("../lib/promos.js");
const dodo = await import("../lib/dodo.js");

test("normalizePromoCode uppercases and trims", () => {
  assert.equal(store.normalizePromoCode("  launch50 "), "LAUNCH50");
  assert.equal(store.normalizePromoCode(""), "");
  assert.equal(store.normalizePromoCode(null), "");
});

test("addPromo stores the record and derives percentOff from basis points", async () => {
  const rec = await store.addPromo({
    code: "launch50",
    name: "Launch 50",
    amountBp: 5000,
    firstCycleOnly: true,
    subscriptionCycles: 1,
    usageLimit: 100,
    restrictedTiers: ["pro"],
    restrictedProductIds: ["pdt_proMonth01", "pdt_proAnnual01"],
    dodoDiscountId: "dsc_abc",
  });
  assert.equal(rec.code, "LAUNCH50");
  assert.equal(rec.percentOff, 50);
  assert.equal(rec.firstCycleOnly, true);
  assert.equal(rec.status, "active");

  const found = await store.findPromoByCode("LAUNCH50");
  assert.ok(found);
  assert.equal(found.percentOff, 50);
  assert.equal(await store.findPromoByCode("missing"), null);
});

test("validatePromoForCheckout: missing code → PROMO_MISSING", async () => {
  const r = await promos.validatePromoForCheckout({ code: "" });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_MISSING");
});

test("validatePromoForCheckout: unknown code → PROMO_NOT_FOUND", async () => {
  const r = await promos.validatePromoForCheckout({
    code: "NOPE",
    tier: "pro",
    email: "a@b.com",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_NOT_FOUND");
});

test("validatePromoForCheckout: tier restriction is enforced", async () => {
  // A Pro-only promo must reject a Free checkout.
  const r = await promos.validatePromoForCheckout({
    code: "LAUNCH50",
    tier: "free",
    email: "a@b.com",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_TIER_NOT_ELIGIBLE");
});

test("validatePromoForCheckout: email is required for the per-account gate", async () => {
  const r = await promos.validatePromoForCheckout({
    code: "LAUNCH50",
    tier: "pro",
    email: "",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_EMAIL_REQUIRED");
});

test("validatePromoForCheckout: a fresh eligible account succeeds", async () => {
  const r = await promos.validatePromoForCheckout({
    code: "LAUNCH50",
    tier: "pro",
    email: "fresh@example.com",
  });
  assert.equal(r.ok, true);
  assert.equal(r.promo.code, "LAUNCH50");
});

test("redemption ledger: one-per-account is enforced (by email and by customerId)", async () => {
  await store.addPromoRedemption({
    code: "LAUNCH50",
    email: "Used@Example.com",
    customerId: "cus_used",
    subscriptionId: "sub_1",
    licenseKey: "DUST-XXXXX",
  });
  // Same email (case-insensitive) is now blocked.
  const byEmail = await promos.validatePromoForCheckout({
    code: "LAUNCH50",
    tier: "pro",
    email: "used@example.com",
  });
  assert.equal(byEmail.ok, false);
  assert.equal(byEmail.error, "PROMO_ALREADY_REDEEMED");
  // Same Dodo customer id (different email) is also blocked.
  assert.equal(
    await store.hasAccountRedeemedAnyPromo({ customerId: "cus_used" }),
    true,
  );
  assert.equal(
    await store.hasAccountRedeemedAnyPromo({ email: "brand-new@example.com" }),
    false,
  );
});

test("redemption ledger: replays for the same subscription are deduped", async () => {
  const first = await store.addPromoRedemption({
    code: "LAUNCH50",
    email: "dedupe@example.com",
    subscriptionId: "sub_dupe",
  });
  const second = await store.addPromoRedemption({
    code: "LAUNCH50",
    email: "dedupe@example.com",
    subscriptionId: "sub_dupe",
  });
  assert.equal(first.deduped, false);
  assert.equal(second.deduped, true);
});

test("countPromoRedemptions excludes flagged (stacking) redemptions", async () => {
  await store.addPromo({ code: "COUNTME", amountBp: 2000 });
  await store.addPromoRedemption({
    code: "COUNTME",
    email: "ok@example.com",
    subscriptionId: "sub_ok",
  });
  await store.addPromoRedemption({
    code: "COUNTME",
    email: "stack@example.com",
    subscriptionId: "sub_flag",
    flagged: true,
    flagReason: "account_already_redeemed_another_promo",
  });
  assert.equal(await store.countPromoRedemptions("COUNTME"), 1);
});

test("revoked promo is rejected at checkout", async () => {
  await store.addPromo({ code: "DEAD10", amountBp: 1000 });
  await store.updatePromo("DEAD10", { status: "revoked" });
  const r = await promos.validatePromoForCheckout({
    code: "DEAD10",
    tier: "pro",
    email: "x@y.com",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_REVOKED");
});

test("expired promo is rejected at checkout", async () => {
  await store.addPromo({
    code: "OLD20",
    amountBp: 2000,
    expiresAt: new Date(Date.now() - 86400000).toISOString(),
  });
  const r = await promos.validatePromoForCheckout({
    code: "OLD20",
    tier: "pro",
    email: "x@y.com",
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, "PROMO_EXPIRED");
});

test("productIdForPlan recovers ids from the configured checkout links", () => {
  assert.equal(promos.productIdForPlan("pro", "monthly"), "pdt_proMonth01");
  assert.equal(promos.productIdForPlan("pro", "annual"), "pdt_proAnnual01");
});

test("restrictedProductIdsForTiers never returns an empty list", () => {
  assert.deepEqual(promos.restrictedProductIdsForTiers(["pro"]).sort(), [
    "pdt_proAnnual01",
    "pdt_proMonth01",
  ]);
  // Empty tiers → all paid products (so a promo can't apply to unrelated
  // products in the same Dodo business).
  assert.equal(promos.restrictedProductIdsForTiers([]).length, 2);
});

test("matchRedeemedPromo matches a webhook payload by code and by discount id", async () => {
  await store.addPromo({
    code: "WEBHOOK1",
    amountBp: 5000,
    dodoDiscountId: "dsc_webhook_id",
  });
  const byCode = await promos.matchRedeemedPromo({
    discountCodes: ["WEBHOOK1"],
  });
  assert.equal(byCode?.code, "WEBHOOK1");
  const byId = await promos.matchRedeemedPromo({
    discountIds: ["dsc_webhook_id"],
  });
  assert.equal(byId?.code, "WEBHOOK1");
  const none = await promos.matchRedeemedPromo({});
  assert.equal(none, null);
});

test("dodoPublicConfig.promo reflects whether the Dodo API key is set", () => {
  delete process.env.DODO_PAYMENTS_API_KEY;
  assert.equal(dodo.dodoPublicConfig().promo, false);
  process.env.DODO_PAYMENTS_API_KEY = "test_key";
  assert.equal(dodo.dodoPublicConfig().promo, true);
  delete process.env.DODO_PAYMENTS_API_KEY;
});
