// Tests for the Dodo Payments integration (signature verification, event
// parsing, product→tier mapping, store idempotency + dedupe).
// Run with: node --test
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Configure env BEFORE importing modules that read it at load time (store.js
// reads DATA_DIR when imported).
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "dodo-test-"));
process.env.DATA_DIR = TMP;
process.env.DODO_WEBHOOK_SECRET =
  "whsec_" + Buffer.from("a-very-secret-signing-key").toString("base64");
process.env.DODO_PRO_PRODUCT_IDS = "pdt_pro_monthly, pdt_pro_annual";
process.env.DODO_CHECKOUT_PRO_MONTHLY = "https://checkout.dodopayments.com/buy/pdt_pro_monthly";
process.env.DODO_CHECKOUT_PRO_ANNUAL = "https://checkout.dodopayments.com/buy/pdt_pro_annual";

const dodo = await import("../lib/dodo.js");
const store = await import("../lib/store.js");

function sign(id, ts, body) {
  const raw = process.env.DODO_WEBHOOK_SECRET;
  const base = raw.startsWith("whsec_") ? raw.slice(6) : raw;
  const key = Buffer.from(base, "base64");
  const sig = crypto
    .createHmac("sha256", key)
    .update(`${id}.${ts}.${body}`)
    .digest("base64");
  return `v1,${sig}`;
}

test("isDodoConfigured reflects the webhook secret", () => {
  assert.equal(dodo.isDodoConfigured(), true);
});

test("verifyDodoSignature accepts a valid StandardWebhooks signature", () => {
  const id = "evt_1";
  const ts = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ type: "payment.succeeded" });
  const res = dodo.verifyDodoSignature({
    id,
    timestamp: ts,
    signature: sign(id, ts, body),
    payload: Buffer.from(body),
  });
  assert.equal(res.ok, true);
});

test("verifyDodoSignature accepts a space-delimited multi-signature header", () => {
  const id = "evt_multi";
  const ts = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ type: "payment.succeeded" });
  const header = `v1,AAAAinvalid ${sign(id, ts, body)}`;
  const res = dodo.verifyDodoSignature({
    id,
    timestamp: ts,
    signature: header,
    payload: Buffer.from(body),
  });
  assert.equal(res.ok, true);
});

test("verifyDodoSignature rejects a tampered body", () => {
  const id = "evt_2";
  const ts = Math.floor(Date.now() / 1000).toString();
  const body = JSON.stringify({ type: "payment.succeeded" });
  const res = dodo.verifyDodoSignature({
    id,
    timestamp: ts,
    signature: sign(id, ts, body),
    payload: Buffer.from(body + "tampered"),
  });
  assert.equal(res.ok, false);
  assert.equal(res.error, "signature_mismatch");
});

test("verifyDodoSignature rejects an out-of-tolerance timestamp", () => {
  const id = "evt_3";
  const ts = (Math.floor(Date.now() / 1000) - 4000).toString();
  const body = "{}";
  const res = dodo.verifyDodoSignature({
    id,
    timestamp: ts,
    signature: sign(id, ts, body),
    payload: Buffer.from(body),
  });
  assert.equal(res.ok, false);
  assert.equal(res.error, "timestamp_out_of_tolerance");
});

test("verifyDodoSignature rejects missing headers", () => {
  const res = dodo.verifyDodoSignature({
    id: "",
    timestamp: "",
    signature: "",
    payload: Buffer.from("{}"),
  });
  assert.equal(res.ok, false);
  assert.equal(res.error, "missing_headers");
});

test("productTier maps configured product ids", () => {
  assert.equal(dodo.productTier("pdt_pro_monthly"), "pro");
  assert.equal(dodo.productTier("pdt_pro_annual"), "pro");
  assert.equal(dodo.productTier("prod_unknown"), null);
  assert.equal(dodo.productTier(""), null);
});

test("parseDodoEvent extracts a one-time payment", () => {
  const event = {
    type: "payment.succeeded",
    data: {
      payment_id: "pay_123",
      customer: { customer_id: "cus_1", email: "a@b.com", name: "Ada" },
      product_cart: [{ product_id: "pdt_pro_monthly", quantity: 1 }],
    },
  };
  const p = dodo.parseDodoEvent(event);
  assert.equal(p.email, "a@b.com");
  assert.equal(p.name, "Ada");
  assert.equal(p.paymentId, "pay_123");
  assert.equal(p.customerId, "cus_1");
  assert.equal(p.tier, "pro");
  assert.equal(p.billingPeriod, "monthly");
  assert.deepEqual(p.productIds, ["pdt_pro_monthly"]);
});

test("dodoPublicConfig exposes only configured checkout links", () => {
  const cfg = dodo.dodoPublicConfig();
  assert.equal(cfg.enabled, true);
  assert.equal(cfg.links.proMonthly, "https://checkout.dodopayments.com/buy/pdt_pro_monthly");
  assert.equal(cfg.links.proAnnual, "https://checkout.dodopayments.com/buy/pdt_pro_annual");
});

test("markDodoEventProcessed is idempotent", async () => {
  const first = await store.markDodoEventProcessed("evt_dup", { type: "x" });
  const second = await store.markDodoEventProcessed("evt_dup", { type: "x" });
  assert.equal(first, true);
  assert.equal(second, false);
  assert.equal(await store.wasDodoEventProcessed("evt_dup"), true);
  assert.equal(await store.wasDodoEventProcessed("evt_never"), false);
});

test("findLicenseByDodo locates licenses by subscription or payment id", async () => {
  await store.addLicense({
    email: "x@y.com",
    tier: "pro",
    source: "dodo",
    dodo: { subscriptionId: "sub_a", paymentId: "pay_a", productId: "pdt_pro_monthly" },
  });
  const bySub = await store.findLicenseByDodo({ subscriptionId: "sub_a" });
  const byPay = await store.findLicenseByDodo({ paymentId: "pay_a" });
  const miss = await store.findLicenseByDodo({ subscriptionId: "nope" });
  assert.ok(bySub);
  assert.equal(bySub.tier, "pro");
  assert.ok(byPay);
  assert.equal(byPay.key, bySub.key);
  assert.equal(miss, null);
  assert.equal(await store.findLicenseByDodo({}), null);
});
