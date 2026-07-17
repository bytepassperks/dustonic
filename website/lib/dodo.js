// Dodo Payments integration helpers.
//
// Everything here is inert until DODO_WEBHOOK_SECRET is set, so the site is
// safe to deploy before Dodo is configured. The webhook signature scheme is
// StandardWebhooks (https://www.standardwebhooks.com/) which Dodo uses:
//   signedContent = `${webhook-id}.${webhook-timestamp}.${rawBody}`
//   signature     = base64(HMAC_SHA256(base64decode(secret), signedContent))
// and the `webhook-signature` header is a space-delimited list of
// `v1,<base64sig>` tokens. All env vars are read lazily (at call time) so
// tests and runtime can toggle configuration without re-importing.

import crypto from "node:crypto";
import { billingPeriodForProduct } from "./promos.js";

const WEBHOOK_TOLERANCE_SECONDS = 300;

export function isDodoConfigured() {
  return Boolean(process.env.DODO_WEBHOOK_SECRET);
}

function secretKeyBytes() {
  const raw = process.env.DODO_WEBHOOK_SECRET || "";
  const base = raw.startsWith("whsec_") ? raw.slice(6) : raw;
  return Buffer.from(base, "base64");
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// Verify a StandardWebhooks signature. `payload` is the RAW request body
// (Buffer or string) — it must be the exact bytes Dodo signed.
export function verifyDodoSignature({ id, timestamp, signature, payload }) {
  if (!isDodoConfigured()) return { ok: false, error: "not_configured" };
  if (!id || !timestamp || !signature) {
    return { ok: false, error: "missing_headers" };
  }
  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return { ok: false, error: "bad_timestamp" };
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > WEBHOOK_TOLERANCE_SECONDS) {
    return { ok: false, error: "timestamp_out_of_tolerance" };
  }
  const key = secretKeyBytes();
  if (key.length === 0) return { ok: false, error: "bad_secret" };

  const body = Buffer.isBuffer(payload)
    ? payload.toString("utf8")
    : String(payload ?? "");
  const expected = crypto
    .createHmac("sha256", key)
    .update(`${id}.${timestamp}.${body}`)
    .digest("base64");

  const passed = String(signature)
    .split(" ")
    .map((token) => (token.includes(",") ? token.split(",")[1] : token))
    .filter(Boolean)
    .some((sig) => timingSafeEqualStr(sig, expected));

  return passed ? { ok: true } : { ok: false, error: "signature_mismatch" };
}

function idSet(envName) {
  return new Set(
    (process.env[envName] || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

// Map a Dodo product id to Pro via the configured product id list.
export function productTier(productId) {
  if (!productId) return null;
  const pid = String(productId);
  if (idSet("DODO_PRO_PRODUCT_IDS").has(pid)) return "pro";
  return null;
}

// Normalise a Dodo webhook event into the fields we care about. Dodo nests the
// resource under `data`; shapes differ between one-time payments and
// subscriptions, so we read each field from its known locations.
export function parseDodoEvent(event) {
  const data = event?.data || {};
  const customer = data.customer || {};

  const email = customer.email || data.customer_email || data.email || null;
  const name = customer.name || data.customer_name || data.name || "";

  const productIds = [];
  if (data.product_id) productIds.push(String(data.product_id));
  for (const list of [data.product_cart, data.products]) {
    if (Array.isArray(list)) {
      for (const item of list) {
        if (item?.product_id) productIds.push(String(item.product_id));
      }
    }
  }

  const subscriptionId =
    data.subscription_id || data.subscription?.subscription_id || null;
  const paymentId = data.payment_id || null;
  const customerId = customer.customer_id || data.customer_id || null;

  // Any discount applied to this purchase. Dodo's shapes vary (singular vs.
  // array, code vs. id, nested objects), so we collect every place a code or a
  // discount id can appear and dedupe.
  const discountCodes = new Set();
  const discountIds = new Set();
  const addCode = (c) => c && discountCodes.add(String(c).trim().toUpperCase());
  const addId = (i) => i && discountIds.add(String(i));
  const addCodeOrId = (v) => {
    if (String(v).startsWith("dsc_")) addId(v);
    else addCode(v);
  };
  addCode(data.discount_code);
  addId(data.discount_id);
  for (const c of [data.discount_codes, data.discount_ids]) {
    if (Array.isArray(c)) c.forEach(addCodeOrId);
  }
  if (Array.isArray(data.discounts)) {
    for (const d of data.discounts) {
      if (typeof d === "string") addCodeOrId(d);
      else if (d) {
        addCode(d.code);
        addId(d.discount_id || d.id);
      }
    }
  }

  let tier = null;
  for (const pid of productIds) {
    const mapped = productTier(pid);
    if (mapped) {
      tier = mapped;
      break;
    }
  }

  // Derive billing period from the product id (monthly / annual / null).
  let billingPeriod = null;
  for (const pid of productIds) {
    const bp = billingPeriodForProduct(pid);
    if (bp) {
      billingPeriod = bp;
      break;
    }
  }

  return {
    type: event?.type || "",
    email,
    name,
    productIds,
    tier,
    billingPeriod,
    subscriptionId,
    paymentId,
    customerId,
    discountCodes: [...discountCodes],
    discountIds: [...discountIds],
  };
}

// Hosted-checkout links shown on the "Buy" buttons, sourced from env.
export function checkoutLinks() {
  const candidates = {
    proMonthly: process.env.DODO_CHECKOUT_PRO_MONTHLY,
    proAnnual: process.env.DODO_CHECKOUT_PRO_ANNUAL,
  };
  const out = {};
  for (const [k, v] of Object.entries(candidates)) {
    if (v) out[k] = v;
  }
  return out;
}

// Public config consumed by the front-end to decide whether to wire the Buy
// buttons to Dodo checkout (vs. falling back to the contact modal).
export function dodoPublicConfig() {
  const links = checkoutLinks();
  // `promo` is true only when the Dodo API key is set, since promo checkout
  // creates a hosted session server-side (a static link can't carry a code).
  return {
    enabled: Object.keys(links).length > 0,
    links,
    promo: Boolean(process.env.DODO_PAYMENTS_API_KEY),
  };
}
