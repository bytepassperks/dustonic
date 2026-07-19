// Promo / discount-code helpers.
//
// The actual percentage discount lives in Dodo Payments (the merchant of
// record charges the card, so a code that only existed in our DB could never
// reduce what Dodo bills). Dodo natively supports percentage discount codes
// with a global usage cap, an expiry, a product restriction, and a
// subscription-cycle limit (`subscription_cycles = 1` => the discount applies
// to the first billing cycle only, full price on renewal). What Dodo does NOT
// enforce is "one promo per account / first-time customer only / no stacking";
// that is enforced here + via the redemption ledger in store.js.
//
// All Dodo calls are gated on DODO_PAYMENTS_API_KEY so the module is inert
// until Dodo is configured. Env vars are read lazily so tests can toggle them.

import {
  findPromoByCode,
  hasAccountRedeemedAnyPromo,
  normalizePromoCode,
} from "./store.js";

const PAID_TIERS = ["pro"];

export function isDodoApiConfigured() {
  return Boolean(process.env.DODO_PAYMENTS_API_KEY);
}

function dodoApiBase() {
  return (process.env.DODO_API_BASE || "https://live.dodopayments.com").replace(
    /\/+$/,
    "",
  );
}

async function dodoFetch(pathname, { method = "GET", body } = {}) {
  if (!isDodoApiConfigured()) {
    throw new Error("dodo_api_not_configured");
  }
  const res = await fetch(`${dodoApiBase()}${pathname}`, {
    method,
    headers: {
      Authorization: `Bearer ${process.env.DODO_PAYMENTS_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, json, text };
}

/* ---------- Product-id mapping (derived from the configured checkout links) ---------- */
// The "Buy" buttons already point at static Dodo links of the form
// https://checkout.dodopayments.com/buy/pdt_xxx, so we reuse those to recover
// the product id for a (tier, period) without introducing new env vars.

function productIdFromLink(link) {
  const m = String(link || "").match(/pdt_[A-Za-z0-9_]+/);
  return m ? m[0] : null;
}

const PLAN_ENV = {
  proMonthly: "DODO_CHECKOUT_PRO_MONTHLY",
  proAnnual: "DODO_CHECKOUT_PRO_ANNUAL",
};

export function productIdForPlan(tier, period) {
  const key = `${tier}${period === "annual" ? "Annual" : "Monthly"}`;
  const env = PLAN_ENV[key];
  return env ? productIdFromLink(process.env[env]) : null;
}

export function productIdsForTier(tier) {
  return [
    productIdForPlan(tier, "monthly"),
    productIdForPlan(tier, "annual"),
  ].filter(Boolean);
}

// Reverse-map: given a product id, return "monthly" | "annual" | null.
export function billingPeriodForProduct(productId) {
  if (!productId) return null;
  const pid = String(productId);
  for (const tier of PAID_TIERS) {
    if (pid === productIdForPlan(tier, "monthly")) return "monthly";
    if (pid === productIdForPlan(tier, "annual")) return "annual";
  }
  return null;
}

// Product ids a promo should be restricted to. We NEVER leave this empty: the
// Dodo business hosts unrelated products, and an empty restriction would let an
// Dustonic promo apply to any product. Empty `tiers` => all Dustonic paid products.
export function restrictedProductIdsForTiers(tiers) {
  const list = Array.isArray(tiers) && tiers.length ? tiers : PAID_TIERS;
  const ids = new Set();
  for (const t of list) for (const id of productIdsForTier(t)) ids.add(id);
  return [...ids];
}

/* ---------- Dodo Discounts API client ---------- */

export async function createDodoDiscount({
  code,
  name,
  amountBp,
  expiresAt,
  usageLimit,
  subscriptionCycles,
  restrictedProductIds,
}) {
  const body = {
    type: "percentage",
    amount: amountBp,
    code: normalizePromoCode(code),
    name: name || normalizePromoCode(code),
  };
  if (expiresAt) body.expires_at = expiresAt;
  if (usageLimit != null) body.usage_limit = usageLimit;
  if (subscriptionCycles != null) body.subscription_cycles = subscriptionCycles;
  if (Array.isArray(restrictedProductIds) && restrictedProductIds.length) {
    body.restricted_to = restrictedProductIds;
  }
  const { ok, status, json, text } = await dodoFetch("/discounts", {
    method: "POST",
    body,
  });
  if (!ok) {
    const err = new Error(`dodo_create_discount_failed:${status}`);
    err.detail = json || text;
    throw err;
  }
  return json;
}

export async function getDodoDiscountByCode(code) {
  const { ok, status, json } = await dodoFetch(
    `/discounts/code/${encodeURIComponent(normalizePromoCode(code))}`,
  );
  if (status === 404) return null;
  if (!ok) {
    const err = new Error(`dodo_get_discount_failed:${status}`);
    err.detail = json;
    throw err;
  }
  return json;
}

export async function deleteDodoDiscount(discountId) {
  const { ok, status, json } = await dodoFetch(
    `/discounts/${encodeURIComponent(discountId)}`,
    { method: "DELETE" },
  );
  if (!ok && status !== 404) {
    const err = new Error(`dodo_delete_discount_failed:${status}`);
    err.detail = json;
    throw err;
  }
  return { ok: true, status };
}

// Create a one-time hosted-checkout session with the promo pre-applied. The
// code is applied server-side (never handed to the browser as a reusable URL),
// so a customer can only obtain the discount through our validated flow.
export async function createDodoCheckoutSession({
  productId,
  code,
  email,
  returnUrl,
}) {
  const body = {
    product_cart: [{ product_id: productId, quantity: 1 }],
  };
  if (code) body.discount_codes = [normalizePromoCode(code)];
  if (email) body.customer = { email };
  if (returnUrl) body.return_url = returnUrl;
  const { ok, status, json, text } = await dodoFetch("/checkouts", {
    method: "POST",
    body,
  });
  if (!ok) {
    const err = new Error(`dodo_create_session_failed:${status}`);
    err.detail = json || text;
    throw err;
  }
  return json; // { session_id, checkout_url }
}

/* ---------- Validation ---------- */

function promoExpired(promo, now = Date.now()) {
  if (!promo.expiresAt) return false;
  const t = Date.parse(promo.expiresAt);
  return Number.isFinite(t) && t <= now;
}

// Validate a code for a prospective checkout. Returns a structured result with
// a machine-readable `error` on failure so the endpoint can map it to a code.
//   tier      — the plan the customer is buying ("pro")
//   email     — the account redeeming (required for the per-account gate)
//   customerId— optional Dodo customer id (extra match for the per-account gate)
//   checkDodo — when true, cross-checks Dodo's live record (existence + usage)
export async function validatePromoForCheckout({
  code,
  tier,
  email,
  customerId,
  checkDodo = false,
} = {}) {
  const normalized = normalizePromoCode(code);
  if (!normalized) return { ok: false, error: "PROMO_MISSING" };

  const promo = await findPromoByCode(normalized);
  if (!promo) return { ok: false, error: "PROMO_NOT_FOUND" };
  if (promo.status !== "active") {
    return { ok: false, error: "PROMO_REVOKED", promo };
  }
  if (promoExpired(promo)) return { ok: false, error: "PROMO_EXPIRED", promo };

  if (
    tier &&
    Array.isArray(promo.restrictedTiers) &&
    promo.restrictedTiers.length
  ) {
    if (!promo.restrictedTiers.includes(tier)) {
      return { ok: false, error: "PROMO_TIER_NOT_ELIGIBLE", promo };
    }
  }

  if (!email) return { ok: false, error: "PROMO_EMAIL_REQUIRED", promo };

  const already = await hasAccountRedeemedAnyPromo({ email, customerId });
  if (already) return { ok: false, error: "PROMO_ALREADY_REDEEMED", promo };

  if (checkDodo && isDodoApiConfigured()) {
    let live = null;
    try {
      live = await getDodoDiscountByCode(normalized);
    } catch {
      // If the live lookup fails we still trust our own store rather than
      // blocking a legitimate purchase on a transient Dodo error.
      return { ok: true, promo, live: null };
    }
    if (!live) return { ok: false, error: "PROMO_NOT_FOUND", promo };
    if (
      live.usage_limit != null &&
      Number(live.times_used) >= Number(live.usage_limit)
    ) {
      return { ok: false, error: "PROMO_USAGE_EXCEEDED", promo, live };
    }
    return { ok: true, promo, live };
  }

  return { ok: true, promo };
}

// Fetch a Dodo payment by id — used to enrich webhook events with discount info
// that may not be present in the webhook payload itself.
export async function getDodoPayment(paymentId) {
  if (!paymentId || !isDodoApiConfigured()) return null;
  try {
    const { ok, json } = await dodoFetch(
      `/payments/${encodeURIComponent(paymentId)}`,
    );
    return ok ? json : null;
  } catch {
    return null;
  }
}

// Match the discount codes/ids present on a Dodo webhook payload back to one of
// our promos, so the webhook can record the redemption against the right promo.
// If the webhook payload doesn't carry discount info, falls back to querying the
// Dodo Payments API for the payment details.
export async function matchRedeemedPromo(parsed) {
  const codes = new Set((parsed.discountCodes || []).map(normalizePromoCode));
  const ids = new Set(parsed.discountIds || []);

  // Fallback: if the webhook payload carried no discount info, look up the
  // payment via the Dodo API (which always includes discounts).
  if (!codes.size && !ids.size && parsed.paymentId && isDodoApiConfigured()) {
    const payment = await getDodoPayment(parsed.paymentId);
    if (payment) {
      if (payment.discount_id) ids.add(String(payment.discount_id));
      if (Array.isArray(payment.discounts)) {
        for (const d of payment.discounts) {
          if (d?.code) codes.add(normalizePromoCode(d.code));
          if (d?.discount_id) ids.add(String(d.discount_id));
        }
      }
    }
  }

  if (!codes.size && !ids.size) return null;
  for (const code of codes) {
    const promo = await findPromoByCode(code);
    if (promo) return promo;
  }
  // Fall back to matching by Dodo discount id against our mirrored promos.
  if (ids.size) {
    const { listPromos } = await import("./store.js");
    const promos = await listPromos();
    return (
      promos.find((p) => p.dodoDiscountId && ids.has(p.dodoDiscountId)) || null
    );
  }
  return null;
}
