import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import compression from "compression";
import express from "express";
import { renderDashboard, renderLogin } from "./lib/admin-views.js";
import {
  createSession,
  isAdminConfigured,
  parseCookies,
  SESSION_COOKIE,
  verifyCredentials,
  verifySession,
} from "./lib/auth.js";
import {
  dodoPublicConfig,
  isDodoConfigured,
  parseDodoEvent,
  verifyDodoSignature,
} from "./lib/dodo.js";
import { isMailConfigured, sendMail } from "./lib/email.js";
import {
  billingPeriodForProduct,
  createDodoCheckoutSession,
  createDodoDiscount,
  deleteDodoDiscount,
  getDodoPayment,
  isDodoApiConfigured,
  matchRedeemedPromo,
  productIdForPlan,
  restrictedProductIdsForTiers,
  validatePromoForCheckout,
} from "./lib/promos.js";
import {
  addLicense,
  addPromo,
  addPromoRedemption,
  addRequest,
  findLicenseByDodo,
  findPromoByCode,
  getLicenseByKey,
  listLicenses,
  listPromoRedemptions,
  listPromos,
  listRequests,
  markDodoEventProcessed,
  normalizeEmail,
  normalizePromoCode,
  updateLicense,
  updatePromo,
  updateRequest,
  wasDodoEventProcessed,
} from "./lib/store.js";
import { DEFAULT_TIER, isValidTier, tierEntitlements } from "./lib/tiers.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const SITE_URL = process.env.SITE_URL || "https://dustonic.com";

const CONTACT_TO = process.env.CONTACT_TO || "harryroger798@gmail.com";

app.disable("x-powered-by");
app.set("trust proxy", true);

// Gzip/Brotli-style compression for HTML/CSS/JS/JSON/SVG responses.
app.use(compression());

// Baseline security + privacy headers on every response.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://*.googletagmanager.com https://app.airalytics.net",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https://*.google-analytics.com https://*.googletagmanager.com https://fazier.com https://tinylaunch.com https://www.tinylaunch.com https://findly.tools https://statics.startupbase.io https://www.shipit.buzz https://twelve.tools https://wired.business https://auraplusplus.com",
  "connect-src 'self' https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com https://app.airalytics.net",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), interest-cohort=()",
  );
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  res.setHeader("Content-Security-Policy", CSP);
  next();
});

// The Dodo webhook signature is computed over the raw request bytes, so it must
// be registered with a raw body parser BEFORE the global JSON parser consumes
// the stream. All other routes still use express.json below.
app.post(
  "/api/dodo/webhook",
  express.raw({ type: "*/*", limit: "256kb" }),
  handleDodoWebhook,
);

app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

// security.txt (RFC 9116) — lives under the dot-prefixed well-known dir, which
// express.static ignores by default, so serve it explicitly.
app.get("/.well-known/security.txt", (_req, res) => {
  res.type("text/plain");
  res.sendFile(path.join(__dirname, "public", ".well-known", "security.txt"));
});

// Lightweight in-memory rate limit (per-IP) to deter contact-form spam.
const HITS = new Map();
function rateLimited(ip, max = 5, windowMs = 60_000) {
  const now = Date.now();
  const entry = HITS.get(ip) || { count: 0, start: now };
  if (now - entry.start > windowMs) {
    entry.count = 0;
    entry.start = now;
  }
  entry.count += 1;
  HITS.set(ip, entry);
  return entry.count > max;
}

function clientIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
}

async function persistSubmission(payload) {
  const dir = process.env.DATA_DIR || path.join(__dirname, "data");
  await mkdir(dir, { recursive: true });
  const line = `${JSON.stringify({ ...payload, at: new Date().toISOString() })}\n`;
  await new Promise((resolve, reject) => {
    const stream = createWriteStream(
      path.join(dir, "contact-submissions.jsonl"),
      { flags: "a" },
    );
    stream.write(line, (err) => (err ? reject(err) : resolve()));
    stream.end();
  });
}

async function notifyAdminOfRequest(payload) {
  const text = [
    `New access request for Dustonic.`,
    "",
    `Name: ${payload.name}`,
    `Email: ${payload.email}`,
    payload.company ? `Company: ${payload.company}` : null,
    payload.plan ? `Interested plan: ${payload.plan}` : null,
    "",
    payload.message,
    "",
    `Approve / reject in the admin panel: ${SITE_URL}/admin`,
  ]
    .filter((l) => l !== null)
    .join("\n");
  await sendMail({
    to: CONTACT_TO,
    subject: `New Dustonic inquiry — ${payload.name}`,
    text,
    replyTo: payload.email,
  });
}

function licenseEmailBody({ name, tier, key }) {
  const t = tierEntitlements(tier);
  return [
    `Hi ${name || "there"},`,
    "",
    `Your Dustonic ${t.name} access has been approved. Here is your license key:`,
    "",
    `    ${key}`,
    "",
    `To activate:`,
    `  1. Download and open Dustonic: ${SITE_URL}/download`,
    `  2. Open Settings → License (or the "Activate license" prompt).`,
    `  3. Paste the key above and click Activate.`,
    "",
    `Your ${t.name} plan unlocks:`,
    t.safeCleaning ? "  • Protected core cleaning rules" : null,
    t.manualClean ? "  • Manual scan and cleanup" : null,
    t.proRules ? "  • Deep-clean and developer cache rules" : null,
    t.scheduledClean ? "  • Scheduled and automatic cleaning" : null,
    t.duplicateFinder ? "  • Duplicate and large-file finder tools" : null,
    "",
    `Keep this key safe — it is tied to your email. Reply to this message if you need help.`,
    "",
    `— The Dustonic crew`,
  ]
    .filter((l) => l !== null)
    .join("\n");
}

async function issueLicense({
  email,
  name,
  tier,
  requestId,
  sendKey,
  source,
  dodo,
  expiresAt,
}) {
  const license = await addLicense({
    email,
    name,
    tier,
    requestId,
    source,
    dodo,
    expiresAt: expiresAt || null,
  });
  let delivered = false;
  if (sendKey && isMailConfigured()) {
    try {
      await sendMail({
        to: email,
        subject: `Your Dustonic ${tierEntitlements(tier).name} license key`,
        text: licenseEmailBody({ name, tier, key: license.key }),
      });
      delivered = true;
    } catch (err) {
      console.error("[license] email failed:", err);
    }
  }
  await updateLicense(license.key, { emailDelivered: delivered }).catch(
    () => {},
  );
  return { license, delivered };
}

/* ---------------- Dodo Payments webhook ---------------- */

// Events that grant access (issue a license) vs. revoke it. A subscription's
// first charge fires both payment.succeeded and subscription.active, and
// renewals fire payment.succeeded again — issuance is deduped per
// subscription/payment id so at most one license is created.
const DODO_ISSUE_EVENTS = new Set(["payment.succeeded", "subscription.active"]);
const DODO_RENEW_EVENTS = new Set(["subscription.renewed"]);
// A reversed payment (refund / chargeback) fully revokes the license — the
// money came back, so access should not survive.
const DODO_REVOKE_EVENTS = new Set(["refund.succeeded", "payment.refunded"]);
// End of the paid relationship (the plan lapsed or was cancelled) downgrades
// the account to Free rather than revoking it: the license key stays valid but
// resolves to the Free tier, so the app drops to Free limits on next validate.
const DODO_DOWNGRADE_EVENTS = new Set([
  "subscription.expired",
  "subscription.cancelled",
]);

async function issueLicenseFromDodo(parsed) {
  if (!parsed.email) {
    console.warn("[dodo] issue event missing customer email; skipping");
    return { skipped: "no_email" };
  }
  const existing = await findLicenseByDodo({
    subscriptionId: parsed.subscriptionId,
    paymentId: parsed.paymentId,
  });
  if (existing) {
    // Even on a deduped issue event, make sure any promo on the payload is
    // recorded (the discount may only appear on a later event for the same
    // subscription); recording is idempotent per subscription+code.
    const promo = await recordPromoRedemption(parsed, existing.key);
    return { deduped: existing.key, ...(promo ? { promo } : {}) };
  }

  // Compute expiresAt for subscription-based purchases. Monthly subs get a
  // 35-day safety net, annual subs get 370 days. If the subscription renews,
  // the `subscription.renewed` event will extend the expiry. If Dodo fires
  // `subscription.expired`/`.cancelled` first, the downgrade handler runs.
  let expiresAt = null;
  if (parsed.subscriptionId && parsed.billingPeriod) {
    const d = new Date();
    if (parsed.billingPeriod === "monthly") {
      d.setDate(d.getDate() + 35);
    } else if (parsed.billingPeriod === "annual") {
      d.setDate(d.getDate() + 370);
    }
    expiresAt = d.toISOString();
  }

  const tier = parsed.tier || process.env.DODO_DEFAULT_TIER || "pro";
  const { license, delivered } = await issueLicense({
    email: parsed.email,
    name: parsed.name || "",
    tier,
    requestId: null,
    sendKey: true,
    source: "dodo",
    dodo: {
      customerId: parsed.customerId || null,
      subscriptionId: parsed.subscriptionId || null,
      paymentId: parsed.paymentId || null,
      productId: parsed.productIds[0] || null,
    },
    expiresAt,
  });
  console.log(
    `[dodo] issued ${tier} license ${license.key} for ${parsed.email}; period=${parsed.billingPeriod || "lifetime"}; emailed=${delivered}`,
  );
  const promo = await recordPromoRedemption(parsed, license.key);
  return {
    issued: license.key,
    tier,
    emailed: delivered,
    ...(promo ? { promo } : {}),
  };
}

// Records a promo redemption against the ledger when a paid event carries a
// discount code/id that maps to one of our promos. Enforcement of
// one-promo-per-account happens at /api/promo/checkout (before Dodo charges);
// here we additionally FLAG any redemption from an account that already
// redeemed a promo on a different subscription, so the admin can act on a
// bypass attempt (Dodo has already charged, so we can't reject at this point).
async function recordPromoRedemption(parsed, licenseKey) {
  if (!(parsed.discountCodes?.length || parsed.discountIds?.length))
    return null;
  const promo = await matchRedeemedPromo(parsed);
  if (!promo) return null;

  const ledger = await listPromoRedemptions();
  const e = normalizeEmail(parsed.email);
  const priorOther = ledger.some(
    (r) =>
      !r.flagged &&
      r.subscriptionId !== parsed.subscriptionId &&
      ((e && normalizeEmail(r.email) === e) ||
        (parsed.customerId && r.customerId === parsed.customerId)),
  );

  const res = await addPromoRedemption({
    code: promo.code,
    email: parsed.email,
    customerId: parsed.customerId,
    subscriptionId: parsed.subscriptionId,
    paymentId: parsed.paymentId,
    licenseKey,
    flagged: priorOther,
    flagReason: priorOther ? "account_already_redeemed_another_promo" : null,
  });
  if (!res.deduped) {
    console.log(
      `[promo] redemption ${promo.code} for ${parsed.email}${priorOther ? " (FLAGGED: stacking attempt)" : ""}`,
    );
  }
  return { code: promo.code, flagged: priorOther, deduped: res.deduped };
}

// End-of-billing downgrade: keep the license key valid but resolve it to Free.
async function downgradeLicenseFromDodo(parsed) {
  const target = await findLicenseByDodo({
    subscriptionId: parsed.subscriptionId,
    paymentId: parsed.paymentId,
  });
  if (!target) return { skipped: "license_not_found" };
  if (target.tier === DEFAULT_TIER && target.status === "active") {
    return { already_free: target.key };
  }
  await updateLicense(target.key, {
    tier: DEFAULT_TIER,
    status: "active",
    downgradedAt: new Date().toISOString(),
    downgradeReason: parsed.type,
  });
  console.log(
    `[dodo] downgraded license ${target.key} to ${DEFAULT_TIER} (${parsed.type})`,
  );
  return { downgraded: target.key, tier: DEFAULT_TIER };
}

async function revokeLicenseFromDodo(parsed) {
  const target = await findLicenseByDodo({
    subscriptionId: parsed.subscriptionId,
    paymentId: parsed.paymentId,
  });
  if (!target) return { skipped: "license_not_found" };
  if (target.status === "revoked") return { already_revoked: target.key };
  await updateLicense(target.key, {
    status: "revoked",
    revokedAt: new Date().toISOString(),
  });
  console.log(`[dodo] revoked license ${target.key} (${parsed.type})`);
  return { revoked: target.key };
}

// Subscription renewed — extend the existing license's expiry rather than
// issuing a new one. Falls back to issueLicenseFromDodo (which will dedup)
// if no existing license is found (edge case: renewal before initial issue).
async function renewLicenseFromDodo(parsed) {
  const existing = await findLicenseByDodo({
    subscriptionId: parsed.subscriptionId,
    paymentId: parsed.paymentId,
  });
  if (!existing) return issueLicenseFromDodo(parsed);

  const patch = { lastValidatedAt: new Date().toISOString() };
  if (parsed.billingPeriod) {
    const d = new Date();
    if (parsed.billingPeriod === "monthly") d.setDate(d.getDate() + 35);
    else if (parsed.billingPeriod === "annual") d.setDate(d.getDate() + 370);
    patch.expiresAt = d.toISOString();
  }
  // Restore tier in case the license was previously downgraded.
  const tier = parsed.tier || existing.tier;
  if (tier !== existing.tier || existing.downgradedAt) {
    patch.tier = tier;
    patch.downgradedAt = null;
    patch.downgradeReason = null;
  }
  await updateLicense(existing.key, patch);
  console.log(
    `[dodo] renewed license ${existing.key}; new expiry=${patch.expiresAt || "unchanged"}`,
  );
  const promo = await recordPromoRedemption(parsed, existing.key);
  return { renewed: existing.key, ...(promo ? { promo } : {}) };
}

async function processDodoEvent(event) {
  const type = event?.type || "";
  const parsed = parseDodoEvent(event);
  if (DODO_RENEW_EVENTS.has(type)) return renewLicenseFromDodo(parsed);
  if (DODO_ISSUE_EVENTS.has(type)) return issueLicenseFromDodo(parsed);
  if (DODO_DOWNGRADE_EVENTS.has(type)) return downgradeLicenseFromDodo(parsed);
  if (DODO_REVOKE_EVENTS.has(type)) return revokeLicenseFromDodo(parsed);
  return { ignored: type };
}

async function handleDodoWebhook(req, res) {
  if (!isDodoConfigured()) {
    return res.status(503).json({ ok: false, error: "dodo_not_configured" });
  }
  const eventId = req.header("webhook-id");
  const verification = verifyDodoSignature({
    id: eventId,
    timestamp: req.header("webhook-timestamp"),
    signature: req.header("webhook-signature"),
    payload: req.body, // Buffer, from express.raw
  });
  if (!verification.ok) {
    console.warn("[dodo] signature rejected:", verification.error);
    return res.status(401).json({ ok: false, error: verification.error });
  }

  let event;
  try {
    const raw = Buffer.isBuffer(req.body)
      ? req.body.toString("utf8")
      : String(req.body || "");
    event = JSON.parse(raw);
  } catch {
    return res.status(400).json({ ok: false, error: "invalid_json" });
  }

  if (await wasDodoEventProcessed(eventId)) {
    return res.json({ ok: true, deduped: true });
  }

  try {
    const result = await processDodoEvent(event);
    await markDodoEventProcessed(eventId, { type: event?.type, ...result });
    return res.json({ ok: true, ...result });
  } catch (err) {
    // Leave the event unmarked so Dodo retries the delivery.
    console.error("[dodo] processing failed:", err);
    return res.status(500).json({ ok: false, error: "processing_error" });
  }
}

/* ---------------- Contact form ---------------- */

app.post("/api/contact", async (req, res) => {
  const ip = clientIp(req);
  if (rateLimited(`contact:${ip}`)) {
    return res.status(429).json({
      ok: false,
      error: "Too many requests. Please try again shortly.",
    });
  }

  const { name, email, company, plan, message, website } = req.body || {};
  // Honeypot: bots fill the hidden "website" field.
  if (website) return res.json({ ok: true });

  const emailOk =
    typeof email === "string" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
  if (!name || !emailOk || !message) {
    return res.status(400).json({
      ok: false,
      error: "Please provide your name, a valid email, and a message.",
    });
  }

  const payload = {
    name: String(name).slice(0, 200),
    email: String(email).slice(0, 200),
    company: company ? String(company).slice(0, 200) : "",
    plan: plan ? String(plan).slice(0, 80) : "",
    message: String(message).slice(0, 5000),
  };

  try {
    await persistSubmission(payload);
    await addRequest(payload).catch((err) =>
      console.error("[contact] failed to record access request:", err),
    );
    if (isMailConfigured()) {
      await notifyAdminOfRequest(payload);
      return res.json({ ok: true, delivered: true });
    }
    console.warn(
      "[contact] Mailgun not configured — submission persisted and recorded as a pending request.",
    );
    return res.json({ ok: true, delivered: false });
  } catch (err) {
    console.error("[contact] delivery failed:", err);
    return res.status(502).json({
      ok: false,
      error: "We couldn't send your message. Please email us directly.",
    });
  }
});

/* ---------------- License validation (desktop app) ---------------- */

app.options("/api/license/validate", (_req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.sendStatus(204);
});

app.post("/api/license/validate", async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  const ip = clientIp(req);
  if (rateLimited(`validate:${ip}`, 30, 60_000)) {
    return res.status(429).json({ valid: false, error: "rate_limited" });
  }
  const key = req.body?.key || "";
  if (!key) {
    return res.status(400).json({ valid: false, error: "missing_key" });
  }
  const license = await getLicenseByKey(key);
  if (!license || license.status !== "active") {
    return res.json({ valid: false });
  }

  // Auto-downgrade expired licenses to Free.
  if (
    license.expiresAt &&
    Date.parse(license.expiresAt) <= Date.now() &&
    license.tier !== DEFAULT_TIER
  ) {
    await updateLicense(license.key, {
      tier: DEFAULT_TIER,
      downgradedAt: new Date().toISOString(),
      downgradeReason: "validity_expired",
      lastValidatedAt: new Date().toISOString(),
    });
    console.log(
      `[license] auto-downgraded ${license.key} to ${DEFAULT_TIER} (validity expired)`,
    );
    return res.json({
      valid: true,
      tier: DEFAULT_TIER,
      email: license.email,
      entitlements: tierEntitlements(DEFAULT_TIER),
    });
  }

  updateLicense(license.key, {
    lastValidatedAt: new Date().toISOString(),
  }).catch(() => {});
  const tier = isValidTier(license.tier) ? license.tier : DEFAULT_TIER;
  return res.json({
    valid: true,
    tier,
    email: license.email,
    entitlements: tierEntitlements(tier),
  });
});

/* ---------------- Promo codes (public) ---------------- */

const PROMO_ERROR_MESSAGES = {
  PROMO_MISSING: "Enter a promo code.",
  PROMO_NOT_FOUND: "That promo code isn't valid.",
  PROMO_REVOKED: "That promo code is no longer active.",
  PROMO_EXPIRED: "That promo code has expired.",
  PROMO_TIER_NOT_ELIGIBLE: "That promo code doesn't apply to this plan.",
  PROMO_EMAIL_REQUIRED: "Enter your email to apply a promo code.",
  PROMO_ALREADY_REDEEMED:
    "This account has already used a promo code. Only one promo can be used per account.",
  PROMO_USAGE_EXCEEDED: "This promo code has reached its usage limit.",
  PROMO_NOT_CONFIGURED: "Promo codes are not available right now.",
  PROMO_INVALID_PLAN: "Choose a valid plan.",
  PROMO_CHECKOUT_FAILED: "We couldn't start checkout. Please try again.",
};

function promoError(error) {
  return {
    valid: false,
    error,
    message: PROMO_ERROR_MESSAGES[error] || "That promo code can't be used.",
  };
}

// Validate a promo code for a prospective purchase (no charge happens here).
app.post("/api/promo/validate", async (req, res) => {
  res.set("Cache-Control", "no-store");
  const ip = clientIp(req);
  if (rateLimited(`promo:${ip}`, 20, 60_000)) {
    return res.status(429).json(promoError("PROMO_MISSING"));
  }
  const code = normalizePromoCode(req.body?.code);
  const tier = isValidTier(req.body?.tier) ? req.body.tier : null;
  const email = normalizeEmail(req.body?.email);
  const result = await validatePromoForCheckout({
    code,
    tier,
    email,
    checkDodo: false,
  });
  if (!result.ok) return res.json(promoError(result.error));
  const p = result.promo;
  return res.json({
    valid: true,
    code: p.code,
    percentOff: p.percentOff,
    firstCycleOnly: p.firstCycleOnly,
    message:
      `${p.percentOff}% off` +
      (p.firstCycleOnly ? " your first billing cycle." : "."),
  });
});

// Create a one-time hosted-checkout session with the promo applied server-side.
app.post("/api/promo/checkout", async (req, res) => {
  res.set("Cache-Control", "no-store");
  const ip = clientIp(req);
  if (rateLimited(`promo:${ip}`, 20, 60_000)) {
    return res.status(429).json(promoError("PROMO_MISSING"));
  }
  if (!isDodoApiConfigured()) {
    return res.status(503).json(promoError("PROMO_NOT_CONFIGURED"));
  }
  const code = normalizePromoCode(req.body?.code);
  const tier = isValidTier(req.body?.tier) ? req.body.tier : null;
  const period = req.body?.period === "annual" ? "annual" : "monthly";
  const email = normalizeEmail(req.body?.email);
  if (!tier || tier === DEFAULT_TIER) {
    return res.status(400).json(promoError("PROMO_INVALID_PLAN"));
  }
  const productId = productIdForPlan(tier, period);
  if (!productId) {
    return res.status(400).json(promoError("PROMO_INVALID_PLAN"));
  }

  const result = await validatePromoForCheckout({
    code,
    tier,
    email,
    checkDodo: true,
  });
  if (!result.ok) return res.status(400).json(promoError(result.error));

  try {
    const session = await createDodoCheckoutSession({
      productId,
      code,
      email,
      returnUrl: `${SITE_URL}/download`,
    });
    const url = session?.checkout_url || session?.payment_link || null;
    if (!url) throw new Error("no_checkout_url");
    return res.json({
      valid: true,
      url,
      sessionId: session.session_id || null,
    });
  } catch (err) {
    console.error("[promo] checkout session failed:", err?.detail || err);
    return res.status(502).json(promoError("PROMO_CHECKOUT_FAILED"));
  }
});

/* ---------------- Admin panel ---------------- */

function currentAdmin(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifySession(cookies[SESSION_COOKIE]);
}

function setSessionCookie(res, value, maxAge) {
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(value)}; Max-Age=${Math.floor(maxAge / 1000)}; Path=/; HttpOnly; SameSite=Lax`,
  );
}

function requireAdmin(req, res, next) {
  if (currentAdmin(req)) return next();
  return res.redirect("/admin/login");
}

function sendHtml(res, body) {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.set("Cache-Control", "no-store");
  res.send(body);
}

app.get("/admin", requireAdmin, async (req, res) => {
  const [requests, licenses, promos, redemptions] = await Promise.all([
    listRequests(),
    listLicenses(),
    listPromos(),
    listPromoRedemptions(),
  ]);
  sendHtml(
    res,
    renderDashboard({
      requests,
      licenses,
      promos,
      redemptions,
      promoApiReady: isDodoApiConfigured(),
      promoError:
        typeof req.query.promo_error === "string" ? req.query.promo_error : "",
    }),
  );
});

app.get("/admin/login", (req, res) => {
  if (currentAdmin(req)) return res.redirect("/admin");
  if (!isAdminConfigured()) {
    return sendHtml(
      res,
      renderLogin({
        error:
          "Admin is not configured. Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH (or ADMIN_PASSWORD) env vars.",
      }),
    );
  }
  sendHtml(res, renderLogin({}));
});

app.post("/admin/login", (req, res) => {
  const ip = clientIp(req);
  if (rateLimited(`login:${ip}`, 8, 60_000)) {
    return sendHtml(
      res,
      renderLogin({ error: "Too many attempts. Try again shortly." }),
    );
  }
  const { email, password } = req.body || {};
  if (!verifyCredentials(email, password)) {
    return sendHtml(res, renderLogin({ error: "Invalid email or password." }));
  }
  const token = createSession(String(email).trim().toLowerCase());
  setSessionCookie(res, token, 1000 * 60 * 60 * 12);
  res.redirect("/admin");
});

app.post("/admin/logout", (_req, res) => {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
  res.redirect("/admin/login");
});

app.post("/admin/requests/:id/approve", requireAdmin, async (req, res) => {
  const tier = isValidTier(req.body.tier) ? req.body.tier : "pro";
  const requests = await listRequests();
  const request = requests.find((r) => r.id === req.params.id);
  if (!request) return res.redirect("/admin");
  const { license, delivered } = await issueLicense({
    email: request.email,
    name: request.name,
    tier,
    requestId: request.id,
    sendKey: true,
  });
  await updateRequest(request.id, {
    status: "approved",
    tier,
    licenseKey: license.key,
    decidedAt: new Date().toISOString(),
  });
  console.log(
    `[admin] approved ${request.email} as ${tier}; key emailed=${delivered}`,
  );
  res.redirect("/admin");
});

app.post("/admin/requests/:id/reject", requireAdmin, async (req, res) => {
  await updateRequest(req.params.id, {
    status: "rejected",
    decidedAt: new Date().toISOString(),
  });
  res.redirect("/admin");
});

app.post("/admin/licenses/create", requireAdmin, async (req, res) => {
  const { email, name } = req.body || {};
  const tier = isValidTier(req.body.tier) ? req.body.tier : "pro";
  const emailOk =
    typeof email === "string" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
  if (emailOk) {
    // Compute expiresAt from the validity dropdown (months).
    let expiresAt = null;
    const validityMonths = Number(req.body.validityMonths);
    if (Number.isFinite(validityMonths) && validityMonths > 0) {
      const d = new Date();
      d.setMonth(d.getMonth() + validityMonths);
      expiresAt = d.toISOString();
    }
    await issueLicense({
      email: String(email).trim(),
      name: name ? String(name).slice(0, 200) : "",
      tier,
      requestId: null,
      sendKey: req.body.email_key === "1",
      expiresAt,
    });
  }
  res.redirect("/admin");
});

app.post("/admin/licenses/:key/revoke", requireAdmin, async (req, res) => {
  await updateLicense(req.params.key, {
    status: "revoked",
    revokedAt: new Date().toISOString(),
  });
  res.redirect("/admin");
});

// Manually change a license's tier (for example, downgrade Pro → Free).
app.post("/admin/licenses/:key/downgrade", requireAdmin, async (req, res) => {
  const tier = isValidTier(req.body.tier) ? req.body.tier : DEFAULT_TIER;
  const license = await getLicenseByKey(req.params.key);
  if (license) {
    await updateLicense(license.key, {
      tier,
      status: "active",
      downgradedAt: new Date().toISOString(),
      downgradeReason: "admin",
    });
    console.log(`[admin] set license ${license.key} tier=${tier}`);
  }
  res.redirect("/admin");
});

// Set or update the validity (expiresAt) of an existing license.
app.post("/admin/licenses/:key/validity", requireAdmin, async (req, res) => {
  const license = await getLicenseByKey(req.params.key);
  if (license) {
    let expiresAt = null;
    const months = Number(req.body.validityMonths);
    if (Number.isFinite(months) && months > 0) {
      const d = new Date(license.createdAt || Date.now());
      d.setMonth(d.getMonth() + months);
      expiresAt = d.toISOString();
    }
    await updateLicense(license.key, { expiresAt });
    console.log(
      `[admin] set validity for ${license.key} → ${expiresAt || "lifetime"}`,
    );
  }
  res.redirect("/admin");
});

// Backfill: set correct expiresAt on Dodo subscription licenses that currently
// show "lifetime". Uses the product id stored on the license to determine the
// billing period (monthly → +35d, annual → +370d from creation date).
app.post(
  "/admin/licenses/backfill-validity",
  requireAdmin,
  async (req, res) => {
    const licenses = await listLicenses();
    let fixed = 0;
    for (const l of licenses) {
      if (l.source !== "dodo" || l.expiresAt || !l.dodo?.subscriptionId)
        continue;
      const pid = l.dodo.productId;
      const period = pid ? billingPeriodForProduct(pid) : null;
      if (!period) continue;
      const d = new Date(l.createdAt || Date.now());
      if (period === "monthly") d.setDate(d.getDate() + 35);
      else if (period === "annual") d.setDate(d.getDate() + 370);
      await updateLicense(l.key, { expiresAt: d.toISOString() });
      console.log(
        `[backfill] set ${l.key} expiresAt=${d.toISOString()} (${period})`,
      );
      fixed++;
    }
    console.log(`[backfill] fixed ${fixed} license(s)`);
    res.redirect("/admin");
  },
);

/* ---------------- Promo management (admin) ---------------- */

function adminWantsJson(req) {
  return (req.headers.accept || "").includes("application/json");
}

app.post("/admin/promos/create", requireAdmin, async (req, res) => {
  const fail = (status, error) => {
    if (adminWantsJson(req))
      return res.status(status).json({ ok: false, error });
    return res.redirect(`/admin?promo_error=${encodeURIComponent(error)}`);
  };

  const code = normalizePromoCode(req.body.code);
  if (!code || !/^[A-Z0-9_-]{3,40}$/.test(code)) {
    return fail(400, "invalid_code");
  }
  const percent = Number(req.body.percent);
  if (!Number.isFinite(percent) || percent <= 0 || percent > 100) {
    return fail(400, "invalid_percent");
  }
  const amountBp = Math.round(percent * 100);

  // Optional restrictions.
  const tiers = []
    .concat(req.body.tiers || [])
    .filter((t) => t === "pro");
  const usageLimit =
    req.body.usageLimit !== "" && req.body.usageLimit != null
      ? Math.max(1, Math.floor(Number(req.body.usageLimit)))
      : null;
  const rawCycles = req.body.validityCycles;
  const subscriptionCycles =
    rawCycles !== "" && rawCycles != null
      ? Math.max(1, Math.floor(Number(rawCycles)))
      : null;
  const firstCycleOnly = subscriptionCycles === 1;
  let expiresAt = null;
  if (req.body.expiresAt) {
    const t = Date.parse(req.body.expiresAt);
    if (Number.isFinite(t)) expiresAt = new Date(t).toISOString();
  }

  if (!isDodoApiConfigured()) {
    return fail(503, "dodo_not_configured");
  }

  const existing = await findPromoByCode(code);
  if (existing && existing.status === "active") {
    return fail(409, "code_exists");
  }

  const restrictedProductIds = restrictedProductIdsForTiers(tiers);

  try {
    const discount = await createDodoDiscount({
      code,
      name: req.body.name ? String(req.body.name).slice(0, 80) : code,
      amountBp,
      expiresAt,
      usageLimit,
      subscriptionCycles,
      restrictedProductIds,
    });
    const promo = await addPromo({
      code,
      name: req.body.name ? String(req.body.name).slice(0, 80) : code,
      amountBp,
      firstCycleOnly,
      subscriptionCycles,
      usageLimit,
      expiresAt,
      restrictedTiers: tiers,
      restrictedProductIds,
      dodoDiscountId: discount?.discount_id || discount?.id || null,
      createdBy: currentAdmin(req)?.email || "admin",
    });
    console.log(`[admin] created promo ${code} (${percent}% off)`);
    if (adminWantsJson(req)) return res.json({ ok: true, promo });
    return res.redirect("/admin");
  } catch (err) {
    console.error("[admin] promo create failed:", err?.detail || err);
    return fail(502, "dodo_create_failed");
  }
});

app.post("/admin/promos/:code/revoke", requireAdmin, async (req, res) => {
  const code = normalizePromoCode(req.params.code);
  const promo = await findPromoByCode(code);
  if (promo) {
    if (promo.dodoDiscountId && isDodoApiConfigured()) {
      try {
        await deleteDodoDiscount(promo.dodoDiscountId);
      } catch (err) {
        console.error(
          "[admin] dodo discount delete failed:",
          err?.detail || err,
        );
      }
    }
    await updatePromo(code, {
      status: "revoked",
      revokedAt: new Date().toISOString(),
    });
    console.log(`[admin] revoked promo ${code}`);
  }
  if (adminWantsJson(req)) return res.json({ ok: true });
  res.redirect("/admin");
});

// Backfill promo redemption for a license by looking up the Dodo payment.
// Accepts an optional ?paymentId= query/body param for licenses created before
// the dodo.paymentId field was stored.
app.post(
  "/admin/licenses/:key/backfill-promo",
  requireAdmin,
  async (req, res) => {
    const license = await getLicenseByKey(req.params.key);
    if (!license) {
      if (adminWantsJson(req))
        return res.status(404).json({ ok: false, error: "license_not_found" });
      return res.redirect("/admin");
    }
    const paymentId = req.body?.paymentId || license?.dodo?.paymentId || null;
    if (!paymentId) {
      if (adminWantsJson(req))
        return res.status(400).json({ ok: false, error: "no_dodo_payment" });
      return res.redirect("/admin");
    }
    const payment = await getDodoPayment(paymentId);
    if (!payment) {
      if (adminWantsJson(req)) {
        return res.status(502).json({ ok: false, error: "dodo_lookup_failed" });
      }
      return res.redirect("/admin");
    }
    // Enrich the license with dodo metadata if missing.
    if (!license.dodo?.paymentId) {
      await updateLicense(license.key, {
        dodo: {
          ...license.dodo,
          paymentId: payment.payment_id || paymentId,
          subscriptionId:
            payment.subscription_id || license.dodo?.subscriptionId || null,
          customerId:
            payment.customer?.customer_id || license.dodo?.customerId || null,
          productId:
            payment.product_cart?.[0]?.product_id ||
            license.dodo?.productId ||
            null,
        },
      });
    }
    const discountCodes = [];
    const discountIds = [];
    if (payment.discount_id) discountIds.push(payment.discount_id);
    if (Array.isArray(payment.discounts)) {
      for (const d of payment.discounts) {
        if (d?.code) discountCodes.push(d.code);
        if (d?.discount_id) discountIds.push(d.discount_id);
      }
    }
    const parsed = {
      discountCodes,
      discountIds,
      paymentId,
      email: license.email,
      customerId:
        payment.customer?.customer_id || license.dodo?.customerId || null,
      subscriptionId:
        payment.subscription_id || license.dodo?.subscriptionId || null,
    };
    const promo = await matchRedeemedPromo(parsed);
    if (promo) {
      await addPromoRedemption({
        code: promo.code,
        email: license.email,
        customerId: parsed.customerId,
        subscriptionId: parsed.subscriptionId,
        paymentId,
        licenseKey: license.key,
        flagged: false,
        flagReason: null,
      });
      console.log(
        `[admin] backfilled promo ${promo.code} for license ${license.key}`,
      );
    }
    if (adminWantsJson(req))
      return res.json({ ok: true, promo: promo?.code || null });
    res.redirect("/admin");
  },
);

// Public checkout config for the front-end "Buy" buttons (no secrets).
app.get("/api/dodo/config", (_req, res) => {
  res.set("Cache-Control", "public, max-age=300");
  res.json(dodoPublicConfig());
});

app.get("/healthz", (_req, res) => res.json({ ok: true }));
app.get("/upgrade", (_req, res) => res.redirect(302, "/#pricing"));

// The guides hub lives at public/guides.html, but the per-guide articles live
// in public/guides/. Without this, express.static sees the directory and
// redirects /guides -> /guides/ (which 404s). Serve the hub explicitly.
app.get("/guides", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "guides.html"));
});

// Renamed guide slug -> keep the old URL alive for existing links / crawlers.
app.get("/guides/best-proxy-for-multiple-accounts", (_req, res) => {
  res.redirect(301, "/guides/residential-vs-datacenter-vs-mobile-proxies");
});

app.use(
  express.static(path.join(__dirname, "public"), {
    extensions: ["html"],
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".webmanifest")) {
        res.setHeader("Content-Type", "application/manifest+json");
      }
      if (/\.(?:css|js|png|svg|ico|woff2?)$/.test(filePath)) {
        res.setHeader("Cache-Control", "public, max-age=86400");
      }
      if (/\.(?:txt|xml|webmanifest)$/.test(filePath)) {
        res.setHeader("Cache-Control", "public, max-age=3600");
      }
      if (/\.(?:exe|zip|deb|rpm|AppImage|dmg|msi)$/.test(filePath)) {
        res.setHeader("Cache-Control", "public, max-age=3600");
      }
    },
  }),
);

// Custom 404 — return a real 404 status with a branded page (no soft-404s).
app.use((req, res) => {
  res.status(404);
  if (req.accepts("html")) {
    res.set("Content-Type", "text/html; charset=utf-8");
    return res.sendFile(path.join(__dirname, "public", "404.html"));
  }
  res.type("txt").send("404 Not Found");
});

app.listen(PORT, () => {
  console.log(`Dustonic website running on http://localhost:${PORT}`);
  console.log(
    `  admin configured: ${isAdminConfigured()} · mail configured: ${isMailConfigured()}`,
  );
});
