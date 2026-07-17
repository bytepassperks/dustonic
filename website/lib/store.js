// Tiny append-friendly JSON store for access requests and issued licenses.
// Persisted under DATA_DIR (a Render persistent disk in production) so that
// approvals and license keys survive redeploys. All read-modify-write
// operations are serialized through a single promise chain to avoid races.

import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const REQUESTS_FILE = "requests.json";
const LICENSES_FILE = "licenses.json";
const DODO_EVENTS_FILE = "dodo-events.json";
const PROMOS_FILE = "promos.json";
const PROMO_REDEMPTIONS_FILE = "promo-redemptions.json";

let chain = Promise.resolve();
function withLock(fn) {
  const run = chain.then(fn, fn);
  chain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

async function readJson(file, fallback) {
  try {
    const raw = await readFile(path.join(DATA_DIR, file), "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === "ENOENT") return fallback;
    throw err;
  }
}

async function writeJson(file, data) {
  await mkdir(DATA_DIR, { recursive: true });
  const tmp = path.join(DATA_DIR, `${file}.${process.pid}.tmp`);
  await writeFile(tmp, JSON.stringify(data, null, 2));
  await rename(tmp, path.join(DATA_DIR, file));
}

const LICENSE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I, O, 0, 1
export function generateLicenseKey() {
  const bytes = crypto.randomBytes(20);
  let body = "";
  for (let i = 0; i < 20; i++) {
    body += LICENSE_ALPHABET[bytes[i] % LICENSE_ALPHABET.length];
    if (i % 5 === 4 && i !== 19) body += "-";
  }
  return `DUST-${body}`;
}

export function normalizeKey(key) {
  return String(key || "")
    .trim()
    .toUpperCase();
}

export function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

export function normalizePromoCode(code) {
  return String(code || "")
    .trim()
    .toUpperCase();
}

/* ---------------- Requests ---------------- */

export async function addRequest(input) {
  return withLock(async () => {
    const requests = await readJson(REQUESTS_FILE, []);
    const record = {
      id: crypto.randomUUID(),
      name: input.name,
      email: input.email,
      company: input.company || "",
      plan: input.plan || "",
      message: input.message || "",
      status: "pending",
      createdAt: new Date().toISOString(),
      decidedAt: null,
      tier: null,
      licenseKey: null,
    };
    requests.unshift(record);
    await writeJson(REQUESTS_FILE, requests);
    return record;
  });
}

export async function listRequests() {
  return withLock(() => readJson(REQUESTS_FILE, []));
}

export async function updateRequest(id, patch) {
  return withLock(async () => {
    const requests = await readJson(REQUESTS_FILE, []);
    const idx = requests.findIndex((r) => r.id === id);
    if (idx === -1) return null;
    requests[idx] = { ...requests[idx], ...patch };
    await writeJson(REQUESTS_FILE, requests);
    return requests[idx];
  });
}

/* ---------------- Licenses ---------------- */

export async function addLicense(input) {
  return withLock(async () => {
    const licenses = await readJson(LICENSES_FILE, []);
    const record = {
      key: input.key || generateLicenseKey(),
      tier: input.tier,
      email: input.email,
      name: input.name || "",
      status: "active",
      requestId: input.requestId || null,
      source: input.source || "manual",
      dodo: input.dodo || null,
      expiresAt: input.expiresAt || null,
      emailDelivered: input.emailDelivered ?? null,
      createdAt: new Date().toISOString(),
      revokedAt: null,
      lastValidatedAt: null,
    };
    licenses.unshift(record);
    await writeJson(LICENSES_FILE, licenses);
    return record;
  });
}

export async function listLicenses() {
  return withLock(() => readJson(LICENSES_FILE, []));
}

export async function getLicenseByKey(key) {
  const normalized = normalizeKey(key);
  const licenses = await withLock(() => readJson(LICENSES_FILE, []));
  return licenses.find((l) => normalizeKey(l.key) === normalized) || null;
}

export async function updateLicense(key, patch) {
  const normalized = normalizeKey(key);
  return withLock(async () => {
    const licenses = await readJson(LICENSES_FILE, []);
    const idx = licenses.findIndex((l) => normalizeKey(l.key) === normalized);
    if (idx === -1) return null;
    licenses[idx] = { ...licenses[idx], ...patch };
    await writeJson(LICENSES_FILE, licenses);
    return licenses[idx];
  });
}

// Find a license previously issued for a given Dodo subscription or payment so
// webhook handlers can dedupe issuance and target revocations.
export async function findLicenseByDodo({ subscriptionId, paymentId } = {}) {
  if (!subscriptionId && !paymentId) return null;
  const licenses = await withLock(() => readJson(LICENSES_FILE, []));
  return (
    licenses.find(
      (l) =>
        l.dodo &&
        ((subscriptionId && l.dodo.subscriptionId === subscriptionId) ||
          (paymentId && l.dodo.paymentId === paymentId)),
    ) || null
  );
}

/* ---------------- Dodo webhook idempotency ---------------- */

export async function wasDodoEventProcessed(id) {
  if (!id) return false;
  const events = await withLock(() => readJson(DODO_EVENTS_FILE, {}));
  return Boolean(events[id]);
}

// Records a webhook event id as processed. Returns false if it was already
// present (so callers can treat the delivery as a replay).
export async function markDodoEventProcessed(id, meta = {}) {
  if (!id) return false;
  return withLock(async () => {
    const events = await readJson(DODO_EVENTS_FILE, {});
    if (events[id]) return false;
    events[id] = { ...meta, at: new Date().toISOString() };
    await writeJson(DODO_EVENTS_FILE, events);
    return true;
  });
}

/* ---------------- Promotions ---------------- */
// A promo mirrors a Dodo discount (the real % off lives in Dodo, since Dodo is
// the merchant of record). Dodo enforces the global usage cap and the
// first-billing-cycle limit; our redemption ledger is the enforcement layer for
// the things Dodo does NOT track: one promo per account, and first-time-only.

export async function addPromo(input) {
  return withLock(async () => {
    const promos = await readJson(PROMOS_FILE, []);
    const code = normalizePromoCode(input.code);
    const record = {
      code,
      name: input.name || code,
      amountBp: input.amountBp,
      percentOff: Math.round((input.amountBp || 0) / 100),
      firstCycleOnly: Boolean(input.firstCycleOnly),
      subscriptionCycles: input.subscriptionCycles ?? null,
      usageLimit: input.usageLimit ?? null,
      expiresAt: input.expiresAt || null,
      restrictedTiers: Array.isArray(input.restrictedTiers)
        ? input.restrictedTiers
        : [],
      restrictedProductIds: Array.isArray(input.restrictedProductIds)
        ? input.restrictedProductIds
        : [],
      dodoDiscountId: input.dodoDiscountId || null,
      status: "active",
      createdAt: new Date().toISOString(),
      revokedAt: null,
      createdBy: input.createdBy || "admin",
    };
    const idx = promos.findIndex((p) => normalizePromoCode(p.code) === code);
    if (idx !== -1) promos.splice(idx, 1);
    promos.unshift(record);
    await writeJson(PROMOS_FILE, promos);
    return record;
  });
}

export async function listPromos() {
  return withLock(() => readJson(PROMOS_FILE, []));
}

export async function findPromoByCode(code) {
  const normalized = normalizePromoCode(code);
  if (!normalized) return null;
  const promos = await withLock(() => readJson(PROMOS_FILE, []));
  return promos.find((p) => normalizePromoCode(p.code) === normalized) || null;
}

export async function updatePromo(code, patch) {
  const normalized = normalizePromoCode(code);
  return withLock(async () => {
    const promos = await readJson(PROMOS_FILE, []);
    const idx = promos.findIndex(
      (p) => normalizePromoCode(p.code) === normalized,
    );
    if (idx === -1) return null;
    promos[idx] = { ...promos[idx], ...patch };
    await writeJson(PROMOS_FILE, promos);
    return promos[idx];
  });
}

// Append a redemption to the ledger. Deduped per (subscriptionId|paymentId, code)
// so webhook replays don't double-count. `flagged` marks a redemption that
// violated our one-per-account rule (recorded for the admin to act on).
export async function addPromoRedemption(input) {
  return withLock(async () => {
    const ledger = await readJson(PROMO_REDEMPTIONS_FILE, []);
    const code = normalizePromoCode(input.code);
    const subscriptionId = input.subscriptionId || null;
    const paymentId = input.paymentId || null;
    const dupe = ledger.find(
      (r) =>
        normalizePromoCode(r.code) === code &&
        ((subscriptionId && r.subscriptionId === subscriptionId) ||
          (paymentId && r.paymentId === paymentId)),
    );
    if (dupe) return { deduped: true, redemption: dupe };
    const record = {
      id: crypto.randomUUID(),
      code,
      email: normalizeEmail(input.email),
      customerId: input.customerId || null,
      subscriptionId,
      paymentId,
      licenseKey: input.licenseKey || null,
      flagged: Boolean(input.flagged),
      flagReason: input.flagReason || null,
      redeemedAt: new Date().toISOString(),
    };
    ledger.unshift(record);
    await writeJson(PROMO_REDEMPTIONS_FILE, ledger);
    return { deduped: false, redemption: record };
  });
}

export async function listPromoRedemptions() {
  return withLock(() => readJson(PROMO_REDEMPTIONS_FILE, []));
}

// Count of valid (non-flagged) redemptions for a code — used for display only;
// the authoritative global cap is enforced by Dodo's usage_limit.
export async function countPromoRedemptions(code) {
  const normalized = normalizePromoCode(code);
  const ledger = await withLock(() => readJson(PROMO_REDEMPTIONS_FILE, []));
  return ledger.filter(
    (r) => normalizePromoCode(r.code) === normalized && !r.flagged,
  ).length;
}

// Has this account (matched by email OR Dodo customer id) ever validly redeemed
// ANY promo? This is the "one promo per account / first-time-only" gate.
export async function hasAccountRedeemedAnyPromo({ email, customerId } = {}) {
  const e = normalizeEmail(email);
  const ledger = await withLock(() => readJson(PROMO_REDEMPTIONS_FILE, []));
  return ledger.some(
    (r) =>
      !r.flagged &&
      ((e && normalizeEmail(r.email) === e) ||
        (customerId && r.customerId === customerId)),
  );
}
