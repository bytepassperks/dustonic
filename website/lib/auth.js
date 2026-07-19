// Admin authentication: scrypt password verification + a stateless,
// HMAC-signed session cookie. No external dependencies (Node crypto only).

import crypto from "node:crypto";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "dev-insecure-session-secret-change-me";
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours
export const SESSION_COOKIE = "dustonic_admin";

const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ""; // plaintext fallback

export function isAdminConfigured() {
  return Boolean(ADMIN_EMAIL && (ADMIN_PASSWORD_HASH || ADMIN_PASSWORD));
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function verifyHash(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  let actual;
  try {
    actual = crypto.scryptSync(password, salt, expected.length);
  } catch {
    return false;
  }
  return (
    actual.length === expected.length &&
    crypto.timingSafeEqual(actual, expected)
  );
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function verifyCredentials(email, password) {
  if (!isAdminConfigured()) return false;
  const emailOk = safeEqual(
    String(email || "")
      .trim()
      .toLowerCase(),
    ADMIN_EMAIL,
  );
  let passwordOk = false;
  if (ADMIN_PASSWORD_HASH)
    passwordOk = verifyHash(password, ADMIN_PASSWORD_HASH);
  else if (ADMIN_PASSWORD) passwordOk = safeEqual(password, ADMIN_PASSWORD);
  // Always evaluate both to keep timing roughly constant.
  return emailOk && passwordOk;
}

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

export function createSession(email) {
  const payload = Buffer.from(
    JSON.stringify({ email, exp: Date.now() + SESSION_TTL_MS }),
  ).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

export function verifySession(token) {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = sign(payload);
  if (!safeEqual(sig, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export { SESSION_TTL_MS };
