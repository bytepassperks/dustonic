// Single source of truth for Dustonic desktop entitlements.
// Keep these camelCase fields aligned with src-tauri/src/license.rs.
export const TIERS = {
  free: {
    id: "free",
    name: "Free",
    safeCleaning: true,
    manualClean: true,
    proRules: false,
    scheduledClean: false,
    autoClean: false,
    duplicateFinder: false,
    largeFileFinder: false,
  },
  pro: {
    id: "pro",
    name: "Pro",
    safeCleaning: true,
    manualClean: true,
    proRules: true,
    scheduledClean: true,
    autoClean: true,
    duplicateFinder: true,
    largeFileFinder: true,
  },
};

export const DEFAULT_TIER = "free";
export function isValidTier(tier) {
  return Object.prototype.hasOwnProperty.call(TIERS, tier);
}
export function tierEntitlements(tier) {
  return TIERS[isValidTier(tier) ? tier : DEFAULT_TIER];
}
export function planToTier(plan) {
  return String(plan || "").toLowerCase().includes("pro") ? "pro" : "free";
}
