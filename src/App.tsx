import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Activity,
  ArrowLeft,
  Check,
  CheckCircle2,
  ChevronRight,
  HardDrive,
  LoaderCircle,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import productConfig from "../config/product.json";

type Risk = "Safe" | "Caution";
type Rule = {
  id: string;
  category: string;
  name: string;
  description: string;
  risk: Risk;
  platforms: string[];
  paths: string[];
  target: "Files" | "Directories" | "Contents" | "Action";
  default_enabled: boolean;
  pro_only: boolean;
};
type Category = { name: string; rules: Rule[] };
type Catalog = { platform: string; categories: Category[] };
type RuleScan = {
  rule_id: string;
  category: string;
  name: string;
  description: string;
  risk: Risk;
  pro_only: boolean;
  items: number;
  bytes: number;
  samples: string[];
  skipped: number;
};
type ScanReport = { rules: RuleScan[]; total_items: number; total_bytes: number; skipped: number };
type CleanReport = {
  bytes_freed: number;
  items: number;
  skipped: number;
  quarantine_id: string | null;
};
type SystemStats = {
  disk_free: number;
  disk_total: number;
  memory_used: number;
  memory_total: number;
};
type Entitlements = {
  id: string;
  name: string;
  safeCleaning: boolean;
  manualClean: boolean;
  proRules: boolean;
  scheduledClean: boolean;
  autoClean: boolean;
  duplicateFinder: boolean;
  largeFileFinder: boolean;
};
type LicenseStatus = {
  activated: boolean;
  tier: string;
  name: string;
  keyMasked: string | null;
  email: string | null;
  entitlements: Entitlements;
};

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = -1;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
};

const percent = (used: number, total: number) => (total ? Math.round((used / total) * 100) : 0);

const displayError = (reason: unknown) => {
  const raw = String(reason);
  try {
    const payload = JSON.parse(raw) as { code?: string };
    if (payload.code === "PRO_REQUIRED") return "Dustonic Pro is required for this cleaning rule.";
    if (payload.code === "LICENSE_INVALID") return "That license key is not valid.";
    if (payload.code === "LICENSE_KEY_REQUIRED") return "Enter a license key to continue.";
    if (payload.code === "LICENSE_VALIDATION_FAILED") {
      return "License validation is unavailable right now. Please try again.";
    }
  } catch {
    // Backend errors that are not structured are shown as-is for diagnostics.
  }
  return raw;
};

export default function App() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [cleaned, setCleaned] = useState<CleanReport | null>(null);
  const [busy, setBusy] = useState<"loading" | "scanning" | "cleaning" | "restoring" | null>(
    "loading",
  );
  const [error, setError] = useState<string | null>(null);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [view, setView] = useState<"dashboard" | "license">("dashboard");
  const [licenseKey, setLicenseKey] = useState("");

  useEffect(() => {
    Promise.all([
      invoke<Catalog>("get_rule_catalog"),
      invoke<SystemStats>("get_system_stats"),
      invoke<LicenseStatus>("get_license_status"),
    ])
      .then(([nextCatalog, nextStats, nextLicense]) => {
        setCatalog(nextCatalog);
        setStats(nextStats);
        setLicense(nextLicense);
        setSelected(
          nextCatalog.categories.flatMap((category) =>
            category.rules.filter((rule) => rule.default_enabled).map((rule) => rule.id),
          ),
        );
      })
      .catch((reason) => setError(displayError(reason)))
      .finally(() => setBusy(null));
  }, []);

  const allRules = useMemo(
    () => catalog?.categories.flatMap((category) => category.rules) ?? [],
    [catalog],
  );
  const selectedCount = selected.length;

  const toggleRule = (id: string) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((value) => value !== id) : [...current, id],
    );
  };

  const scan = async () => {
    setError(null);
    setCleaned(null);
    setBusy("scanning");
    try {
      setReport(await invoke<ScanReport>("scan_rules", { ruleIds: selected }));
    } catch (reason) {
      setError(displayError(reason));
    } finally {
      setBusy(null);
    }
  };

  const clean = async () => {
    if (!report || selected.length === 0) return;
    setError(null);
    setBusy("cleaning");
    try {
      setCleaned(await invoke<CleanReport>("clean_rules", { ruleIds: selected, permanent: false }));
      setReport(null);
      setStats(await invoke<SystemStats>("get_system_stats"));
    } catch (reason) {
      setError(displayError(reason));
    } finally {
      setBusy(null);
    }
  };

  const restore = async () => {
    setError(null);
    setBusy("restoring");
    try {
      const restored = await invoke<CleanReport>("restore_last_quarantine");
      setCleaned(restored);
      setStats(await invoke<SystemStats>("get_system_stats"));
    } catch (reason) {
      setError(displayError(reason));
    } finally {
      setBusy(null);
    }
  };

  const activate = async () => {
    setError(null);
    setBusy("loading");
    try {
      const nextLicense = await invoke<LicenseStatus>("activate_license", { key: licenseKey });
      setLicense(nextLicense);
      setLicenseKey("");
      setView("dashboard");
    } catch (reason) {
      setError(displayError(reason));
    } finally {
      setBusy(null);
    }
  };

  const deactivate = async () => {
    setError(null);
    setBusy("loading");
    try {
      setLicense(await invoke<LicenseStatus>("deactivate_license"));
    } catch (reason) {
      setError(displayError(reason));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="min-h-screen overflow-hidden bg-ink text-slate-100">
      <div className="pointer-events-none absolute -left-40 -top-40 h-96 w-96 rounded-full bg-teal/10 blur-3xl" />
      <div className="pointer-events-none absolute -right-40 top-1/3 h-[32rem] w-[32rem] rounded-full bg-blue/10 blur-3xl" />
      <div className="relative mx-auto flex min-h-screen max-w-6xl flex-col px-6 py-7 lg:px-10">
        <header className="flex flex-wrap items-center justify-between gap-5 border-b border-white/[0.07] pb-6">
          <div className="flex items-center gap-3">
            <img src="/logo.png" alt="Dustonic" className="h-10 w-10 rounded-xl shadow-glow" />
            <div>
              <p className="text-lg font-semibold tracking-tight">Dustonic</p>
              <p className="text-xs text-slate-500">PC care, made simple</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs text-slate-400">
            {stats && (
              <>
                <span className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">
                  Disk {formatBytes(stats.disk_free)} free
                </span>
                <span className="hidden rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 sm:inline">
                  Memory {percent(stats.memory_used, stats.memory_total)}% used
                </span>
              </>
            )}
            <button
              type="button"
              onClick={() => setView("license")}
              className="rounded-full border border-teal/20 bg-teal/10 px-3 py-1.5 text-teal transition hover:bg-teal/20"
            >
              {license?.entitlements.proRules ? "Dustonic Pro" : "Go Pro"}
            </button>
            <span className="flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-teal shadow-[0_0_10px_#12B5A5]" />
              Protected
            </span>
          </div>
        </header>

        <section className="flex-1 py-12">
          {view === "license" ? (
            <LicenseScreen
              license={license}
              licenseKey={licenseKey}
              setLicenseKey={setLicenseKey}
              busy={busy === "loading"}
              error={error}
              onActivate={activate}
              onDeactivate={deactivate}
              onClose={() => setView("dashboard")}
            />
          ) : cleaned ? (
            <ResultScreen report={cleaned} onRestore={restore} restoring={busy === "restoring"} />
          ) : (
            <>
              <div className="flex flex-col justify-between gap-7 lg:flex-row lg:items-end">
                <div>
                  <p className="mb-4 flex items-center gap-2 text-sm font-medium text-teal">
                    <ShieldCheck size={17} /> {catalog?.platform ?? "System"} protection
                  </p>
                  <h1 className="text-4xl font-semibold leading-tight tracking-[-0.04em] sm:text-5xl">
                    {report ? "Review your cleanup" : "A cleaner PC starts here."}
                  </h1>
                  <p className="mt-4 max-w-xl text-base leading-7 text-slate-400">
                    {report
                      ? "Choose which categories to include, then clean safely with one-click undo."
                      : "Find digital clutter, reclaim space, and keep your system feeling fresh."}
                  </p>
                </div>
                <div className="flex gap-3">
                  {report && (
                    <button
                      type="button"
                      onClick={() => setReport(null)}
                      className="button-secondary"
                    >
                      <ArrowLeft size={17} /> Change scan
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={report ? clean : scan}
                    disabled={busy !== null || selectedCount === 0}
                    className="button-primary"
                  >
                    {busy === "scanning" || busy === "cleaning" ? (
                      <LoaderCircle className="animate-spin" size={18} />
                    ) : report ? (
                      <Trash2 size={18} />
                    ) : (
                      <ScanSearch size={18} />
                    )}
                    {busy === "scanning"
                      ? "Scanning…"
                      : busy === "cleaning"
                        ? "Cleaning…"
                        : report
                          ? "Clean selected"
                          : "Scan my PC"}
                  </button>
                </div>
              </div>

              {error && (
                <div className="mt-7 rounded-xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-200">
                  {error}
                </div>
              )}

              <div className="mt-10 grid gap-4 sm:grid-cols-3">
                <SummaryCard
                  icon={<HardDrive size={18} />}
                  label="Reclaimable"
                  value={formatBytes(report?.total_bytes ?? 0)}
                />
                <SummaryCard
                  icon={<Activity size={18} />}
                  label="Items found"
                  value={(report?.total_items ?? 0).toLocaleString()}
                />
                <SummaryCard
                  icon={<CheckCircle2 size={18} />}
                  label="Selected rules"
                  value={`${selectedCount} / ${allRules.length}`}
                />
              </div>

              <div className="mt-8 grid gap-8 lg:grid-cols-[1fr_280px]">
                <div className="space-y-7">
                  {report ? (
                    <ScanResults report={report} selected={selected} onToggle={toggleRule} />
                  ) : (
                    <RulePicker
                      catalog={catalog}
                      selected={selected}
                      onToggle={toggleRule}
                      isPro={license?.entitlements.proRules ?? false}
                      onUpgrade={() => setView("license")}
                    />
                  )}
                </div>
                <aside className="h-fit rounded-2xl border border-white/[0.08] bg-panel/80 p-5">
                  <p className="text-sm font-medium text-slate-200">Safe by design</p>
                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    Dustonic previews every item before cleanup and moves files to a private
                    quarantine instead of deleting them.
                  </p>
                  <div className="mt-5 flex items-center gap-2 text-xs text-teal">
                    <ShieldCheck size={15} /> Protected system paths
                  </div>
                </aside>
              </div>
            </>
          )}
        </section>

        <footer className="flex flex-col gap-2 border-t border-white/[0.07] pt-5 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <span>Dustonic 0.1.0 · Built for a cleaner tomorrow</span>
          <span>Lightweight. Private. Yours.</span>
        </footer>
      </div>
    </main>
  );
}

function SummaryCard({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-white/[0.08] bg-panel/80 p-5">
      <div className="flex items-center gap-2 text-teal">
        {icon}
        <span className="text-xs text-slate-500">{label}</span>
      </div>
      <p className="mt-3 text-2xl font-semibold tracking-tight">{value}</p>
    </div>
  );
}

function RulePicker({
  catalog,
  selected,
  onToggle,
  isPro,
  onUpgrade,
}: {
  catalog: Catalog | null;
  selected: string[];
  onToggle: (id: string) => void;
  isPro: boolean;
  onUpgrade: () => void;
}) {
  if (!catalog) {
    return (
      <div className="rounded-2xl border border-white/[0.08] bg-panel/80 p-8 text-sm text-slate-500">
        Loading cleaning rules…
      </div>
    );
  }
  return (
    <div className="space-y-5">
      {catalog.categories.map((category) => (
        <div key={category.name} className="rounded-2xl border border-white/[0.08] bg-panel/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">{category.name}</h2>
            <span className="text-xs text-slate-600">{category.rules.length} rules</span>
          </div>
          <div className="divide-y divide-white/[0.06]">
            {category.rules.map((rule) => (
              <RuleRow
                key={rule.id}
                rule={rule}
                checked={selected.includes(rule.id)}
                disabled={rule.pro_only && !isPro}
                onToggle={() => (rule.pro_only && !isPro ? onUpgrade() : onToggle(rule.id))}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ScanResults({
  report,
  selected,
  onToggle,
}: {
  report: ScanReport;
  selected: string[];
  onToggle: (id: string) => void;
}) {
  const grouped = report.rules.reduce<Record<string, RuleScan[]>>((groups, rule) => {
    if (!groups[rule.category]) {
      groups[rule.category] = [];
    }
    groups[rule.category].push(rule);
    return groups;
  }, {});
  return (
    <div className="space-y-5">
      {Object.entries(grouped).map(([category, rules]) => (
        <div key={category} className="rounded-2xl border border-white/[0.08] bg-panel/80 p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-200">{category}</h2>
          <div className="divide-y divide-white/[0.06]">
            {rules.map((rule) => (
              <div key={rule.rule_id} className="flex items-center gap-4 py-4 first:pt-0 last:pb-0">
                <input
                  type="checkbox"
                  checked={selected.includes(rule.rule_id)}
                  onChange={() => onToggle(rule.rule_id)}
                  className="checkbox"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium text-slate-200">{rule.name}</p>
                    <RiskBadge risk={rule.risk} />
                  </div>
                  <p className="mt-1 text-xs text-slate-500">{rule.description}</p>
                </div>
                <div className="text-right">
                  <p className="text-sm font-medium text-slate-200">{formatBytes(rule.bytes)}</p>
                  <p className="text-xs text-slate-600">{rule.items.toLocaleString()} items</p>
                </div>
                <ChevronRight className="hidden text-slate-700 sm:block" size={16} />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function RuleRow({
  rule,
  checked,
  disabled,
  onToggle,
}: {
  rule: Rule;
  checked: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  return (
    <label
      className={`flex items-center gap-4 py-4 first:pt-0 last:pb-0 ${
        disabled ? "cursor-pointer opacity-60" : "cursor-pointer"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        disabled={disabled}
        className="checkbox"
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-medium text-slate-200">{rule.name}</p>
          <RiskBadge risk={rule.risk} />
          {rule.pro_only && (
            <span className="rounded-full bg-blue/10 px-2 py-0.5 text-[10px] text-blue-300">
              Pro
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-slate-500">{rule.description}</p>
      </div>
      <ChevronRight className="hidden text-slate-700 sm:block" size={16} />
    </label>
  );
}

function RiskBadge({ risk }: { risk: Risk }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[10px] ${
        risk === "Safe" ? "bg-teal/10 text-teal" : "bg-amber-400/10 text-amber-300"
      }`}
    >
      {risk}
    </span>
  );
}

function ResultScreen({
  report,
  onRestore,
  restoring,
}: {
  report: CleanReport;
  onRestore: () => void;
  restoring: boolean;
}) {
  return (
    <div className="mx-auto max-w-xl py-14 text-center">
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-teal/10 text-teal">
        <Check size={32} />
      </div>
      <p className="mt-7 text-sm font-medium text-teal">Cleanup complete</p>
      <h1 className="mt-3 text-4xl font-semibold tracking-[-0.04em]">
        Your PC is feeling lighter.
      </h1>
      <p className="mt-4 text-slate-400">
        {formatBytes(report.bytes_freed)} moved safely to quarantine across{" "}
        {report.items.toLocaleString()} items.
      </p>
      <button
        type="button"
        onClick={onRestore}
        disabled={restoring || !report.quarantine_id}
        className="button-secondary mx-auto mt-9"
      >
        {restoring ? <LoaderCircle className="animate-spin" size={17} /> : <RotateCcw size={17} />}
        {restoring ? "Restoring…" : "Undo cleanup"}
      </button>
    </div>
  );
}

function LicenseScreen({
  license,
  licenseKey,
  setLicenseKey,
  busy,
  error,
  onActivate,
  onDeactivate,
  onClose,
}: {
  license: LicenseStatus | null;
  licenseKey: string;
  setLicenseKey: (value: string) => void;
  busy: boolean;
  error: string | null;
  onActivate: () => void;
  onDeactivate: () => void;
  onClose: () => void;
}) {
  const isPro = license?.entitlements.proRules ?? false;
  return (
    <div className="mx-auto max-w-3xl py-6">
      <button type="button" onClick={onClose} className="button-secondary">
        <ArrowLeft size={17} /> Back to dashboard
      </button>
      <div className="mt-8 grid gap-6 md:grid-cols-[1.1fr_0.9fr]">
        <div>
          <p className="flex items-center gap-2 text-sm font-medium text-teal">
            <ShieldCheck size={17} /> Dustonic licensing
          </p>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-0.04em]">
            Keep your PC clean, on your terms.
          </h1>
          <p className="mt-4 leading-7 text-slate-400">
            Pro unlocks deeper cleaning rules, scheduled protection, and the tools coming next.
          </p>
          <div className="mt-8 space-y-3">
            {[
              "Developer and deep-clean categories",
              "Scheduled and automatic cleaning",
              "Duplicate and large-file finders",
            ].map((feature) => (
              <div key={feature} className="flex items-center gap-3 text-sm text-slate-300">
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-teal/10 text-teal">
                  <Check size={14} />
                </span>
                {feature}
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={() => void openUrl(productConfig.checkoutUrl)}
            className="button-primary mt-9"
          >
            Upgrade with Dustonic Pro <ChevronRight size={17} />
          </button>
        </div>
        <div className="h-fit rounded-2xl border border-white/[0.08] bg-panel/80 p-6">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Current plan</p>
          <p className="mt-3 text-2xl font-semibold">{license?.name ?? "Free"}</p>
          {isPro ? (
            <>
              <p className="mt-2 text-sm text-teal">Your Pro license is active.</p>
              <div className="mt-6 space-y-2 rounded-xl border border-white/[0.07] bg-white/[0.03] p-4 text-sm">
                <p className="text-slate-300">{license?.keyMasked}</p>
                <p className="text-xs text-slate-500">{license?.email ?? "Licensed account"}</p>
              </div>
              <button
                type="button"
                onClick={onDeactivate}
                disabled={busy}
                className="button-secondary mt-5 w-full"
              >
                {busy ? <LoaderCircle className="animate-spin" size={16} /> : null}
                Deactivate license
              </button>
            </>
          ) : (
            <>
              <p className="mt-2 text-sm text-slate-500">
                Free includes safe core cleaning and manual cleanup.
              </p>
              <label
                className="mt-7 block text-xs font-medium text-slate-400"
                htmlFor="license-key"
              >
                Have a license key?
              </label>
              <input
                id="license-key"
                value={licenseKey}
                onChange={(event) => setLicenseKey(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") onActivate();
                }}
                placeholder="DUST-XXXXX-XXXXX"
                className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-teal/50"
              />
              <button
                type="button"
                onClick={onActivate}
                disabled={busy || !licenseKey.trim()}
                className="button-primary mt-3 w-full"
              >
                {busy ? <LoaderCircle className="animate-spin" size={16} /> : null}
                Activate license
              </button>
            </>
          )}
          {error && <p className="mt-4 text-xs leading-5 text-red-300">{error}</p>}
        </div>
      </div>
    </div>
  );
}
