import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Activity,
  ArrowLeft,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  FolderOpen,
  HardDrive,
  LoaderCircle,
  LockKeyhole,
  MemoryStick,
  RotateCcw,
  ScanSearch,
  Settings2,
  ShieldCheck,
  Sparkles,
  Trash2,
  Zap,
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
type Busy = "loading" | "scanning" | "cleaning" | "restoring" | null;

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
    if (payload.code === "LICENSE_VALIDATION_FAILED")
      return "License validation is unavailable right now. Please try again.";
  } catch {
    /* Backend errors that are not structured are shown as-is. */
  }
  return raw;
};

export default function App() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [cleaned, setCleaned] = useState<CleanReport | null>(null);
  const [busy, setBusy] = useState<Busy>("loading");
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
  const isPro = license?.entitlements.proRules ?? false;
  const toggleRule = (id: string) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((value) => value !== id) : [...current, id],
    );
  const selectAll = () =>
    setSelected(allRules.filter((rule) => !rule.pro_only || isPro).map((rule) => rule.id));
  const clearAll = () => setSelected([]);

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
      setCleaned(await invoke<CleanReport>("restore_last_quarantine"));
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
      setLicense(await invoke<LicenseStatus>("activate_license", { key: licenseKey }));
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

  const diskUsed = stats ? stats.disk_total - stats.disk_free : 0;
  const diskPercent = stats ? percent(diskUsed, stats.disk_total) : 0;
  const memoryPercent = stats ? percent(stats.memory_used, stats.memory_total) : 0;

  return (
    <main className="app-shell">
      <div className="ambient ambient-teal" />
      <div className="ambient ambient-blue" />
      <div className="app-frame">
        <header className="topbar">
          <div className="brand-lockup">
            <img src="/logo.png" alt="Dustonic" className="brand-mark" />
            <div>
              <p className="brand-name">Dustonic</p>
              <p className="brand-tagline">PC care, made simple</p>
            </div>
          </div>
          <div className="topbar-actions">
            <div className="status-pill">
              <span className="status-dot" /> Protected
            </div>
            <button type="button" className="icon-button" aria-label="Help">
              <CircleHelp size={17} />
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label="Settings"
              onClick={() => setView("license")}
            >
              <Settings2 size={17} />
            </button>
            <button
              type="button"
              className={`plan-button ${isPro ? "is-pro" : ""}`}
              onClick={() => setView("license")}
            >
              {isPro ? <Sparkles size={15} /> : <Zap size={15} />}
              {isPro ? "Dustonic Pro" : "Go Pro"}
              <ArrowUpRight size={14} />
            </button>
          </div>
        </header>
        <div className="workspace">
          <aside className="side-rail">
            <div className="rail-section">
              <p className="rail-label">Workspace</p>
              <button
                type="button"
                className={`rail-link ${view === "dashboard" ? "active" : ""}`}
                onClick={() => setView("dashboard")}
              >
                <ScanSearch size={16} /> Overview
              </button>
              <button
                type="button"
                className={`rail-link ${view === "license" ? "active" : ""}`}
                onClick={() => setView("license")}
              >
                <Sparkles size={16} /> Pro features{" "}
                {isPro ? <span className="rail-pro">ACTIVE</span> : null}
              </button>
            </div>
            <div className="rail-note">
              <ShieldCheck size={17} />
              <p>
                <strong>Safe by design</strong>
                <span>Preview first. Undo anytime.</span>
              </p>
            </div>
            <div className="rail-footer">
              Dustonic 0.1.0
              <br />
              <span>Open source · Private</span>
            </div>
          </aside>
          <section className="main-content">
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
              <ResultScreen
                report={cleaned}
                onRestore={restore}
                restoring={busy === "restoring"}
                onAgain={() => setCleaned(null)}
              />
            ) : (
              <Dashboard
                catalog={catalog}
                stats={stats}
                diskFree={formatBytes(stats?.disk_free ?? 0)}
                diskPercent={diskPercent}
                memoryPercent={memoryPercent}
                report={report}
                selected={selected}
                selectedCount={selectedCount}
                totalRules={allRules.length}
                isPro={isPro}
                busy={busy}
                error={error}
                onToggle={toggleRule}
                onSelectAll={selectAll}
                onClearAll={clearAll}
                onUpgrade={() => setView("license")}
                onScan={scan}
                onClean={clean}
                onReset={() => setReport(null)}
              />
            )}
          </section>
        </div>
      </div>
    </main>
  );
}

function Dashboard({
  catalog,
  stats,
  diskFree,
  diskPercent,
  memoryPercent,
  report,
  selected,
  selectedCount,
  totalRules,
  isPro,
  busy,
  error,
  onToggle,
  onSelectAll,
  onClearAll,
  onUpgrade,
  onScan,
  onClean,
  onReset,
}: {
  catalog: Catalog | null;
  stats: SystemStats | null;
  diskFree: string;
  diskPercent: number;
  memoryPercent: number;
  report: ScanReport | null;
  selected: string[];
  selectedCount: number;
  totalRules: number;
  isPro: boolean;
  busy: Busy;
  error: string | null;
  onToggle: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onUpgrade: () => void;
  onScan: () => void;
  onClean: () => void;
  onReset: () => void;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="kicker">
            <span className="kicker-line" /> {catalog?.platform ?? "System"} protection
          </p>
          <h1>{report ? "Review your cleanup." : "A cleaner PC starts here."}</h1>
          <p className="lede">
            {report
              ? "Everything is ready for your review. Nothing moves until you say so."
              : "A quick, private scan for the clutter taking up space on your machine."}
          </p>
        </div>
        <button
          type="button"
          className="scan-button"
          onClick={report ? onClean : onScan}
          disabled={busy !== null || selectedCount === 0}
        >
          {busy === "scanning" || busy === "cleaning" ? (
            <LoaderCircle className="spin" size={18} />
          ) : report ? (
            <Trash2 size={18} />
          ) : (
            <ScanSearch size={18} />
          )}
          <span>
            {busy === "scanning"
              ? "Scanning…"
              : busy === "cleaning"
                ? "Cleaning…"
                : report
                  ? "Clean selected"
                  : "Smart Scan"}
          </span>
          {!busy && <ChevronRight size={16} />}
        </button>
      </div>
      {busy === "scanning" && <ScanProgress />}
      {error && (
        <div className="error-banner" role="alert">
          <Activity size={16} />
          {error}
        </div>
      )}
      <div className="stats-grid">
        <StatCard
          icon={<HardDrive size={17} />}
          label="Disk space free"
          value={diskFree}
          meta={stats ? `${diskPercent}% in use` : "Loading system stats"}
          chart={<StorageBar percent={diskPercent} />}
        />
        <StatCard
          icon={<MemoryStick size={17} />}
          label="Memory in use"
          value={stats ? `${memoryPercent}%` : "—"}
          meta={
            stats
              ? `${formatBytes(stats.memory_used)} of ${formatBytes(stats.memory_total)}`
              : "Loading system stats"
          }
          chart={<StorageBar percent={memoryPercent} blue />}
        />
        <StatCard
          icon={<CheckCircle2 size={17} />}
          label={report ? "Ready to reclaim" : "Rules selected"}
          value={report ? formatBytes(report.total_bytes) : `${selectedCount} / ${totalRules}`}
          meta={report ? `${report.total_items.toLocaleString()} items found` : "Safe paths only"}
        />
      </div>
      <div className="content-grid">
        <div className="rules-column">
          {report ? (
            <ScanResults
              report={report}
              selected={selected}
              onToggle={onToggle}
              onSelectAll={onSelectAll}
              onClearAll={onClearAll}
              onReset={onReset}
            />
          ) : (
            <RulePicker
              catalog={catalog}
              selected={selected}
              onToggle={onToggle}
              isPro={isPro}
              onUpgrade={onUpgrade}
              onSelectAll={onSelectAll}
              onClearAll={onClearAll}
            />
          )}
        </div>
        <aside className="upgrade-card">
          <div className="upgrade-glow" />
          <div className="upgrade-card-content">
            <span className="upgrade-icon">
              <Sparkles size={17} />
            </span>
            <p className="upgrade-eyebrow">Dustonic Pro</p>
            <h2>
              Clean deeper.
              <br />
              <em>Keep it simple.</em>
            </h2>
            <p>
              Unlock developer caches, automatic cleaning, and the tools on our roadmap. One
              payment, lifetime access.
            </p>
            <button type="button" className="upgrade-link" onClick={onUpgrade}>
              See what’s included <ArrowUpRight size={15} />
            </button>
          </div>
        </aside>
      </div>
    </>
  );
}

function StatCard({
  icon,
  label,
  value,
  meta,
  chart,
}: { icon: ReactNode; label: string; value: string; meta: string; chart?: ReactNode }) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span className="stat-icon">{icon}</span>
        <span>{label}</span>
      </div>
      <p className="stat-value">{value}</p>
      <p className="stat-meta">{meta}</p>
      {chart}
    </div>
  );
}
function StorageBar({ percent: value, blue = false }: { percent: number; blue?: boolean }) {
  return (
    <div className="storage-track">
      <span className={blue ? "blue" : ""} style={{ width: `${Math.min(value, 100)}%` }} />
    </div>
  );
}
function ScanProgress() {
  return (
    <div className="scan-progress">
      <div className="progress-orb">
        <LoaderCircle className="spin" size={20} />
      </div>
      <div>
        <strong>Scanning your system</strong>
        <span>Checking safe paths and measuring what can go.</span>
      </div>
      <div className="progress-pulse">
        <i />
        <i />
        <i />
      </div>
    </div>
  );
}

function RulePicker({
  catalog,
  selected,
  onToggle,
  isPro,
  onUpgrade,
  onSelectAll,
  onClearAll,
}: {
  catalog: Catalog | null;
  selected: string[];
  onToggle: (id: string) => void;
  isPro: boolean;
  onUpgrade: () => void;
  onSelectAll: () => void;
  onClearAll: () => void;
}) {
  if (!catalog)
    return (
      <div className="empty-card">
        <LoaderCircle className="spin" size={20} />
        Loading cleaning rules…
      </div>
    );
  return (
    <div className="rules-panel">
      <PanelHeader
        title="Cleaning rules"
        subtitle="Choose what Dustonic should look for."
        onSelectAll={onSelectAll}
        onClearAll={onClearAll}
      />
      <div className="category-stack">
        {catalog.categories.map((category) => (
          <div className="category-card" key={category.name}>
            <div className="category-heading">
              <div>
                <h2>{category.name}</h2>
                <span>{category.rules.length} rules</span>
              </div>
              <span className="folder-mark">
                <FolderOpen size={15} />
              </span>
            </div>
            <div className="rule-list">
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
    </div>
  );
}
function PanelHeader({
  title,
  subtitle,
  onSelectAll,
  onClearAll,
}: { title: string; subtitle: string; onSelectAll: () => void; onClearAll: () => void }) {
  return (
    <div className="panel-header">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      <div className="selection-actions">
        <button type="button" onClick={onSelectAll}>
          Select all
        </button>
        <button type="button" onClick={onClearAll}>
          Clear
        </button>
      </div>
    </div>
  );
}
function RuleRow({
  rule,
  checked,
  disabled,
  onToggle,
}: { rule: Rule; checked: boolean; disabled: boolean; onToggle: () => void }) {
  return (
    <label
      className={`rule-row ${disabled ? "locked" : ""}`}
      onClick={(event) => {
        if (disabled) {
          event.preventDefault();
          onToggle();
        }
      }}
      onKeyDown={(event) => {
        if (disabled && (event.key === "Enter" || event.key === " ")) {
          event.preventDefault();
          onToggle();
        }
      }}
      tabIndex={disabled ? 0 : undefined}
    >
      <input type="checkbox" checked={checked} onChange={onToggle} disabled={disabled} />
      <span className="custom-check">{checked && <Check size={12} />}</span>
      <span className="rule-copy">
        <span className="rule-title">
          {rule.name}{" "}
          {rule.pro_only && (
            <span className="pro-badge">
              <Sparkles size={10} /> PRO
            </span>
          )}{" "}
          <RiskBadge risk={rule.risk} />
        </span>
        <span className="rule-description">{rule.description}</span>
      </span>
      {disabled ? (
        <LockKeyhole size={15} className="lock-icon" />
      ) : (
        <ChevronRight size={15} className="row-chevron" />
      )}
    </label>
  );
}
function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`risk-badge ${risk === "Safe" ? "safe" : "caution"}`}>{risk}</span>;
}

function ScanResults({
  report,
  selected,
  onToggle,
  onSelectAll,
  onClearAll,
  onReset,
}: {
  report: ScanReport;
  selected: string[];
  onToggle: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onReset: () => void;
}) {
  const grouped = report.rules.reduce<Record<string, RuleScan[]>>((groups, rule) => {
    if (!groups[rule.category]) groups[rule.category] = [];
    groups[rule.category].push(rule);
    return groups;
  }, {});
  return (
    <div className="rules-panel">
      <div className="results-summary">
        <div>
          <p className="kicker">
            <span className="kicker-line" /> Scan complete
          </p>
          <h2>
            {formatBytes(report.total_bytes)} <small>reclaimable</small>
          </h2>
          <p>
            {report.total_items.toLocaleString()} items found across {report.rules.length} cleaning
            rules.
          </p>
        </div>
        <div className="summary-check">
          <CheckCircle2 size={18} />
          <span>
            Previewed
            <br />
            <strong>Before cleanup</strong>
          </span>
        </div>
      </div>
      <div className="results-toolbar">
        <span>Review results</span>
        <div className="selection-actions">
          <button type="button" onClick={onSelectAll}>
            Select all
          </button>
          <button type="button" onClick={onClearAll}>
            Clear
          </button>
          <button type="button" onClick={onReset}>
            <ArrowLeft size={13} /> Change scan
          </button>
        </div>
      </div>
      <div className="category-stack">
        {Object.entries(grouped).map(([category, rules]) => (
          <div className="category-card" key={category}>
            <div className="category-heading">
              <div>
                <h2>{category}</h2>
                <span>
                  {rules.reduce((sum, rule) => sum + rule.items, 0).toLocaleString()} items
                </span>
              </div>
              <span className="folder-mark">
                <FolderOpen size={15} />
              </span>
            </div>
            <div className="rule-list">
              {rules.map((rule) => (
                <div className="result-row" key={rule.rule_id}>
                  <label className="result-check">
                    <input
                      type="checkbox"
                      checked={selected.includes(rule.rule_id)}
                      onChange={() => onToggle(rule.rule_id)}
                    />
                    <span className="custom-check">
                      {selected.includes(rule.rule_id) && <Check size={12} />}
                    </span>
                  </label>
                  <div className="rule-copy">
                    <span className="rule-title">
                      {rule.name}{" "}
                      {rule.pro_only && (
                        <span className="pro-badge">
                          <Sparkles size={10} /> PRO
                        </span>
                      )}{" "}
                      <RiskBadge risk={rule.risk} />
                    </span>
                    <span className="rule-description">{rule.description}</span>
                  </div>
                  <div className="result-size">
                    <strong>{formatBytes(rule.bytes)}</strong>
                    <span>{rule.items.toLocaleString()} items</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ResultScreen({
  report,
  onRestore,
  restoring,
  onAgain,
}: { report: CleanReport; onRestore: () => void; restoring: boolean; onAgain: () => void }) {
  return (
    <div className="result-screen">
      <div className="success-ring">
        <Check size={32} />
      </div>
      <p className="kicker centered-kicker">
        <span className="kicker-line" /> Cleanup complete
      </p>
      <h1>Your PC is feeling lighter.</h1>
      <p className="result-lede">
        <strong>{formatBytes(report.bytes_freed)}</strong> moved safely to quarantine across{" "}
        {report.items.toLocaleString()} items.
      </p>
      <div className="result-actions">
        <button type="button" onClick={onAgain} className="secondary-button">
          Scan again <ScanSearch size={15} />
        </button>
        <button
          type="button"
          onClick={onRestore}
          disabled={restoring || !report.quarantine_id}
          className="secondary-button undo-button"
        >
          {restoring ? <LoaderCircle className="spin" size={15} /> : <RotateCcw size={15} />}
          {restoring ? "Restoring…" : "Undo cleanup"}
        </button>
      </div>
      <div className="quarantine-note">
        <ShieldCheck size={15} /> Your files are still in Dustonic’s private quarantine.
      </div>
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
    <div className="license-screen">
      <button type="button" onClick={onClose} className="back-link">
        <ArrowLeft size={15} /> Back to overview
      </button>
      <div className="license-hero">
        <div>
          <p className="kicker">
            <span className="kicker-line" /> Dustonic Pro
          </p>
          <h1>
            More control.
            <br />
            <em>Less clutter.</em>
          </h1>
          <p className="lede">
            Go deeper when you need to, then get out of the way. Pro is a one-time purchase with
            lifetime access.
          </p>
        </div>
        <div className="pro-stamp">
          <Sparkles size={22} />
          <span>
            ONE-TIME
            <br />
            <strong>LIFETIME</strong>
          </span>
        </div>
      </div>
      <div className="license-grid">
        <div className="feature-list">
          <FeatureLine
            title="Deep-clean rules"
            text="Developer caches and categories that need a closer look."
          />
          <FeatureLine
            title="Automatic protection"
            text="Scheduled and automatic cleaning, when you want it."
          />
          <FeatureLine
            title="Tools on the way"
            text="Duplicate and large-file finders are included in Pro."
          />
        </div>
        <div className="license-card">
          <p className="card-eyebrow">Current plan</p>
          <div className="current-plan">
            <span className={`plan-icon ${isPro ? "pro" : ""}`}>
              {isPro ? <Sparkles size={17} /> : <ShieldCheck size={17} />}
            </span>
            <div>
              <strong>{license?.name ?? "Free"}</strong>
              <span>{isPro ? "Lifetime Pro is active" : "Core cleaning and manual scans"}</span>
            </div>
          </div>
          {isPro ? (
            <>
              <div className="license-detail">
                <span>License key</span>
                <strong>{license?.keyMasked}</strong>
                <small>{license?.email ?? "Licensed account"}</small>
              </div>
              <button
                type="button"
                onClick={onDeactivate}
                disabled={busy}
                className="secondary-button full-button"
              >
                {busy && <LoaderCircle className="spin" size={15} />} Deactivate license
              </button>
            </>
          ) : (
            <>
              <label htmlFor="license-key" className="input-label">
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
                className="license-input"
              />
              <button
                type="button"
                onClick={onActivate}
                disabled={busy || !licenseKey.trim()}
                className="scan-button full-button"
              >
                {busy && <LoaderCircle className="spin" size={15} />} Activate license
              </button>
            </>
          )}
          {error && <p className="license-error">{error}</p>}
        </div>
      </div>
      <div className="checkout-strip">
        <div>
          <Sparkles size={18} />
          <span>
            <strong>Ready for a cleaner baseline?</strong>
            <small>Unlock Pro once. Keep it for the life of the app.</small>
          </span>
        </div>
        <button
          type="button"
          onClick={() => void openUrl(productConfig.checkoutUrl)}
          className="upgrade-link"
        >
          Go Pro — one-time, lifetime <ArrowUpRight size={15} />
        </button>
      </div>
    </div>
  );
}
function FeatureLine({ title, text }: { title: string; text: string }) {
  return (
    <div className="feature-line">
      <span className="feature-check">
        <Check size={13} />
      </span>
      <span>
        <strong>{title}</strong>
        <small>{text}</small>
      </span>
    </div>
  );
}
