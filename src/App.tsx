import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  HardDrive,
  Info,
  LayoutDashboard,
  Lightbulb,
  LoaderCircle,
  LockKeyhole,
  Moon,
  RotateCcw,
  ScanSearch,
  Settings2,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  X,
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
type Screen = "clean" | "license" | "settings";

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
const percent = (value: number, total: number) =>
  total ? Math.min(100, Math.round((value / total) * 100)) : 0;
const displayError = (reason: unknown) => {
  const raw = String(reason);
  try {
    const payload = JSON.parse(raw) as { code?: string };
    if (payload.code === "PRO_REQUIRED") return "Dustonic Pro is required for this rule.";
    if (payload.code === "LICENSE_INVALID") return "That license key is not valid.";
    if (payload.code === "LICENSE_KEY_REQUIRED") return "Enter a license key to continue.";
    if (payload.code === "LICENSE_VALIDATION_FAILED")
      return "License validation is unavailable right now.";
  } catch {
    // Backend errors that are not structured are shown as returned.
  }
  return raw;
};

export default function App() {
  const [screen, setScreen] = useState<Screen>("clean");
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      return localStorage.getItem("dustonic-theme") === "dark" ? "dark" : "light";
    } catch {
      return "light";
    }
  });
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [cleaned, setCleaned] = useState<CleanReport | null>(null);
  const [licenseKey, setLicenseKey] = useState("");
  const [busy, setBusy] = useState<Busy>("loading");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("dustonic-theme", theme);
    } catch {
      // Theme persistence is optional in restricted WebViews.
    }
  }, [theme]);

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
  const isPro = license?.entitlements.proRules ?? false;
  const toggleRule = (id: string) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
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
      setScreen("clean");
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
    <main className="desktop-app">
      <AppRail screen={screen} isPro={isPro} onNavigate={setScreen} />
      <section className="app-pane">
        <header className="app-header">
          <div className="breadcrumb">
            <span>Dustonic</span>
            <ChevronRight size={13} />
            <strong>
              {screen === "clean" ? "Clean" : screen === "license" ? "Pro" : "Settings"}
            </strong>
          </div>
          <div className="header-actions">
            <span className="protected-status">
              <span className="status-dot" /> Protected
            </span>
            <button type="button" className="header-icon" aria-label="Help">
              <CircleHelp size={16} />
            </button>
            <button
              type="button"
              className="theme-toggle"
              aria-label={`Use ${theme === "light" ? "dark" : "light"} theme`}
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
            >
              {theme === "light" ? <Moon size={15} /> : <Sun size={15} />}
            </button>
          </div>
        </header>
        <div className="app-content">
          {screen === "clean" ? (
            <CleanScreen
              catalog={catalog}
              stats={stats}
              report={report}
              cleaned={cleaned}
              selected={selected}
              isPro={isPro}
              busy={busy}
              error={error}
              onToggle={toggleRule}
              onSelectAll={selectAll}
              onClearAll={clearAll}
              onUpgrade={() => setScreen("license")}
              onScan={scan}
              onClean={clean}
              onRestore={restore}
              onAgain={() => setCleaned(null)}
              onChangeScan={() => setReport(null)}
              onDismissError={() => setError(null)}
            />
          ) : screen === "license" ? (
            <LicenseScreen
              license={license}
              licenseKey={licenseKey}
              setLicenseKey={setLicenseKey}
              busy={busy === "loading"}
              error={error}
              onActivate={activate}
              onDeactivate={deactivate}
              onCheckout={() => void openUrl(productConfig.checkoutUrl)}
            />
          ) : (
            <SettingsScreen theme={theme} onThemeChange={setTheme} />
          )}
        </div>
      </section>
    </main>
  );
}

function AppRail({
  screen,
  isPro,
  onNavigate,
}: {
  screen: Screen;
  isPro: boolean;
  onNavigate: (screen: Screen) => void;
}) {
  return (
    <nav className="app-rail" aria-label="Primary navigation">
      <button
        type="button"
        className="rail-logo"
        aria-label="Dustonic Clean"
        onClick={() => onNavigate("clean")}
      >
        <img src="/logo.png" alt="" />
      </button>
      <div className="rail-nav">
        <RailButton active={screen === "clean"} label="Clean" onClick={() => onNavigate("clean")}>
          <LayoutDashboard size={19} />
        </RailButton>
        <RailButton
          active={screen === "license"}
          label="Pro and license"
          onClick={() => onNavigate("license")}
        >
          <Sparkles size={19} />
          {!isPro && <span className="rail-badge">PRO</span>}
        </RailButton>
      </div>
      <div className="rail-bottom">
        <RailButton
          active={screen === "settings"}
          label="Settings and about"
          onClick={() => onNavigate("settings")}
        >
          <Settings2 size={19} />
        </RailButton>
        <span className="rail-version">0.1</span>
      </div>
    </nav>
  );
}

function RailButton({
  active,
  label,
  onClick,
  children,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={`rail-button ${active ? "active" : ""}`}
      aria-label={label}
      aria-current={active ? "page" : undefined}
      title={label}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function CleanScreen({
  catalog,
  stats,
  report,
  cleaned,
  selected,
  isPro,
  busy,
  error,
  onToggle,
  onSelectAll,
  onClearAll,
  onUpgrade,
  onScan,
  onClean,
  onRestore,
  onAgain,
  onChangeScan,
  onDismissError,
}: {
  catalog: Catalog | null;
  stats: SystemStats | null;
  report: ScanReport | null;
  cleaned: CleanReport | null;
  selected: string[];
  isPro: boolean;
  busy: Busy;
  error: string | null;
  onToggle: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onUpgrade: () => void;
  onScan: () => void;
  onClean: () => void;
  onRestore: () => void;
  onAgain: () => void;
  onChangeScan: () => void;
  onDismissError: () => void;
}) {
  const diskUsed = stats ? stats.disk_total - stats.disk_free : 0;
  const memoryUsed = stats?.memory_used ?? 0;
  const selectedBytes = report
    ? report.rules
        .filter((rule) => selected.includes(rule.rule_id))
        .reduce((sum, rule) => sum + rule.bytes, 0)
    : 0;
  return (
    <div className="clean-screen">
      <div className="screen-titlebar">
        <div>
          <h1>{cleaned ? "Cleanup complete" : report ? "Review scan results" : "Clean your PC"}</h1>
          <p>
            {cleaned
              ? "Your selected files were moved safely to quarantine."
              : report
                ? "Choose what to remove. Nothing changes until you confirm."
                : "A focused scan for temporary files, caches, and safe-to-remove clutter."}
          </p>
        </div>
        {!cleaned && !report && (
          <button
            type="button"
            className="primary-button"
            onClick={onScan}
            disabled={busy !== null || selected.length === 0}
          >
            {busy === "scanning" ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <ScanSearch size={16} />
            )}
            {busy === "scanning" ? "Scanning…" : "Scan now"}
          </button>
        )}
        {report && (
          <button
            type="button"
            className="primary-button"
            onClick={onClean}
            disabled={busy !== null || selected.length === 0}
          >
            {busy === "cleaning" ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <Trash2 size={16} />
            )}
            {busy === "cleaning" ? "Cleaning…" : "Clean selected"}
          </button>
        )}
      </div>
      {error && (
        <div className="notice error-notice" role="alert">
          <Info size={16} /> <span>{error}</span>
          <button type="button" aria-label="Dismiss error" onClick={onDismissError}>
            <X size={14} />
          </button>
        </div>
      )}
      {cleaned ? (
        <CompletionPanel report={cleaned} busy={busy} onRestore={onRestore} onAgain={onAgain} />
      ) : (
        <>
          <div className="status-strip">
            <Meter
              icon={<HardDrive size={15} />}
              label="Disk free"
              value={stats ? formatBytes(stats.disk_free) : "—"}
              detail={stats ? `${percent(diskUsed, stats.disk_total)}% used` : "Loading"}
              progress={percent(diskUsed, stats?.disk_total ?? 0)}
            />
            <Meter
              icon={<ActivityIcon />}
              label="Memory"
              value={stats ? formatBytes(memoryUsed) : "—"}
              detail={stats ? `${percent(memoryUsed, stats.memory_total)}% used` : "Loading"}
              progress={percent(memoryUsed, stats?.memory_total ?? 0)}
            />
            <div className="status-note">
              <ShieldCheck size={16} />
              <span>
                <strong>Safe by design</strong>
                <small>Preview first · Undo anytime</small>
              </span>
            </div>
          </div>
          {busy === "scanning" && (
            <div className="scan-line">
              <LoaderCircle className="spin" size={15} /> Checking safe paths and measuring what can
              go…
            </div>
          )}
          {report ? (
            <ResultsList
              report={report}
              selected={selected}
              selectedBytes={selectedBytes}
              onToggle={onToggle}
              onSelectAll={onSelectAll}
              onClearAll={onClearAll}
              onChangeScan={onChangeScan}
            />
          ) : (
            <RuleList
              catalog={catalog}
              selected={selected}
              isPro={isPro}
              onToggle={onToggle}
              onUpgrade={onUpgrade}
              onSelectAll={onSelectAll}
              onClearAll={onClearAll}
            />
          )}
        </>
      )}
      {!cleaned && (
        <div className="bottom-action">
          <span>
            <strong>{selected.length}</strong> selected
            {report && (
              <>
                {" "}
                · <strong>{formatBytes(selectedBytes)}</strong> reclaimable
              </>
            )}
          </span>
          <span className="bottom-hint">
            {report ? "Files move to quarantine" : "Select rules to include in scan"}
          </span>
        </div>
      )}
    </div>
  );
}

function ActivityIcon() {
  return (
    <span className="activity-icon">
      <span />
    </span>
  );
}

function Meter({
  icon,
  label,
  value,
  detail,
  progress,
}: { icon: ReactNode; label: string; value: string; detail: string; progress: number }) {
  return (
    <div className="meter">
      <span className="meter-icon">{icon}</span>
      <span className="meter-copy">
        <small>{label}</small>
        <strong>{value}</strong>
        <em>{detail}</em>
        <span className="meter-track">
          <i style={{ width: `${progress}%` }} />
        </span>
      </span>
    </div>
  );
}

function RuleList({
  catalog,
  selected,
  isPro,
  onToggle,
  onUpgrade,
  onSelectAll,
  onClearAll,
}: {
  catalog: Catalog | null;
  selected: string[];
  isPro: boolean;
  onToggle: (id: string) => void;
  onUpgrade: () => void;
  onSelectAll: () => void;
  onClearAll: () => void;
}) {
  if (!catalog)
    return (
      <div className="list-empty">
        <LoaderCircle className="spin" size={18} /> Loading cleaning rules…
      </div>
    );
  return (
    <div className="list-panel">
      <ListToolbar
        title="Cleaning rules"
        subtitle={`${catalog.platform} · ${catalog.categories.reduce((sum, category) => sum + category.rules.length, 0)} available`}
        onSelectAll={onSelectAll}
        onClearAll={onClearAll}
      />
      <div className="rule-groups">
        {catalog.categories.map((category) => (
          <RuleGroup
            key={category.name}
            title={category.name}
            rules={category.rules}
            selected={selected}
            isPro={isPro}
            onToggle={onToggle}
            onUpgrade={onUpgrade}
          />
        ))}
      </div>
    </div>
  );
}

function ResultsList({
  report,
  selected,
  selectedBytes,
  onToggle,
  onSelectAll,
  onClearAll,
  onChangeScan,
}: {
  report: ScanReport;
  selected: string[];
  selectedBytes: number;
  onToggle: (id: string) => void;
  onSelectAll: () => void;
  onClearAll: () => void;
  onChangeScan: () => void;
}) {
  const groups = report.rules.reduce<Record<string, RuleScan[]>>((result, rule) => {
    if (!result[rule.category]) {
      result[rule.category] = [];
    }
    result[rule.category].push(rule);
    return result;
  }, {});
  return (
    <div className="list-panel">
      <div className="result-callout">
        <div>
          <small>READY TO RECLAIM</small>
          <strong>{formatBytes(selectedBytes)}</strong>
          <span>
            {report.total_items.toLocaleString()} items found · {report.skipped} skipped
          </span>
        </div>
        <CheckCircle2 size={22} />
      </div>
      <ListToolbar
        title="Scan results"
        subtitle="Review the items before cleanup"
        onSelectAll={onSelectAll}
        onClearAll={onClearAll}
        extra={
          <button type="button" className="text-button" onClick={onChangeScan}>
            <RotateCcw size={13} /> New scan
          </button>
        }
      />
      <div className="rule-groups">
        {Object.entries(groups).map(([category, rules]) => (
          <div className="rule-group" key={category}>
            <GroupHeader
              title={category}
              count={rules.reduce((sum, rule) => sum + rule.items, 0)}
            />
            <div className="rule-items">
              {rules.map((rule) => (
                <ResultRow
                  key={rule.rule_id}
                  rule={rule}
                  checked={selected.includes(rule.rule_id)}
                  onToggle={() => onToggle(rule.rule_id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function RuleGroup({
  title,
  rules,
  selected,
  isPro,
  onToggle,
  onUpgrade,
}: {
  title: string;
  rules: Rule[];
  selected: string[];
  isPro: boolean;
  onToggle: (id: string) => void;
  onUpgrade: () => void;
}) {
  return (
    <div className="rule-group">
      <GroupHeader title={title} count={rules.length} />
      <div className="rule-items">
        {rules.map((rule) => (
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
  );
}

function GroupHeader({ title, count }: { title: string; count: number }) {
  return (
    <div className="group-header">
      <span>
        <ChevronDown size={14} />
        <strong>{title}</strong>
      </span>
      <small>
        {count} {count === 1 ? "rule" : "rules"}
      </small>
    </div>
  );
}

function ListToolbar({
  title,
  subtitle,
  onSelectAll,
  onClearAll,
  extra,
}: {
  title: string;
  subtitle: string;
  onSelectAll: () => void;
  onClearAll: () => void;
  extra?: ReactNode;
}) {
  return (
    <div className="list-toolbar">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      <div className="toolbar-actions">
        {extra}
        <button type="button" className="text-button" onClick={onSelectAll}>
          Select all
        </button>
        <button type="button" className="text-button" onClick={onClearAll}>
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
      className={`rule-item ${disabled ? "locked" : ""}`}
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
      <span className="checkbox">{checked && <Check size={12} />}</span>
      <span className="rule-info">
        <strong>{rule.name}</strong>
        <small>{rule.description}</small>
      </span>
      <Tag label={rule.risk} tone={rule.risk === "Safe" ? "safe" : "warning"} />
      {rule.pro_only && <Tag label="Pro" tone="pro" icon={<Sparkles size={10} />} />}
      {disabled ? (
        <LockKeyhole className="row-lock" size={14} />
      ) : (
        <span className="row-size">
          <ChevronRight size={14} />
        </span>
      )}
    </label>
  );
}

function ResultRow({
  rule,
  checked,
  onToggle,
}: { rule: RuleScan; checked: boolean; onToggle: () => void }) {
  return (
    <label className="rule-item">
      <input type="checkbox" checked={checked} onChange={onToggle} />
      <span className="checkbox">{checked && <Check size={12} />}</span>
      <span className="rule-info">
        <strong>{rule.name}</strong>
        <small>{rule.description}</small>
      </span>
      <Tag label={rule.risk} tone={rule.risk === "Safe" ? "safe" : "warning"} />
      {rule.pro_only && <Tag label="Pro" tone="pro" />}
      <span className="result-size">
        <strong>{formatBytes(rule.bytes)}</strong>
        <small>{rule.items.toLocaleString()} items</small>
      </span>
    </label>
  );
}

function Tag({
  label,
  tone,
  icon,
}: { label: string; tone: "safe" | "warning" | "pro"; icon?: ReactNode }) {
  return (
    <span className={`tag ${tone}`}>
      {icon}
      {label}
    </span>
  );
}

function CompletionPanel({
  report,
  busy,
  onRestore,
  onAgain,
}: { report: CleanReport; busy: Busy; onRestore: () => void; onAgain: () => void }) {
  return (
    <div className="completion">
      <span className="completion-icon">
        <Check size={25} />
      </span>
      <small className="eyebrow">CLEANUP COMPLETE</small>
      <h2>{formatBytes(report.bytes_freed)} reclaimed</h2>
      <p>{report.items.toLocaleString()} items were moved to Dustonic quarantine.</p>
      <div className="completion-actions">
        <button type="button" className="primary-button" onClick={onAgain}>
          <ScanSearch size={15} /> Scan again
        </button>
        <button
          type="button"
          className="secondary-button"
          onClick={onRestore}
          disabled={busy === "restoring" || !report.quarantine_id}
        >
          {busy === "restoring" ? (
            <LoaderCircle className="spin" size={15} />
          ) : (
            <RotateCcw size={15} />
          )}{" "}
          {busy === "restoring" ? "Restoring…" : "Undo cleanup"}
        </button>
      </div>
      <div className="completion-note">
        <ShieldCheck size={15} /> Files remain recoverable until you empty quarantine.
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
  onCheckout,
}: {
  license: LicenseStatus | null;
  licenseKey: string;
  setLicenseKey: (value: string) => void;
  busy: boolean;
  error: string | null;
  onActivate: () => void;
  onDeactivate: () => void;
  onCheckout: () => void;
}) {
  const isPro = license?.entitlements.proRules ?? false;
  return (
    <div className="settings-screen">
      <ScreenHeading
        eyebrow="DUSTONIC PRO"
        title="License and plan"
        text="Keep the core cleaner free. Unlock deeper rules and future tools with a lifetime Pro license."
      />
      <div className="settings-grid">
        <section className="settings-card">
          <div className="card-heading">
            <span className={`plan-mark ${isPro ? "pro" : ""}`}>
              {isPro ? <Sparkles size={17} /> : <ShieldCheck size={17} />}
            </span>
            <div>
              <small>Current plan</small>
              <h2>{license?.name ?? "Free"}</h2>
            </div>
          </div>
          {isPro ? (
            <>
              <div className="license-detail">
                <small>License key</small>
                <strong>{license?.keyMasked}</strong>
                <span>{license?.email ?? "Licensed account"}</span>
              </div>
              <button
                type="button"
                className="secondary-button wide"
                onClick={onDeactivate}
                disabled={busy}
              >
                {busy && <LoaderCircle className="spin" size={14} />} Deactivate license
              </button>
            </>
          ) : (
            <>
              <label htmlFor="license-key">Have a license key?</label>
              <input
                id="license-key"
                className="text-input"
                value={licenseKey}
                onChange={(event) => setLicenseKey(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") onActivate();
                }}
                placeholder="DUST-XXXXX-XXXXX"
              />
              <button
                type="button"
                className="primary-button wide"
                onClick={onActivate}
                disabled={busy || !licenseKey.trim()}
              >
                {busy && <LoaderCircle className="spin" size={14} />} Activate license
              </button>
            </>
          )}
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </section>
        <section className="settings-card feature-card">
          <small className="eyebrow">LIFETIME ACCESS</small>
          <h2>More control, less clutter.</h2>
          <p>
            Pro unlocks developer caches, scheduled and automatic cleaning, plus duplicate and
            large-file finders as they arrive.
          </p>
          <div className="feature-checkline">
            <CheckCircle2 size={15} /> Deep-clean rules
          </div>
          <div className="feature-checkline">
            <CheckCircle2 size={15} /> Scheduled and automatic cleaning
          </div>
          <div className="feature-checkline">
            <CheckCircle2 size={15} /> Future finder tools included
          </div>
          <button type="button" className="primary-button" onClick={onCheckout}>
            Go Pro — one-time, lifetime <ChevronRight size={15} />
          </button>
        </section>
      </div>
    </div>
  );
}

function SettingsScreen({
  theme,
  onThemeChange,
}: { theme: "light" | "dark"; onThemeChange: (theme: "light" | "dark") => void }) {
  return (
    <div className="settings-screen">
      <ScreenHeading
        eyebrow="APPLICATION"
        title="Settings"
        text="A few quiet controls for how Dustonic looks and behaves."
      />
      <section className="settings-card preference-card">
        <div className="preference-row">
          <span className="preference-icon">
            <Sun size={16} />
          </span>
          <span>
            <strong>Appearance</strong>
            <small>Choose the theme used by the app.</small>
          </span>
          <div className="segmented">
            <button
              type="button"
              className={theme === "light" ? "selected" : ""}
              onClick={() => onThemeChange("light")}
            >
              <Sun size={13} /> Light
            </button>
            <button
              type="button"
              className={theme === "dark" ? "selected" : ""}
              onClick={() => onThemeChange("dark")}
            >
              <Moon size={13} /> Dark
            </button>
          </div>
        </div>
        <div className="preference-row">
          <span className="preference-icon">
            <ShieldCheck size={16} />
          </span>
          <span>
            <strong>Safe cleaning</strong>
            <small>Files move to quarantine before deletion.</small>
          </span>
          <span className="preference-value">Always on</span>
        </div>
        <div className="about-row">
          <Info size={15} />
          <span>
            <strong>Dustonic 0.1.0</strong>
            <small>Open source · Windows and Linux · No telemetry</small>
          </span>
        </div>
      </section>
    </div>
  );
}

function ScreenHeading({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) {
  return (
    <div className="screen-heading">
      <small className="eyebrow">{eyebrow}</small>
      <h1>{title}</h1>
      <p>{text}</p>
    </div>
  );
}
