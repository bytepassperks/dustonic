import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  BarChart3,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Copy,
  ExternalLink,
  FileSearch,
  Files,
  FolderOpen,
  HardDrive,
  Info,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  Moon,
  PackageOpen,
  Power,
  RotateCcw,
  ScanSearch,
  Search,
  Settings2,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import { Component, type ErrorInfo, type ReactNode } from "react";
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
type Screen =
  | "clean"
  | "smart"
  | "analyzer"
  | "large"
  | "duplicates"
  | "startup"
  | "apps"
  | "registry"
  | "license"
  | "settings";
type DiskEntry = {
  name: string;
  path: string;
  bytes: number;
  percent: number;
  is_directory: boolean;
  risk: Risk;
  selectable: boolean;
};
type SmartCleanPlan = {
  rules: string[];
  groups: SmartCleanGroup[];
  bytes: number;
  items: number;
  remaining_free_runs: number | null;
};
type SmartCleanGroup = {
  rule_id: string;
  category: string;
  name: string;
  bytes: number;
  items: number;
  paths: string[];
};
type SmartCleanStatus = {
  remaining_free_runs: number | null;
  used_today: number;
  limit: number | null;
};
type LargeFile = { path: string; bytes: number; modified: number | null };
type DuplicateGroup = { size: number; count: number; files: string[] };
type ScanProgress = { done: number; total: number; name: string };
type DuplicateRemoval = { group: string[]; remove: string[]; keep: string };
type StartupItem = {
  id: string;
  display_name: string;
  command: string;
  enabled: boolean;
  source: string;
};
type InstalledProgram = {
  id: string;
  name: string;
  version: string | null;
  publisher: string | null;
  estimated_size: number | null;
  location: string | null;
  uninstall_command: string | null;
  removal_command: string | null;
};
type UninstallResult = {
  supported: boolean;
  launched: boolean;
  command: string | null;
  message: string;
};
type RegistryFinding = {
  id: string;
  key_path: string;
  value_name: string;
  reason: string;
};
type RegistryScanResult = {
  supported: boolean;
  findings: RegistryFinding[];
  message: string;
};
type RegistryCleanResult = {
  supported: boolean;
  cleaned: number;
  backup_path: string | null;
  message: string;
};

const screenLabel = (screen: Screen) =>
  ({
    clean: "Clean",
    smart: "Smart Clean",
    analyzer: "Disk analyzer",
    large: "Large files",
    duplicates: "Duplicates",
    startup: "Startup",
    apps: "Apps",
    registry: "Registry tools",
    license: "Pro",
    settings: "Settings",
  })[screen];

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
    if (payload.code === "SMART_CLEAN_LIMIT")
      return "Free plan includes 2 Smart Cleans per day — upgrade to Pro for unlimited.";
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
  const [smartPlan, setSmartPlan] = useState<SmartCleanPlan | null>(null);
  const [smartStatus, setSmartStatus] = useState<SmartCleanStatus | null>(null);
  const [licenseKey, setLicenseKey] = useState("");
  const [busyByScreen, setBusyByScreen] = useState<Partial<Record<Screen, Busy>>>({
    clean: "loading",
  });
  const [errorByScreen, setErrorByScreen] = useState<Partial<Record<Screen, string | null>>>({});
  const busyFor = (target: Screen) => busyByScreen[target] ?? null;
  const setBusyFor = (target: Screen, next: Busy) =>
    setBusyByScreen((current) => ({ ...current, [target]: next }));
  const errorFor = (target: Screen) => errorByScreen[target] ?? null;
  const setErrorFor = (target: Screen, next: string | null) =>
    setErrorByScreen((current) => ({ ...current, [target]: next }));
  const [analyzerPath, setAnalyzerPath] = useState("");
  const [analyzerEntries, setAnalyzerEntries] = useState<DiskEntry[] | null>(null);
  const [selectedAnalyzer, setSelectedAnalyzer] = useState<string[]>([]);
  const [largePath, setLargePath] = useState("");
  const [largeThreshold, setLargeThreshold] = useState(100);
  const [largeFiles, setLargeFiles] = useState<LargeFile[] | null>(null);
  const [selectedLarge, setSelectedLarge] = useState<string[]>([]);
  const [duplicatePath, setDuplicatePath] = useState("");
  const [duplicateGroups, setDuplicateGroups] = useState<DuplicateGroup[] | null>(null);
  const [duplicateKeep, setDuplicateKeep] = useState<Record<number, string>>({});
  const [duplicateRemoved, setDuplicateRemoved] = useState<Record<number, string[]>>({});
  const [finderCleaned, setFinderCleaned] = useState<CleanReport | null>(null);
  const [startupItems, setStartupItems] = useState<StartupItem[] | null>(null);
  const [programs, setPrograms] = useState<InstalledProgram[] | null>(null);
  const [programSearch, setProgramSearch] = useState("");
  const [registryResult, setRegistryResult] = useState<RegistryScanResult | null>(null);
  const [registrySelected, setRegistrySelected] = useState<string[]>([]);
  const [registryCleaned, setRegistryCleaned] = useState<RegistryCleanResult | null>(null);
  const [analyzerProgress, setAnalyzerProgress] = useState<ScanProgress | null>(null);
  const [largeProgress, setLargeProgress] = useState<ScanProgress | null>(null);
  const [duplicateProgress, setDuplicateProgress] = useState<ScanProgress | null>(null);

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
      .catch((reason) =>
        setErrorByScreen((current) => ({ ...current, clean: displayError(reason) })),
      )
      .finally(() => setBusyByScreen((current) => ({ ...current, clean: null })));
  }, []);

  useEffect(() => {
    let disposed = false;
    const subscriptions = Promise.all([
      listen<ScanProgress>("analyze://progress", (event) => {
        if (!disposed) setAnalyzerProgress(event.payload);
      }),
      listen<ScanProgress>("large-files://progress", (event) => {
        if (!disposed) setLargeProgress(event.payload);
      }),
      listen<ScanProgress>("duplicates://progress", (event) => {
        if (!disposed) setDuplicateProgress(event.payload);
      }),
    ]);
    return () => {
      disposed = true;
      void subscriptions.then((unlisten) => {
        for (const dispose of unlisten) dispose();
      });
    };
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
    setErrorFor("clean", null);
    setCleaned(null);
    setBusyFor("clean", "scanning");
    try {
      setReport(await invoke<ScanReport>("scan_rules", { ruleIds: selected }));
    } catch (reason) {
      setErrorFor("clean", displayError(reason));
    } finally {
      setBusyFor("clean", null);
    }
  };
  const clean = async () => {
    if (!report || selected.length === 0) return;
    setErrorFor("clean", null);
    setBusyFor("clean", "cleaning");
    try {
      setCleaned(await invoke<CleanReport>("clean_rules", { ruleIds: selected, permanent: false }));
      setReport(null);
      setStats(await invoke<SystemStats>("get_system_stats"));
    } catch (reason) {
      setErrorFor("clean", displayError(reason));
    } finally {
      setBusyFor("clean", null);
    }
  };
  const restore = async (target: Screen = "clean") => {
    setErrorFor(target, null);
    setBusyFor(target, "restoring");
    try {
      const restored = await invoke<CleanReport>("restore_last_quarantine");
      setCleaned(restored);
      setFinderCleaned(restored);
      setStats(await invoke<SystemStats>("get_system_stats"));
    } catch (reason) {
      setErrorFor(target, displayError(reason));
    } finally {
      setBusyFor(target, null);
    }
  };
  const activate = async () => {
    setErrorFor("license", null);
    setBusyFor("license", "loading");
    try {
      setLicense(await invoke<LicenseStatus>("activate_license", { key: licenseKey }));
      setLicenseKey("");
      setScreen("clean");
    } catch (reason) {
      setErrorFor("license", displayError(reason));
    } finally {
      setBusyFor("license", null);
    }
  };
  const deactivate = async () => {
    setErrorFor("license", null);
    setBusyFor("license", "loading");
    try {
      setLicense(await invoke<LicenseStatus>("deactivate_license"));
    } catch (reason) {
      setErrorFor("license", displayError(reason));
    } finally {
      setBusyFor("license", null);
    }
  };
  const loadSmartClean = async () => {
    setErrorFor("smart", null);
    try {
      const [status, plan] = await Promise.all([
        invoke<SmartCleanStatus>("get_smart_clean_status"),
        invoke<SmartCleanPlan>("get_smart_clean_plan"),
      ]);
      setSmartStatus(status);
      setSmartPlan(plan);
    } catch (reason) {
      setErrorFor("smart", displayError(reason));
    }
  };
  const runSmartClean = async () => {
    setErrorFor("smart", null);
    setBusyFor("smart", "cleaning");
    try {
      const result = await invoke<CleanReport>("smart_clean");
      setCleaned(result);
      setSmartPlan(null);
      setSmartStatus(await invoke<SmartCleanStatus>("get_smart_clean_status"));
      setStats(await invoke<SystemStats>("get_system_stats"));
    } catch (reason) {
      setErrorFor("smart", displayError(reason));
    } finally {
      setBusyFor("smart", null);
    }
  };
  const reviewSmartClean = async () => {
    setCleaned(null);
    await loadSmartClean();
  };
  const analyzeDisk = async (path?: string) => {
    setErrorFor("analyzer", null);
    setFinderCleaned(null);
    setBusyFor("analyzer", "scanning");
    setAnalyzerProgress({ done: 0, total: 0, name: "" });
    try {
      const nextPath = typeof path === "string" ? path : analyzerPath;
      setAnalyzerPath(nextPath);
      setAnalyzerEntries(await invoke<DiskEntry[]>("analyze_disk", { path: nextPath || null }));
      setSelectedAnalyzer([]);
    } catch (reason) {
      setErrorFor("analyzer", displayError(reason));
    } finally {
      setAnalyzerProgress(null);
      setBusyFor("analyzer", null);
    }
  };
  const quarantineAnalyzer = async () => {
    if (!selectedAnalyzer.length) return;
    setErrorFor("analyzer", null);
    setBusyFor("analyzer", "cleaning");
    try {
      const confirmed = window.confirm(
        `Move ${selectedAnalyzer.length} selected analyzer item(s) to quarantine? You can undo this from the restore action.`,
      );
      if (!confirmed) return;
      setFinderCleaned(
        await invoke<CleanReport>("quarantine_analyzer_items", { paths: selectedAnalyzer }),
      );
      setAnalyzerEntries(
        (entries) => entries?.filter((entry) => !selectedAnalyzer.includes(entry.path)) ?? null,
      );
      setSelectedAnalyzer([]);
    } catch (reason) {
      setErrorFor("analyzer", displayError(reason));
    } finally {
      setBusyFor("analyzer", null);
    }
  };
  const findLargeFiles = async () => {
    setErrorFor("large", null);
    setFinderCleaned(null);
    setBusyFor("large", "scanning");
    setLargeProgress({ done: 0, total: 0, name: "" });
    try {
      const files = await invoke<LargeFile[]>("find_large_files", {
        path: largePath || null,
        minBytes: largeThreshold * 1024 * 1024,
      });
      setLargeFiles(files);
      setSelectedLarge([]);
    } catch (reason) {
      setErrorFor("large", displayError(reason));
    } finally {
      setLargeProgress(null);
      setBusyFor("large", null);
    }
  };
  const findDuplicates = async () => {
    setErrorFor("duplicates", null);
    setFinderCleaned(null);
    setBusyFor("duplicates", "scanning");
    setDuplicateProgress({ done: 0, total: 0, name: "" });
    try {
      const groups = await invoke<DuplicateGroup[]>("find_duplicates", {
        path: duplicatePath || null,
      });
      setDuplicateGroups(groups);
      setDuplicateKeep(Object.fromEntries(groups.map((group, index) => [index, group.files[0]])));
      setDuplicateRemoved(
        Object.fromEntries(groups.map((group, index) => [index, group.files.slice(1)])),
      );
    } catch (reason) {
      setErrorFor("duplicates", displayError(reason));
    } finally {
      setDuplicateProgress(null);
      setBusyFor("duplicates", null);
    }
  };
  const removeLargeFiles = async () => {
    if (selectedLarge.length === 0) return;
    setErrorFor("large", null);
    setBusyFor("large", "cleaning");
    try {
      setFinderCleaned(
        await invoke<CleanReport>("quarantine_paths", {
          paths: selectedLarge,
          keepPaths: [],
        }),
      );
      setLargeFiles((files) => files?.filter((file) => !selectedLarge.includes(file.path)) ?? null);
      setSelectedLarge([]);
    } catch (reason) {
      setErrorFor("large", displayError(reason));
    } finally {
      setBusyFor("large", null);
    }
  };
  const removeDuplicates = async () => {
    if (!duplicateGroups) return;
    const selections: DuplicateRemoval[] = duplicateGroups.flatMap((group, index) => {
      const remove = duplicateRemoved[index] ?? [];
      if (!remove.length) return [];
      return [
        {
          group: group.files,
          remove,
          keep: duplicateKeep[index] ?? group.files[0],
        },
      ];
    });
    if (!selections.length) return;
    setErrorFor("duplicates", null);
    setBusyFor("duplicates", "cleaning");
    try {
      setFinderCleaned(await invoke<CleanReport>("quarantine_duplicate_files", { selections }));
      const removed = new Set(selections.flatMap((selection) => selection.remove));
      setDuplicateGroups((groups) =>
        groups
          ? groups
              .map((group) => ({
                ...group,
                files: group.files.filter((file) => !removed.has(file)),
              }))
              .filter((group) => group.files.length > 1)
          : null,
      );
      setDuplicateRemoved({});
    } catch (reason) {
      setErrorFor("duplicates", displayError(reason));
    } finally {
      setBusyFor("duplicates", null);
    }
  };
  const loadStartup = async () => {
    setErrorFor("startup", null);
    setBusyFor("startup", "loading");
    try {
      setStartupItems(await invoke<StartupItem[]>("list_startup_items"));
    } catch (reason) {
      setErrorFor("startup", displayError(reason));
    } finally {
      setBusyFor("startup", null);
    }
  };
  const toggleStartup = async (id: string, enabled: boolean) => {
    setErrorFor("startup", null);
    try {
      const updated = await invoke<StartupItem>("set_startup_item_enabled", { id, enabled });
      setStartupItems(
        (items) => items?.map((item) => (item.id === updated.id ? updated : item)) ?? null,
      );
    } catch (reason) {
      setErrorFor("startup", displayError(reason));
    }
  };
  const loadPrograms = async () => {
    setErrorFor("apps", null);
    setBusyFor("apps", "loading");
    try {
      setPrograms(await invoke<InstalledProgram[]>("list_installed_programs"));
    } catch (reason) {
      setErrorFor("apps", displayError(reason));
    } finally {
      setBusyFor("apps", null);
    }
  };
  const uninstallProgram = async (id: string) => {
    setErrorFor("apps", null);
    try {
      const result = await invoke<UninstallResult>("uninstall_program", { id });
      if (result.command && !result.launched) {
        await navigator.clipboard?.writeText(result.command).catch(() => undefined);
      }
      setErrorFor("apps", result.message);
    } catch (reason) {
      setErrorFor("apps", displayError(reason));
    }
  };
  const scanRegistry = async () => {
    setErrorFor("registry", null);
    setRegistryCleaned(null);
    setBusyFor("registry", "scanning");
    try {
      const result = await invoke<RegistryScanResult>("scan_registry");
      setRegistryResult(result);
      setRegistrySelected(result.findings.map((finding) => finding.id));
    } catch (reason) {
      setErrorFor("registry", displayError(reason));
    } finally {
      setBusyFor("registry", null);
    }
  };
  const cleanRegistry = async () => {
    if (!registrySelected.length) return;
    setErrorFor("registry", null);
    setBusyFor("registry", "cleaning");
    try {
      setRegistryCleaned(
        await invoke<RegistryCleanResult>("clean_registry", { findingIds: registrySelected }),
      );
      setRegistryResult((result) =>
        result
          ? {
              ...result,
              findings: result.findings.filter((finding) => !registrySelected.includes(finding.id)),
            }
          : null,
      );
      setRegistrySelected([]);
    } catch (reason) {
      setErrorFor("registry", displayError(reason));
    } finally {
      setBusyFor("registry", null);
    }
  };

  return (
    <main className="desktop-app">
      <AppRail
        screen={screen}
        isPro={isPro}
        onNavigate={(next) => {
          setScreen(next);
          if (next === "smart") void loadSmartClean();
        }}
      />
      <section className="app-pane">
        <header className="app-header">
          <div className="breadcrumb">
            <button type="button" className="breadcrumb-home" onClick={() => setScreen("clean")}>
              Dustonic
            </button>
            <ChevronRight size={13} />
            <strong>{screenLabel(screen)}</strong>
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
        <AppErrorBoundary>
          <div className="app-content">
            {screen === "clean" ? (
              <CleanScreen
                catalog={catalog}
                stats={stats}
                report={report}
                cleaned={cleaned}
                selected={selected}
                isPro={isPro}
                busy={busyFor("clean")}
                error={errorFor("clean")}
                onToggle={toggleRule}
                onSelectAll={selectAll}
                onClearAll={clearAll}
                onUpgrade={() => setScreen("license")}
                onScan={scan}
                onClean={clean}
                onRestore={() => restore("clean")}
                onAgain={() => setCleaned(null)}
                onChangeScan={() => setReport(null)}
                onDismissError={() => setErrorFor("clean", null)}
              />
            ) : screen === "smart" ? (
              <SmartCleanScreen
                plan={smartPlan}
                status={smartStatus}
                cleaned={cleaned}
                busy={busyFor("smart")}
                error={errorFor("smart")}
                onRun={runSmartClean}
                onAgain={reviewSmartClean}
                onRestore={() => restore("smart")}
                onDismissError={() => setErrorFor("smart", null)}
              />
            ) : screen === "analyzer" ? (
              <AnalyzerScreen
                path={analyzerPath}
                entries={analyzerEntries}
                selected={selectedAnalyzer}
                busy={busyFor("analyzer")}
                progress={analyzerProgress}
                error={errorFor("analyzer")}
                onPathChange={setAnalyzerPath}
                onAnalyze={analyzeDisk}
                onDrill={(path) => analyzeDisk(path)}
                onToggle={(path) =>
                  setSelectedAnalyzer((current) =>
                    current.includes(path)
                      ? current.filter((item) => item !== path)
                      : [...current, path],
                  )
                }
                onQuarantine={quarantineAnalyzer}
                onRestore={() => restore("analyzer")}
                onDismissError={() => setErrorFor("analyzer", null)}
              />
            ) : screen === "large" ? (
              <LargeFilesScreen
                path={largePath}
                threshold={largeThreshold}
                files={largeFiles}
                selected={selectedLarge}
                cleaned={finderCleaned}
                busy={busyFor("large")}
                progress={largeProgress}
                error={errorFor("large")}
                isPro={isPro}
                onPathChange={setLargePath}
                onThresholdChange={setLargeThreshold}
                onFind={findLargeFiles}
                onToggle={(path) =>
                  setSelectedLarge((current) =>
                    current.includes(path)
                      ? current.filter((item) => item !== path)
                      : [...current, path],
                  )
                }
                onRemove={removeLargeFiles}
                onRestore={() => restore("large")}
                onAgain={() => setFinderCleaned(null)}
                onUpgrade={() => setScreen("license")}
                onDismissError={() => setErrorFor("large", null)}
              />
            ) : screen === "duplicates" ? (
              <DuplicatesScreen
                path={duplicatePath}
                groups={duplicateGroups}
                keep={duplicateKeep}
                removed={duplicateRemoved}
                cleaned={finderCleaned}
                busy={busyFor("duplicates")}
                progress={duplicateProgress}
                error={errorFor("duplicates")}
                isPro={isPro}
                onPathChange={setDuplicatePath}
                onFind={findDuplicates}
                onKeepChange={(index, value) =>
                  setDuplicateKeep((current) => ({ ...current, [index]: value }))
                }
                onToggle={(index, path) =>
                  setDuplicateRemoved((current) => ({
                    ...current,
                    [index]: (current[index] ?? []).includes(path)
                      ? (current[index] ?? []).filter((item) => item !== path)
                      : [...(current[index] ?? []), path],
                  }))
                }
                onRemove={removeDuplicates}
                onRestore={() => restore("duplicates")}
                onAgain={() => setFinderCleaned(null)}
                onUpgrade={() => setScreen("license")}
                onDismissError={() => setErrorFor("duplicates", null)}
              />
            ) : screen === "startup" ? (
              <StartupScreen
                items={startupItems}
                busy={busyFor("startup")}
                error={errorFor("startup")}
                onLoad={loadStartup}
                onToggle={toggleStartup}
                onDismissError={() => setErrorFor("startup", null)}
              />
            ) : screen === "apps" ? (
              <AppsScreen
                programs={programs}
                search={programSearch}
                busy={busyFor("apps")}
                error={errorFor("apps")}
                onSearch={setProgramSearch}
                onLoad={loadPrograms}
                onUninstall={uninstallProgram}
                onDismissError={() => setErrorFor("apps", null)}
              />
            ) : screen === "registry" ? (
              <RegistryScreen
                result={registryResult}
                cleaned={registryCleaned}
                selected={registrySelected}
                busy={busyFor("registry")}
                error={errorFor("registry")}
                isPro={isPro}
                onScan={scanRegistry}
                onToggle={(id) =>
                  setRegistrySelected((current) =>
                    current.includes(id)
                      ? current.filter((value) => value !== id)
                      : [...current, id],
                  )
                }
                onClean={cleanRegistry}
                onUpgrade={() => setScreen("license")}
                onDismissError={() => setErrorFor("registry", null)}
              />
            ) : screen === "license" ? (
              <LicenseScreen
                license={license}
                licenseKey={licenseKey}
                setLicenseKey={setLicenseKey}
                busy={busyFor("license") === "loading"}
                error={errorFor("license")}
                onActivate={activate}
                onDeactivate={deactivate}
                onCheckout={() => void openUrl(productConfig.checkoutUrl)}
              />
            ) : (
              <SettingsScreen theme={theme} onThemeChange={setTheme} />
            )}
          </div>
        </AppErrorBoundary>
        <footer className="status-bar">
          <span>
            <span className="status-dot" />
            {screen === "clean" ? "Ready" : `${screenLabel(screen)} ready`}
          </span>
          <span>{isPro ? "Pro license active" : "Free plan"} · Quarantine protected</span>
        </footer>
      </section>
    </main>
  );
}

type AppErrorBoundaryState = { hasError: boolean };

class AppErrorBoundary extends Component<{ children: ReactNode }, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Dustonic UI render error", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="app-error-state" role="alert">
          <div className="app-error-card">
            <span className="app-error-mark">!</span>
            <small className="eyebrow">DUSTONIC UI</small>
            <h1>This screen ran into a problem</h1>
            <p>Your files are untouched. Reload the app to return to the utility workspace.</p>
            <button
              type="button"
              className="primary-button"
              onClick={() => window.location.reload()}
            >
              Reload Dustonic
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
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
          active={screen === "smart"}
          label="Smart Clean"
          onClick={() => onNavigate("smart")}
        >
          <Sparkles size={19} />
        </RailButton>
        <RailButton
          active={screen === "analyzer"}
          label="Disk analyzer"
          onClick={() => onNavigate("analyzer")}
        >
          <BarChart3 size={19} />
        </RailButton>
        <RailButton
          active={screen === "large"}
          label="Large files"
          onClick={() => onNavigate("large")}
        >
          <FileSearch size={19} />
          {!isPro && <span className="rail-badge">PRO</span>}
        </RailButton>
        <RailButton
          active={screen === "duplicates"}
          label="Duplicate finder"
          onClick={() => onNavigate("duplicates")}
        >
          <Files size={19} />
          {!isPro && <span className="rail-badge">PRO</span>}
        </RailButton>
        <RailButton
          active={screen === "startup"}
          label="Startup manager"
          onClick={() => onNavigate("startup")}
        >
          <Power size={19} />
        </RailButton>
        <RailButton
          active={screen === "apps"}
          label="Installed apps"
          onClick={() => onNavigate("apps")}
        >
          <PackageOpen size={19} />
        </RailButton>
        <RailButton
          active={screen === "registry"}
          label="Windows registry tools"
          onClick={() => onNavigate("registry")}
        >
          <Wrench size={19} />
          {!isPro && <span className="rail-badge">PRO</span>}
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
        <span className="rail-version">0.2.15</span>
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
      <TableHeader className="rules-table-header">
        <span />
        <span>Rule</span>
        <span>Risk</span>
        <span>Access</span>
        <span>Action</span>
      </TableHeader>
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
      <TableHeader className="rules-table-header">
        <span />
        <span>Rule</span>
        <span>Risk</span>
        <span>Access</span>
        <span>Size</span>
      </TableHeader>
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

function FinderHeading({
  eyebrow,
  title,
  text,
  icon,
}: {
  eyebrow: string;
  title: string;
  text: string;
  icon: ReactNode;
}) {
  return (
    <div className="finder-heading">
      <span className="finder-icon">{icon}</span>
      <div>
        <h1>{title}</h1>
      </div>
    </div>
  );
}

function TableHeader({ className = "", children }: { className?: string; children: ReactNode }) {
  return <div className={`table-header ${className}`}>{children}</div>;
}

function PathControl({
  path,
  onChange,
  onScan,
  busy,
  action,
}: {
  path: string;
  onChange: (value: string) => void;
  onScan: () => void;
  busy: boolean;
  action: string;
}) {
  return (
    <div className="finder-controls">
      <div className="path-input">
        <FolderOpen size={15} />
        <input
          value={path}
          onChange={(event) => onChange(event.target.value)}
          placeholder="User home directory"
          aria-label="Folder path"
        />
      </div>
      <button type="button" className="primary-button" onClick={onScan} disabled={busy}>
        {busy ? <LoaderCircle className="spin" size={15} /> : <ScanSearch size={15} />}
        {busy ? "Scanning…" : action}
      </button>
    </div>
  );
}

function FinderError({
  error,
  onDismiss,
}: {
  error: string | null;
  onDismiss: () => void;
}) {
  if (!error) return null;
  return (
    <div className="notice error-notice" role="alert">
      <Info size={16} />
      <span>{error}</span>
      <button type="button" aria-label="Dismiss error" onClick={onDismiss}>
        <X size={14} />
      </button>
    </div>
  );
}

function FinderScanningState({
  progress,
  message,
}: {
  progress: ScanProgress | null;
  message: string;
}) {
  const measured = progress?.total
    ? `Measured ${progress.done} of ${progress.total} folders…`
    : "Preparing the folder scan…";
  return (
    <output className="finder-scanning" aria-live="polite">
      <LoaderCircle className="spin" size={22} />
      <strong>{message}</strong>
      <span>{measured}</span>
      {progress?.name && <small>Current: {progress.name}</small>}
    </output>
  );
}

function AnalyzerScreen({
  path,
  entries,
  selected,
  progress,
  busy,
  error,
  onPathChange,
  onAnalyze,
  onDrill,
  onToggle,
  onQuarantine,
  onRestore,
  onDismissError,
}: {
  path: string;
  entries: DiskEntry[] | null;
  selected: string[];
  progress: ScanProgress | null;
  busy: Busy;
  error: string | null;
  onPathChange: (value: string) => void;
  onAnalyze: () => void;
  onDrill: (path: string) => void;
  onToggle: (path: string) => void;
  onQuarantine: () => void;
  onRestore: () => void;
  onDismissError: () => void;
}) {
  const totalBytes = entries?.reduce((total, entry) => total + entry.bytes, 0) ?? 0;
  return (
    <div className="finder-screen">
      <FinderHeading
        eyebrow="FREE TOOL"
        title="Disk space analyzer"
        text="See where your storage is going, one folder at a time. Dustonic only reads and measures."
        icon={<BarChart3 size={18} />}
      />
      <PathControl
        path={path}
        onChange={onPathChange}
        onScan={() => void onAnalyze()}
        busy={busy === "scanning"}
        action="Analyze folder"
      />
      <FinderError error={error} onDismiss={onDismissError} />
      <div className="finder-list-panel">
        <div className="finder-list-header">
          <div>
            <h2>{path || "User home directory"}</h2>
            <p>Immediate children · sorted largest first · quarantine-first cleanup</p>
          </div>
          {entries && (
            <span className="result-count">
              {entries.length} items · {formatBytes(totalBytes)}
            </span>
          )}
        </div>
        <TableHeader className="analyzer-table-header">
          <span />
          <span>Name</span>
          <span>Distribution</span>
          <span>Size</span>
          <span />
        </TableHeader>
        {busy === "scanning" ? (
          <FinderScanningState
            progress={progress}
            message="Measuring folder sizes — large folders like your home or C: can take a minute"
          />
        ) : !entries ? (
          <div className="list-empty">
            <BarChart3 size={18} /> Choose a folder to see its storage breakdown.
          </div>
        ) : entries.length === 0 ? (
          <div className="list-empty">This folder is empty or cannot be read.</div>
        ) : (
          <div className="analysis-items">
            {entries.map((entry) => (
              <div className="analysis-row" key={entry.path}>
                <input
                  type="checkbox"
                  checked={selected.includes(entry.path)}
                  disabled={!entry.selectable}
                  onChange={() => onToggle(entry.path)}
                  aria-label={`Select ${entry.name}`}
                />
                <span className="analysis-type">
                  {entry.is_directory ? <FolderOpen size={15} /> : <Files size={15} />}
                </span>
                <span className="analysis-copy">
                  <strong>{entry.name}</strong>
                  <small>
                    {entry.is_directory ? "Folder · " : "File · "}
                    <span className={`risk-badge ${entry.risk.toLowerCase()}`}>{entry.risk}</span>
                    {!entry.selectable && " · protected"}
                  </small>
                </span>
                <span className="analysis-bar">
                  <i style={{ width: `${Math.max(entry.percent, 1)}%` }} />
                </span>
                <span className="analysis-size">
                  <strong>{formatBytes(entry.bytes)}</strong>
                  <small>{entry.percent.toFixed(1)}%</small>
                </span>
                {entry.is_directory && (
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={`Open ${entry.name}`}
                    onClick={() => onDrill(entry.path)}
                  >
                    <ChevronRight size={14} />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
        {entries && entries.length > 0 && (
          <div className="finder-action-bar">
            <span>
              {selected.length} selected ·{" "}
              {formatBytes(
                entries
                  .filter((entry) => selected.includes(entry.path))
                  .reduce((total, entry) => total + entry.bytes, 0),
              )}
            </span>
            <button
              type="button"
              className="primary-button"
              disabled={!selected.length || busy !== null}
              onClick={onQuarantine}
            >
              <Trash2 size={15} /> Move to quarantine
            </button>
            <button type="button" className="secondary-button" onClick={onRestore}>
              <RotateCcw size={15} /> Restore last
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function SmartCleanScreen({
  plan,
  status,
  cleaned,
  busy,
  error,
  onRun,
  onAgain,
  onRestore,
  onDismissError,
}: {
  plan: SmartCleanPlan | null;
  status: SmartCleanStatus | null;
  cleaned: CleanReport | null;
  busy: Busy;
  error: string | null;
  onRun: () => void;
  onAgain: () => void;
  onRestore: () => void;
  onDismissError: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <div className="finder-screen">
      <FinderHeading
        eyebrow="FREE TOOL"
        title="Smart Clean"
        text="A local recommendation engine that selects only safe, stale, high-value cleanup items. No cloud, chatbot, or telemetry."
        icon={<Sparkles size={18} />}
      />
      <FinderError error={error} onDismiss={onDismissError} />
      {cleaned ? (
        <div className="completion">
          <CheckCircle2 size={36} className="completion-icon" />
          <small className="eyebrow">QUARANTINE COMPLETE</small>
          <h2>{formatBytes(cleaned.bytes_freed)} moved safely</h2>
          <p>{cleaned.items} items are ready to restore if you change your mind.</p>
          <div className="completion-actions">
            <button type="button" className="secondary-button" onClick={onRestore}>
              <RotateCcw size={15} /> Restore last quarantine
            </button>
            <button
              type="button"
              className="primary-button"
              onClick={() => {
                setConfirming(false);
                onAgain();
              }}
            >
              Run another review
            </button>
          </div>
        </div>
      ) : (
        <div className="smart-panel">
          <div className="smart-panel-copy">
            <span className="pro-lock-icon">
              <Sparkles size={19} />
            </span>
            <small className="eyebrow">RECOMMENDATION ENGINE</small>
            <h2>One safe pass, reviewed before it runs</h2>
            <p>
              Smart Clean scores the existing cleaner rules by safety, reclaimable size, and
              staleness, then quarantines the recommended safe items. Nothing is permanently
              deleted.
            </p>
          </div>
          <div className="smart-plan">
            <div>
              <span>Estimated reclaim</span>
              <strong>{plan ? formatBytes(plan.bytes) : "Preparing…"}</strong>
            </div>
            <div>
              <span>Recommended items</span>
              <strong>{plan?.items ?? "—"}</strong>
            </div>
            <div>
              <span>Free runs remaining</span>
              <strong>{status?.remaining_free_runs ?? "Unlimited"}</strong>
            </div>
          </div>
          {plan && plan.groups.length > 0 && (
            <div className="smart-review">
              <div className="smart-review-heading">
                <strong>Review these recommended items</strong>
                <span>
                  Showing sample paths from each rule; totals include every matching item.
                </span>
              </div>
              <div className="smart-review-list">
                {plan.groups.map((group) => (
                  <details key={group.rule_id} className="smart-review-group">
                    <summary>
                      <span>
                        <strong>{group.name}</strong>
                        <small>
                          {group.category} · {group.items} items
                        </small>
                      </span>
                      <b>{formatBytes(group.bytes)}</b>
                    </summary>
                    <div className="smart-paths">
                      {group.paths.map((path) => (
                        <code key={path}>{path}</code>
                      ))}
                      {group.items > group.paths.length && (
                        <small>{group.items - group.paths.length} more items included</small>
                      )}
                    </div>
                  </details>
                ))}
              </div>
            </div>
          )}
          <div className="finder-action-bar">
            <span>All selected items are marked Safe · Undo remains available</span>
            {!confirming ? (
              <button
                type="button"
                className="primary-button"
                disabled={!plan?.items || busy !== null || status?.remaining_free_runs === 0}
                onClick={() => setConfirming(true)}
              >
                <Sparkles size={15} /> Review complete — continue
              </button>
            ) : (
              <span className="smart-confirm-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setConfirming(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="primary-button"
                  disabled={busy !== null}
                  onClick={onRun}
                >
                  {busy === "cleaning" ? (
                    <LoaderCircle className="spin" size={15} />
                  ) : (
                    <Sparkles size={15} />
                  )}
                  {busy === "cleaning" ? "Cleaning…" : "Clean reviewed items"}
                </button>
              </span>
            )}
          </div>
          {status?.remaining_free_runs === 0 && (
            <div className="notice">
              Smart Clean is limited to 2 free runs per day. Upgrade to Pro for unlimited runs.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ProLockedTool({
  title,
  text,
  onUpgrade,
}: {
  title: string;
  text: string;
  onUpgrade: () => void;
}) {
  return (
    <div className="pro-locked-panel">
      <span className="pro-lock-icon">
        <LockKeyhole size={19} />
      </span>
      <small className="eyebrow">DUSTONIC PRO</small>
      <h2>{title}</h2>
      <p>{text}</p>
      <button type="button" className="primary-button" onClick={onUpgrade}>
        Unlock Pro — one-time, lifetime <ChevronRight size={15} />
      </button>
    </div>
  );
}

function LargeFilesScreen({
  path,
  threshold,
  files,
  progress,
  selected,
  cleaned,
  busy,
  error,
  isPro,
  onPathChange,
  onThresholdChange,
  onFind,
  onToggle,
  onRemove,
  onRestore,
  onAgain,
  onUpgrade,
  onDismissError,
}: {
  path: string;
  threshold: number;
  files: LargeFile[] | null;
  progress: ScanProgress | null;
  selected: string[];
  cleaned: CleanReport | null;
  busy: Busy;
  error: string | null;
  isPro: boolean;
  onPathChange: (value: string) => void;
  onThresholdChange: (value: number) => void;
  onFind: () => void;
  onToggle: (path: string) => void;
  onRemove: () => void;
  onRestore: () => void;
  onAgain: () => void;
  onUpgrade: () => void;
  onDismissError: () => void;
}) {
  const totalBytes = files?.reduce((total, file) => total + file.bytes, 0) ?? 0;
  return (
    <div className="finder-screen">
      <FinderHeading
        eyebrow="PRO TOOL"
        title="Large file finder"
        text="Find the space-hungry files hiding in your home folder. Review every path before anything moves."
        icon={<FileSearch size={18} />}
      />
      {!isPro ? (
        <ProLockedTool
          title="Find the files worth moving"
          text="Large-file finder is included with Pro. Files are quarantined first, so cleanup stays undoable."
          onUpgrade={onUpgrade}
        />
      ) : cleaned ? (
        <CompletionPanel report={cleaned} busy={busy} onRestore={onRestore} onAgain={onAgain} />
      ) : (
        <>
          <PathControl
            path={path}
            onChange={onPathChange}
            onScan={onFind}
            busy={busy === "scanning"}
            action="Find large files"
          />
          <div className="threshold-control">
            <label htmlFor="large-threshold">Minimum size</label>
            <input
              id="large-threshold"
              type="range"
              min="1"
              max="1024"
              step="1"
              value={threshold}
              onChange={(event) => onThresholdChange(Number(event.target.value))}
            />
            <strong>
              {threshold >= 1024 ? `${(threshold / 1024).toFixed(1)} GB` : `${threshold} MB`}
            </strong>
          </div>
          <FinderError error={error} onDismiss={onDismissError} />
          <div className="finder-list-panel">
            <div className="finder-list-header">
              <div>
                <h2>
                  {files
                    ? `${files.length} large files · ${formatBytes(totalBytes)}`
                    : "No scan yet"}
                </h2>
                <p>Top 200 results · files move to quarantine before removal</p>
              </div>
              {files && <span className="result-count">{selected.length} selected</span>}
            </div>
            <TableHeader className="file-table-header">
              <span />
              <span>File</span>
              <span>Size</span>
            </TableHeader>
            {busy === "scanning" ? (
              <FinderScanningState
                progress={progress}
                message="Scanning for large files — large folders can take a minute"
              />
            ) : !files ? (
              <div className="list-empty">
                <FileSearch size={18} /> Scan a folder to find large files.
              </div>
            ) : (
              <div className="analysis-items">
                {files.map((file) => (
                  <label className="finder-file-row" key={file.path}>
                    <input
                      type="checkbox"
                      checked={selected.includes(file.path)}
                      onChange={() => onToggle(file.path)}
                    />
                    <span className="checkbox">
                      {selected.includes(file.path) && <Check size={12} />}
                    </span>
                    <span className="finder-file-copy">
                      <strong>{file.path.split(/[\\/]/).pop()}</strong>
                      <small>{file.path}</small>
                    </span>
                    <span className="result-size">
                      <strong>{formatBytes(file.bytes)}</strong>
                      <small>
                        {file.modified ? new Date(file.modified * 1000).toLocaleDateString() : "—"}
                      </small>
                    </span>
                  </label>
                ))}
              </div>
            )}
          </div>
          <div className="finder-action-bar">
            <span>
              <strong>{selected.length}</strong> selected
            </span>
            <button
              type="button"
              className="secondary-button"
              onClick={onRemove}
              disabled={busy !== null || selected.length === 0}
            >
              {busy === "cleaning" ? (
                <LoaderCircle className="spin" size={14} />
              ) : (
                <Trash2 size={14} />
              )}
              Move to quarantine
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function DuplicatesScreen({
  path,
  groups,
  progress,
  keep,
  removed,
  cleaned,
  busy,
  error,
  isPro,
  onPathChange,
  onFind,
  onKeepChange,
  onToggle,
  onRemove,
  onRestore,
  onAgain,
  onUpgrade,
  onDismissError,
}: {
  path: string;
  groups: DuplicateGroup[] | null;
  progress: ScanProgress | null;
  keep: Record<number, string>;
  removed: Record<number, string[]>;
  cleaned: CleanReport | null;
  busy: Busy;
  error: string | null;
  isPro: boolean;
  onPathChange: (value: string) => void;
  onFind: () => void;
  onKeepChange: (index: number, value: string) => void;
  onToggle: (index: number, path: string) => void;
  onRemove: () => void;
  onRestore: () => void;
  onAgain: () => void;
  onUpgrade: () => void;
  onDismissError: () => void;
}) {
  const selectedCount = Object.values(removed).reduce((sum, values) => sum + values.length, 0);
  const totalReclaimable =
    groups?.reduce((total, group) => total + group.size * Math.max(group.count - 1, 0), 0) ?? 0;
  return (
    <div className="finder-screen">
      <FinderHeading
        eyebrow="PRO TOOL"
        title="Duplicate finder"
        text="Compare identical files by content, keep the copy you trust, and reclaim the rest safely."
        icon={<Files size={18} />}
      />
      {!isPro ? (
        <ProLockedTool
          title="Clean up copies, not originals"
          text="Duplicate finder is included with Pro. Dustonic always requires one copy to remain in every group."
          onUpgrade={onUpgrade}
        />
      ) : cleaned ? (
        <CompletionPanel report={cleaned} busy={busy} onRestore={onRestore} onAgain={onAgain} />
      ) : (
        <>
          <PathControl
            path={path}
            onChange={onPathChange}
            onScan={onFind}
            busy={busy === "scanning"}
            action="Find duplicates"
          />
          <FinderError error={error} onDismiss={onDismissError} />
          <div className="finder-list-panel">
            <div className="finder-list-header">
              <div>
                <h2>
                  {groups
                    ? `${groups.length} duplicate groups · ${formatBytes(totalReclaimable)} reclaimable`
                    : "No scan yet"}
                </h2>
                <p>Identical content · one copy is always kept</p>
              </div>
              {groups && <span className="result-count">{selectedCount} selected</span>}
            </div>
            <TableHeader className="duplicate-table-header">
              <span />
              <span>File</span>
              <span>Action</span>
            </TableHeader>
            {busy === "scanning" ? (
              <FinderScanningState
                progress={progress}
                message="Checking files for duplicates — hashing can take a minute"
              />
            ) : !groups ? (
              <div className="list-empty">
                <Files size={18} /> Scan a folder to find identical files.
              </div>
            ) : groups.length === 0 ? (
              <div className="list-empty">No duplicate files found.</div>
            ) : (
              <div className="duplicate-groups">
                {groups.map((group, index) => (
                  <div className="duplicate-group" key={`${group.files[0]}-${group.size}`}>
                    <div className="duplicate-group-header">
                      <strong>{formatBytes(group.size)} each</strong>
                      <span>{group.count} identical copies</span>
                    </div>
                    {group.files.map((file) => {
                      const isKeep = (keep[index] ?? group.files[0]) === file;
                      const isRemoved = (removed[index] ?? []).includes(file);
                      return (
                        <label className={`finder-file-row ${isKeep ? "kept" : ""}`} key={file}>
                          <input
                            type="checkbox"
                            checked={isRemoved}
                            onChange={() => !isKeep && onToggle(index, file)}
                            disabled={isKeep}
                          />
                          <span className="checkbox">{isRemoved && <Check size={12} />}</span>
                          <span className="finder-file-copy">
                            <strong>{file.split(/[\\/]/).pop()}</strong>
                            <small>{file}</small>
                          </span>
                          {isKeep ? (
                            <span className="tag safe">Keep</span>
                          ) : (
                            <button
                              type="button"
                              className="text-button keep-button"
                              onClick={(event) => {
                                event.preventDefault();
                                onKeepChange(index, file);
                              }}
                            >
                              Keep this
                            </button>
                          )}
                        </label>
                      );
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="finder-action-bar">
            <span>
              <strong>{selectedCount}</strong> selected · one copy kept per group
            </span>
            <button
              type="button"
              className="secondary-button"
              onClick={onRemove}
              disabled={busy !== null || selectedCount === 0}
            >
              {busy === "cleaning" ? (
                <LoaderCircle className="spin" size={14} />
              ) : (
                <Trash2 size={14} />
              )}
              Move duplicates to quarantine
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function StartupScreen({
  items,
  busy,
  error,
  onLoad,
  onToggle,
  onDismissError,
}: {
  items: StartupItem[] | null;
  busy: Busy;
  error: string | null;
  onLoad: () => void;
  onToggle: (id: string, enabled: boolean) => void;
  onDismissError: () => void;
}) {
  const groups = items?.reduce<Record<string, StartupItem[]>>((result, item) => {
    if (!result[item.source]) result[item.source] = [];
    result[item.source].push(item);
    return result;
  }, {});
  return (
    <div className="system-screen">
      <FinderHeading
        eyebrow="FREE TOOL"
        title="Startup manager"
        text="See what starts with your system. Dustonic changes reversible startup settings, never deletes entries."
        icon={<Power size={18} />}
      />
      <div className="system-toolbar">
        <span>{items ? `${items.length} startup entries` : "Review boot-time applications"}</span>
        <button type="button" className="primary-button" onClick={onLoad} disabled={busy !== null}>
          {busy === "loading" ? (
            <LoaderCircle className="spin" size={15} />
          ) : (
            <RotateCcw size={15} />
          )}
          {items ? "Refresh" : "Load startup entries"}
        </button>
      </div>
      <FinderError error={error} onDismiss={onDismissError} />
      {!groups ? (
        <div className="list-empty system-empty">
          <Power size={18} /> Load startup entries to review them by source.
        </div>
      ) : Object.keys(groups).length === 0 ? (
        <div className="list-empty system-empty">No startup entries were found.</div>
      ) : (
        <div className="system-groups">
          {Object.entries(groups).map(([source, sourceItems]) => (
            <div className="finder-list-panel" key={source}>
              <div className="finder-list-header">
                <div>
                  <h2>{source}</h2>
                  <p>Changes are reversible and apply without deleting the entry.</p>
                </div>
                <span className="result-count">{sourceItems.length} entries</span>
              </div>
              <TableHeader className="startup-table-header">
                <span>Status</span>
                <span>Application / command</span>
                <span>Enabled</span>
              </TableHeader>
              <div className="startup-items">
                {sourceItems.map((item) => (
                  <div className="startup-row" key={item.id}>
                    <span className={`startup-status ${item.enabled ? "on" : ""}`} />
                    <span className="finder-file-copy">
                      <strong>{item.display_name}</strong>
                      <small>{item.command || "No command recorded"}</small>
                    </span>
                    <label className="switch">
                      <input
                        type="checkbox"
                        checked={item.enabled}
                        onChange={(event) => onToggle(item.id, event.target.checked)}
                      />
                      <span />
                    </label>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AppsScreen({
  programs,
  search,
  busy,
  error,
  onSearch,
  onLoad,
  onUninstall,
  onDismissError,
}: {
  programs: InstalledProgram[] | null;
  search: string;
  busy: Busy;
  error: string | null;
  onSearch: (value: string) => void;
  onLoad: () => void;
  onUninstall: (id: string) => void;
  onDismissError: () => void;
}) {
  const filtered = programs?.filter((program) =>
    `${program.name} ${program.publisher ?? ""}`.toLowerCase().includes(search.toLowerCase()),
  );
  const knownSize =
    filtered?.reduce((total, program) => total + (program.estimated_size ?? 0), 0) ?? 0;
  return (
    <div className="system-screen">
      <FinderHeading
        eyebrow="FREE TOOL"
        title="Installed apps"
        text="Review installed programs without touching them automatically. Windows hands off to the vendor uninstaller; Linux shows the exact manual command."
        icon={<PackageOpen size={18} />}
      />
      <div className="system-toolbar">
        <div className="search-input">
          <Search size={15} />
          <input
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Search installed apps"
            aria-label="Search installed apps"
          />
        </div>
        <button type="button" className="primary-button" onClick={onLoad} disabled={busy !== null}>
          {busy === "loading" ? (
            <LoaderCircle className="spin" size={15} />
          ) : (
            <RotateCcw size={15} />
          )}
          {programs ? "Refresh" : "Load apps"}
        </button>
      </div>
      <FinderError error={error} onDismiss={onDismissError} />
      <div className="finder-list-panel">
        <div className="finder-list-header">
          <div>
            <h2>
              {filtered
                ? `${filtered.length} applications · ${formatBytes(knownSize)} known size`
                : "No scan yet"}
            </h2>
            <p>Uninstall actions are explicit and never silently remove files.</p>
          </div>
        </div>
        <TableHeader className="app-table-header">
          <span />
          <span>Application</span>
          <span>Estimated size</span>
          <span>Action</span>
        </TableHeader>
        {!filtered ? (
          <div className="list-empty">
            <PackageOpen size={18} /> Load the installed-program inventory to begin.
          </div>
        ) : filtered.length === 0 ? (
          <div className="list-empty">
            {programs?.length === 0 ? "No installed programs found." : "No matching applications."}
          </div>
        ) : (
          <div className="app-items">
            {filtered.map((program) => (
              <div className="app-row" key={program.id}>
                <span className="analysis-type">
                  <PackageOpen size={15} />
                </span>
                <span className="finder-file-copy">
                  <strong>{program.name}</strong>
                  <small>
                    {[program.version, program.publisher, program.location]
                      .filter(Boolean)
                      .join(" · ") || "No additional metadata"}
                  </small>
                </span>
                <span className="result-size">
                  <strong>
                    {program.estimated_size != null ? formatBytes(program.estimated_size) : "—"}
                  </strong>
                  <small>{program.estimated_size != null ? "estimated" : "size unknown"}</small>
                </span>
                <button
                  type="button"
                  className="secondary-button app-action"
                  onClick={() => onUninstall(program.id)}
                >
                  {program.removal_command ? <Copy size={13} /> : <ExternalLink size={13} />}
                  {program.removal_command ? "Copy command" : "Uninstall"}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function RegistryScreen({
  result,
  cleaned,
  selected,
  busy,
  error,
  isPro,
  onScan,
  onToggle,
  onClean,
  onUpgrade,
  onDismissError,
}: {
  result: RegistryScanResult | null;
  cleaned: RegistryCleanResult | null;
  selected: string[];
  busy: Busy;
  error: string | null;
  isPro: boolean;
  onScan: () => void;
  onToggle: (id: string) => void;
  onClean: () => void;
  onUpgrade: () => void;
  onDismissError: () => void;
}) {
  return (
    <div className="system-screen">
      <FinderHeading
        eyebrow="PRO · WINDOWS ONLY"
        title="Registry tools"
        text="A deliberately small, review-first scan for dead App Paths and uninstall references. Backup comes before every removal."
        icon={<Wrench size={18} />}
      />
      {!isPro ? (
        <ProLockedTool
          title="A safer registry cleaner"
          text="Registry tools are part of Dustonic Pro and are available on Windows only. Every selected key is exported before removal."
          onUpgrade={onUpgrade}
        />
      ) : (
        <>
          <div className="system-toolbar">
            <span>
              {result?.supported === false
                ? "Windows only"
                : (result?.message ?? "Conservative scan · no broad registry sweep")}
            </span>
            <button
              type="button"
              className="primary-button"
              onClick={onScan}
              disabled={busy !== null}
            >
              {busy === "scanning" ? (
                <LoaderCircle className="spin" size={15} />
              ) : (
                <ScanSearch size={15} />
              )}
              Scan registry
            </button>
          </div>
          <FinderError error={error} onDismiss={onDismissError} />
          {cleaned ? (
            <div className="registry-result">
              <CheckCircle2 size={22} />
              <strong>{cleaned.cleaned} entries backed up and cleaned</strong>
              <span>{cleaned.message}</span>
              {cleaned.backup_path && <code>{cleaned.backup_path}</code>}
            </div>
          ) : (
            <div className="finder-list-panel">
              <div className="finder-list-header">
                <div>
                  <h2>{result ? `${result.findings.length} findings` : "No scan yet"}</h2>
                  <p>Only explicitly selected findings are eligible for cleanup.</p>
                </div>
                {result && <span className="result-count">{selected.length} selected</span>}
              </div>
              <TableHeader className="registry-table-header">
                <span />
                <span>Value / key path</span>
                <span>Reason</span>
              </TableHeader>
              {!result ? (
                <div className="list-empty">
                  <Wrench size={18} /> Scan the supported Windows registry areas to review findings.
                </div>
              ) : result.findings.length === 0 ? (
                <div className="list-empty">{result.message}</div>
              ) : (
                <div className="registry-items">
                  {result.findings.map((finding) => (
                    <label className="finder-file-row" key={finding.id}>
                      <input
                        type="checkbox"
                        checked={selected.includes(finding.id)}
                        onChange={() => onToggle(finding.id)}
                      />
                      <span className="checkbox">
                        {selected.includes(finding.id) && <Check size={12} />}
                      </span>
                      <span className="finder-file-copy">
                        <strong>{finding.value_name}</strong>
                        <small>{finding.key_path}</small>
                      </span>
                      <span className="registry-reason">{finding.reason}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}
          {result?.findings.length ? (
            <div className="finder-action-bar">
              <span>
                <strong>{selected.length}</strong> selected · backup before cleanup
              </span>
              <button
                type="button"
                className="secondary-button"
                onClick={onClean}
                disabled={busy !== null || !selected.length}
              >
                {busy === "cleaning" ? (
                  <LoaderCircle className="spin" size={14} />
                ) : (
                  <Wrench size={14} />
                )}
                Back up and clean
              </button>
            </div>
          ) : null}
        </>
      )}
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
      <div className={`settings-grid ${isPro ? "single-card" : ""}`}>
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
        {!isPro ? (
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
        ) : (
          <section className="settings-card feature-card pro-confirmation">
            <small className="eyebrow">PRO ACTIVE</small>
            <h2>Thanks for going Pro.</h2>
            <p>Every Dustonic feature is unlocked and ready to use.</p>
            <div className="feature-checkline">
              <CheckCircle2 size={15} /> Deep-clean rules
            </div>
            <div className="feature-checkline">
              <CheckCircle2 size={15} /> Scheduled and automatic cleaning
            </div>
            <div className="feature-checkline">
              <CheckCircle2 size={15} /> Finder and registry tools
            </div>
          </section>
        )}
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
            <strong>Dustonic 0.2.7</strong>
            <small>Windows and Linux · No telemetry</small>
          </span>
        </div>
      </section>
    </div>
  );
}

function ScreenHeading({ eyebrow, title, text }: { eyebrow: string; title: string; text: string }) {
  return (
    <div className="screen-heading">
      <h1>{title}</h1>
    </div>
  );
}
