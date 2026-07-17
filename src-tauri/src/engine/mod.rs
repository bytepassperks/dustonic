use chrono::Utc;
use dirs::home_dir;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::UNIX_EPOCH,
};
use sysinfo::{Disks, System};
use walkdir::WalkDir;

const RULES_JSON: &str = include_str!("rules.json");
const MAX_SAMPLES: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum Risk {
    Safe,
    Caution,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum Target {
    Files,
    Directories,
    Contents,
    Action,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub name: String,
    pub description: String,
    pub risk: Risk,
    pub platforms: Vec<String>,
    pub paths: Vec<String>,
    pub target: Target,
    pub default_enabled: bool,
    pub pro_only: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleInfo {
    #[serde(flatten)]
    pub rule: Rule,
    pub available: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Catalog {
    pub platform: String,
    pub categories: Vec<Category>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Category {
    pub name: String,
    pub rules: Vec<RuleInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleScan {
    pub rule_id: String,
    pub category: String,
    pub name: String,
    pub description: String,
    pub risk: Risk,
    pub pro_only: bool,
    pub items: u64,
    pub bytes: u64,
    pub samples: Vec<String>,
    pub skipped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanReport {
    pub rules: Vec<RuleScan>,
    pub total_items: u64,
    pub total_bytes: u64,
    pub skipped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanReport {
    pub bytes_freed: u64,
    pub items: u64,
    pub skipped: u64,
    pub quarantine_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemStats {
    pub disk_free: u64,
    pub disk_total: u64,
    pub memory_used: u64,
    pub memory_total: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManifestEntry {
    original: String,
    quarantined: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Manifest {
    id: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug)]
struct Engine {
    app_data: PathBuf,
}

impl Engine {
    fn new(app_data: PathBuf) -> Self {
        Self { app_data }
    }

    fn rules(&self) -> Vec<Rule> {
        serde_json::from_str(RULES_JSON).expect("embedded rules must be valid")
    }

    fn catalog(&self) -> Catalog {
        let platform = current_platform().to_string();
        let mut groups: HashMap<String, Vec<RuleInfo>> = HashMap::new();
        for rule in self
            .rules()
            .into_iter()
            .filter(|r| r.platforms.iter().any(|p| p == &platform))
        {
            groups
                .entry(rule.category.clone())
                .or_default()
                .push(RuleInfo {
                    available: true,
                    rule,
                });
        }
        let mut categories: Vec<_> = groups
            .into_iter()
            .map(|(name, mut rules)| {
                rules.sort_by(|a, b| a.rule.name.cmp(&b.rule.name));
                Category { name, rules }
            })
            .collect();
        categories.sort_by(|a, b| a.name.cmp(&b.name));
        Catalog {
            platform,
            categories,
        }
    }

    fn selected_rules(&self, ids: &[String]) -> Result<Vec<Rule>, String> {
        let platform = current_platform();
        let all = self.rules();
        let mut selected = Vec::new();
        for id in ids {
            let rule = all
                .iter()
                .find(|rule| &rule.id == id)
                .ok_or_else(|| format!("Unknown cleaning rule: {id}"))?;
            if !rule.platforms.iter().any(|p| p == platform) {
                return Err(format!("Rule is not available on this platform: {id}"));
            }
            selected.push(rule.clone());
        }
        Ok(selected)
    }

    fn scan(&self, ids: &[String]) -> Result<ScanReport, String> {
        let selected = self.selected_rules(ids)?;
        let rules: Result<Vec<_>, _> = selected
            .par_iter()
            .map(|rule| self.scan_rule(rule))
            .collect();
        let rules = rules?;
        Ok(ScanReport {
            total_items: rules.iter().map(|r| r.items).sum(),
            total_bytes: rules.iter().map(|r| r.bytes).sum(),
            skipped: rules.iter().map(|r| r.skipped).sum(),
            rules,
        })
    }

    fn scan_rule(&self, rule: &Rule) -> Result<RuleScan, String> {
        let mut result = RuleScan {
            rule_id: rule.id.clone(),
            category: rule.category.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            risk: rule.risk.clone(),
            pro_only: rule.pro_only,
            items: 0,
            bytes: 0,
            samples: Vec::new(),
            skipped: 0,
        };
        if rule.target == Target::Action {
            return Ok(result);
        }
        for pattern in &rule.paths {
            let matches = resolve_matches(pattern, &self.app_data)?;
            for path in matches {
                if !is_safe_path(&path, &self.app_data) {
                    result.skipped += 1;
                    continue;
                }
                let entries = entries_for_scan(&path, &rule.target);
                for entry in entries {
                    match entry {
                        Ok((item, bytes)) => {
                            result.items += 1;
                            result.bytes += bytes;
                            if result.samples.len() < MAX_SAMPLES {
                                result.samples.push(item.display().to_string());
                            }
                        }
                        Err(_) => result.skipped += 1,
                    }
                }
            }
        }
        Ok(result)
    }

    fn clean(&self, ids: &[String], permanent: bool) -> Result<CleanReport, String> {
        let selected = self.selected_rules(ids)?;
        self.clean_rules(&selected, permanent)
    }

    fn clean_rules(&self, selected: &[Rule], permanent: bool) -> Result<CleanReport, String> {
        let quarantine_id = if permanent {
            None
        } else {
            Some(Utc::now().format("%Y%m%d%H%M%S%3f").to_string())
        };
        let quarantine_dir = quarantine_id
            .as_ref()
            .map(|id| self.app_data.join("quarantine").join(id));
        if let Some(dir) = &quarantine_dir {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut entries = Vec::new();
        let mut report = CleanReport {
            bytes_freed: 0,
            items: 0,
            skipped: 0,
            quarantine_id: quarantine_id.clone(),
        };
        for rule in selected {
            if rule.target == Target::Action {
                perform_action(&rule.id)?;
                continue;
            }
            for pattern in &rule.paths {
                for path in resolve_matches(pattern, &self.app_data)? {
                    if !is_safe_path(&path, &self.app_data) {
                        report.skipped += 1;
                        continue;
                    }
                    for item in entries_for_clean(&path, &rule.target) {
                        let item = match item {
                            Ok(item) => item,
                            Err(_) => {
                                report.skipped += 1;
                                continue;
                            }
                        };
                        if !is_safe_path(&item, &self.app_data) || !item.exists() {
                            report.skipped += 1;
                            continue;
                        }
                        let bytes = item_size(&item).unwrap_or(0);
                        let operation = if permanent {
                            remove_item(&item)
                        } else {
                            let destination = quarantine_dir
                                .as_ref()
                                .unwrap()
                                .join(format!("item-{}", entries.len()));
                            fs::rename(&item, &destination).map(|_| {
                                entries.push(ManifestEntry {
                                    original: item.display().to_string(),
                                    quarantined: destination.display().to_string(),
                                })
                            })
                        };
                        match operation {
                            Ok(_) => {
                                report.items += 1;
                                report.bytes_freed += bytes;
                            }
                            Err(_) => report.skipped += 1,
                        }
                    }
                }
            }
        }
        if let (Some(id), Some(dir)) = (&quarantine_id, &quarantine_dir) {
            let manifest = Manifest {
                id: id.clone(),
                entries,
            };
            fs::write(
                dir.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(report)
    }

    fn restore_last(&self) -> Result<CleanReport, String> {
        let Some(dir) = latest_quarantine(&self.app_data) else {
            return Ok(CleanReport {
                bytes_freed: 0,
                items: 0,
                skipped: 0,
                quarantine_id: None,
            });
        };
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(dir.join("manifest.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut report = CleanReport {
            bytes_freed: 0,
            items: 0,
            skipped: 0,
            quarantine_id: Some(manifest.id.clone()),
        };
        for entry in manifest.entries {
            let original = PathBuf::from(&entry.original);
            let quarantined = PathBuf::from(&entry.quarantined);
            if let Some(parent) = original.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::rename(&quarantined, &original) {
                Ok(_) => {
                    report.items += 1;
                    report.bytes_freed += item_size(&original).unwrap_or(0);
                }
                Err(_) => report.skipped += 1,
            }
        }
        let _ = fs::remove_dir_all(dir);
        Ok(report)
    }

    fn empty_quarantine(&self) -> Result<(), String> {
        let dir = self.app_data.join("quarantine");
        if dir.exists() {
            fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

pub fn catalog(app_data: PathBuf) -> Catalog {
    Engine::new(app_data).catalog()
}

pub fn scan(app_data: PathBuf, ids: Vec<String>) -> Result<ScanReport, String> {
    Engine::new(app_data).scan(&ids)
}

pub fn clean(app_data: PathBuf, ids: Vec<String>, permanent: bool) -> Result<CleanReport, String> {
    Engine::new(app_data).clean(&ids, permanent)
}

pub fn restore_last(app_data: PathBuf) -> Result<CleanReport, String> {
    Engine::new(app_data).restore_last()
}

pub fn empty_quarantine(app_data: PathBuf) -> Result<(), String> {
    Engine::new(app_data).empty_quarantine()
}

pub fn stats() -> SystemStats {
    let mut system = System::new();
    system.refresh_memory();
    let disks = Disks::new_with_refreshed_list();
    let root = Path::new(if cfg!(windows) { "C:\\" } else { "/" });
    let disk = disks
        .list()
        .iter()
        .filter(|disk| root.starts_with(disk.mount_point()) || disk.mount_point() == root)
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .or_else(|| disks.list().first());
    SystemStats {
        disk_free: disk.map(|d| d.available_space()).unwrap_or(0),
        disk_total: disk.map(|d| d.total_space()).unwrap_or(0),
        memory_used: system.used_memory(),
        memory_total: system.total_memory(),
    }
}

pub fn flush_dns() -> Result<(), String> {
    perform_action("linux-dns").or_else(|_| perform_action("windows-dns"))
}

pub fn empty_trash() -> Result<(), String> {
    if cfg!(windows) {
        perform_action("windows-recycle-bin")
    } else {
        perform_action("linux-recycle-bin")
    }
}

fn current_platform() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else {
        "Linux"
    }
}

fn expand_template(template: &str) -> Result<PathBuf, String> {
    let mut expanded = template.to_string();
    if expanded.starts_with('~') {
        let home = home_dir().ok_or("Could not determine the user home directory")?;
        expanded = format!("{}{}", home.display(), &expanded[1..]);
    }
    if let Some(home) = home_dir() {
        expanded = expanded.replace("$HOME", &home.display().to_string());
    }
    for key in [
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "TEMP",
        "LOCALAPPDATA",
        "APPDATA",
        "WINDIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            expanded = expanded.replace(&format!("%{key}%"), &value);
        }
    }
    Ok(PathBuf::from(expanded))
}

fn resolve_matches(pattern: &str, app_data: &Path) -> Result<Vec<PathBuf>, String> {
    let expanded = expand_template(pattern)?;
    if !expanded.to_string_lossy().contains('*') {
        return Ok(if expanded.exists() {
            vec![expanded]
        } else {
            Vec::new()
        });
    }
    let mut root = PathBuf::new();
    for component in expanded.components() {
        let value = component.as_os_str().to_string_lossy();
        if value.contains('*') {
            break;
        }
        root.push(component);
    }
    if root.as_os_str().is_empty() || !is_safe_path(&root, app_data) {
        return Err("Cleaning pattern resolves outside a safe root".into());
    }
    let suffix: Vec<String> = expanded
        .strip_prefix(&root)
        .unwrap_or(&expanded)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let mut matches = Vec::new();
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(suffix.len())
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let relative: Vec<_> = entry
            .path()
            .strip_prefix(&root)
            .unwrap_or(entry.path())
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();
        if glob_components_match(&suffix, &relative) {
            matches.push(entry.path().to_path_buf());
        }
    }
    Ok(matches)
}

fn glob_components_match(pattern: &[String], path: &[String]) -> bool {
    pattern.len() == path.len()
        && pattern.iter().zip(path).all(|(pattern, value)| {
            if pattern == "*" {
                true
            } else {
                wildcard_match(pattern, value)
            }
        })
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return false;
    };
    if !value.starts_with(first) {
        return false;
    }
    let mut offset = first.len();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some(index) = value[offset..].find(part) else {
            return false;
        };
        offset += index + part.len();
    }
    pattern.ends_with('*') || offset == value.len()
}

fn entries_for_scan(path: &Path, target: &Target) -> Vec<Result<(PathBuf, u64), io::Error>> {
    match target {
        Target::Contents => WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|entry| match entry {
                Ok(entry) if entry.path() != path && entry.file_type().is_file() => {
                    Some(item_size(entry.path()).map(|size| (entry.path().to_path_buf(), size)))
                }
                Ok(_) => None,
                Err(error) => Some(Err(io::Error::other(error))),
            })
            .collect(),
        Target::Files => {
            if is_regular_file(path) {
                vec![item_size(path).map(|size| (path.to_path_buf(), size))]
            } else {
                Vec::new()
            }
        }
        Target::Directories => {
            if path.is_dir() {
                vec![Ok((path.to_path_buf(), item_size(path).unwrap_or(0)))]
            } else {
                Vec::new()
            }
        }
        Target::Action => Vec::new(),
    }
}

fn entries_for_clean(path: &Path, target: &Target) -> Vec<Result<PathBuf, io::Error>> {
    match target {
        Target::Contents => match fs::read_dir(path) {
            Ok(entries) => entries.map(|entry| entry.map(|e| e.path())).collect(),
            Err(error) => vec![Err(error)],
        },
        Target::Files if is_regular_file(path) => vec![Ok(path.to_path_buf())],
        Target::Files => Vec::new(),
        Target::Directories if path.is_dir() => vec![Ok(path.to_path_buf())],
        Target::Directories => Vec::new(),
        Target::Action => Vec::new(),
    }
}

fn item_size(path: &Path) -> Result<u64, io::Error> {
    if is_regular_file(path) {
        return Ok(fs::symlink_metadata(path)?.len());
    }
    Ok(WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .is_file()
                .then(|| fs::symlink_metadata(entry.path()).ok())
                .flatten()
                .map(|m| m.len())
        })
        .sum())
}

fn remove_item(path: &Path) -> Result<(), io::Error> {
    if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn is_safe_path(path: &Path, app_data: &Path) -> bool {
    let normalized = lexical_normalize(path);
    let protected = if cfg!(windows) {
        vec![
            PathBuf::from(r"C:\"),
            PathBuf::from(r"C:\Windows"),
            PathBuf::from(r"C:\Windows\System32"),
        ]
    } else {
        vec![
            PathBuf::from("/"),
            PathBuf::from("/home"),
            PathBuf::from("/usr"),
            PathBuf::from("/etc"),
            PathBuf::from("/bin"),
        ]
    };
    if normalized == lexical_normalize(app_data)
        || normalized.starts_with(lexical_normalize(app_data))
    {
        return false;
    }
    !protected.contains(&normalized) && !normalized.file_name().is_some_and(|name| name == ".")
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            _ => normalized.push(component),
        }
    }
    normalized
}

fn latest_quarantine(app_data: &Path) -> Option<PathBuf> {
    fs::read_dir(app_data.join("quarantine"))
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .max_by_key(|entry| {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(UNIX_EPOCH)
        })
        .map(|entry| entry.path())
}

fn perform_action(id: &str) -> Result<(), String> {
    match id {
        "linux-dns" => {
            let commands = [
                ["resolvectl", "flush-caches"],
                ["systemd-resolve", "--flush-caches"],
            ];
            for args in commands {
                if Command::new(args[0])
                    .args(&args[1..])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    return Ok(());
                }
            }
            Err("No supported Linux DNS flush command succeeded".into())
        }
        "windows-dns" => Command::new("ipconfig")
            .args(["/flushdns"])
            .status()
            .map_err(|e| e.to_string())?
            .success()
            .then_some(())
            .ok_or_else(|| "Windows DNS flush failed".into()),
        "linux-recycle-bin" => {
            let items = trash::os_limited::list().map_err(|e| e.to_string())?;
            trash::os_limited::purge_all(items).map_err(|e| e.to_string())
        }
        "windows-recycle-bin" => Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Clear-RecycleBin -Force"])
            .status()
            .map_err(|e| e.to_string())?
            .success()
            .then_some(())
            .ok_or_else(|| "Windows Recycle Bin cleanup failed".into()),
        _ => Err(format!("Unsupported cleaning action: {id}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn fixture() -> (tempfile::TempDir, Engine) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("one.tmp"), b"12345").unwrap();
        fs::write(root.join("nested/two.tmp"), b"1234567").unwrap();
        let engine = Engine::new(temp.path().join("DustonicDev"));
        (temp, engine)
    }

    #[test]
    fn expands_home_and_environment_paths() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("HOME", "/tmp/dustonic-home");
        assert_eq!(
            expand_template("$HOME/.cache").unwrap(),
            PathBuf::from("/tmp/dustonic-home/.cache")
        );
    }

    #[test]
    fn denylist_blocks_protected_paths() {
        let (_, engine) = fixture();
        assert!(!is_safe_path(Path::new("/"), &engine.app_data));
        assert!(!is_safe_path(Path::new("/home"), &engine.app_data));
        assert!(!is_safe_path(&engine.app_data, &engine.app_data));
        assert!(is_safe_path(
            Path::new("/tmp/dustonic-safe"),
            &engine.app_data
        ));
    }

    #[test]
    fn scans_fixture_bytes_and_items() {
        let (temp, engine) = fixture();
        let rule = Rule {
            id: "fixture".into(),
            category: "Test".into(),
            name: "Fixture".into(),
            description: "Fixture".into(),
            risk: Risk::Safe,
            platforms: vec!["Linux".into()],
            paths: vec![temp.path().join("cache").display().to_string()],
            target: Target::Contents,
            default_enabled: true,
            pro_only: false,
        };
        let report = engine.scan_rule(&rule).unwrap();
        assert_eq!(report.items, 2);
        assert_eq!(report.bytes, 12);
    }

    #[test]
    fn quarantine_restore_returns_files() {
        let (temp, engine) = fixture();
        let rule = Rule {
            id: "fixture".into(),
            category: "Test".into(),
            name: "Fixture".into(),
            description: "Fixture".into(),
            risk: Risk::Safe,
            platforms: vec!["Linux".into()],
            paths: vec![temp.path().join("cache").display().to_string()],
            target: Target::Contents,
            default_enabled: true,
            pro_only: false,
        };
        let report = engine.clean_rules(&[rule], false).unwrap();
        assert_eq!(report.items, 2);
        assert!(!temp.path().join("cache/one.tmp").exists());
        let restored = engine.restore_last().unwrap();
        assert_eq!(restored.items, 2);
        assert!(temp.path().join("cache/one.tmp").exists());
        assert!(temp.path().join("cache/nested/two.tmp").exists());
    }

    #[test]
    fn permanent_delete_removes_fixture_items() {
        let (temp, engine) = fixture();
        let path = temp.path().join("cache/one.tmp");
        let rule = Rule {
            id: "fixture".into(),
            category: "Test".into(),
            name: "Fixture".into(),
            description: "Fixture".into(),
            risk: Risk::Safe,
            platforms: vec!["Linux".into()],
            paths: vec![path.display().to_string()],
            target: Target::Files,
            default_enabled: true,
            pro_only: false,
        };
        let report = engine.clean_rules(&[rule], true).unwrap();
        assert_eq!(report.items, 1);
        assert!(!path.exists());
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
}
