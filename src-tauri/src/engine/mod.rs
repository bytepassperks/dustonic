use chrono::Utc;
use dirs::home_dir;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::UNIX_EPOCH,
};
use sysinfo::{Disks, System};
use walkdir::WalkDir;

use crate::license::{self, Entitlements};

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

#[derive(Clone, Debug, Serialize)]
pub struct DiskEntry {
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub percent: f64,
    pub is_directory: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LargeFile {
    pub path: String,
    pub bytes: u64,
    pub modified: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DuplicateGroup {
    pub size: u64,
    pub count: usize,
    pub files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DuplicateRemoval {
    pub group: Vec<String>,
    pub remove: Vec<String>,
    pub keep: String,
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

    fn analyze_disk(&self, root: Option<&str>) -> Result<Vec<DiskEntry>, String> {
        let root = analysis_root(root)?;
        if !root.is_dir() {
            return Err("Disk analyzer target must be a directory".into());
        }
        let children = fs::read_dir(&root).map_err(|error| error.to_string())?;
        let mut entries = Vec::new();
        for child in children.flatten() {
            let path = child.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            let bytes = if metadata.is_dir() {
                item_size(&path).unwrap_or(0)
            } else if metadata.is_file() {
                metadata.len()
            } else {
                continue;
            };
            entries.push((path, bytes, metadata.is_dir()));
        }
        let total: u64 = entries.iter().map(|(_, bytes, _)| *bytes).sum();
        let mut result: Vec<_> = entries
            .into_iter()
            .map(|(path, bytes, is_directory)| DiskEntry {
                name: path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                path: path.display().to_string(),
                bytes,
                percent: if total == 0 {
                    0.0
                } else {
                    (bytes as f64 / total as f64) * 100.0
                },
                is_directory,
            })
            .collect();
        result.sort_by(|left, right| {
            right
                .bytes
                .cmp(&left.bytes)
                .then(left.name.cmp(&right.name))
        });
        Ok(result)
    }

    fn find_large_files(
        &self,
        root: Option<&str>,
        min_bytes: u64,
        entitlements: &Entitlements,
    ) -> Result<Vec<LargeFile>, String> {
        require_entitlement(entitlements.large_file_finder)?;
        let root = analysis_root(root)?;
        if !root.is_dir() {
            return Err("Large-file finder target must be a directory".into());
        }
        let mut files = Vec::new();
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.len() < min_bytes {
                continue;
            }
            files.push(LargeFile {
                path: entry.path().display().to_string(),
                bytes: metadata.len(),
                modified: metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs()),
            });
        }
        files.sort_by(|left, right| {
            right
                .bytes
                .cmp(&left.bytes)
                .then(left.path.cmp(&right.path))
        });
        files.truncate(200);
        Ok(files)
    }

    fn find_duplicates(
        &self,
        root: Option<&str>,
        entitlements: &Entitlements,
    ) -> Result<Vec<DuplicateGroup>, String> {
        require_entitlement(entitlements.duplicate_finder)?;
        let root = analysis_root(root)?;
        if !root.is_dir() {
            return Err("Duplicate finder target must be a directory".into());
        }
        let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            by_size
                .entry(metadata.len())
                .or_default()
                .push(entry.path().to_path_buf());
        }
        let mut by_hash: HashMap<(u64, [u8; 32]), Vec<PathBuf>> = HashMap::new();
        for (size, paths) in by_size.into_iter().filter(|(_, paths)| paths.len() > 1) {
            for path in paths {
                let mut file = match fs::File::open(&path) {
                    Ok(file) => file,
                    Err(_) => continue,
                };
                let mut hasher = blake3::Hasher::new();
                if io::copy(&mut file, &mut hasher).is_err() {
                    continue;
                }
                by_hash
                    .entry((size, *hasher.finalize().as_bytes()))
                    .or_default()
                    .push(path);
            }
        }
        let mut groups: Vec<_> = by_hash
            .into_values()
            .filter(|paths| paths.len() > 1)
            .map(|mut paths| {
                paths.sort();
                DuplicateGroup {
                    size: fs::symlink_metadata(&paths[0])
                        .map(|metadata| metadata.len())
                        .unwrap_or(0),
                    count: paths.len(),
                    files: paths
                        .into_iter()
                        .map(|path| path.display().to_string())
                        .collect(),
                }
            })
            .collect();
        groups.sort_by(|left, right| {
            right
                .size
                .cmp(&left.size)
                .then(left.files[0].cmp(&right.files[0]))
        });
        Ok(groups)
    }

    fn selected_rules(
        &self,
        ids: &[String],
        entitlements: &Entitlements,
    ) -> Result<Vec<Rule>, String> {
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
            if rule.pro_only && !entitlements.pro_rules {
                return Err(license::error_code(
                    "PRO_REQUIRED",
                    Some(&format!("rule_id={}", rule.id)),
                ));
            }
            selected.push(rule.clone());
        }
        Ok(selected)
    }

    fn scan(&self, ids: &[String], entitlements: &Entitlements) -> Result<ScanReport, String> {
        let selected = self.selected_rules(ids, entitlements)?;
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

    fn clean(
        &self,
        ids: &[String],
        permanent: bool,
        entitlements: &Entitlements,
    ) -> Result<CleanReport, String> {
        let selected = self.selected_rules(ids, entitlements)?;
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

    fn quarantine_paths(
        &self,
        paths: &[String],
        keep_paths: &[String],
    ) -> Result<CleanReport, String> {
        let keep: HashSet<_> = keep_paths.iter().map(PathBuf::from).collect();
        let mut unique = HashSet::new();
        let mut items = Vec::new();
        for value in paths {
            let path = PathBuf::from(value);
            if !unique.insert(path.clone()) {
                continue;
            }
            if keep.contains(&path)
                || !is_safe_path(&path, &self.app_data)
                || !is_regular_file(&path)
            {
                return Err(format!(
                    "Refusing to quarantine unsafe file: {}",
                    path.display()
                ));
            }
            items.push(path);
        }
        self.quarantine_items(&items)
    }

    fn quarantine_duplicate_files(
        &self,
        selections: &[DuplicateRemoval],
    ) -> Result<CleanReport, String> {
        let mut paths = Vec::new();
        let mut keeps = Vec::new();
        for selection in selections {
            let group: HashSet<_> = selection.group.iter().map(PathBuf::from).collect();
            let remove: HashSet<_> = selection.remove.iter().map(PathBuf::from).collect();
            let keep = PathBuf::from(&selection.keep);
            if group.len() < 2
                || !group.contains(&keep)
                || remove.contains(&keep)
                || remove.is_empty()
                || remove.len() >= group.len()
                || !remove.is_subset(&group)
            {
                return Err("Duplicate cleanup must keep at least one copy".into());
            }
            keeps.push(selection.keep.clone());
            paths.extend(selection.remove.iter().cloned());
        }
        self.quarantine_paths(&paths, &keeps)
    }

    fn quarantine_items(&self, items: &[PathBuf]) -> Result<CleanReport, String> {
        let quarantine_id = Utc::now().format("%Y%m%d%H%M%S%3f").to_string();
        let quarantine_dir = self.app_data.join("quarantine").join(&quarantine_id);
        fs::create_dir_all(&quarantine_dir).map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        let mut report = CleanReport {
            bytes_freed: 0,
            items: 0,
            skipped: 0,
            quarantine_id: Some(quarantine_id.clone()),
        };
        for item in items {
            if !is_safe_path(item, &self.app_data) || !is_regular_file(item) {
                report.skipped += 1;
                continue;
            }
            let destination = quarantine_dir.join(format!("item-{}", entries.len()));
            let bytes = item_size(item).unwrap_or(0);
            match fs::rename(item, &destination) {
                Ok(()) => {
                    entries.push(ManifestEntry {
                        original: item.display().to_string(),
                        quarantined: destination.display().to_string(),
                    });
                    report.items += 1;
                    report.bytes_freed += bytes;
                }
                Err(_) => report.skipped += 1,
            }
        }
        let manifest = Manifest {
            id: quarantine_id,
            entries,
        };
        fs::write(
            quarantine_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
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

pub fn scan(
    app_data: PathBuf,
    ids: Vec<String>,
    entitlements: Entitlements,
) -> Result<ScanReport, String> {
    Engine::new(app_data).scan(&ids, &entitlements)
}

pub fn clean(
    app_data: PathBuf,
    ids: Vec<String>,
    permanent: bool,
    entitlements: Entitlements,
) -> Result<CleanReport, String> {
    Engine::new(app_data).clean(&ids, permanent, &entitlements)
}

pub fn restore_last(app_data: PathBuf) -> Result<CleanReport, String> {
    Engine::new(app_data).restore_last()
}

pub fn empty_quarantine(app_data: PathBuf) -> Result<(), String> {
    Engine::new(app_data).empty_quarantine()
}

pub fn analyze_disk(app_data: PathBuf, root: Option<String>) -> Result<Vec<DiskEntry>, String> {
    Engine::new(app_data).analyze_disk(root.as_deref())
}

pub fn find_large_files(
    app_data: PathBuf,
    root: Option<String>,
    min_bytes: u64,
    entitlements: Entitlements,
) -> Result<Vec<LargeFile>, String> {
    Engine::new(app_data).find_large_files(root.as_deref(), min_bytes, &entitlements)
}

pub fn find_duplicates(
    app_data: PathBuf,
    root: Option<String>,
    entitlements: Entitlements,
) -> Result<Vec<DuplicateGroup>, String> {
    Engine::new(app_data).find_duplicates(root.as_deref(), &entitlements)
}

pub fn quarantine_paths(
    app_data: PathBuf,
    paths: Vec<String>,
    keep_paths: Vec<String>,
) -> Result<CleanReport, String> {
    Engine::new(app_data).quarantine_paths(&paths, &keep_paths)
}

pub fn quarantine_duplicate_files(
    app_data: PathBuf,
    selections: Vec<DuplicateRemoval>,
) -> Result<CleanReport, String> {
    Engine::new(app_data).quarantine_duplicate_files(&selections)
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

fn analysis_root(root: Option<&str>) -> Result<PathBuf, String> {
    match root {
        Some(root) if !root.trim().is_empty() => Ok(PathBuf::from(root)),
        _ => home_dir().ok_or("Could not determine the user home directory".into()),
    }
}

fn require_entitlement(enabled: bool) -> Result<(), String> {
    if enabled {
        Ok(())
    } else {
        Err(license::error_code("PRO_REQUIRED", None))
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
            PathBuf::from(r"C:\Users"),
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
            PathBuf::from(r"C:\ProgramData"),
        ]
    } else {
        vec![
            PathBuf::from("/"),
            PathBuf::from("/home"),
            PathBuf::from("/usr"),
            PathBuf::from("/etc"),
            PathBuf::from("/bin"),
            PathBuf::from("/boot"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/opt"),
            PathBuf::from("/root"),
            PathBuf::from("/sbin"),
            PathBuf::from("/sys"),
            PathBuf::from("/proc"),
            PathBuf::from("/var"),
            PathBuf::from("/dev"),
        ]
    };
    if let Some(home) = home_dir() {
        if normalized == lexical_normalize(&home) {
            return false;
        }
    }
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
        let home = home_dir().expect("test environment should have a home directory");
        assert!(!is_safe_path(&home, &engine.app_data));
        assert!(is_safe_path(
            &home.join(".cache").join("dustonic-test"),
            &engine.app_data
        ));
        assert!(!is_safe_path(&engine.app_data, &engine.app_data));
        assert!(is_safe_path(
            Path::new("/tmp/dustonic-safe"),
            &engine.app_data
        ));
    }

    #[test]
    fn pro_rule_is_rejected_without_pro_entitlement() {
        let (_, engine) = fixture();
        let error = engine
            .selected_rules(&["linux-dev-cache".into()], &Entitlements::free())
            .unwrap_err();
        let payload: serde_json::Value = serde_json::from_str(&error).unwrap();
        assert_eq!(payload["code"], "PRO_REQUIRED");
        assert!(engine
            .selected_rules(&["linux-dev-cache".into()], &Entitlements::pro())
            .is_ok());
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

    #[test]
    fn disk_analyzer_sorts_immediate_children_and_reports_percentages() {
        let (temp, engine) = fixture();
        fs::write(temp.path().join("small.txt"), b"12").unwrap();
        let entries = engine
            .analyze_disk(Some(temp.path().to_str().unwrap()))
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "cache");
        assert_eq!(entries[0].bytes, 12);
        assert_eq!(entries[1].name, "small.txt");
        assert!((entries.iter().map(|entry| entry.percent).sum::<f64>() - 100.0).abs() < 0.001);
    }

    #[test]
    fn large_file_finder_filters_by_threshold() {
        let (temp, engine) = fixture();
        fs::write(temp.path().join("large.bin"), vec![0_u8; 20]).unwrap();
        fs::write(temp.path().join("tiny.bin"), vec![0_u8; 3]).unwrap();
        let files = engine
            .find_large_files(
                Some(temp.path().to_str().unwrap()),
                10,
                &Entitlements::pro(),
            )
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].path,
            temp.path().join("large.bin").display().to_string()
        );
        let error = engine
            .find_large_files(
                Some(temp.path().to_str().unwrap()),
                10,
                &Entitlements::free(),
            )
            .unwrap_err();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&error).unwrap()["code"],
            "PRO_REQUIRED"
        );
    }

    #[test]
    fn duplicate_finder_groups_identical_files_only() {
        let (temp, engine) = fixture();
        let duplicate_a = temp.path().join("duplicate-a.bin");
        let duplicate_b = temp.path().join("duplicate-b.bin");
        let unique = temp.path().join("unique.bin");
        fs::write(&duplicate_a, b"same content").unwrap();
        fs::write(&duplicate_b, b"same content").unwrap();
        fs::write(&unique, b"different!").unwrap();
        let groups = engine
            .find_duplicates(Some(temp.path().to_str().unwrap()), &Entitlements::pro())
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].count, 2);
        assert!(groups[0].files.contains(&duplicate_a.display().to_string()));
        assert!(groups[0].files.contains(&duplicate_b.display().to_string()));
        assert!(!groups[0].files.contains(&unique.display().to_string()));
    }

    #[test]
    fn duplicate_cleanup_requires_one_copy_to_remain() {
        let (temp, engine) = fixture();
        let first = temp.path().join("first.bin");
        let second = temp.path().join("second.bin");
        fs::write(&first, b"same").unwrap();
        fs::write(&second, b"same").unwrap();
        let selection = DuplicateRemoval {
            group: vec![first.display().to_string(), second.display().to_string()],
            remove: vec![first.display().to_string(), second.display().to_string()],
            keep: first.display().to_string(),
        };
        assert!(engine.quarantine_duplicate_files(&[selection]).is_err());
        let selection = DuplicateRemoval {
            group: vec![first.display().to_string(), second.display().to_string()],
            remove: vec![second.display().to_string()],
            keep: first.display().to_string(),
        };
        let report = engine.quarantine_duplicate_files(&[selection]).unwrap();
        assert_eq!(report.items, 1);
        assert!(first.exists());
        assert!(!second.exists());
        assert_eq!(engine.restore_last().unwrap().items, 1);
        assert!(second.exists());
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
}
