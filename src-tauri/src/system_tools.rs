use serde::Serialize;
use std::{fs, path::PathBuf, process::Command};

#[derive(Clone, Debug, Serialize)]
pub struct StartupItem {
    pub id: String,
    pub display_name: String,
    pub command: String,
    pub enabled: bool,
    pub source: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct InstalledProgram {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub estimated_size: Option<u64>,
    pub location: Option<String>,
    pub uninstall_command: Option<String>,
    pub removal_command: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UninstallResult {
    pub supported: bool,
    pub launched: bool,
    pub command: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegistryFinding {
    pub id: String,
    pub key_path: String,
    pub value_name: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegistryScanResult {
    pub supported: bool,
    pub findings: Vec<RegistryFinding>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegistryCleanResult {
    pub supported: bool,
    pub cleaned: usize,
    pub backup_path: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
struct DesktopEntry {
    name: String,
    exec: String,
    hidden: bool,
}

pub fn list_startup_items(app_data: PathBuf) -> Result<Vec<StartupItem>, String> {
    platform::list_startup_items(app_data)
}

pub fn set_startup_item_enabled(
    app_data: PathBuf,
    id: String,
    enabled: bool,
) -> Result<StartupItem, String> {
    platform::set_startup_item_enabled(app_data, &id, enabled)
}

pub fn list_installed_programs() -> Result<Vec<InstalledProgram>, String> {
    platform::list_installed_programs()
}

pub fn uninstall_program(id: String) -> Result<UninstallResult, String> {
    platform::uninstall_program(&id)
}

pub fn scan_registry(app_data: PathBuf) -> Result<RegistryScanResult, String> {
    platform::scan_registry(app_data)
}

pub fn clean_registry(
    app_data: PathBuf,
    finding_ids: Vec<String>,
) -> Result<RegistryCleanResult, String> {
    platform::clean_registry(app_data, &finding_ids)
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::collections::HashMap;

    const USER_SOURCE: &str = "User autostart";
    const SYSTEM_SOURCE: &str = "System autostart";

    fn user_autostart_dir() -> Result<PathBuf, String> {
        dirs::home_dir()
            .map(|home| home.join(".config/autostart"))
            .ok_or_else(|| "Could not determine the user home directory".into())
    }

    fn system_autostart_dir() -> PathBuf {
        PathBuf::from("/etc/xdg/autostart")
    }

    fn desktop_value(entry: &DesktopEntry, key: &str) -> Option<String> {
        match key {
            "Name" => Some(entry.name.clone()),
            "Exec" => Some(entry.exec.clone()),
            _ => None,
        }
    }

    pub(super) fn parse_desktop_entry(content: &str) -> DesktopEntry {
        let mut entry = DesktopEntry::default();
        let mut in_desktop_entry = false;
        let mut values = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line == "[Desktop Entry]" {
                in_desktop_entry = true;
                continue;
            }
            if line.starts_with('[') {
                in_desktop_entry = false;
            }
            if !in_desktop_entry || line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim(), value.trim());
            }
        }
        entry.name = values
            .get("Name")
            .copied()
            .unwrap_or("Unnamed application")
            .to_string();
        entry.exec = values.get("Exec").copied().unwrap_or_default().to_string();
        entry.hidden = values
            .get("Hidden")
            .or_else(|| values.get("X-GNOME-Autostart-enabled"))
            .is_some_and(|value| value.eq_ignore_ascii_case("true"));
        entry
    }

    fn read_desktop(path: &PathBuf, source: &str, id: String) -> Option<StartupItem> {
        let content = fs::read_to_string(path).ok()?;
        let entry = parse_desktop_entry(&content);
        Some(StartupItem {
            id,
            display_name: desktop_value(&entry, "Name")
                .unwrap_or_else(|| "Unnamed application".into()),
            command: desktop_value(&entry, "Exec").unwrap_or_default(),
            enabled: !entry.hidden,
            source: source.into(),
        })
    }

    fn desktop_files(dir: &PathBuf, source: &str, prefix: &str) -> Vec<StartupItem> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut items = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "desktop")
            {
                if let Some(name) = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                {
                    if let Some(item) = read_desktop(&path, source, format!("{prefix}:{name}")) {
                        items.push(item);
                    }
                }
            }
        }
        items
    }

    pub(super) fn list_startup_items(_app_data: PathBuf) -> Result<Vec<StartupItem>, String> {
        let user = user_autostart_dir()?;
        let system = system_autostart_dir();
        let mut items = desktop_files(&user, USER_SOURCE, "user");
        let user_names: HashMap<_, _> = items
            .iter()
            .filter_map(|item| {
                item.id
                    .strip_prefix("user:")
                    .map(|name| (name.to_string(), item.enabled))
            })
            .collect();
        for mut item in desktop_files(&system, SYSTEM_SOURCE, "system") {
            if let Some(enabled) =
                user_names.get(item.id.strip_prefix("system:").unwrap_or_default())
            {
                item.enabled = *enabled;
            }
            items.push(item);
        }
        items.sort_by(|left, right| {
            left.display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase())
        });
        Ok(items)
    }

    pub(super) fn set_startup_item_enabled(
        _app_data: PathBuf,
        id: &str,
        enabled: bool,
    ) -> Result<StartupItem, String> {
        let (source, filename) = id
            .split_once(':')
            .ok_or_else(|| "Invalid startup item id".to_string())?;
        if filename.contains('/') || filename.contains('\\') || !filename.ends_with(".desktop") {
            return Err("Invalid startup item filename".into());
        }
        let user_dir = user_autostart_dir()?;
        fs::create_dir_all(&user_dir).map_err(|error| error.to_string())?;
        let user_path = user_dir.join(filename);
        match source {
            "user" => {
                let content = fs::read_to_string(&user_path).map_err(|error| error.to_string())?;
                let updated = set_desktop_enabled(&content, enabled);
                fs::write(&user_path, updated).map_err(|error| error.to_string())?;
            }
            "system" => {
                let system_path = system_autostart_dir().join(filename);
                if !system_path.exists() {
                    return Err("System startup entry no longer exists".into());
                }
                if enabled {
                    if user_path.exists() {
                        fs::remove_file(&user_path).map_err(|error| error.to_string())?;
                    }
                } else {
                    let content =
                        fs::read_to_string(&system_path).map_err(|error| error.to_string())?;
                    fs::write(&user_path, set_desktop_enabled(&content, false))
                        .map_err(|error| error.to_string())?;
                }
            }
            _ => return Err("Unsupported startup item source".into()),
        }
        list_startup_items(PathBuf::new())?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| "Startup item disappeared after update".into())
    }

    fn set_desktop_enabled(content: &str, enabled: bool) -> String {
        let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
        let mut replaced = false;
        for line in &mut lines {
            if line.starts_with("Hidden=") || line.starts_with("X-GNOME-Autostart-enabled=") {
                *line = format!("Hidden={}", if enabled { "false" } else { "true" });
                replaced = true;
                break;
            }
        }
        if !replaced {
            if let Some(index) = lines.iter().position(|line| line == "[Desktop Entry]") {
                lines.insert(
                    index + 1,
                    format!("Hidden={}", if enabled { "false" } else { "true" }),
                );
            } else {
                lines.push(format!("Hidden={}", if enabled { "false" } else { "true" }));
            }
        }
        format!("{}\n", lines.join("\n"))
    }

    fn parse_dpkg_output(output: &str) -> Vec<InstalledProgram> {
        output
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                let name = fields.first()?.trim();
                if name.is_empty() {
                    return None;
                }
                let version = fields
                    .get(1)
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty());
                Some(InstalledProgram {
                    id: format!("dpkg:{name}"),
                    name: name.into(),
                    version: version.map(str::to_string),
                    publisher: None,
                    estimated_size: None,
                    location: None,
                    uninstall_command: None,
                    removal_command: Some(format!("sudo apt remove {name}")),
                })
            })
            .collect()
    }

    fn parse_flatpak_output(output: &str) -> Vec<InstalledProgram> {
        output
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                let name = fields.first()?.trim();
                if name.is_empty() || name == "Application ID" {
                    return None;
                }
                let version = fields
                    .get(1)
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty());
                Some(InstalledProgram {
                    id: format!("flatpak:{name}"),
                    name: name.into(),
                    version: version.map(str::to_string),
                    publisher: None,
                    estimated_size: None,
                    location: fields.get(3).map(|value| value.trim().to_string()),
                    uninstall_command: None,
                    removal_command: Some(format!("flatpak uninstall {name}")),
                })
            })
            .collect()
    }

    pub(super) fn list_installed_programs() -> Result<Vec<InstalledProgram>, String> {
        let mut programs = Vec::new();
        if let Ok(output) = Command::new("dpkg-query")
            .args(["-W", "-f=${Package}\\t${Version}\\n"])
            .output()
        {
            programs.extend(parse_dpkg_output(&String::from_utf8_lossy(&output.stdout)));
        }
        if let Ok(output) = Command::new("flatpak")
            .args(["list", "--columns=application,version,branch,installation"])
            .output()
        {
            programs.extend(parse_flatpak_output(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
        programs.sort_by_key(|program| program.name.to_lowercase());
        Ok(programs)
    }

    pub(super) fn uninstall_program(id: &str) -> Result<UninstallResult, String> {
        let command = if let Some(name) = id.strip_prefix("dpkg:") {
            format!("sudo apt remove {name}")
        } else if let Some(name) = id.strip_prefix("flatpak:") {
            format!("flatpak uninstall {name}")
        } else {
            return Err("Unknown installed program id".into());
        };
        Ok(UninstallResult {
            supported: false,
            launched: false,
            command: Some(command.clone()),
            message: format!(
                "Linux does not run uninstall commands automatically. Copy and run: {command}"
            ),
        })
    }

    pub(super) fn scan_registry(_app_data: PathBuf) -> Result<RegistryScanResult, String> {
        Ok(RegistryScanResult {
            supported: false,
            findings: Vec::new(),
            message: "Registry cleaning is supported on Windows only.".into(),
        })
    }

    pub(super) fn clean_registry(
        _app_data: PathBuf,
        _finding_ids: &[String],
    ) -> Result<RegistryCleanResult, String> {
        Ok(RegistryCleanResult {
            supported: false,
            cleaned: 0,
            backup_path: None,
            message: "Registry cleaning is supported on Windows only.".into(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn desktop_parser_and_toggle_round_trip() {
            let source = "[Desktop Entry]\nName=Dustonic Test\nExec=dustonic --background\n";
            let parsed = parse_desktop_entry(source);
            assert_eq!(parsed.name, "Dustonic Test");
            assert!(parsed.exec.contains("--background"));
            assert!(!parsed.hidden);
            let disabled = set_desktop_enabled(source, false);
            assert!(parse_desktop_entry(&disabled).hidden);
            let enabled = set_desktop_enabled(&disabled, true);
            assert!(!parse_desktop_entry(&enabled).hidden);
        }

        #[test]
        fn package_output_parsers_return_manual_commands() {
            let dpkg = parse_dpkg_output("dustonic\t0.1.0\n");
            assert_eq!(
                dpkg[0].removal_command.as_deref(),
                Some("sudo apt remove dustonic")
            );
            let flatpak = parse_flatpak_output("Application ID\tVersion\tBranch\tInstallation\norg.example.App\t1.2\tstable\tsystem\n");
            assert_eq!(
                flatpak[0].removal_command.as_deref(),
                Some("flatpak uninstall org.example.App")
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::collections::HashMap;
    use winreg::{
        enums::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
            KEY_WRITE,
        },
        RegKey,
    };

    pub(super) fn list_startup_items(_app_data: PathBuf) -> Result<Vec<StartupItem>, String> {
        let mut items = Vec::new();
        for (root, root_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let hive = RegKey::predef(root);
            let Ok(key) = hive.open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                KEY_READ,
            ) else {
                continue;
            };
            for value in key.enum_values().flatten() {
                items.push(StartupItem {
                    id: format!("run:{root_name}:{}", value.0),
                    display_name: value.0,
                    command: String::from_utf8_lossy(&value.1.bytes).into_owned(),
                    enabled: true,
                    source: format!("{root_name} Run"),
                });
            }
        }
        let disabled_root = RegKey::predef(HKEY_CURRENT_USER);
        for source_name in ["HKCU", "HKLM"] {
            let Ok(disabled) = disabled_root.open_subkey_with_flags(
                format!("Software\\Dustonic\\StartupDisabled\\{source_name}"),
                KEY_READ,
            ) else {
                continue;
            };
            for value in disabled.enum_values().flatten() {
                items.push(StartupItem {
                    id: format!("run:{source_name}:{}", value.0),
                    display_name: value.0,
                    command: String::from_utf8_lossy(&value.1.bytes).into_owned(),
                    enabled: false,
                    source: format!("{source_name} Run"),
                });
            }
        }
        if let Some(startup) =
            dirs::data_dir().map(|dir| dir.join("Microsoft/Windows/Start Menu/Programs/Startup"))
        {
            if let Ok(entries) = fs::read_dir(startup) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .extension()
                        .is_some_and(|extension| extension == "lnk" || extension == "disabled")
                    {
                        let enabled = path.extension().is_some_and(|extension| extension == "lnk");
                        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                        let name = file_name.strip_suffix(".disabled").unwrap_or(&file_name);
                        items.push(StartupItem {
                            id: format!("folder:{name}"),
                            display_name: name.trim_end_matches(".lnk").into(),
                            command: path.display().to_string(),
                            enabled,
                            source: "User Startup folder".into(),
                        });
                    }
                }
            }
        }
        Ok(items)
    }

    pub(super) fn set_startup_item_enabled(
        _app_data: PathBuf,
        id: &str,
        enabled: bool,
    ) -> Result<StartupItem, String> {
        let mut parts = id.splitn(3, ':');
        let kind = parts.next().ok_or("Invalid Windows startup item id")?;
        if kind == "folder" {
            let name = parts.next().ok_or("Missing Startup folder filename")?;
            let filename = name;
            if filename.contains('\\') || filename.contains('/') {
                return Err("Invalid Startup folder filename".into());
            }
            let startup = dirs::data_dir()
                .ok_or("Could not determine the Windows Startup folder")?
                .join("Microsoft/Windows/Start Menu/Programs/Startup");
            let active = startup.join(filename);
            let disabled = startup.join(format!("{filename}.disabled"));
            if enabled {
                fs::rename(disabled, active).map_err(|error| error.to_string())?;
            } else {
                fs::rename(active, disabled).map_err(|error| error.to_string())?;
            }
            return list_startup_items(PathBuf::new())?
                .into_iter()
                .find(|item| item.id == id)
                .ok_or_else(|| "Startup folder entry disappeared after update".into());
        }
        if kind != "run" {
            return Err("Invalid Windows startup item type".into());
        }
        let source = parts.next().ok_or("Missing startup registry source")?;
        let name = parts.next().ok_or("Missing startup value name")?;
        let (root, source_name) = match *source {
            "HKCU" => (RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
            "HKLM" => (RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
            _ => return Err("Unknown startup registry source".into()),
        };
        let run_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let disabled_path = "Software\\Dustonic\\StartupDisabled";
        let run = root
            .open_subkey_with_flags(run_path, KEY_READ | KEY_WRITE)
            .map_err(|error| error.to_string())?;
        let disabled = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!("{disabled_path}\\{source_name}"))
            .map_err(|error| error.to_string())?
            .0;
        if enabled {
            let value: String = disabled
                .get_value(name)
                .map_err(|error| error.to_string())?;
            run.set_value(name, &value)
                .map_err(|error| error.to_string())?;
            disabled
                .delete_value(name)
                .map_err(|error| error.to_string())?;
        } else {
            let value: String = run.get_value(name).map_err(|error| error.to_string())?;
            disabled
                .set_value(name, &value)
                .map_err(|error| error.to_string())?;
            run.delete_value(name).map_err(|error| error.to_string())?;
        }
        list_startup_items(PathBuf::new())?
            .into_iter()
            .find(|item| item.id == id)
            .or_else(|| {
                Some(StartupItem {
                    id: id.into(),
                    display_name: name.into(),
                    command: String::new(),
                    enabled,
                    source: format!("{source_name} Run"),
                })
            })
            .ok_or_else(|| "Startup entry disappeared after update".into())
    }

    pub(super) fn list_installed_programs() -> Result<Vec<InstalledProgram>, String> {
        let mut programs = Vec::new();
        for (root, root_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            for flags in [KEY_READ | KEY_WOW64_32KEY, KEY_READ | KEY_WOW64_64KEY] {
                let hive = RegKey::predef(root);
                let Ok(key) = hive.open_subkey_with_flags(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    flags,
                ) else {
                    continue;
                };
                for (subkey_name, _) in key
                    .enum_keys()
                    .flatten()
                    .filter_map(|name| Some((name, ())))
                {
                    let Ok(app) = key.open_subkey_with_flags(&subkey_name, flags) else {
                        continue;
                    };
                    let Ok(name) = app.get_value::<String, _>("DisplayName") else {
                        continue;
                    };
                    programs.push(InstalledProgram {
                        id: format!("uninstall:{root_name}:{subkey_name}"),
                        name,
                        version: app.get_value("DisplayVersion").ok(),
                        publisher: app.get_value("Publisher").ok(),
                        estimated_size: app
                            .get_value::<u64, _>("EstimatedSize")
                            .ok()
                            .map(|kb| kb * 1024),
                        location: app.get_value("InstallLocation").ok(),
                        uninstall_command: app.get_value("UninstallString").ok(),
                        removal_command: None,
                    });
                }
            }
        }
        programs.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        Ok(programs)
    }

    pub(super) fn uninstall_program(id: &str) -> Result<UninstallResult, String> {
        let mut pieces = id.splitn(3, ':');
        if pieces.next() != Some("uninstall") {
            return Err("Unknown installed program id".into());
        }
        let source = pieces.next().ok_or("Missing registry source")?;
        let key_name = pieces.next().ok_or("Missing uninstall key")?;
        let root = if source == "HKCU" {
            RegKey::predef(HKEY_CURRENT_USER)
        } else {
            RegKey::predef(HKEY_LOCAL_MACHINE)
        };
        let key = root
            .open_subkey_with_flags(
                format!("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{key_name}"),
                KEY_READ,
            )
            .map_err(|error| error.to_string())?;
        let command: String = key
            .get_value("UninstallString")
            .map_err(|error| error.to_string())?;
        Command::new("cmd")
            .args(["/C", &command])
            .spawn()
            .map_err(|error| error.to_string())?;
        Ok(UninstallResult {
            supported: true,
            launched: true,
            command: Some(command),
            message: "The vendor uninstaller was launched.".into(),
        })
    }

    pub(super) fn scan_registry(_app_data: PathBuf) -> Result<RegistryScanResult, String> {
        let mut findings = Vec::new();
        for (root, root_name) in [(HKEY_CURRENT_USER, "HKCU"), (HKEY_LOCAL_MACHINE, "HKLM")] {
            let hive = RegKey::predef(root);
            let Ok(app_paths) = hive.open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
                KEY_READ,
            ) else {
                continue;
            };
            for subkey_name in app_paths.enum_keys().flatten() {
                let Ok(key) = app_paths.open_subkey(&subkey_name) else {
                    continue;
                };
                let Ok(target) = key.get_value::<String, _>("") else {
                    continue;
                };
                if !PathBuf::from(&target).exists() {
                    let key_path = format!("{root_name}\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{subkey_name}");
                    findings.push(RegistryFinding {
                        id: key_path.clone(),
                        key_path,
                        value_name: "(Default)".into(),
                        reason: format!("Referenced executable does not exist: {target}"),
                    });
                }
            }
        }
        Ok(RegistryScanResult {
            supported: true,
            message: format!("{} conservative findings require review.", findings.len()),
            findings,
        })
    }

    pub(super) fn clean_registry(
        app_data: PathBuf,
        finding_ids: &[String],
    ) -> Result<RegistryCleanResult, String> {
        if finding_ids.is_empty() {
            return Ok(RegistryCleanResult {
                supported: true,
                cleaned: 0,
                backup_path: None,
                message: "No registry findings were selected.".into(),
            });
        }
        let backup_dir = app_data.join("quarantine").join(format!(
            "registry-{}",
            chrono::Utc::now().timestamp_millis()
        ));
        fs::create_dir_all(&backup_dir).map_err(|error| error.to_string())?;
        let mut cleaned = 0;
        for (index, id) in finding_ids.iter().enumerate() {
            if !id.starts_with("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\")
                && !id
                    .starts_with("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\")
            {
                continue;
            }
            let export_path = backup_dir.join(format!("finding-{index}.reg"));
            let status = Command::new("reg")
                .args(["export", id, &export_path.display().to_string(), "/y"])
                .status();
            if !status.is_ok_and(|status| status.success()) {
                continue;
            }
            let _ = Command::new("reg")
                .args(["delete", id, "/ve", "/f"])
                .status();
            cleaned += 1;
        }
        Ok(RegistryCleanResult {
            supported: true,
            cleaned,
            backup_path: Some(backup_dir.display().to_string()),
            message: "Selected registry values were backed up before removal.".into(),
        })
    }
}
