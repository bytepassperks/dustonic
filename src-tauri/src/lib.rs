use std::fs;
use tauri::{AppHandle, Emitter, Manager};

mod app_dirs;
mod engine;
mod license;
mod system_tools;

fn app_data(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .data_dir()
        .map(|path| path.join(app_dirs::app_name()))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_rule_catalog(app: AppHandle) -> Result<engine::Catalog, String> {
    Ok(engine::catalog(app_data(&app)?))
}

#[tauri::command(async)]
fn scan_rules(app: AppHandle, rule_ids: Vec<String>) -> Result<engine::ScanReport, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    engine::scan(data_dir, rule_ids, entitlements)
}

#[tauri::command(async)]
fn clean_rules(
    app: AppHandle,
    rule_ids: Vec<String>,
    permanent: bool,
) -> Result<engine::CleanReport, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    engine::clean(data_dir, rule_ids, permanent, entitlements)
}

#[tauri::command]
fn get_license_status(app: AppHandle) -> Result<license::LicenseStatus, String> {
    Ok(license::LicenseManager::new(app_data(&app)?).status())
}

#[tauri::command]
async fn activate_license(app: AppHandle, key: String) -> Result<license::LicenseStatus, String> {
    license::LicenseManager::new(app_data(&app)?)
        .activate(&key)
        .await
}

#[tauri::command]
fn deactivate_license(app: AppHandle) -> Result<license::LicenseStatus, String> {
    license::LicenseManager::new(app_data(&app)?).deactivate()
}

#[tauri::command(async)]
fn restore_last_quarantine(app: AppHandle) -> Result<engine::CleanReport, String> {
    engine::restore_last(app_data(&app)?)
}

#[tauri::command(async)]
fn empty_quarantine(app: AppHandle) -> Result<(), String> {
    engine::empty_quarantine(app_data(&app)?)
}

#[tauri::command]
fn get_system_stats() -> engine::SystemStats {
    engine::stats()
}

#[tauri::command(async)]
fn flush_dns() -> Result<(), String> {
    engine::flush_dns()
}

#[tauri::command(async)]
fn empty_trash() -> Result<(), String> {
    engine::empty_trash()
}

#[tauri::command(async)]
fn list_startup_items(app: AppHandle) -> Result<Vec<system_tools::StartupItem>, String> {
    system_tools::list_startup_items(app_data(&app)?)
}

#[tauri::command(async)]
fn set_startup_item_enabled(
    app: AppHandle,
    id: String,
    enabled: bool,
) -> Result<system_tools::StartupItem, String> {
    system_tools::set_startup_item_enabled(app_data(&app)?, id, enabled)
}

#[tauri::command(async)]
fn list_installed_programs() -> Result<Vec<system_tools::InstalledProgram>, String> {
    system_tools::list_installed_programs()
}

#[tauri::command(async)]
fn uninstall_program(id: String) -> Result<system_tools::UninstallResult, String> {
    system_tools::uninstall_program(id)
}

#[tauri::command(async)]
fn scan_registry(app: AppHandle) -> Result<system_tools::RegistryScanResult, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    if !entitlements.pro_rules {
        return Err(license::error_code("PRO_REQUIRED", None));
    }
    system_tools::scan_registry(data_dir)
}

#[tauri::command(async)]
fn clean_registry(
    app: AppHandle,
    finding_ids: Vec<String>,
) -> Result<system_tools::RegistryCleanResult, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    if !entitlements.pro_rules {
        return Err(license::error_code("PRO_REQUIRED", None));
    }
    system_tools::clean_registry(data_dir, finding_ids)
}

#[tauri::command(async)]
fn analyze_disk(app: AppHandle, path: Option<String>) -> Result<Vec<engine::DiskEntry>, String> {
    let event_app = app.clone();
    engine::analyze_disk_with_progress(app_data(&app)?, path, move |progress| {
        let _ = event_app.emit("analyze://progress", progress);
    })
}

#[tauri::command(async)]
fn find_large_files(
    app: AppHandle,
    path: Option<String>,
    min_bytes: u64,
) -> Result<Vec<engine::LargeFile>, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    let event_app = app.clone();
    engine::find_large_files_with_progress(
        data_dir,
        path,
        min_bytes,
        entitlements,
        move |progress| {
            let _ = event_app.emit("large-files://progress", progress);
        },
    )
}

#[tauri::command(async)]
fn find_duplicates(
    app: AppHandle,
    path: Option<String>,
) -> Result<Vec<engine::DuplicateGroup>, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    let event_app = app.clone();
    engine::find_duplicates_with_progress(data_dir, path, entitlements, move |progress| {
        let _ = event_app.emit("duplicates://progress", progress);
    })
}

#[tauri::command(async)]
fn quarantine_paths(
    app: AppHandle,
    paths: Vec<String>,
    keep_paths: Vec<String>,
) -> Result<engine::CleanReport, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    if !entitlements.large_file_finder {
        return Err(license::error_code("PRO_REQUIRED", None));
    }
    engine::quarantine_paths(data_dir, paths, keep_paths)
}

#[tauri::command(async)]
fn quarantine_duplicate_files(
    app: AppHandle,
    selections: Vec<engine::DuplicateRemoval>,
) -> Result<engine::CleanReport, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    if !entitlements.duplicate_finder {
        return Err(license::error_code("PRO_REQUIRED", None));
    }
    engine::quarantine_duplicate_files(data_dir, selections)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let app_data_dir = app.path().data_dir()?.join(app_dirs::app_name());
            fs::create_dir_all(app_data_dir)?;
            let manager =
                license::LicenseManager::new(app.path().data_dir()?.join(app_dirs::app_name()));
            tauri::async_runtime::spawn(async move {
                manager.refresh().await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_rule_catalog,
            scan_rules,
            clean_rules,
            restore_last_quarantine,
            empty_quarantine,
            get_system_stats,
            flush_dns,
            empty_trash,
            get_license_status,
            activate_license,
            deactivate_license,
            analyze_disk,
            find_large_files,
            find_duplicates,
            quarantine_paths,
            quarantine_duplicate_files,
            list_startup_items,
            set_startup_item_enabled,
            list_installed_programs,
            uninstall_program,
            scan_registry,
            clean_registry
        ])
        .run(tauri::generate_context!())
        .expect("error while running Dustonic");
}
