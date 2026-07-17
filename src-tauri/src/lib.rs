use std::fs;
use tauri::{AppHandle, Manager};

mod app_dirs;
mod engine;
mod license;

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

#[tauri::command]
fn scan_rules(app: AppHandle, rule_ids: Vec<String>) -> Result<engine::ScanReport, String> {
    let data_dir = app_data(&app)?;
    let entitlements = license::LicenseManager::new(data_dir.clone()).current_entitlements();
    engine::scan(data_dir, rule_ids, entitlements)
}

#[tauri::command]
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

#[tauri::command]
fn restore_last_quarantine(app: AppHandle) -> Result<engine::CleanReport, String> {
    engine::restore_last(app_data(&app)?)
}

#[tauri::command]
fn empty_quarantine(app: AppHandle) -> Result<(), String> {
    engine::empty_quarantine(app_data(&app)?)
}

#[tauri::command]
fn get_system_stats() -> engine::SystemStats {
    engine::stats()
}

#[tauri::command]
fn flush_dns() -> Result<(), String> {
    engine::flush_dns()
}

#[tauri::command]
fn empty_trash() -> Result<(), String> {
    engine::empty_trash()
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
            deactivate_license
        ])
        .run(tauri::generate_context!())
        .expect("error while running Dustonic");
}
