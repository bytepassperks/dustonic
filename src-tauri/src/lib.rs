use std::fs;
use tauri::{AppHandle, Manager};

mod app_dirs;
mod engine;

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
    engine::scan(app_data(&app)?, rule_ids)
}

#[tauri::command]
fn clean_rules(
    app: AppHandle,
    rule_ids: Vec<String>,
    permanent: bool,
) -> Result<engine::CleanReport, String> {
    engine::clean(app_data(&app)?, rule_ids, permanent)
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
        .setup(|app| {
            let app_data_dir = app.path().data_dir()?.join(app_dirs::app_name());
            fs::create_dir_all(app_data_dir)?;
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
            empty_trash
        ])
        .run(tauri::generate_context!())
        .expect("error while running Dustonic");
}
