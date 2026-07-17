use serde::Serialize;
use std::fs;
use tauri::Manager;

mod app_dirs;

#[derive(Debug, Serialize)]
struct ScanCategory {
    name: String,
    items: u32,
    size: String,
}

#[tauri::command]
fn scan_system() -> Vec<ScanCategory> {
    vec![
        ScanCategory {
            name: "System cache".into(),
            items: 128,
            size: "42 MB".into(),
        },
        ScanCategory {
            name: "Browser traces".into(),
            items: 74,
            size: "18 MB".into(),
        },
        ScanCategory {
            name: "Temporary files".into(),
            items: 51,
            size: "9 MB".into(),
        },
    ]
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().data_dir()?.join(app_dirs::app_name());
            fs::create_dir_all(app_data_dir)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![scan_system])
        .run(tauri::generate_context!())
        .expect("error while running Dustonic");
}
