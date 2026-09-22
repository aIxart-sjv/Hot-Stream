mod commands;
pub mod discovery;
pub mod enforce;
pub mod model;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_hotspot_state,
            commands::get_enforcement_state,
            commands::block_client,
            commands::unblock_client,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Hot-Stream");
}
