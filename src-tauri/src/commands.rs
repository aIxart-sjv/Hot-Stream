use crate::discovery;
use crate::enforce::{helper_client, BlockedState};
use crate::model::{normalize_mac, HotspotState};

/// The hotspot and its clients, read fresh from the system on every call.
///
/// Runs on the blocking pool so the external tools it spawns can never stall the UI thread.
/// Errors are returned as text for the UI to display; they are never swallowed.
#[tauri::command]
pub async fn get_hotspot_state() -> Result<HotspotState, String> {
    tauri::async_runtime::spawn_blocking(discovery::snapshot)
        .await
        .map_err(|e| format!("discovery task failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// The kernel's actual set of blocked clients, via the privileged helper. If the helper is not
/// installed or not yet granted its capability, this reports that plainly — the UI must never
/// show a device as unblocked just because this call failed.
#[tauri::command]
pub async fn get_enforcement_state() -> Result<BlockedState, String> {
    tauri::async_runtime::spawn_blocking(helper_client::status)
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

#[tauri::command]
pub async fn block_client(mac: String) -> Result<BlockedState, String> {
    normalize_mac(&mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    tauri::async_runtime::spawn_blocking(move || helper_client::block(&mac))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

#[tauri::command]
pub async fn unblock_client(mac: String) -> Result<BlockedState, String> {
    normalize_mac(&mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    tauri::async_runtime::spawn_blocking(move || helper_client::unblock(&mac))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}
