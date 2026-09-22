use crate::discovery;
use crate::enforce::{helper_client, EnforcementState};
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

/// The kernel's actual enforcement state (individual blocks, the max-clients admission policy
/// if configured, and bandwidth limits if configured), via the privileged helper. If the
/// helper is not installed or not yet granted its capability, this reports that plainly — the
/// UI must never show a device as unblocked/admitted/unrestricted just because this call
/// failed.
///
/// `iface` should be the hotspot's *current* interface (`HotspotState.hotspot.interface` from
/// the same `get_hotspot_state` reading the caller just used), or `None` if no hotspot is
/// currently running. Block and admission are read regardless; bandwidth limits are only read
/// when `iface` is given — see `helper_client::status` for why.
#[tauri::command]
pub async fn get_enforcement_state(iface: Option<String>) -> Result<EnforcementState, String> {
    tauri::async_runtime::spawn_blocking(move || helper_client::status(iface.as_deref()))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

/// `iface` must be the hotspot's *current* interface (`HotspotState.hotspot.interface` from
/// the same `get_hotspot_state` reading the caller just used) — both enforcement rules are
/// (re-)scoped to it on every write. See `enforce::kernel` for why this matters: an
/// unscoped admission rule was proven, in sandbox testing, to also catch unrelated traffic
/// (e.g. Internet replies arriving on the uplink).
#[tauri::command]
pub async fn block_client(iface: String, mac: String) -> Result<EnforcementState, String> {
    normalize_mac(&mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    tauri::async_runtime::spawn_blocking(move || helper_client::block(&iface, &mac))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

#[tauri::command]
pub async fn unblock_client(iface: String, mac: String) -> Result<EnforcementState, String> {
    normalize_mac(&mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    tauri::async_runtime::spawn_blocking(move || helper_client::unblock(&iface, &mac))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

/// Set (or, with `max: null`, clear) the maximum-clients limit.
///
/// `connected_macs_oldest_first` is the client list exactly as `get_hotspot_state` returns it
/// (already ordered oldest-connection-first — see `discovery::assemble_clients`); this command
/// admits the first `max` of them and denies the rest. Called both when the user explicitly
/// changes the limit and, with the same (unchanged) `max`, on every regular poll so that
/// clients joining or leaving are reflected — see the frontend's poll loop.
#[tauri::command]
pub async fn set_admission(
    iface: String,
    max: Option<u32>,
    connected_macs_oldest_first: Vec<String>,
) -> Result<EnforcementState, String> {
    for mac in &connected_macs_oldest_first {
        normalize_mac(mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    }
    let admitted: Vec<String> = match max {
        Some(max) => connected_macs_oldest_first.into_iter().take(max as usize).collect(),
        None => Vec::new(),
    };
    tauri::async_runtime::spawn_blocking(move || helper_client::set_admission(&iface, max, &admitted))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}

/// Set (or, with `null`, clear) `mac`'s download and/or upload limit, independently. `iface`
/// must be the hotspot's *current* interface, same requirement as `block_client`/
/// `unblock_client`/`set_admission` — see `enforce::shaping` for why every write needs it
/// supplied fresh.
#[tauri::command]
pub async fn set_bandwidth(
    iface: String,
    mac: String,
    download_kbit: Option<u32>,
    upload_kbit: Option<u32>,
) -> Result<EnforcementState, String> {
    normalize_mac(&mac).ok_or_else(|| format!("not a valid MAC address: {mac:?}"))?;
    tauri::async_runtime::spawn_blocking(move || helper_client::set_bandwidth(&iface, &mac, download_kbit, upload_kbit))
        .await
        .map_err(|e| format!("enforcement task failed: {e}"))?
}
