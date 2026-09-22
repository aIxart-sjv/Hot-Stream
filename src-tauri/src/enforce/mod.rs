//! Client enforcement: a dedicated, independently-removable nftables table (`inet hotstream`)
//! with two independent, simultaneously-enforceable policies:
//!
//!   - **individual block**: a MAC in the `blocked` set is always dropped, full stop.
//!   - **admission (max clients)**: when configured, a MAC not in the `admitted` set is
//!     dropped too. Not configured = no restriction from this policy at all.
//!
//! Both are plain, independent `drop` rules in the same chain — dropped is dropped regardless
//! of which rule caused it, so neither policy can silently override or "rescue" the other (see
//! `kernel` for exactly how). This is why a blocked client stays blocked even while admitted,
//! and why changing the admission limit never touches the block list or vice versa.
//!
//! Enforced at the `raw` prerouting hook — before conntrack/NAT, so it cannot be bypassed by
//! an established connection and does not depend on or alter NetworkManager's, ufw's, Docker's
//! or libvirt's own rules.
//!
//! A third, independent policy family — **per-device bandwidth limits** — lives in [`shaping`]
//! rather than [`kernel`]: it is enforced with `tc` (traffic control), a different subsystem
//! with different semantics (rate-limiting, not drop/accept), so it does not fit the same
//! nftables table. It composes with the two drop-based policies the same way they compose with
//! each other: independently. A bandwidth-limited client that is also blocked is still simply
//! blocked (drop happens before any packet could be shaped); a bandwidth-limited client that
//! is admitted and unblocked is shaped exactly at its configured rate regardless of what the
//! other two policies are doing.
//!
//! This module (and [`shaping`]) talks to `nft`/`tc` directly and needs `CAP_NET_ADMIN`; only
//! [`bin/hot-stream-helper`] links against it. The GUI (unprivileged) never calls it — it goes
//! through [`helper_client`] instead, which spawns that helper as a subprocess. That split is
//! the actual privilege boundary; kernel state (never the UI, never a policy file) is the only
//! truth either side trusts, which is why every mutation reads the kernel back before
//! returning, and why the configured maximum itself lives in the kernel (an nftables set
//! `size`) rather than in any new persisted policy file — it survives a GUI restart exactly the
//! way the block list already did in M2, and is lost on reboot exactly the way the block list
//! already was. The same principle extends to bandwidth limits: their configured rates live
//! entirely in `tc`'s own class state, read back the same way, no new file either.

pub mod ambient;
pub mod helper_client;
pub mod kernel;
pub mod shaping;

use serde::{Deserialize, Serialize};

use crate::model::Mac;

/// The wire format between the helper (stdout, on success) and the GUI. Also what `kernel`
/// functions return after reading the kernel back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EnforcementState {
    /// The hotspot interface both `nft`-based rules are currently scoped to, read back from
    /// the kernel itself — `None` when nothing is configured yet. Exposed mainly for
    /// transparency: it lets a caller notice a mismatch against the currently *discovered*
    /// hotspot interface (e.g. right after the hotspot moves to a different adapter) rather
    /// than assume the kernel-enforced scope is automatically current.
    #[serde(default)]
    pub iface: Option<String>,
    /// Every currently-blocked MAC, sorted, straight from the kernel.
    pub blocked: Vec<Mac>,
    /// `None` when no maximum-clients limit is configured at all — not the same as a limit of
    /// zero, which nftables' own set-size semantics treat as "unlimited" and which Hot-Stream
    /// therefore never represents as a configurable value (see `kernel`).
    #[serde(default)]
    pub admission: Option<Admission>,
    /// Per-client bandwidth limits, straight from `tc` — only MACs with at least one direction
    /// currently limited appear here (absence means fully unrestricted, not "unknown"). Unlike
    /// `blocked`/`admission`, a `tc` read is not self-describing about which interface it
    /// covers (see `shaping`), so this is only ever populated when the caller supplied the
    /// hotspot's current interface to the read that produced this value; otherwise it is empty.
    #[serde(default)]
    pub bandwidth: Vec<BandwidthLimit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BandwidthLimit {
    pub mac: Mac,
    /// Kilobits/second. `None` means that direction is unrestricted for this client.
    #[serde(default)]
    pub download_kbit: Option<u32>,
    #[serde(default)]
    pub upload_kbit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Admission {
    pub max: u32,
    /// Every currently-admitted MAC, sorted, straight from the kernel.
    pub admitted: Vec<Mac>,
}

impl EnforcementState {
    pub fn is_blocked(&self, mac: &str) -> bool {
        self.blocked.iter().any(|m| m == mac)
    }

    /// Whether the max-clients policy allows `mac` through. `true` when no limit is
    /// configured at all — this policy alone never restricts anyone in that case. A client's
    /// overall usability is `!is_blocked(mac) && is_admitted(mac)`: the two policies are
    /// independent and both apply.
    pub fn is_admitted(&self, mac: &str) -> bool {
        match &self.admission {
            None => true,
            Some(a) => a.admitted.iter().any(|m| m == mac),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_limit_json_contract_with_the_ui_is_camel_case() {
        let limit = BandwidthLimit { mac: "ce:da:1e:90:d4:aa".into(), download_kbit: Some(5000), upload_kbit: None };
        let json = serde_json::to_value(&limit).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"mac": "ce:da:1e:90:d4:aa", "downloadKbit": 5000, "uploadKbit": null}),
            "{json}"
        );
    }
}
