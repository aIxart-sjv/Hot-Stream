//! Client blocking: a dedicated, independently-removable nftables table (`inet hotstream`)
//! holding the set of blocked MACs, enforced by one rule at the `raw` prerouting hook — before
//! conntrack/NAT, so it cannot be bypassed by an established connection and does not depend on
//! or alter NetworkManager's, ufw's, Docker's or libvirt's own rules.
//!
//! This module talks to `nft` directly and needs `CAP_NET_ADMIN`; only [`bin/hot-stream-helper`]
//! links against it. The GUI (unprivileged) never calls it — it goes through [`helper_client`]
//! instead, which spawns that helper as a subprocess. That split is the actual privilege
//! boundary; kernel state (never the UI, never a policy file) is the only truth either side
//! trusts, which is why every mutation reads the kernel back before returning.

pub mod ambient;
pub mod helper_client;
pub mod kernel;

use serde::{Deserialize, Serialize};

use crate::model::Mac;

/// The wire format between the helper (stdout, on success) and the GUI. Also what `kernel`
/// functions return after reading the kernel back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockedState {
    /// Every currently-blocked MAC, sorted, straight from the kernel.
    pub blocked: Vec<Mac>,
}

impl BlockedState {
    pub fn is_blocked(&self, mac: &str) -> bool {
        self.blocked.iter().any(|m| m == mac)
    }
}
