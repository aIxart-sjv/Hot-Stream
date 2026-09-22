//! Raises `CAP_NET_ADMIN` into this process's *ambient* capability set.
//!
//! Discovered empirically: `setcap cap_net_admin+ep hot-stream-helper` alone is not enough.
//! File capabilities (the `ep` flags) apply only to the process directly `exec`'d from that
//! file — they do **not** propagate to a child process it spawns (here, `nft`). The ambient
//! set is the one Linux mechanism that does carry a capability across `execve` into an
//! otherwise-unprivileged child.
//!
//! Raising a capability into the ambient set requires it to already be present in both this
//! process's *permitted* and *inheritable* sets. The file's `p` flag does give a fresh
//! `hot-stream-helper` process the capability in its permitted set even when launched by a
//! fully unprivileged parent (that's the whole point of file capabilities) — but a process's
//! inheritable set after `execve` is inherited from its *parent's* inheritable set, not
//! granted by the file's own `i` flag; an ordinary shell has nothing inheritable, so it stays
//! empty regardless of `+eip` on the file. So this process must move the capability from its
//! own permitted set into its own inheritable set first (which any process may do for
//! capabilities it already holds), and only then raise it into ambient.
//!
//! Without this, `nft` fails with "Operation not permitted" even though `getcap` correctly
//! shows the helper itself holding the capability: the helper has it, its child does not.
//!
//! This call is *best-effort*, not a precondition: real root, and "fake root" inside a test
//! network namespace, both reach `nft` successfully without it (their children are root by
//! process ancestry, not by inherited capability) — and raising into the ambient set can fail
//! for them too (nothing to move into inheritable from an empty permitted set outside
//! CAP_NET_ADMIN's normal grant path), even though `nft` itself will work fine there. So its
//! own success or failure is never treated as the verdict on whether privilege was sufficient;
//! only the real operation's own result is (see `bin/hot-stream-helper.rs`).

use caps::{CapSet, Capability};

const CAP: Capability = Capability::CAP_NET_ADMIN;

/// Called once, before spawning `nft` for the first time. On success, every child process this
/// helper spawns afterwards inherits `CAP_NET_ADMIN`.
pub fn raise_net_admin() -> Result<(), String> {
    // Move CAP_NET_ADMIN from our permitted set (granted by the file's `p` flag) into our own
    // inheritable set. A process may always do this for a capability it already holds
    // permitted; it does not require the capability to be inheritable already.
    caps::raise(None, CapSet::Inheritable, CAP)
        .map_err(|e| format!("could not add CAP_NET_ADMIN to the inheritable set: {e}"))?;
    // Now raise it into the ambient set, which requires it in both permitted and inheritable —
    // both true at this point — so it survives the exec of `nft`.
    caps::raise(None, CapSet::Ambient, CAP)
        .map_err(|e| format!(
            "could not raise CAP_NET_ADMIN into the ambient set: {e}. Grant the capability with \
             the inheritable flag included: `sudo setcap cap_net_admin+eip <path to this binary>` \
             (not just `+ep`)."
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failing_without_the_capability_gives_a_message_not_a_panic() {
        // Ordinary `cargo test` runs with no capabilities at all, so this should fail cleanly.
        // (If the tests ever run as real root, succeeding is also fine — root has the
        // capability in both sets already.)
        let _ = raise_net_admin();
    }

    #[test]
    fn calling_it_repeatedly_does_not_panic() {
        let _ = raise_net_admin();
        let _ = raise_net_admin();
    }
}
