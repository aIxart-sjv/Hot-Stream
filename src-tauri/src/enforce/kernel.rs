//! The privileged half: builds and applies the nftables state, and reads it back. Only the
//! `hot-stream-helper` binary calls this — it is the only code that needs `CAP_NET_ADMIN`.
//!
//! Design, chosen after probing real `nft` behaviour (see the M2 investigation):
//! - `add table` / `add set` / `add chain` are idempotent: safe to re-issue every call.
//! - `add rule` is **not** idempotent — issuing it twice creates two rules. So every apply does
//!   `flush chain` then adds exactly one rule, rather than trying to detect "already added".
//! - `delete element` on a MAC that is not in the set is an error. So unblock never deletes: it
//!   computes the whole desired set and does `flush set` + `add element` for all of it, same as
//!   block. This makes block/unblock/apply idempotent and race-free by construction — there is
//!   no "add" and "remove" code path to keep in sync, just "make the kernel match this set".
//! - `list set` on a table or set that does not exist yet fails with "No such file or
//!   directory"; that is read as "nothing is blocked", not as an error.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::discovery::error::DiscoveryError;
use crate::discovery::exec; // shared low-level "run a program with a timeout" utility
use crate::model::{normalize_mac, Mac};

use super::BlockedState;

const TABLE: &str = "hotstream";
const SET: &str = "blocked";
const CHAIN: &str = "block_clients";
const NFT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
pub enum EnforceError {
    /// A MAC reached privileged code without being in canonical `normalize_mac` form. This
    /// should be unreachable if callers validate first, but is checked again here regardless:
    /// nothing crosses into an `nft` script without passing this check immediately before.
    InvalidMac(String),
    Exec(DiscoveryError),
    Parse { what: &'static str, detail: String },
    /// The kernel's state right after applying does not match what was requested. A real
    /// problem (e.g. `nft` partially failed) that must be surfaced, never hidden.
    Inconsistent { detail: String },
}

impl fmt::Display for EnforceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforceError::InvalidMac(m) => write!(f, "refusing to use invalid MAC address: {m:?}"),
            EnforceError::Exec(e) => write!(f, "{e}"),
            EnforceError::Parse { what, detail } => write!(f, "could not parse {what}: {detail}"),
            EnforceError::Inconsistent { detail } => {
                write!(f, "kernel state after applying does not match what was requested: {detail}")
            }
        }
    }
}

impl std::error::Error for EnforceError {}

impl From<DiscoveryError> for EnforceError {
    fn from(e: DiscoveryError) -> Self {
        EnforceError::Exec(e)
    }
}

/// Re-validate a MAC immediately before it is used to build `nft` script text. The only gate
/// between untrusted input and a privileged command line: nothing skips it.
fn validated(mac: &str) -> Result<Mac, EnforceError> {
    normalize_mac(mac).ok_or_else(|| EnforceError::InvalidMac(mac.to_string()))
}

/// The `nft -f -` script that brings the kernel to exactly `desired`. Every element of
/// `desired` is re-validated; the first invalid one aborts script generation entirely (no
/// partial script is ever returned).
fn build_apply_script(desired: &BTreeSet<Mac>) -> Result<String, EnforceError> {
    let mut checked = Vec::with_capacity(desired.len());
    for mac in desired {
        checked.push(validated(mac)?);
    }

    let mut script = format!(
        "add table inet {TABLE}\n\
         add set inet {TABLE} {SET} {{ type ether_addr; }}\n\
         add chain inet {TABLE} {CHAIN} {{ type filter hook prerouting priority raw; policy accept; }}\n\
         flush chain inet {TABLE} {CHAIN}\n\
         add rule inet {TABLE} {CHAIN} ether saddr @{SET} drop\n\
         flush set inet {TABLE} {SET}\n"
    );
    if !checked.is_empty() {
        script.push_str(&format!("add element inet {TABLE} {SET} {{ {} }}\n", checked.join(", ")));
    }
    Ok(script)
}

#[derive(Deserialize)]
struct RawObject {
    #[serde(default)]
    set: Option<RawSet>,
}

#[derive(Deserialize)]
struct RawSet {
    #[serde(default)]
    elem: Vec<String>,
}

/// Parse `nft -j list set ...`.
fn parse_list_set_json(json: &str) -> Result<BTreeSet<Mac>, EnforceError> {
    let objects: Vec<RawObject> = serde_json::from_str(json)
        .and_then(|v: serde_json::Value| {
            serde_json::from_value(v["nftables"].clone())
        })
        .map_err(|e| EnforceError::Parse { what: "`nft list set` output", detail: e.to_string() })?;
    Ok(objects
        .into_iter()
        .filter_map(|o| o.set)
        .flat_map(|s| s.elem)
        .filter_map(|m| normalize_mac(&m))
        .collect())
}

/// `nft` says this when the table or set named does not exist yet — the correct reading is
/// "nothing is blocked", not an error.
fn is_missing(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

/// The kernel's actual blocked set, read fresh. Never cached, never trusted from anywhere else.
pub fn read_blocked() -> Result<BTreeSet<Mac>, EnforceError> {
    let args = ["-j", "list", "set", "inet", TABLE, SET];
    match exec::run("nft", &args, NFT_TIMEOUT) {
        Ok(out) => parse_list_set_json(&out),
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing(&stderr) => Ok(BTreeSet::new()),
        Err(e) => Err(e.into()),
    }
}

/// Bring the kernel to exactly `desired`, then read it back and confirm. This is the only
/// place that mutates kernel state; block/unblock/clear all reduce to calling this.
fn apply(desired: BTreeSet<Mac>) -> Result<BlockedState, EnforceError> {
    let script = build_apply_script(&desired)?;
    exec::run_with_stdin("nft", &["-f", "-"], Some(&script), NFT_TIMEOUT)?;

    let actual = read_blocked()?;
    if actual != desired {
        // Surface this rather than reporting the caller's wish as fact (kernel state is the
        // only truth this module trusts, including about its own writes).
        return Err(EnforceError::Inconsistent {
            detail: format!("requested {desired:?}, kernel now reports {actual:?}"),
        });
    }
    Ok(BlockedState { blocked: actual.into_iter().collect() })
}

pub fn block(mac: &str) -> Result<BlockedState, EnforceError> {
    let mac = validated(mac)?;
    let mut desired = read_blocked()?;
    desired.insert(mac);
    apply(desired)
}

pub fn unblock(mac: &str) -> Result<BlockedState, EnforceError> {
    let mac = validated(mac)?;
    let mut desired = read_blocked()?;
    desired.remove(&mac);
    apply(desired)
}

/// Remove the whole Hot-Stream table. Not wired to the UI in M2 (no product requirement to
/// disable enforcement entirely yet); exposed for testing and manual rollback, since the
/// product requirement is a table that "can be independently reconciled and removed".
pub fn clear() -> Result<BlockedState, EnforceError> {
    // `delete table` on a table that does not exist is itself an error, unlike `add`, so this
    // must be its own idempotent step rather than reusing `apply`.
    match exec::run("nft", &["delete", "table", "inet", TABLE], NFT_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing(&stderr) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(BlockedState { blocked: Vec::new() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(macs: &[&str]) -> BTreeSet<Mac> {
        macs.iter().map(|m| m.to_string()).collect()
    }

    // ---- build_apply_script ------------------------------------------------------------

    #[test]
    fn an_empty_desired_set_produces_a_script_with_no_add_element_line() {
        let script = build_apply_script(&set(&[])).unwrap();
        assert!(!script.contains("add element"), "{script}");
        for must in [
            "add table inet hotstream",
            "add set inet hotstream blocked { type ether_addr; }",
            "add chain inet hotstream block_clients { type filter hook prerouting priority raw; policy accept; }",
            "flush chain inet hotstream block_clients",
            "add rule inet hotstream block_clients ether saddr @blocked drop",
            "flush set inet hotstream blocked",
        ] {
            assert!(script.contains(must), "missing {must:?} in:\n{script}");
        }
    }

    #[test]
    fn the_chain_is_flushed_before_the_rule_is_added_so_repeats_cannot_duplicate_it() {
        let script = build_apply_script(&set(&["ce:da:1e:90:d4:aa"])).unwrap();
        let flush_at = script.find("flush chain inet hotstream block_clients").unwrap();
        let add_rule_at = script.find("add rule inet hotstream block_clients").unwrap();
        assert!(flush_at < add_rule_at, "flush must precede add rule:\n{script}");
        assert_eq!(script.matches("add rule").count(), 1);
    }

    #[test]
    fn the_set_is_flushed_before_elements_are_added_so_repeats_cannot_duplicate_them() {
        let script = build_apply_script(&set(&["ce:da:1e:90:d4:aa"])).unwrap();
        let flush_at = script.find("flush set inet hotstream blocked").unwrap();
        let add_elem_at = script.find("add element").unwrap();
        assert!(flush_at < add_elem_at, "flush must precede add element:\n{script}");
    }

    #[test]
    fn a_non_empty_desired_set_lists_every_mac_sorted_and_comma_separated() {
        let script = build_apply_script(&set(&["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"])).unwrap();
        assert!(
            script.contains(
                "add element inet hotstream blocked { be:49:b6:59:5e:1d, ce:da:1e:90:d4:aa }"
            ),
            "{script}"
        );
    }

    #[test]
    fn a_single_mac_has_no_trailing_comma() {
        let script = build_apply_script(&set(&["ce:da:1e:90:d4:aa"])).unwrap();
        assert!(script.contains("add element inet hotstream blocked { ce:da:1e:90:d4:aa }"), "{script}");
    }

    /// Security-critical: even though every caller of `block`/`unblock` is expected to have
    /// validated already, the script builder must independently refuse anything that is not a
    /// canonical MAC, so a bug anywhere upstream can never inject text into a privileged
    /// `nft -f -` script.
    #[test]
    fn adversarial_strings_are_rejected_and_never_reach_script_text() {
        for evil in [
            "aa:bb:cc:dd:ee:ff }; add rule inet hotstream block_clients accept #",
            "aa:bb:cc:dd:ee:ff\nflush ruleset",
            "aa:bb:cc:dd:ee:ff; flush ruleset;",
            "$(reboot)",
            "aa:bb:cc:dd:ee:ff\"",
            "",
            "not-a-mac",
        ] {
            let err = build_apply_script(&set(&[evil])).unwrap_err();
            assert!(matches!(err, EnforceError::InvalidMac(_)), "{evil:?} -> {err:?}");
        }
    }

    #[test]
    fn a_valid_but_uppercase_mac_is_normalised_in_the_script() {
        let script = build_apply_script(&set(&["CE:DA:1E:90:D4:AA"])).unwrap();
        assert!(script.contains("ce:da:1e:90:d4:aa"), "{script}");
        assert!(!script.to_lowercase().contains("ce:da:1e:90:d4:aa\nCE"), "should not appear twice");
    }

    // ---- parse_list_set_json ------------------------------------------------------------

    #[test]
    fn a_populated_set_is_parsed_from_real_nft_output() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"set": {"family": "inet", "name": "blocked", "table": "hotstream", "type": "ether_addr", "handle": 1, "elem": ["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"]}}]}"#;
        assert_eq!(parse_list_set_json(json).unwrap(), set(&["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"]));
    }

    #[test]
    fn an_empty_set_has_no_elem_key_at_all_and_parses_to_empty() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.6"}}, {"set": {"family": "inet", "name": "blocked", "table": "hotstream", "type": "ether_addr", "handle": 1}}]}"#;
        assert!(parse_list_set_json(json).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_a_parse_error_not_a_panic() {
        assert!(matches!(parse_list_set_json("not json"), Err(EnforceError::Parse { .. })));
    }

    #[test]
    fn json_with_no_set_object_parses_to_empty_rather_than_failing() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.6"}}]}"#;
        assert!(parse_list_set_json(json).unwrap().is_empty());
    }

    // ---- is_missing ------------------------------------------------------------

    #[test]
    fn the_missing_table_or_set_error_text_is_recognised() {
        // Captured verbatim from a real `nft -j list set inet <missing> blocked` / missing set.
        assert!(is_missing("Error: No such file or directory\nlist set inet doesnotexist blocked\n              ^^^^^^^^^^^^"));
        assert!(is_missing("Error: No such file or directory\nlist set inet hotstream doesnotexist"));
    }

    #[test]
    fn a_genuine_permission_error_is_not_mistaken_for_a_missing_table() {
        assert!(!is_missing("Error: Operation not permitted (you must be root)"));
    }

    // ---- validated ------------------------------------------------------------

    #[test]
    fn block_and_unblock_reject_an_invalid_mac_before_touching_the_kernel() {
        assert!(matches!(block("not-a-mac"), Err(EnforceError::InvalidMac(_))));
        assert!(matches!(unblock("not-a-mac"), Err(EnforceError::InvalidMac(_))));
    }
}
