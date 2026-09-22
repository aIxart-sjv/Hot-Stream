//! The privileged half: builds and applies the nftables state, and reads it back. Only the
//! `hot-stream-helper` binary calls this — it is the only code that needs `CAP_NET_ADMIN`.
//!
//! Design, chosen after probing real `nft` behaviour (see the M2/M3 investigations):
//! - `add table` / `add set` / `add chain` are idempotent: safe to re-issue every call. `add
//!   set` on an existing set also updates its `size` in place — no delete+recreate needed to
//!   change the configured maximum.
//! - `add rule` is **not** idempotent — issuing it twice creates two rules. So every apply does
//!   `flush chain` then adds each rule at most once, rather than trying to detect "already
//!   added".
//! - `delete element` on a MAC that is not in the set is an error. So block/unblock/admission
//!   changes never delete individual elements: they compute the whole desired set and do
//!   `flush set` + `add element` for all of it. This makes every write idempotent and
//!   race-free by construction — there is no "add" and "remove" code path to keep in sync,
//!   just "make the kernel match this state".
//! - `list table`/`list set` on a table/set that does not exist yet fails with "No such file
//!   or directory"; that is read as "nothing configured", not as an error.
//! - An nftables set `size` is enforced by the kernel (exceeding it fails with "Too many open
//!   files in system" — an odd but consistent message) and is itself readable back via `list`.
//!   That is what lets the *configured maximum* itself live entirely in kernel state, with no
//!   new persisted policy file: it is read back the same way the admitted set's members are.
//!   One consequence: nftables treats `size 0` as "unlimited", not "zero capacity" — so a
//!   configured maximum of zero is rejected as invalid input rather than silently meaning
//!   something other than what it says.
//! - **Resizing an existing set must happen as its own `nft` call, before the batch that
//!   flushes and refills it — not combined into the same atomic `-f` script.** Proven by a
//!   direct reproduction: `add set ... size 3` followed, in the *same* batch, by an `add
//!   element` bringing the set up to 3 members fails with "too many open files in system",
//!   because the batch validates that `add element` against the set's size as it was before
//!   the batch started, not the new size requested earlier in the same batch. Resizing
//!   first, as a separate call, sidesteps this entirely — that call alone is already known to
//!   work (idempotent create-or-resize, verified directly).
//! - **Both rules must be scoped to the hotspot's own ingress interface** (`iifname
//!   "<iface>"`). Proven necessary, not just tidy, by a sandbox test: the admission rule is an
//!   *exclusion* match (`ether saddr != @admitted drop`), so without an interface qualifier it
//!   also matches every packet arriving from anywhere else with some other, non-client source
//!   MAC — on the real machine, that includes ordinary Internet reply traffic arriving on the
//!   uplink, which would have been dropped outright. (The block rule is an *inclusion* match
//!   against specific real client MACs that would never legitimately appear on another
//!   interface, so M2 was safe without this — but it is scoped now too, for the same
//!   correctness reasoning applied consistently.) The interface is supplied fresh by the
//!   caller on every write (from live discovery, never cached here), so if the hotspot ever
//!   moves to a different interface, the next block/unblock/admission write re-scopes
//!   correctly — see `enforce` and `commands` for where that interface comes from.
//!
//! Two independent policies share one chain, as two independent `drop` rules (see the module
//! doc for why that means neither can override the other): the block rule is always present;
//! the admission rule exists only when a maximum is configured, tagged with an nft comment so
//! its presence — not the `admitted` set's mere existence — is what `read_state` trusts to
//! mean "a limit is active". Disabling the limit removes that rule but deliberately leaves the
//! `admitted` set itself in place (unreferenced, harmless) rather than deleting it: deleting
//! has the same not-idempotent-on-missing problem as deleting an element, for no functional
//! benefit.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::discovery::error::DiscoveryError;
use crate::discovery::exec; // shared low-level "run a program with a timeout" utility
use crate::model::{normalize_mac, Mac};

use super::{Admission, EnforcementState};

const TABLE: &str = "hotstream";
const BLOCKED_SET: &str = "blocked";
const ADMITTED_SET: &str = "admitted";
const CHAIN: &str = "block_clients";
const TAG_BLOCK: &str = "hs-block";
const TAG_ADMISSION: &str = "hs-admission";
const NFT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
pub enum EnforceError {
    /// A MAC reached privileged code without being in canonical `normalize_mac` form. This
    /// should be unreachable if callers validate first, but is checked again here regardless:
    /// nothing crosses into an `nft` script without passing this check immediately before.
    InvalidMac(String),
    /// Same defence, for the interface name the rules are scoped to.
    InvalidIface(String),
    /// A configured maximum of 0 was requested. Rejected rather than honoured: nftables' own
    /// set-size semantics treat `size 0` as "unlimited", so using it to mean "admit nobody"
    /// would silently do the opposite of what was asked.
    InvalidMax,
    /// More MACs were asked to be admitted than the configured maximum allows. Should be
    /// unreachable — callers are expected to cap the admitted list themselves — but checked
    /// here too, since silently truncating someone's admission list is worse than refusing.
    TooManyAdmitted { max: u32, got: usize },
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
            EnforceError::InvalidIface(i) => write!(f, "refusing to use invalid interface name: {i:?}"),
            EnforceError::InvalidMax => {
                write!(f, "a maximum of 0 is not supported (nftables treats it as \"unlimited\", not \"none\")")
            }
            EnforceError::TooManyAdmitted { max, got } => {
                write!(f, "{got} clients were passed to admit, but the configured maximum is {max}")
            }
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

/// A Linux network interface name: 1-15 bytes (`IFNAMSIZ - 1`), no `/` or whitespace — real
/// kernel interface names are always a subset of this, and rejecting anything else means
/// nothing but a genuine interface name can ever be interpolated into a privileged script.
fn validated_iface(iface: &str) -> Result<String, EnforceError> {
    let ok = !iface.is_empty()
        && iface.len() <= 15
        && iface.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(iface.to_string())
    } else {
        Err(EnforceError::InvalidIface(iface.to_string()))
    }
}

/// The full desired kernel state for one atomic apply. Internal to this module — the public,
/// JSON-facing shape is [`EnforcementState`]; this uses `BTreeSet` for natural dedup/sort
/// while building the script, and always carries the interface both rules are scoped to.
#[derive(Debug, Clone, PartialEq)]
struct Desired {
    iface: String,
    blocked: BTreeSet<Mac>,
    /// `(max, admitted)`. `None` = no limit configured at all.
    admission: Option<(u32, BTreeSet<Mac>)>,
}

/// The `nft -f -` script that brings the kernel to exactly `desired`. Every MAC is
/// re-validated; the first invalid one — or an invalid interface, or an invalid/over-full
/// admission request — aborts script generation entirely (no partial script is ever
/// returned).
fn build_apply_script(desired: &Desired) -> Result<String, EnforceError> {
    let iface = validated_iface(&desired.iface)?;

    let mut blocked = Vec::with_capacity(desired.blocked.len());
    for mac in &desired.blocked {
        blocked.push(validated(mac)?);
    }

    let admission = match &desired.admission {
        Some((0, _)) => return Err(EnforceError::InvalidMax),
        Some((max, admitted)) => {
            if admitted.len() > *max as usize {
                return Err(EnforceError::TooManyAdmitted { max: *max, got: admitted.len() });
            }
            let mut checked = Vec::with_capacity(admitted.len());
            for mac in admitted {
                checked.push(validated(mac)?);
            }
            Some((*max, checked))
        }
        None => None,
    };

    let mut script = format!(
        "add table inet {TABLE}\n\
         add set inet {TABLE} {BLOCKED_SET} {{ type ether_addr; }}\n\
         add chain inet {TABLE} {CHAIN} {{ type filter hook prerouting priority raw; policy accept; }}\n\
         flush chain inet {TABLE} {CHAIN}\n"
    );

    if let Some((max, _)) = &admission {
        script.push_str(&format!("add set inet {TABLE} {ADMITTED_SET} {{ type ether_addr; size {max}; }}\n"));
    }

    script.push_str(&format!(
        "add rule inet {TABLE} {CHAIN} iifname \"{iface}\" ether saddr @{BLOCKED_SET} drop comment \"{TAG_BLOCK}\"\n"
    ));
    if admission.is_some() {
        script.push_str(&format!(
            "add rule inet {TABLE} {CHAIN} iifname \"{iface}\" ether saddr != @{ADMITTED_SET} drop comment \"{TAG_ADMISSION}\"\n"
        ));
    }

    script.push_str(&format!("flush set inet {TABLE} {BLOCKED_SET}\n"));
    if !blocked.is_empty() {
        script.push_str(&format!("add element inet {TABLE} {BLOCKED_SET} {{ {} }}\n", blocked.join(", ")));
    }

    if let Some((_, admitted)) = &admission {
        script.push_str(&format!("flush set inet {TABLE} {ADMITTED_SET}\n"));
        if !admitted.is_empty() {
            script.push_str(&format!("add element inet {TABLE} {ADMITTED_SET} {{ {} }}\n", admitted.join(", ")));
        }
    }

    Ok(script)
}

#[derive(Deserialize)]
struct RawObject {
    #[serde(default)]
    set: Option<RawSet>,
    #[serde(default)]
    rule: Option<RawRule>,
}

#[derive(Deserialize)]
struct RawSet {
    name: String,
    #[serde(default)]
    elem: Vec<String>,
    #[serde(default)]
    size: Option<u32>,
}

#[derive(Deserialize)]
struct RawRule {
    #[serde(default)]
    comment: Option<String>,
    /// Each match's fields, flattened just enough to pull `iifname` out of e.g.
    /// `{"match":{"left":{"meta":{"key":"iifname"}},"right":"wlo1", ...}}`.
    #[serde(default)]
    expr: Vec<serde_json::Value>,
}

impl RawRule {
    fn iifname(&self) -> Option<&str> {
        self.expr.iter().find_map(|e| {
            let m = e.get("match")?;
            if m.get("left")?.get("meta")?.get("key")? == "iifname" {
                m.get("right")?.as_str()
            } else {
                None
            }
        })
    }
}

/// Parse `nft -j list table inet hotstream`: the whole table (chain, rules, sets) in one
/// read, so the block and admission state are always read as one consistent snapshot.
fn parse_table_json(json: &str) -> Result<Desired, EnforceError> {
    let objects: Vec<RawObject> = serde_json::from_str(json)
        .and_then(|v: serde_json::Value| serde_json::from_value(v["nftables"].clone()))
        .map_err(|e| EnforceError::Parse { what: "`nft list table` output", detail: e.to_string() })?;

    let find_set = |name: &str| -> Option<&RawSet> {
        objects.iter().find_map(|o| o.set.as_ref().filter(|s| s.name == name))
    };
    let macs_of = |set: &RawSet| -> BTreeSet<Mac> { set.elem.iter().filter_map(|m| normalize_mac(m)).collect() };
    let find_rule = |tag: &str| -> Option<&RawRule> {
        objects.iter().find_map(|o| o.rule.as_ref().filter(|r| r.comment.as_deref() == Some(tag)))
    };

    let block_rule = find_rule(TAG_BLOCK);
    let iface = block_rule
        .and_then(|r| r.iifname())
        .or_else(|| find_rule(TAG_ADMISSION).and_then(|r| r.iifname()))
        .unwrap_or_default()
        .to_string();

    let blocked = find_set(BLOCKED_SET).map(macs_of).unwrap_or_default();

    // The admission RULE's presence (by comment tag), not the admitted SET's mere existence,
    // decides whether a limit is active — see the module doc for why.
    let admission = find_rule(TAG_ADMISSION)
        .and_then(|_| find_set(ADMITTED_SET))
        .map(|s| (s.size.unwrap_or(0), macs_of(s)));

    Ok(Desired { iface, blocked, admission })
}

/// `nft` says this when the table/set/chain named does not exist yet — the correct reading is
/// "nothing configured", not an error.
fn is_missing(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

fn to_wire(desired: &Desired) -> EnforcementState {
    EnforcementState {
        iface: (!desired.iface.is_empty()).then(|| desired.iface.clone()),
        blocked: desired.blocked.iter().cloned().collect(),
        admission: desired
            .admission
            .as_ref()
            .map(|(max, admitted)| Admission { max: *max, admitted: admitted.iter().cloned().collect() }),
        // This module only ever knows about the two `nft`-based policies — `bandwidth` is
        // filled in by whoever merges this with `shaping::read_state` (see
        // `bin/hot-stream-helper`'s `status` command), the same way an `iface` read here says
        // nothing about which interface a *separate* `tc` read would need to be told.
        bandwidth: Vec::new(),
    }
}

/// The kernel's actual full state, read fresh. Never cached, never trusted from anywhere else.
pub fn read_state() -> Result<EnforcementState, EnforceError> {
    Ok(to_wire(&read_desired()?))
}

fn read_desired() -> Result<Desired, EnforceError> {
    match exec::run("nft", &["-j", "list", "table", "inet", TABLE], NFT_TIMEOUT) {
        Ok(out) => parse_table_json(&out),
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing(&stderr) => {
            Ok(Desired { iface: String::new(), blocked: BTreeSet::new(), admission: None })
        }
        Err(e) => Err(e.into()),
    }
}

/// Bring the kernel to exactly `desired`, then read it back and confirm. This is the only
/// place that mutates kernel state; block/unblock/set_admission all reduce to calling this,
/// each only ever changing its own part of `Desired` after reading the current full state —
/// which is what stops one policy from ever clobbering the other.
fn apply(desired: Desired) -> Result<EnforcementState, EnforceError> {
    // Validate everything before issuing *any* nft call: the resize pre-step below must never
    // run — not even as a side effect — for a request that is going to be rejected anyway
    // (e.g. max=0), or a rejected call could still leave a stray resized set behind.
    let script = build_apply_script(&desired)?;

    // Resizing the admitted set — if it needs to exist at all — happens as its own call,
    // before the main batch even runs: see the module doc for why doing it inside the same
    // atomic script as the flush+refill fails. By the time the main script (below) restates
    // the same size, it is already correct, so that restatement is a no-op, not a resize.
    if let Some((max, _)) = &desired.admission {
        // The table itself may not exist yet (this can be the very first call ever made) —
        // the main script below would create it, but never gets to run if this pre-step
        // fails first, so it must ensure the table exists too. `add table` is idempotent.
        exec::run("nft", &["add", "table", "inet", TABLE], NFT_TIMEOUT)?;
        // `{`/`}` must be their own argv tokens — nft's grammar requires the literal brace
        // tokens, not just something that *looks* bracketed once joined (verified directly:
        // omitting them is a syntax error, not a lenient parse).
        let size_stmt = format!("size {max};");
        exec::run("nft", &["add", "set", "inet", TABLE, ADMITTED_SET, "{", "type", "ether_addr;", &size_stmt, "}"], NFT_TIMEOUT)?;
    }

    exec::run_with_stdin("nft", &["-f", "-"], Some(&script), NFT_TIMEOUT)?;

    let actual = read_desired()?;
    if actual != desired {
        // Surface this rather than reporting the caller's wish as fact (kernel state is the
        // only truth this module trusts, including about its own writes).
        return Err(EnforceError::Inconsistent {
            detail: format!("requested {desired:?}, kernel now reports {actual:?}"),
        });
    }
    Ok(to_wire(&actual))
}

/// `iface` is the hotspot's *current* interface, supplied fresh by the caller from live
/// discovery on every call — never cached here, so if it ever changes, the next write
/// re-scopes both rules to the new one (see the module doc).
pub fn block(iface: &str, mac: &str) -> Result<EnforcementState, EnforceError> {
    let mac = validated(mac)?;
    let mut desired = read_desired()?;
    desired.iface = iface.to_string();
    desired.blocked.insert(mac);
    apply(desired)
}

pub fn unblock(iface: &str, mac: &str) -> Result<EnforcementState, EnforceError> {
    let mac = validated(mac)?;
    let mut desired = read_desired()?;
    desired.iface = iface.to_string();
    desired.blocked.remove(&mac);
    apply(desired)
}

/// Set (or, with `max: None`, clear) the maximum-clients admission policy. `admitted` is the
/// full desired admitted set — the caller (the discovery-aware orchestration layer, not this
/// module) decides *which* MACs those are and in what order they were chosen; this module
/// only ever applies an already-decided set. Leaves `blocked` exactly as it currently is.
pub fn set_admission(iface: &str, max: Option<u32>, admitted: &[Mac]) -> Result<EnforcementState, EnforceError> {
    let mut checked = BTreeSet::new();
    for mac in admitted {
        checked.insert(validated(mac)?);
    }
    let mut desired = read_desired()?;
    desired.iface = iface.to_string();
    desired.admission = max.map(|m| (m, checked));
    apply(desired)
}

/// Remove the whole Hot-Stream table (both policies). Not wired to the UI; exposed for
/// testing and manual rollback, since the product requirement is a table that "can be
/// independently reconciled and removed".
pub fn clear() -> Result<EnforcementState, EnforceError> {
    // `delete table` on a table that does not exist is itself an error, unlike `add`, so this
    // must be its own idempotent step rather than reusing `apply`.
    match exec::run("nft", &["delete", "table", "inet", TABLE], NFT_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing(&stderr) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(EnforcementState::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IF: &str = "wlo1";

    fn set(macs: &[&str]) -> BTreeSet<Mac> {
        macs.iter().map(|m| m.to_string()).collect()
    }

    fn desired(blocked: &[&str], admission: Option<(u32, &[&str])>) -> Desired {
        Desired { iface: IF.into(), blocked: set(blocked), admission: admission.map(|(m, a)| (m, set(a))) }
    }

    // ---- build_apply_script: blocking (unchanged behaviour from M2, now interface-scoped) --

    #[test]
    fn an_empty_desired_set_produces_a_script_with_no_add_element_line() {
        let script = build_apply_script(&desired(&[], None)).unwrap();
        assert!(!script.contains("add element"), "{script}");
        for must in [
            "add table inet hotstream",
            "add set inet hotstream blocked { type ether_addr; }",
            "add chain inet hotstream block_clients { type filter hook prerouting priority raw; policy accept; }",
            "flush chain inet hotstream block_clients",
            "add rule inet hotstream block_clients iifname \"wlo1\" ether saddr @blocked drop comment \"hs-block\"",
            "flush set inet hotstream blocked",
        ] {
            assert!(script.contains(must), "missing {must:?} in:\n{script}");
        }
        assert!(!script.contains("admitted"), "no admission requested, must not mention it:\n{script}");
    }

    #[test]
    fn the_chain_is_flushed_before_any_rule_is_added_so_repeats_cannot_duplicate_it() {
        let script = build_apply_script(&desired(&["ce:da:1e:90:d4:aa"], Some((2, &["ce:da:1e:90:d4:aa"])))).unwrap();
        let flush_at = script.find("flush chain inet hotstream block_clients").unwrap();
        let block_rule_at = script.find("ether saddr @blocked").unwrap();
        let admission_rule_at = script.find("ether saddr !=").unwrap();
        assert!(flush_at < block_rule_at && flush_at < admission_rule_at, "flush must precede both rules:\n{script}");
        assert_eq!(script.matches("add rule").count(), 2);
    }

    #[test]
    fn the_blocked_set_is_flushed_before_elements_are_added() {
        let script = build_apply_script(&desired(&["ce:da:1e:90:d4:aa"], None)).unwrap();
        let flush_at = script.find("flush set inet hotstream blocked").unwrap();
        let add_elem_at = script.find("add element inet hotstream blocked").unwrap();
        assert!(flush_at < add_elem_at, "flush must precede add element:\n{script}");
    }

    #[test]
    fn a_non_empty_desired_set_lists_every_mac_sorted_and_comma_separated() {
        let script = build_apply_script(&desired(&["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"], None)).unwrap();
        assert!(
            script.contains("add element inet hotstream blocked { be:49:b6:59:5e:1d, ce:da:1e:90:d4:aa }"),
            "{script}"
        );
    }

    /// Security-critical: even though every caller of `block`/`unblock`/`set_admission` is
    /// expected to have validated already, the script builder must independently refuse
    /// anything that is not a canonical MAC, so a bug anywhere upstream can never inject text
    /// into a privileged `nft -f -` script.
    #[test]
    fn adversarial_strings_are_rejected_and_never_reach_script_text() {
        for evil in [
            "aa:bb:cc:dd:ee:ff }; add rule inet hotstream block_clients accept #",
            "aa:bb:cc:dd:ee:ff\nflush ruleset",
            "$(reboot)",
            "",
            "not-a-mac",
        ] {
            assert!(matches!(build_apply_script(&desired(&[evil], None)).unwrap_err(), EnforceError::InvalidMac(_)));
            assert!(matches!(
                build_apply_script(&desired(&[], Some((1, &[evil])))).unwrap_err(),
                EnforceError::InvalidMac(_)
            ));
        }
    }

    #[test]
    fn an_adversarial_interface_name_is_rejected_before_it_reaches_script_text() {
        for evil in ["wlo1\" ; flush ruleset; #", "wlo1/../etc", "a b", "toolongtoolongtoo", ""] {
            let mut d = desired(&[], None);
            d.iface = evil.to_string();
            assert!(matches!(build_apply_script(&d).unwrap_err(), EnforceError::InvalidIface(_)), "{evil:?}");
        }
    }

    #[test]
    fn a_normal_interface_name_is_accepted() {
        for good in ["wlo1", "wlan0", "ap-br0", "eth0.100"] {
            let mut d = desired(&[], None);
            d.iface = good.to_string();
            assert!(build_apply_script(&d).is_ok(), "{good:?}");
        }
    }

    // ---- build_apply_script: admission (new in M3) --------------------------------------

    #[test]
    fn no_admission_configured_means_only_the_block_rule_exists() {
        let script = build_apply_script(&desired(&[], None)).unwrap();
        assert!(!script.contains(ADMITTED_SET));
        assert!(!script.contains(TAG_ADMISSION));
    }

    #[test]
    fn a_configured_maximum_creates_a_sized_set_and_the_interface_scoped_admission_rule() {
        let script = build_apply_script(&desired(&[], Some((3, &[])))).unwrap();
        assert!(script.contains("add set inet hotstream admitted { type ether_addr; size 3; }"), "{script}");
        assert!(
            script.contains(
                "add rule inet hotstream block_clients iifname \"wlo1\" ether saddr != @admitted drop comment \"hs-admission\""
            ),
            "{script}"
        );
    }

    #[test]
    fn admitted_macs_are_listed_sorted_after_flushing_the_admitted_set() {
        let script =
            build_apply_script(&desired(&[], Some((5, &["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"])))).unwrap();
        let flush_at = script.find("flush set inet hotstream admitted").unwrap();
        let add_at = script.find("add element inet hotstream admitted").unwrap();
        assert!(flush_at < add_at);
        assert!(
            script.contains("add element inet hotstream admitted { be:49:b6:59:5e:1d, ce:da:1e:90:d4:aa }"),
            "{script}"
        );
    }

    #[test]
    fn an_empty_admitted_set_with_a_limit_configured_has_no_add_element_for_it() {
        let script = build_apply_script(&desired(&[], Some((1, &[])))).unwrap();
        assert!(script.contains("flush set inet hotstream admitted"));
        assert!(!script.contains("add element inet hotstream admitted"), "{script}");
    }

    #[test]
    fn a_maximum_of_zero_is_rejected_rather_than_silently_meaning_unlimited() {
        assert!(matches!(build_apply_script(&desired(&[], Some((0, &[])))).unwrap_err(), EnforceError::InvalidMax));
    }

    #[test]
    fn more_admitted_macs_than_the_maximum_is_rejected_not_silently_truncated() {
        let err = build_apply_script(&desired(&[], Some((1, &["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"])))).unwrap_err();
        assert!(matches!(err, EnforceError::TooManyAdmitted { max: 1, got: 2 }), "{err:?}");
    }

    /// The two policies must be independently expressible in the same script — this is what
    /// makes it structurally impossible for one to silently override the other: they are two
    /// separate `drop` rules, not one rule that tries to encode both conditions.
    #[test]
    fn block_and_admission_coexist_as_two_separate_independent_rules() {
        let script = build_apply_script(&desired(&["ce:da:1e:90:d4:aa"], Some((2, &["be:49:b6:59:5e:1d"])))).unwrap();
        assert!(script.contains("ether saddr @blocked drop comment \"hs-block\""));
        assert!(script.contains("ether saddr != @admitted drop comment \"hs-admission\""));
        let block_line = script.lines().find(|l| l.contains(TAG_BLOCK)).unwrap();
        let admission_line = script.lines().find(|l| l.contains(TAG_ADMISSION)).unwrap();
        assert!(!block_line.contains("admitted"));
        assert!(admission_line.contains("@admitted") && !admission_line.contains("@blocked"));
    }

    // ---- parse_table_json ------------------------------------------------------------

    /// Captured verbatim (values anonymised) from a real `nft -j list table inet hotstream`
    /// with both policies configured and both rules interface-scoped.
    const REAL_TABLE_JSON: &str = r#"{"nftables":[
        {"metainfo":{"version":"1.1.6"}},
        {"table":{"family":"inet","name":"hotstream","handle":1}},
        {"chain":{"family":"inet","table":"hotstream","name":"block_clients","handle":1,"type":"filter","hook":"prerouting","prio":-300,"policy":"accept"}},
        {"set":{"family":"inet","name":"blocked","table":"hotstream","type":"ether_addr","handle":2,"elem":["ce:da:1e:90:d4:aa"]}},
        {"set":{"family":"inet","name":"admitted","table":"hotstream","type":"ether_addr","handle":3,"size":2,"elem":["be:49:b6:59:5e:1d","ce:da:1e:90:d4:aa"]}},
        {"rule":{"family":"inet","table":"hotstream","chain":"block_clients","handle":4,"comment":"hs-block","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wlo1"}},
            {"match":{"op":"==","left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"@blocked"}},
            {"drop":null}
        ]}},
        {"rule":{"family":"inet","table":"hotstream","chain":"block_clients","handle":5,"comment":"hs-admission","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wlo1"}},
            {"match":{"op":"!=","left":{"payload":{"protocol":"ether","field":"saddr"}},"right":"@admitted"}},
            {"drop":null}
        ]}}
    ]}"#;

    #[test]
    fn a_real_table_with_both_policies_is_parsed_correctly() {
        let d = parse_table_json(REAL_TABLE_JSON).unwrap();
        assert_eq!(d.iface, "wlo1");
        assert_eq!(d.blocked, set(&["ce:da:1e:90:d4:aa"]));
        let (max, admitted) = d.admission.unwrap();
        assert_eq!(max, 2);
        assert_eq!(admitted, set(&["be:49:b6:59:5e:1d", "ce:da:1e:90:d4:aa"]));
    }

    #[test]
    fn an_admitted_set_present_without_the_tagged_rule_is_not_treated_as_active() {
        // The set can be left over from a previously-configured, now-disabled limit (see the
        // module doc: disabling never deletes the set, only the rule referencing it).
        let json = r#"{"nftables":[
            {"set":{"family":"inet","name":"blocked","table":"hotstream","type":"ether_addr","handle":2}},
            {"set":{"family":"inet","name":"admitted","table":"hotstream","type":"ether_addr","handle":3,"size":2,"elem":["ce:da:1e:90:d4:aa"]}},
            {"rule":{"family":"inet","table":"hotstream","chain":"block_clients","handle":4,"comment":"hs-block","expr":[
                {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wlo1"}},
                {"drop":null}
            ]}}
        ]}"#;
        let d = parse_table_json(json).unwrap();
        assert_eq!(d.admission, None, "a stale set with no tagged rule must not count as an active limit");
    }

    #[test]
    fn no_sets_or_rules_at_all_parses_to_the_empty_default_state() {
        let json = r#"{"nftables":[{"metainfo":{"version":"1.1.6"}}]}"#;
        let d = parse_table_json(json).unwrap();
        assert_eq!(d.iface, "");
        assert!(d.blocked.is_empty());
        assert_eq!(d.admission, None);
    }

    #[test]
    fn malformed_json_is_a_parse_error_not_a_panic() {
        assert!(matches!(parse_table_json("not json"), Err(EnforceError::Parse { .. })));
    }

    // ---- is_missing ------------------------------------------------------------

    #[test]
    fn the_missing_table_error_text_is_recognised() {
        assert!(is_missing("Error: No such file or directory\nlist table inet doesnotexist\n              ^^^^^^^^^^^^"));
    }

    #[test]
    fn a_genuine_permission_error_is_not_mistaken_for_a_missing_table() {
        assert!(!is_missing("Error: Operation not permitted (you must be root)"));
    }

    // ---- validated / public API guards ------------------------------------------------------

    #[test]
    fn block_and_unblock_reject_an_invalid_mac_before_touching_the_kernel() {
        assert!(matches!(block(IF, "not-a-mac"), Err(EnforceError::InvalidMac(_))));
        assert!(matches!(unblock(IF, "not-a-mac"), Err(EnforceError::InvalidMac(_))));
    }

    #[test]
    fn set_admission_rejects_an_invalid_mac_before_touching_the_kernel() {
        assert!(matches!(set_admission(IF, Some(2), &["not-a-mac".into()]), Err(EnforceError::InvalidMac(_))));
    }
}
