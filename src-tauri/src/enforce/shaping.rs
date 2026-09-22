//! The privileged half of per-device bandwidth limiting: builds and applies `tc` (traffic
//! control) state, and reads it back. Only the `hot-stream-helper` binary calls this — it is
//! the only code that needs `CAP_NET_ADMIN` (the same capability `kernel` already needs for
//! `nft`, so no new grant is required).
//!
//! Design, chosen after probing real `tc` behaviour directly against a sandboxed kernel (the
//! M4 investigation) rather than assuming it behaves like `nft`:
//!
//! - Unlike `nft -f -`, `tc` has no atomic multi-statement transaction: every state change is
//!   its own separate invocation. So the flush-and-rewrite-everything pattern `kernel` uses
//!   (safe there because a whole chain/set is cheap to discard and rebuild atomically) is the
//!   wrong shape here — replacing a shared qdisc hierarchy on every call would briefly disturb
//!   *every* client's queue state each time *any one* client's limit changed, which the product
//!   explicitly rules out ("changing one device's limit must not unintentionally change
//!   another device's limit"). Instead, each client's class/filter/queue is its own targeted,
//!   idempotent operation that never touches another client's.
//! - `tc class replace` and `tc qdisc replace <leaf, identified by its parent classid>` are
//!   genuinely idempotent — create-if-missing, update-in-place otherwise — verified directly by
//!   reissuing each several times and confirming no duplication and no disruption to siblings.
//! - `tc qdisc replace <root>`, `tc qdisc add <ingress>` and the matchall ingress-redirect
//!   filter are **not** safely reissuable — verified directly: a second `qdisc replace` on an
//!   already-HTB root errors ("Change operation not supported"), a second plain `add` of an
//!   existing ingress qdisc errors ("Exclusivity flag on"), and a second `add` of the matchall
//!   redirect filter silently creates a *second*, duplicate redirect action rather than
//!   erroring or updating in place. All three are therefore only ever issued after an explicit
//!   existence check, never reissued unconditionally — the one place this module departs from
//!   `kernel`'s "safe to reissue" style, because here, unlike `nft add`, that would not be safe.
//! - A brand-new interface's root qdisc is `noqueue` in practice (confirmed on the real
//!   machine) — never "nothing" — so first-time setup must use `qdisc replace`, not `add`:
//!   `add` fails ("NLM_F_REPLACE needed to override") against any pre-existing root qdisc,
//!   including the implicit default one.
//! - **Download** (laptop → client) is shaped directly on the hotspot's own interface, with HTB
//!   on its egress. **Upload** (client → laptop/Internet) has no equivalent direct hook — Linux
//!   cannot shape ingress with HTB — so it is redirected with an `ingress` qdisc plus `action
//!   mirred egress redirect` to a dedicated IFB device (`hotstream0`, always this one fixed
//!   name: Hot-Stream manages exactly one hotspot interface at a time, so this needs no more
//!   per-iface parameterisation than the `nft` table already has), which gets its own identical
//!   HTB hierarchy on its own egress. This asymmetry (one real interface, one virtual one) is
//!   inherent to how Linux traffic control works, not a Hot-Stream design choice.
//! - Traffic with no configured limit falls through to HTB's `default` class, given a
//!   generously high rate/ceil — so per-device shaping is opt-in per client by construction,
//!   never a cap on unconfigured clients, and clearing a client's limit is exactly "delete its
//!   class/filter/queue", not "set it to some very large number".
//! - Configured rates live entirely in `tc`'s own class state (`rate`, read back as bytes/sec
//!   and converted to kbit), matching the same "kernel is the only truth, no new persisted
//!   policy file" principle `kernel` already established. The MAC → class mapping is read back
//!   the same way, from the `flower` filters' `dst_mac`/`src_mac` match keys.
//! - Unlike an `nft` read, a `tc` read is **not** self-describing about which interface it
//!   covers — `tc class`/`filter show` must be told a device. So, unlike `kernel::read_state`,
//!   every read here takes the hotspot's current interface as an explicit parameter, supplied
//!   fresh by the caller from live discovery (see `bin/hot-stream-helper`'s `status` command).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::discovery::error::DiscoveryError;
use crate::discovery::exec;
use crate::model::{normalize_mac, Mac};

use super::BandwidthLimit;

const ROOT_HANDLE: &str = "1:";
const PARENT_CLASSID: &str = "1:1";
const DEFAULT_CLASSID_NUM: u16 = 999;
const FIRST_CLIENT_CLASSID: u16 = 10;
/// Always this one fixed name, never parameterised by interface — see the module doc.
const IFB: &str = "hotstream0";
const INGRESS_HANDLE: &str = "ffff:";
/// 2 Gbit/s: far above any realistic Wi-Fi throughput, so the classes with no configured limit
/// (the always-present parent and default classes) are never themselves a bottleneck.
const UNLIMITED_KBIT: u32 = 2_000_000;
const TC_TIMEOUT: Duration = Duration::from_secs(5);
const IP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum ShapingError {
    /// Re-validated immediately before use, same defence as `kernel::validated` — see there for
    /// why this is checked again here rather than trusted from any caller.
    InvalidMac(String),
    InvalidIface(String),
    /// A limit of 0 kbit/s was requested for some direction. Rejected rather than honoured: it
    /// does not mean anything sensible to HTB, and "make this client unusable" is what
    /// individual block — a separate, already-existing policy — is for.
    InvalidRate(u32),
    Exec(DiscoveryError),
    Parse { what: &'static str, detail: String },
    /// The kernel's state right after applying does not match what was requested. A real
    /// problem, never hidden — same principle as `kernel::EnforceError::Inconsistent`.
    Inconsistent { detail: String },
}

impl fmt::Display for ShapingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShapingError::InvalidMac(m) => write!(f, "refusing to use invalid MAC address: {m:?}"),
            ShapingError::InvalidIface(i) => write!(f, "refusing to use invalid interface name: {i:?}"),
            ShapingError::InvalidRate(r) => {
                write!(f, "a limit of {r} kbit/s is not supported (use block to make a client unusable instead)")
            }
            ShapingError::Exec(e) => write!(f, "{e}"),
            ShapingError::Parse { what, detail } => write!(f, "could not parse {what}: {detail}"),
            ShapingError::Inconsistent { detail } => {
                write!(f, "kernel state after applying does not match what was requested: {detail}")
            }
        }
    }
}

impl std::error::Error for ShapingError {}

impl From<DiscoveryError> for ShapingError {
    fn from(e: DiscoveryError) -> Self {
        ShapingError::Exec(e)
    }
}

fn validated(mac: &str) -> Result<Mac, ShapingError> {
    normalize_mac(mac).ok_or_else(|| ShapingError::InvalidMac(mac.to_string()))
}

/// Duplicated from `kernel::validated_iface` rather than shared: this module independently
/// re-validates anything that reaches a privileged command line, the same defence kept
/// independently at every such boundary in this codebase (see `kernel`'s own doc comment for
/// why that duplication is deliberate, not an oversight).
fn validated_iface(iface: &str) -> Result<String, ShapingError> {
    let ok = !iface.is_empty()
        && iface.len() <= 15
        && iface.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(iface.to_string())
    } else {
        Err(ShapingError::InvalidIface(iface.to_string()))
    }
}

fn validated_rate(kbit: u32) -> Result<u32, ShapingError> {
    if kbit == 0 {
        Err(ShapingError::InvalidRate(kbit))
    } else {
        Ok(kbit)
    }
}

fn rate_arg(kbit: u32) -> String {
    format!("{kbit}kbit")
}

fn classid(n: u16) -> String {
    format!("1:{n}")
}

fn bytes_to_kbit(bytes_per_sec: u64) -> u32 {
    ((bytes_per_sec * 8) / 1000) as u32
}

/// The next classid to hand to a newly-limited client on one device: one past the highest
/// currently in use there, never below `FIRST_CLIENT_CLASSID`. Deliberately never reuses a
/// freed slot mid-run — simpler, and classids are cheap (a `u16`, never persisted).
fn next_free_classid(used: &BTreeSet<u16>) -> u16 {
    used.iter().copied().max().map_or(FIRST_CLIENT_CLASSID, |m| m + 1).max(FIRST_CLIENT_CLASSID)
}

/// `tc` says this when the device named does not exist — read as "nothing configured on it
/// yet", not an error. (Distinct text from `kernel::is_missing`'s: `tc` and `nft` phrase a
/// missing target differently.)
fn is_missing_device(stderr: &str) -> bool {
    stderr.contains("Cannot find device")
}

/// `ip link show`/`ip link del` report a missing link with different wording depending on the
/// subcommand — both verified directly.
fn is_missing_link(stderr: &str) -> bool {
    stderr.contains("does not exist") || stderr.contains("Cannot find device")
}

/// `tc qdisc del` reports "nothing to delete" differently depending on *what* is missing: the
/// implicit default root (handle `0:`) has its own message distinct from a genuinely absent
/// named qdisc (e.g. `ingress`, never added) — both verified directly.
fn is_missing_qdisc(stderr: &str) -> bool {
    stderr.contains("Cannot delete qdisc with handle of zero") || stderr.contains("Cannot find specified qdisc")
}

// ---- reading kernel state -------------------------------------------------------------------

/// Every `tc -j ... show` call in this module funnels through here: a missing device reads as
/// "nothing configured" (never an error), and anything else that isn't the expected JSON shape
/// is a `Parse` error, never a panic.
fn parse_json<T: for<'de> Deserialize<'de>>(what: &'static str, result: Result<String, DiscoveryError>) -> Result<Vec<T>, ShapingError> {
    match result {
        Ok(out) => serde_json::from_str(&out).map_err(|e| ShapingError::Parse { what, detail: e.to_string() }),
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing_device(&stderr) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Deserialize)]
struct RawQdisc {
    kind: String,
    handle: String,
    #[serde(default)]
    root: bool,
}

fn list_qdiscs(dev: &str, extra_arg: Option<&str>) -> Result<Vec<RawQdisc>, ShapingError> {
    let mut args = vec!["-j", "qdisc", "show", "dev", dev];
    if let Some(a) = extra_arg {
        args.push(a);
    }
    parse_json("`tc qdisc show`", exec::run("tc", &args, TC_TIMEOUT))
}

fn has_our_htb_root(dev: &str) -> Result<bool, ShapingError> {
    Ok(list_qdiscs(dev, None)?.iter().any(|q| q.kind == "htb" && q.handle == ROOT_HANDLE && q.root))
}

fn has_ingress_qdisc(dev: &str) -> Result<bool, ShapingError> {
    Ok(!list_qdiscs(dev, Some("ingress"))?.is_empty())
}

#[derive(Deserialize)]
struct RawFilter {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    options: Option<RawFilterOptions>,
}

#[derive(Deserialize)]
struct RawFilterOptions {
    #[serde(default)]
    classid: Option<String>,
    #[serde(default)]
    keys: Option<RawFlowerKeys>,
}

#[derive(Deserialize)]
struct RawFlowerKeys {
    #[serde(default)]
    dst_mac: Option<String>,
    #[serde(default)]
    src_mac: Option<String>,
}

fn list_filters(dev: &str, parent: &str) -> Result<Vec<RawFilter>, ShapingError> {
    parse_json("`tc filter show`", exec::run("tc", &["-j", "filter", "show", "dev", dev, "parent", parent], TC_TIMEOUT))
}

fn has_redirect_filter(dev: &str) -> Result<bool, ShapingError> {
    Ok(list_filters(dev, INGRESS_HANDLE)?.iter().any(|f| f.kind.as_deref() == Some("matchall")))
}

/// Every MAC currently classified on `dev`'s client-facing chain, and which classid it maps
/// to — keyed by `dst_mac` (download, on the hotspot interface itself) or `src_mac` (upload, on
/// the IFB device, after the ingress redirect has already routed the client's own traffic
/// there).
fn read_classids(dev: &str, want_dst: bool) -> Result<BTreeMap<Mac, u16>, ShapingError> {
    let mut map = BTreeMap::new();
    for f in list_filters(dev, ROOT_HANDLE)? {
        if f.kind.as_deref() != Some("flower") {
            continue;
        }
        let Some(opts) = &f.options else { continue };
        let Some(keys) = &opts.keys else { continue };
        let mac_str = if want_dst { keys.dst_mac.as_deref() } else { keys.src_mac.as_deref() };
        let (Some(mac_str), Some(cls)) = (mac_str, opts.classid.as_deref()) else { continue };
        let Some(mac) = normalize_mac(mac_str) else { continue };
        let Some(num) = cls.strip_prefix("1:").and_then(|n| n.parse::<u16>().ok()) else { continue };
        map.insert(mac, num);
    }
    Ok(map)
}

#[derive(Deserialize)]
struct RawClass {
    handle: String,
    #[serde(default)]
    rate: Option<u64>,
}

/// Every client classid's configured rate on `dev`, in kbit/s — excludes the parent and
/// default classids, which are infrastructure, not a client's own configured limit.
fn read_rates(dev: &str) -> Result<BTreeMap<u16, u32>, ShapingError> {
    let classes: Vec<RawClass> = parse_json("`tc class show`", exec::run("tc", &["-j", "class", "show", "dev", dev], TC_TIMEOUT))?;
    let mut map = BTreeMap::new();
    for c in &classes {
        let Some(num) = c.handle.strip_prefix("1:").and_then(|n| n.parse::<u16>().ok()) else { continue };
        if num == 1 || num == DEFAULT_CLASSID_NUM {
            continue;
        }
        if let Some(bytes) = c.rate {
            map.insert(num, bytes_to_kbit(bytes));
        }
    }
    Ok(map)
}

fn read_direction(dev: &str, want_dst: bool) -> Result<BTreeMap<Mac, u32>, ShapingError> {
    let classids = read_classids(dev, want_dst)?;
    let rates = read_rates(dev)?;
    Ok(classids.into_iter().filter_map(|(mac, num)| rates.get(&num).map(|kbit| (mac, *kbit))).collect())
}

/// The kernel's actual full bandwidth-limit state for `iface`, read fresh — never cached,
/// never trusted from anywhere else. Only MACs with at least one direction currently limited
/// are present; everyone else is implicitly unrestricted.
pub fn read_state(iface: &str) -> Result<Vec<BandwidthLimit>, ShapingError> {
    let iface = validated_iface(iface)?;
    let download = read_direction(&iface, true)?;
    let upload = read_direction(IFB, false)?;
    let mut macs: BTreeSet<Mac> = download.keys().cloned().collect();
    macs.extend(upload.keys().cloned());
    Ok(macs
        .into_iter()
        .map(|mac| BandwidthLimit {
            download_kbit: download.get(&mac).copied(),
            upload_kbit: upload.get(&mac).copied(),
            mac,
        })
        .collect())
}

// ---- applying changes ------------------------------------------------------------------------

/// Idempotent: safe (and, on every call after the first, a no-op past the existence check) to
/// call on every `set_limit`. Creates the shared HTB hierarchy on `dev` if it is not already
/// there, and restates the parent/default classes' rate either way — restating an unchanged
/// rate is a harmless no-op (`class replace`, verified idempotent).
fn ensure_htb_hierarchy(dev: &str) -> Result<(), ShapingError> {
    if !has_our_htb_root(dev)? {
        exec::run(
            "tc",
            &["qdisc", "replace", "dev", dev, "root", "handle", ROOT_HANDLE, "htb", "default", &DEFAULT_CLASSID_NUM.to_string()],
            TC_TIMEOUT,
        )?;
    }
    let cap = rate_arg(UNLIMITED_KBIT);
    exec::run(
        "tc",
        &["class", "replace", "dev", dev, "parent", ROOT_HANDLE, "classid", PARENT_CLASSID, "htb", "rate", &cap, "ceil", &cap],
        TC_TIMEOUT,
    )?;
    let default_classid = classid(DEFAULT_CLASSID_NUM);
    exec::run(
        "tc",
        &["class", "replace", "dev", dev, "parent", PARENT_CLASSID, "classid", &default_classid, "htb", "rate", &cap, "ceil", &cap],
        TC_TIMEOUT,
    )?;
    exec::run("tc", &["qdisc", "replace", "dev", dev, "parent", &default_classid, "fq_codel"], TC_TIMEOUT)?;
    Ok(())
}

/// Idempotent. Creates the `hotstream0` IFB device (and its own HTB hierarchy) only if it is
/// not already there.
fn ensure_ifb() -> Result<(), ShapingError> {
    match exec::run("ip", &["-j", "link", "show", IFB], IP_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing_link(&stderr) => {
            exec::run("ip", &["link", "add", IFB, "type", "ifb"], IP_TIMEOUT)?;
        }
        Err(e) => return Err(e.into()),
    }
    exec::run("ip", &["link", "set", IFB, "up"], IP_TIMEOUT)?;
    ensure_htb_hierarchy(IFB)
}

/// Idempotent. Ensures `hotstream0` exists and that `iface`'s ingress traffic is redirected to
/// it, creating each piece only if it is not already there (see the module doc for why this,
/// unlike `ensure_htb_hierarchy`, cannot just reissue everything unconditionally).
fn ensure_redirect(iface: &str) -> Result<(), ShapingError> {
    ensure_ifb()?;
    if !has_ingress_qdisc(iface)? {
        exec::run("tc", &["qdisc", "add", "dev", iface, "handle", INGRESS_HANDLE, "ingress"], TC_TIMEOUT)?;
    }
    if !has_redirect_filter(iface)? {
        exec::run(
            "tc",
            &[
                "filter", "add", "dev", iface, "parent", INGRESS_HANDLE, "protocol", "all", "prio", "1", "matchall",
                "action", "mirred", "egress", "redirect", "dev", IFB,
            ],
            TC_TIMEOUT,
        )?;
    }
    Ok(())
}

/// Bring `dev`'s shaping for `mac` (identified there by `mac_key`, `"dst_mac"` or `"src_mac"`)
/// to exactly `want_kbit` — `None` meaning no class for this MAC on `dev` at all, so its
/// traffic falls through to the default, unrestricted class. Only ever touches `mac`'s own
/// class/filter/queue: this — not a flush-and-rewrite of the whole chain — is what makes
/// changing one client's limit incapable of disturbing another's (see the module doc).
fn apply_direction(dev: &str, mac: &Mac, mac_key: &str, want_kbit: Option<u32>) -> Result<(), ShapingError> {
    let existing = read_classids(dev, mac_key == "dst_mac")?;
    let current = existing.get(mac).copied();

    match (current, want_kbit) {
        (_, Some(kbit)) => {
            let used: BTreeSet<u16> = existing.values().copied().collect();
            let num = current.unwrap_or_else(|| next_free_classid(&used));
            let cls = classid(num);
            let rate = rate_arg(kbit);
            exec::run(
                "tc",
                &["class", "replace", "dev", dev, "parent", PARENT_CLASSID, "classid", &cls, "htb", "rate", &rate, "ceil", &rate],
                TC_TIMEOUT,
            )?;
            if current.is_none() {
                exec::run("tc", &["qdisc", "replace", "dev", dev, "parent", &cls, "fq_codel"], TC_TIMEOUT)?;
                exec::run(
                    "tc",
                    &[
                        "filter", "add", "dev", dev, "parent", ROOT_HANDLE, "protocol", "all", "prio", "1", "handle",
                        &num.to_string(), "flower", mac_key, mac, "classid", &cls,
                    ],
                    TC_TIMEOUT,
                )?;
            }
        }
        (Some(num), None) => {
            let cls = classid(num);
            exec::run("tc", &["filter", "del", "dev", dev, "parent", ROOT_HANDLE, "prio", "1", "handle", &num.to_string(), "flower"], TC_TIMEOUT)?;
            exec::run("tc", &["qdisc", "del", "dev", dev, "parent", &cls], TC_TIMEOUT)?;
            exec::run("tc", &["class", "del", "dev", dev, "classid", &cls], TC_TIMEOUT)?;
        }
        (None, None) => {}
    }
    Ok(())
}

/// Set (or, with `None`, clear) `mac`'s download and/or upload limit, independently. `iface`
/// is the hotspot's *current* interface, supplied fresh by the caller from live discovery on
/// every call — never cached here (same discipline as `kernel::block`/`set_admission`).
pub fn set_limit(iface: &str, mac: &str, download_kbit: Option<u32>, upload_kbit: Option<u32>) -> Result<Vec<BandwidthLimit>, ShapingError> {
    let iface = validated_iface(iface)?;
    let mac = validated(mac)?;
    if let Some(k) = download_kbit {
        validated_rate(k)?;
    }
    if let Some(k) = upload_kbit {
        validated_rate(k)?;
    }

    ensure_htb_hierarchy(&iface)?;
    apply_direction(&iface, &mac, "dst_mac", download_kbit)?;

    if upload_kbit.is_some() {
        ensure_redirect(&iface)?;
    }
    // Safe even when `hotstream0` was never created: `apply_direction` reads classids via
    // `read_classids`, which reads `Cannot find device` as "nothing configured" and no-ops
    // through the `(None, None)` arm rather than erroring.
    apply_direction(IFB, &mac, "src_mac", upload_kbit)?;

    let actual = read_state(&iface)?;
    let got = actual.iter().find(|b| b.mac == mac).map_or((None, None), |b| (b.download_kbit, b.upload_kbit));
    if got != (download_kbit, upload_kbit) {
        return Err(ShapingError::Inconsistent {
            detail: format!("requested ({download_kbit:?}, {upload_kbit:?}) for {mac}, kernel now reports {got:?}"),
        });
    }
    Ok(actual)
}

/// Remove all Hot-Stream bandwidth shaping: every per-client class/filter/queue (implicitly,
/// as part of deleting the qdiscs they hang off), the ingress redirect, the `hotstream0` IFB
/// device, and the shared HTB hierarchy on `iface` itself — reverting it to whatever qdisc the
/// kernel assigns once its root is gone (`noqueue`, in practice). Not wired to the UI; exposed
/// for testing and manual rollback, mirroring `kernel::clear`.
pub fn clear_all(iface: &str) -> Result<Vec<BandwidthLimit>, ShapingError> {
    let iface = validated_iface(iface)?;
    match exec::run("tc", &["qdisc", "del", "dev", &iface, "ingress"], TC_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing_qdisc(&stderr) || is_missing_device(&stderr) => {}
        Err(e) => return Err(e.into()),
    }
    match exec::run("ip", &["link", "del", IFB], IP_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing_link(&stderr) => {}
        Err(e) => return Err(e.into()),
    }
    match exec::run("tc", &["qdisc", "del", "dev", &iface, "root"], TC_TIMEOUT) {
        Ok(_) => {}
        Err(DiscoveryError::CommandFailed { stderr, .. }) if is_missing_qdisc(&stderr) || is_missing_device(&stderr) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pure conversions -----------------------------------------------------------------

    #[test]
    fn bytes_to_kbit_matches_a_real_captured_conversion() {
        // Captured directly: `tc class replace ... rate 7mbit` reads back as `"rate":875000`
        // (bytes/sec) — 875000 * 8 / 1000 = 7000 kbit, i.e. 7 Mbit, exactly.
        assert_eq!(bytes_to_kbit(875_000), 7_000);
        assert_eq!(bytes_to_kbit(125_000_000), 1_000_000);
    }

    #[test]
    fn rate_arg_formats_as_a_bare_kbit_suffix() {
        assert_eq!(rate_arg(5_000), "5000kbit");
    }

    #[test]
    fn classid_formats_under_the_fixed_parent() {
        assert_eq!(classid(10), "1:10");
        assert_eq!(classid(999), "1:999");
    }

    // ---- next_free_classid -----------------------------------------------------------------

    #[test]
    fn the_first_classid_ever_allocated_is_the_first_client_slot() {
        assert_eq!(next_free_classid(&BTreeSet::new()), FIRST_CLIENT_CLASSID);
    }

    #[test]
    fn allocation_is_one_past_the_highest_in_use_not_the_first_gap() {
        let used: BTreeSet<u16> = [10, 12].into_iter().collect();
        assert_eq!(next_free_classid(&used), 13);
    }

    #[test]
    fn allocation_never_goes_below_the_first_client_slot_even_with_odd_input() {
        let used: BTreeSet<u16> = [1].into_iter().collect();
        assert_eq!(next_free_classid(&used), FIRST_CLIENT_CLASSID);
    }

    // ---- validation guards -----------------------------------------------------------------

    #[test]
    fn an_invalid_mac_is_rejected_before_touching_the_kernel() {
        assert!(matches!(set_limit("wlo1", "not-a-mac", Some(1000), None), Err(ShapingError::InvalidMac(_))));
    }

    #[test]
    fn an_invalid_interface_is_rejected_before_touching_the_kernel() {
        assert!(matches!(
            set_limit("wlo1\" ; rm -rf /", "ce:da:1e:90:d4:aa", Some(1000), None),
            Err(ShapingError::InvalidIface(_))
        ));
    }

    #[test]
    fn a_zero_rate_is_rejected_for_either_direction_rather_than_silently_meaning_something_else() {
        assert!(matches!(set_limit("wlo1", "ce:da:1e:90:d4:aa", Some(0), None), Err(ShapingError::InvalidRate(0))));
        assert!(matches!(set_limit("wlo1", "ce:da:1e:90:d4:aa", None, Some(0)), Err(ShapingError::InvalidRate(0))));
    }

    #[test]
    fn read_state_rejects_an_invalid_interface_before_touching_the_kernel() {
        assert!(matches!(read_state("../etc"), Err(ShapingError::InvalidIface(_))));
    }

    // ---- error-text recognition -------------------------------------------------------------

    #[test]
    fn missing_device_text_is_recognised() {
        assert!(is_missing_device("Cannot find device \"wlo9\""));
        assert!(!is_missing_device("Operation not permitted"));
    }

    #[test]
    fn missing_link_text_covers_both_ip_show_and_ip_del_wording() {
        assert!(is_missing_link("Device \"hotstream0\" does not exist."));
        assert!(is_missing_link("Cannot find device \"hotstream0\""));
        assert!(!is_missing_link("Operation not permitted"));
    }

    #[test]
    fn missing_qdisc_text_covers_both_the_default_root_and_a_named_qdisc() {
        assert!(is_missing_qdisc("Error: Cannot delete qdisc with handle of zero."));
        assert!(is_missing_qdisc("Error: Cannot find specified qdisc on specified device."));
        assert!(!is_missing_qdisc("Error: Operation not permitted"));
    }

    // ---- JSON parsing (captured verbatim from a real sandboxed kernel) --------------------

    #[test]
    fn qdisc_json_identifies_our_htb_root_and_nothing_else() {
        let json = r#"[{"kind":"htb","handle":"1:","root":true,"refcnt":2,"options":{}}]"#;
        let qdiscs: Vec<RawQdisc> = serde_json::from_str(json).unwrap();
        assert!(qdiscs.iter().any(|q| q.kind == "htb" && q.handle == "1:" && q.root));
    }

    #[test]
    fn a_noqueue_root_is_not_mistaken_for_our_htb_root() {
        let json = r#"[{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,"options":{}}]"#;
        let qdiscs: Vec<RawQdisc> = serde_json::from_str(json).unwrap();
        assert!(!qdiscs.iter().any(|q| q.kind == "htb" && q.handle == "1:" && q.root));
    }

    #[test]
    fn flower_filter_json_yields_the_mac_to_classid_mapping() {
        let json = r#"[
            {"parent":"1:","protocol":"all","pref":1,"kind":"flower","chain":0},
            {"parent":"1:","protocol":"all","pref":1,"kind":"flower","chain":0,
             "options":{"handle":10,"classid":"1:10","keys":{"dst_mac":"ce:da:1e:90:d4:aa"},"not_in_hw":true}}
        ]"#;
        let filters: Vec<RawFilter> = serde_json::from_str(json).unwrap();
        let entry = filters.iter().find(|f| f.options.is_some()).unwrap();
        let opts = entry.options.as_ref().unwrap();
        assert_eq!(opts.classid.as_deref(), Some("1:10"));
        assert_eq!(opts.keys.as_ref().unwrap().dst_mac.as_deref(), Some("ce:da:1e:90:d4:aa"));
    }

    #[test]
    fn class_json_rate_is_bytes_per_second() {
        let json = r#"[
            {"class":"htb","handle":"1:50","parent":"1:1","prio":0,"rate":875000,"ceil":875000,"burst":1600,"cburst":1600},
            {"class":"htb","handle":"1:1","root":true,"rate":125000000,"ceil":125000000,"burst":1600,"cburst":1600}
        ]"#;
        let classes: Vec<RawClass> = serde_json::from_str(json).unwrap();
        let c = classes.iter().find(|c| c.handle == "1:50").unwrap();
        assert_eq!(c.rate, Some(875_000));
        assert_eq!(bytes_to_kbit(c.rate.unwrap()), 7_000);
    }

    #[test]
    fn malformed_json_from_a_successful_command_is_a_parse_error_not_a_panic() {
        let err = parse_json::<RawQdisc>("`tc qdisc show`", Ok("not json".to_string())).unwrap_err();
        assert!(matches!(err, ShapingError::Parse { what: "`tc qdisc show`", .. }), "{err:?}");
    }

    #[test]
    fn a_missing_device_error_from_the_command_is_read_as_empty_not_an_error() {
        let result = parse_json::<RawQdisc>(
            "`tc qdisc show`",
            Err(DiscoveryError::CommandFailed { tool: "tc".into(), code: Some(1), stderr: "Cannot find device \"wlo9\"".into() }),
        );
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn a_genuine_command_error_is_not_mistaken_for_a_missing_device() {
        let result = parse_json::<RawQdisc>(
            "`tc qdisc show`",
            Err(DiscoveryError::CommandFailed { tool: "tc".into(), code: Some(1), stderr: "Operation not permitted".into() }),
        );
        assert!(matches!(result, Err(ShapingError::Exec(_))));
    }
}
