//! `hot-stream-helper` — the entire privileged surface of Hot-Stream.
//!
//! It does exactly six things, chosen by the first argument:
//!
//!     hot-stream-helper status [iface]                        print the full enforcement state
//!     hot-stream-helper block   <iface> <mac>                 block a MAC
//!     hot-stream-helper unblock <iface> <mac>                 unblock a MAC
//!     hot-stream-helper set-admission <iface> <max|none> [mac...]
//!         set (or, with "none", clear) the maximum-clients limit and the exact set of
//!         admitted MACs under it. The caller decides which MACs and in what order — this
//!         command only ever applies an already-decided set, same as `block`/`unblock` are
//!         handed an already-decided MAC.
//!     hot-stream-helper set-bandwidth <iface> <mac> <download-kbit|none> <upload-kbit|none>
//!         set (or, with "none", clear) a MAC's download and/or upload limit, independently.
//!
//! Block and admission live in a dedicated, independently-removable nftables table (see
//! `enforce::kernel` for why); bandwidth limits live in `tc` state instead (see
//! `enforce::shaping` for why that is a different mechanism, not the same table).
//!
//! `<iface>` is the hotspot's current interface (e.g. `wlo1`), supplied fresh by the caller
//! every time from live discovery — every enforcement write is (re-)scoped to it. This is not
//! cosmetic: see `enforce::kernel` for the sandbox test that found a real bug
//! (Internet-breaking, had it reached a real machine unverified) from *not* scoping the
//! admission rule to the hotspot's own interface. `status`'s `[iface]` is optional and read-only
//! for a different reason: an `nft` read is self-describing about which interface it covers, so
//! block/admission are always reported regardless; a `tc` read is not, so bandwidth limits can
//! only be reported when the caller supplies the interface to read them from (typically the
//! same live-discovered value, or omitted entirely when no hotspot is currently running).
//!
//! Every command prints the resulting full enforcement state as JSON on success.
//!
//! On success it prints one JSON object (`{"blocked": [...]}`) to stdout and exits 0. On
//! failure it prints one line of plain text to stderr and exits non-zero. Nothing else: no
//! daemon, no socket, no persistent state of its own — every invocation reads the kernel and
//! exits.
//!
//! It is meant to be run un-elevated by the (non-root) GUI process, after being granted the one
//! capability it needs, once, by an administrator:
//!
//!     sudo setcap cap_net_admin+eip /path/to/hot-stream-helper
//!
//! (`+eip`, not just `+ep` — this process spawns `nft` as a child, and the inheritable flag
//! plus an ambient-capability raise, done below, are what let that child see the capability
//! too; see `enforce::ambient` for why.)
//!
//! This binary intentionally does not depend on `tauri`: it is built and audited as a small,
//! separate program, not as part of the GUI.
//!
//! Every mutating command (everything but `status`) holds a process-wide `flock()` for its
//! whole read-modify-write cycle — see `enforce::lock` for the real, reproduced race this
//! closes (two `hot-stream-helper` invocations racing, e.g. from two rapid GUI clicks, silently
//! discarding one another's change).

use std::process::ExitCode;

use hot_stream_lib::enforce::{ambient, kernel, lock, shaping, EnforcementState};

fn usage() -> ! {
    eprintln!(
        "usage: hot-stream-helper status [iface] | block <iface> <mac> | unblock <iface> <mac> | \
         set-admission <iface> <max|none> [mac...] | \
         set-bandwidth <iface> <mac> <download-kbit|none> <upload-kbit|none>"
    );
    std::process::exit(2);
}

/// Parses `<max|none>`: the literal `none` clears the limit; anything else must be a
/// positive integer. Exits with the usage message on anything else, same as a malformed
/// subcommand — this is a command-line shape error, not a runtime `EnforceError`.
fn parse_max(s: &str) -> Option<u32> {
    if s == "none" {
        return None;
    }
    match s.parse::<u32>() {
        Ok(0) | Err(_) => usage(),
        Ok(n) => Some(n),
    }
}

/// Parses `<download-kbit|none>`/`<upload-kbit|none>`: same shape as `<max|none>` (`none`
/// clears that direction's limit, otherwise a positive integer), kept as its own function
/// rather than reusing `parse_max` under a repurposed name — the two are only coincidentally
/// identical in shape, not the same concept.
fn parse_rate(s: &str) -> Option<u32> {
    if s == "none" {
        return None;
    }
    match s.parse::<u32>() {
        Ok(0) | Err(_) => usage(),
        Ok(n) => Some(n),
    }
}

/// `status`'s full behaviour: block/admission are always read (an `nft` read needs no
/// interface — see the module doc); bandwidth limits are read too, but only when `iface` is
/// given, since a `tc` read must be told which device to look at.
fn read_status(iface: Option<&str>) -> Result<EnforcementState, String> {
    let mut state = kernel::read_state().map_err(|e| e.to_string())?;
    if let Some(iface) = iface {
        state.bandwidth = shaping::read_state(iface).map_err(|e| e.to_string())?;
    }
    Ok(state)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Validate the command line before touching capabilities at all: a plain `--help`-shaped
    // mistake should get the usage message, not a confusing capability error.
    match args.as_slice() {
        [cmd] if cmd == "status" => {}
        [cmd, _iface] if cmd == "status" => {}
        [cmd, _iface, _mac] if cmd == "block" || cmd == "unblock" => {}
        [cmd, _iface, _max, ..] if cmd == "set-admission" => {}
        [cmd, _iface, _mac, _down, _up] if cmd == "set-bandwidth" => {}
        _ => usage(),
    }

    // Best-effort: needed for a real file-capability grant on a plain user (the ambient set is
    // the only thing that lets `nft`/`tc`/`ip`, all child processes, see the capability too).
    // Not fatal by itself — real root and "fake root" in a test namespace both reach them
    // successfully without it, since their children are root by ancestry rather than by
    // inherited capability, and `raise_net_admin` itself can fail there (no inheritable set to
    // raise from) despite the child commands working fine. Whether privilege was actually
    // sufficient is decided below, by whether the real operation succeeds — never inferred from
    // this alone.
    let ambient_raised = ambient::raise_net_admin();

    // Serializes this invocation's whole read-modify-write cycle against any other
    // concurrently-running mutating command — see `enforce::lock` for the exact race this
    // closes. `status` is read-only and skips it: reading concurrently with a write is safe,
    // since the next read after any write simply reflects the kernel's latest state, per this
    // crate's "kernel state is the only truth" principle throughout.
    let _lock = if args[0] == "status" {
        None
    } else {
        match lock::acquire() {
            Ok(lock) => Some(lock),
            Err(e) => {
                eprintln!("could not acquire the coordination lock: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // Every mutating command below applies its own change, then re-reads the *complete*
    // picture (both `nft`-based policies and, since `iface` is always known at this point,
    // fresh `tc` state too) rather than returning just the one policy it happened to change.
    // This matters concretely, not just for tidiness: the GUI stores exactly one
    // `EnforcementState` and replaces it wholesale with whatever a command returns (see
    // `main.ts`) — if `block` returned only nft state with bandwidth left empty, blocking a
    // client would appear to silently clear every other client's bandwidth limit from the UI,
    // even though nothing on the kernel side actually changed.
    let result = match args.as_slice() {
        [cmd] if cmd == "status" => read_status(None),
        [cmd, iface] if cmd == "status" => read_status(Some(iface)),
        [cmd, iface, mac] if cmd == "block" => kernel::block(iface, mac).map_err(|e| e.to_string()).and_then(|_| read_status(Some(iface))),
        [cmd, iface, mac] if cmd == "unblock" => {
            kernel::unblock(iface, mac).map_err(|e| e.to_string()).and_then(|_| read_status(Some(iface)))
        }
        [cmd, iface, max, macs @ ..] if cmd == "set-admission" => kernel::set_admission(iface, parse_max(max), macs)
            .map_err(|e| e.to_string())
            .and_then(|_| read_status(Some(iface))),
        [cmd, iface, mac, down, up] if cmd == "set-bandwidth" => {
            let download_kbit = parse_rate(down);
            let upload_kbit = parse_rate(up);
            shaping::set_limit(iface, mac, download_kbit, upload_kbit).map_err(|e| e.to_string()).and_then(|_| read_status(Some(iface)))
        }
        _ => unreachable!("validated above"),
    };

    match result {
        Ok(state) => {
            println!("{}", serde_json::to_string(&state).expect("EnforcementState always serialises"));
            ExitCode::SUCCESS
        }
        Err(message) => {
            // The ambient-raise error is the more specific, actionable one for the case that
            // actually needs it: surface it instead of (or alongside) `nft`'s generic EPERM.
            if let Err(ambient_err) = &ambient_raised {
                if message.to_lowercase().contains("not permitted") {
                    eprintln!("{message}\n{ambient_err}");
                    return ExitCode::FAILURE;
                }
            }
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
