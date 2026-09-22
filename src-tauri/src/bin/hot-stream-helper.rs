//! `hot-stream-helper` — the entire privileged surface of Hot-Stream.
//!
//! It does exactly three things, chosen by the first argument, each against a dedicated,
//! independently-removable nftables table (see `enforce::kernel` for why):
//!
//!     hot-stream-helper status              print the currently-blocked MACs
//!     hot-stream-helper block   <mac>       block a MAC, print the resulting state
//!     hot-stream-helper unblock <mac>       unblock a MAC, print the resulting state
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

use std::process::ExitCode;

use hot_stream_lib::enforce::{ambient, kernel, BlockedState};

fn usage() -> ! {
    eprintln!("usage: hot-stream-helper status | block <mac> | unblock <mac>");
    std::process::exit(2);
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Validate the command line before touching capabilities at all: a plain `--help`-shaped
    // mistake should get the usage message, not a confusing capability error.
    match args.as_slice() {
        [cmd] if cmd == "status" => {}
        [cmd, _mac] if cmd == "block" || cmd == "unblock" => {}
        _ => usage(),
    }

    // Best-effort: needed for a real file-capability grant on a plain user (the ambient set is
    // the only thing that lets `nft`, a child process, see the capability too). Not fatal by
    // itself — real root and "fake root" in a test namespace both reach `nft` successfully
    // without it, since their children are root by ancestry rather than by inherited
    // capability, and `raise_net_admin` itself can fail there (no inheritable set to raise
    // from) despite `nft` working fine. Whether privilege was actually sufficient is decided
    // below, by whether the real operation succeeds — never inferred from this alone.
    let ambient_raised = ambient::raise_net_admin();

    let result = match args.as_slice() {
        [cmd] if cmd == "status" => kernel::read_blocked()
            .map(|blocked| BlockedState { blocked: blocked.into_iter().collect() })
            .map_err(|e| e.to_string()),
        [cmd, mac] if cmd == "block" => kernel::block(mac).map_err(|e| e.to_string()),
        [cmd, mac] if cmd == "unblock" => kernel::unblock(mac).map_err(|e| e.to_string()),
        _ => unreachable!("validated above"),
    };

    match result {
        Ok(state) => {
            println!("{}", serde_json::to_string(&state).expect("BlockedState always serialises"));
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
