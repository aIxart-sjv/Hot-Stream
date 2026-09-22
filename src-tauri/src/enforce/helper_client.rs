//! The unprivileged half: how the GUI process talks to `hot-stream-helper`. This is the entire
//! privilege boundary — the GUI never links against [`super::kernel`] and never touches `nft`
//! itself; it only ever spawns the helper binary and reads back what it prints.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::discovery::error::DiscoveryError;
use crate::discovery::exec;

use super::EnforcementState;

const HELPER_NAME: &str = "hot-stream-helper";
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// Where to look for the helper: first beside the running GUI binary (covers both `cargo run`
/// during development and a normal installed/bundled layout), then fall back to `PATH`.
fn helper_path() -> PathBuf {
    resolve(std::env::current_exe().ok().as_deref())
}

fn resolve(current_exe: Option<&Path>) -> PathBuf {
    if let Some(dir) = current_exe.and_then(Path::parent) {
        let sibling = dir.join(HELPER_NAME);
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from(HELPER_NAME)
}

fn invoke(path: &Path, args: &[&str]) -> Result<EnforcementState, String> {
    match exec::run(&path.to_string_lossy(), args, HELPER_TIMEOUT) {
        Ok(out) => serde_json::from_str(&out)
            .map_err(|e| format!("could not understand the helper's response: {e} (got {out:?})")),
        Err(DiscoveryError::ToolMissing { .. }) => Err(format!(
            "the Hot-Stream enforcement helper is not available at {} (nor on PATH). \
             Build it and grant it the one capability it needs, once: \
             `cargo build --release --bin hot-stream-helper` then \
             `sudo setcap cap_net_admin+eip <path to the built binary>`.",
            path.display()
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// The kernel's actual full enforcement state, via the helper (the GUI itself has no
/// permission to read `nft`/`tc` state — reading it is just as privileged as writing it).
///
/// `iface` is the hotspot's *current* interface if one is running, `None` otherwise. Block and
/// admission are read regardless (an `nft` read needs no interface); bandwidth limits are only
/// read — and so only ever populated in the result — when `iface` is given, since a `tc` read
/// must be told which device to look at (see `shaping`).
pub fn status(iface: Option<&str>) -> Result<EnforcementState, String> {
    match iface {
        Some(iface) => invoke(&helper_path(), &["status", iface]),
        None => invoke(&helper_path(), &["status"]),
    }
}

/// `iface` is the hotspot's *current* interface (from live discovery, e.g.
/// `HotspotState.hotspot.interface`) — both rules are (re-)scoped to it on every write, so a
/// stale or wrong value here would mis-scope enforcement; see `enforce::kernel` for why the
/// interface must be part of every write at all.
pub fn block(iface: &str, mac: &str) -> Result<EnforcementState, String> {
    invoke(&helper_path(), &["block", iface, mac])
}

pub fn unblock(iface: &str, mac: &str) -> Result<EnforcementState, String> {
    invoke(&helper_path(), &["unblock", iface, mac])
}

/// Set (or, with `max: None`, clear) the maximum-clients limit and the exact set of MACs
/// admitted under it. The caller decides which MACs those are (see `enforce::kernel::
/// set_admission`); this just applies an already-decided set.
pub fn set_admission(iface: &str, max: Option<u32>, admitted: &[String]) -> Result<EnforcementState, String> {
    let max_arg = max.map(|m| m.to_string()).unwrap_or_else(|| "none".to_string());
    let mut args: Vec<&str> = vec!["set-admission", iface, &max_arg];
    args.extend(admitted.iter().map(String::as_str));
    invoke(&helper_path(), &args)
}

/// Set (or, with `None`, clear) `mac`'s download and/or upload limit, independently. `iface`
/// is the hotspot's *current* interface (from live discovery), threaded fresh on every call —
/// same discipline as `block`/`unblock`/`set_admission`.
pub fn set_bandwidth(iface: &str, mac: &str, download_kbit: Option<u32>, upload_kbit: Option<u32>) -> Result<EnforcementState, String> {
    let down_arg = download_kbit.map(|k| k.to_string()).unwrap_or_else(|| "none".to_string());
    let up_arg = upload_kbit.map(|k| k.to_string()).unwrap_or_else(|| "none".to_string());
    invoke(&helper_path(), &["set-bandwidth", iface, mac, &down_arg, &up_arg])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_sitting_beside_the_given_executable_is_preferred() {
        let dir = std::env::temp_dir().join(format!("hs-helper-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let helper = dir.join(HELPER_NAME);
        std::fs::write(&helper, b"#!/bin/sh\n").unwrap();
        let fake_exe = dir.join("hot-stream");
        assert_eq!(resolve(Some(&fake_exe)), helper);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn falling_back_to_path_when_no_sibling_exists() {
        let dir = std::env::temp_dir().join(format!("hs-helper-test-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake_exe = dir.join("hot-stream");
        assert_eq!(resolve(Some(&fake_exe)), PathBuf::from(HELPER_NAME));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_current_exe_information_also_falls_back_to_path() {
        assert_eq!(resolve(None), PathBuf::from(HELPER_NAME));
    }

    #[test]
    fn a_missing_helper_gives_an_actionable_error_mentioning_setcap() {
        let err = invoke(&PathBuf::from("hot-stream-helper-does-not-exist"), &["status"]).unwrap_err();
        assert!(err.contains("setcap"), "{err}");
        assert!(err.contains("cap_net_admin"), "{err}");
    }

    #[test]
    fn a_valid_json_reply_is_parsed_into_enforcementstate() {
        let script = write_fake_helper("#!/bin/sh\necho '{\"blocked\":[\"ce:da:1e:90:d4:aa\"]}'\n");
        let state = invoke(&script, &["status"]).unwrap();
        assert_eq!(state.blocked, vec!["ce:da:1e:90:d4:aa"]);
        assert_eq!(state.admission, None);
    }

    #[test]
    fn a_reply_with_admission_is_parsed_too() {
        let script = write_fake_helper(
            "#!/bin/sh\necho '{\"blocked\":[],\"admission\":{\"max\":2,\"admitted\":[\"ce:da:1e:90:d4:aa\"]}}'\n",
        );
        let state = invoke(&script, &["status"]).unwrap();
        let admission = state.admission.unwrap();
        assert_eq!(admission.max, 2);
        assert_eq!(admission.admitted, vec!["ce:da:1e:90:d4:aa"]);
    }

    #[test]
    fn set_admission_passes_iface_max_and_admitted_macs_as_argv() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        set_admission_with(&script, "wlo1", Some(2), &["ce:da:1e:90:d4:aa".to_string(), "be:49:b6:59:5e:1d".to_string()])
            .unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "set-admission wlo1 2 ce:da:1e:90:d4:aa be:49:b6:59:5e:1d");
    }

    #[test]
    fn clearing_admission_passes_none_as_the_max() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        set_admission_with(&script, "wlo1", None, &[]).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "set-admission wlo1 none");
    }

    #[test]
    fn status_with_no_interface_passes_no_extra_argument() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        status_with(&script, None).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "status");
    }

    #[test]
    fn status_with_an_interface_passes_it_through() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        status_with(&script, Some("wlo1")).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "status wlo1");
    }

    #[test]
    fn a_reply_with_bandwidth_limits_is_parsed_too() {
        let script = write_fake_helper(
            "#!/bin/sh\necho '{\"blocked\":[],\"bandwidth\":[{\"mac\":\"ce:da:1e:90:d4:aa\",\"downloadKbit\":5000,\"uploadKbit\":null}]}'\n",
        );
        let state = status_with(&script, Some("wlo1")).unwrap();
        assert_eq!(state.bandwidth.len(), 1);
        assert_eq!(state.bandwidth[0].mac, "ce:da:1e:90:d4:aa");
        assert_eq!(state.bandwidth[0].download_kbit, Some(5000));
        assert_eq!(state.bandwidth[0].upload_kbit, None);
    }

    /// Test-only twin of `status` that takes an explicit path (mirrors `invoke`).
    fn status_with(path: &Path, iface: Option<&str>) -> Result<EnforcementState, String> {
        match iface {
            Some(iface) => invoke(path, &["status", iface]),
            None => invoke(path, &["status"]),
        }
    }

    #[test]
    fn set_bandwidth_passes_iface_mac_and_both_rates_as_argv() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        set_bandwidth_with(&script, "wlo1", "ce:da:1e:90:d4:aa", Some(5000), Some(1000)).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "set-bandwidth wlo1 ce:da:1e:90:d4:aa 5000 1000");
    }

    #[test]
    fn clearing_a_bandwidth_limit_passes_none_for_that_direction() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        set_bandwidth_with(&script, "wlo1", "ce:da:1e:90:d4:aa", None, None).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "set-bandwidth wlo1 ce:da:1e:90:d4:aa none none");
    }

    /// Test-only twin of `set_bandwidth` that takes an explicit path (mirrors `invoke`).
    fn set_bandwidth_with(
        path: &Path,
        iface: &str,
        mac: &str,
        download_kbit: Option<u32>,
        upload_kbit: Option<u32>,
    ) -> Result<EnforcementState, String> {
        let down_arg = download_kbit.map(|k| k.to_string()).unwrap_or_else(|| "none".to_string());
        let up_arg = upload_kbit.map(|k| k.to_string()).unwrap_or_else(|| "none".to_string());
        invoke(path, &["set-bandwidth", iface, mac, &down_arg, &up_arg])
    }

    #[test]
    fn block_passes_the_interface_ahead_of_the_mac() {
        let script = write_fake_helper("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\necho '{\"blocked\":[]}'\n");
        invoke(&script, &["block", "wlo1", "ce:da:1e:90:d4:aa"]).unwrap();
        let args = std::fs::read_to_string(script.parent().unwrap().join("args.txt")).unwrap();
        assert_eq!(args.trim(), "block wlo1 ce:da:1e:90:d4:aa");
    }

    /// Test-only twin of `set_admission` that takes an explicit path (mirrors `invoke`).
    fn set_admission_with(path: &Path, iface: &str, max: Option<u32>, admitted: &[String]) -> Result<EnforcementState, String> {
        let max_arg = max.map(|m| m.to_string()).unwrap_or_else(|| "none".to_string());
        let mut args: Vec<&str> = vec!["set-admission", iface, &max_arg];
        args.extend(admitted.iter().map(String::as_str));
        invoke(path, &args)
    }

    #[test]
    fn stderr_from_a_failing_helper_becomes_the_error_message() {
        let script = write_fake_helper("#!/bin/sh\necho 'operation not permitted' >&2\nexit 1\n");
        let err = invoke(&script, &["block", "ce:da:1e:90:d4:aa"]).unwrap_err();
        assert!(err.contains("operation not permitted"), "{err}");
    }

    #[test]
    fn garbage_stdout_from_a_supposedly_successful_helper_is_reported_not_silently_accepted() {
        let script = write_fake_helper("#!/bin/sh\necho 'not json'\n");
        let err = invoke(&script, &["status"]).unwrap_err();
        assert!(err.contains("could not understand"), "{err}");
    }

    fn write_fake_helper(script: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        // A counter, not just PID+thread-id: the test harness reuses worker threads across
        // sequential tests, so two tests can otherwise land on the exact same directory name
        // and race on each other's `fake-helper.sh` / `args.txt`.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("hs-helper-fake-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fake-helper.sh");
        // Written under a temp name, then renamed into place — not written directly at
        // `path`. `rename` is atomic, so `path` never exists with a writer's file descriptor
        // still open on it. Without this, a concurrent test's `Command::spawn()` (which
        // forks the whole process, inheriting every thread's open fds, not just its own) can
        // occasionally observe *this* thread's write-in-progress fd on `path` mid-`fork()`
        // and fail to exec a completely unrelated file with ETXTBSY ("Text file busy") —
        // reproduced directly in this test suite under `--test-threads` > 1.
        let tmp = dir.join("fake-helper.sh.tmp");
        std::fs::write(&tmp, script).unwrap();
        let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&tmp, perms).unwrap();
        std::fs::rename(&tmp, &path).unwrap();
        path
    }
}
