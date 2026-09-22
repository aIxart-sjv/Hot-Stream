//! The unprivileged half: how the GUI process talks to `hot-stream-helper`. This is the entire
//! privilege boundary — the GUI never links against [`super::kernel`] and never touches `nft`
//! itself; it only ever spawns the helper binary and reads back what it prints.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::discovery::error::DiscoveryError;
use crate::discovery::exec;

use super::BlockedState;

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

fn invoke(path: &Path, args: &[&str]) -> Result<BlockedState, String> {
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

/// The kernel's actual blocked set, via the helper (the GUI itself has no permission to read
/// `nft` state — reading it is just as privileged as writing it).
pub fn status() -> Result<BlockedState, String> {
    invoke(&helper_path(), &["status"])
}

pub fn block(mac: &str) -> Result<BlockedState, String> {
    invoke(&helper_path(), &["block", mac])
}

pub fn unblock(mac: &str) -> Result<BlockedState, String> {
    invoke(&helper_path(), &["unblock", mac])
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
    fn a_valid_json_reply_is_parsed_into_blockedstate() {
        let script = write_fake_helper("#!/bin/sh\necho '{\"blocked\":[\"ce:da:1e:90:d4:aa\"]}'\n");
        let state = invoke(&script, &["status"]).unwrap();
        assert_eq!(state.blocked, vec!["ce:da:1e:90:d4:aa"]);
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
        let dir = std::env::temp_dir().join(format!("hs-helper-fake-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fake-helper.sh");
        std::fs::write(&path, script).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }
}
