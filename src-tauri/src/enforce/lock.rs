//! A single process-wide advisory lock serializing every privileged read-modify-write cycle —
//! both `kernel`'s `nft` operations and `shaping`'s `tc` operations — against concurrent
//! `hot-stream-helper` invocations.
//!
//! Why this exists: every mutating operation in this crate follows the same shape — read the
//! kernel's current state, compute a new desired state from it, then flush-and-rewrite. That
//! shape is safe against a *single* writer, but not against two `hot-stream-helper` processes
//! running concurrently — e.g. the GUI's own "Block device A" and "Block device B" clicked in
//! quick succession, each spawning its own helper process. Reproduced directly: with no lock,
//! two concurrent `block` calls each read the same "before" snapshot, and whichever finished
//! its rewrite second silently discarded the other's change — its own post-write consistency
//! check caught the mismatch and reported an error (so the failure was never silent), but the
//! block itself still did not take effect, which is a real, fixable defect, not merely a
//! cosmetic one.
//!
//! An `flock()` held for the whole read-modify-write cycle of each mutating command turns that
//! race into a queue, at essentially no cost to this app's request rates: nothing here is a hot
//! path, and a user cannot click meaningfully faster than an `nft`/`tc` invocation completes.
//! Scoped to one lock shared by both subsystems, not one each — simpler, and there is no
//! throughput reason to let a `block` and a `set-bandwidth` call run concurrently either.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Where the lock file lives: the current user's XDG runtime directory when available (tmpfs,
/// per-user, cleaned up by the system on logout — exactly the right lifetime for an advisory
/// lock that only needs to outlive concurrently-running helper processes), falling back to
/// `/tmp` for the rare environment without one.
fn lock_path() -> PathBuf {
    let dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(dir).join("hot-stream-helper.lock")
}

/// Held for the duration of one mutating command's entire read-modify-write cycle; releases the
/// lock automatically when dropped. Acquisition blocks (does not fail or time out) until any
/// other holder releases it — the alternative, failing fast, would turn a harmless few-
/// millisecond wait into a spurious user-facing error for something as ordinary as clicking two
/// buttons in quick succession.
pub struct ExclusiveLock {
    _file: File,
}

pub fn acquire() -> io::Result<ExclusiveLock> {
    acquire_at(&lock_path())
}

fn acquire_at(path: &Path) -> io::Result<ExclusiveLock> {
    // Content never matters — this file exists purely as an `flock()` target — so explicitly
    // never truncating avoids any unnecessary write to a file another process might be holding
    // open, with no functional difference either way.
    let file = OpenOptions::new().create(true).write(true).truncate(false).open(path)?;
    // SAFETY: `flock` operates purely on the given fd and a plain integer operation code; the
    // fd stays valid for the call's duration since `file` is not dropped until after it returns.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ExclusiveLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path unique to this call, even across concurrent test threads in the same process
    /// (which share a PID) — same reasoning as `helper_client`'s `write_fake_helper`.
    fn temp_path(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("hs-lock-test-{label}-{}-{n}", std::process::id()))
    }

    #[test]
    fn acquire_creates_the_lock_file_if_it_does_not_exist() {
        let path = temp_path("creates-file");
        assert!(!path.exists());
        let _lock = acquire_at(&path).unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_second_exclusive_attempt_on_a_different_handle_is_blocked_while_the_first_is_held() {
        let path = temp_path("contended");
        let first = acquire_at(&path).unwrap();

        // A raw, independent fd (not going through `acquire_at`, which would block this test
        // thread forever) probes non-blockingly to observe contention without deadlocking.
        let second_fd = OpenOptions::new().write(true).open(&path).unwrap();
        let rc = unsafe { libc::flock(second_fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, -1, "a second exclusive lock must not succeed while the first is held");

        drop(first);
        let rc = unsafe { libc::flock(second_fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "the lock must become available once the ExclusiveLock holding it is dropped");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_independent_lock_files_never_contend_with_each_other() {
        let path_a = temp_path("independent-a");
        let path_b = temp_path("independent-b");
        let _a = acquire_at(&path_a).unwrap();
        let _b = acquire_at(&path_b).unwrap(); // must not block: a completely different file
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }
}
