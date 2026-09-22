use std::io::{ErrorKind, Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::error::DiscoveryError;

/// Generous for `iw` / `ip`, which normally answer in a few milliseconds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Run an external program (no shell involved) and return its stdout.
///
/// Fails explicitly: missing binary, non-zero exit and timeouts each produce their own error.
/// A program that outlives `timeout` is killed. `LC_ALL=C` keeps tool output untranslated.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> Result<String, DiscoveryError> {
    run_with_stdin(program, args, None, timeout)
}

/// Like [`run`], but writes `stdin` to the program's standard input first (e.g. an `nft -f -`
/// script). `None` behaves exactly like `run` (stdin closed immediately).
pub fn run_with_stdin(
    program: &str,
    args: &[&str],
    stdin: Option<&str>,
    timeout: Duration,
) -> Result<String, DiscoveryError> {
    let tool = program.to_string();
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            ErrorKind::NotFound => DiscoveryError::ToolMissing { tool: tool.clone() },
            _ => DiscoveryError::CommandFailed {
                tool: tool.clone(),
                code: None,
                stderr: format!("could not start: {e}"),
            },
        })?;

    // Drain both pipes concurrently so a chatty program can never block on a full pipe.
    let drain = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    };
    let stdout_reader = drain(Box::new(child.stdout.take().expect("stdout is piped")));
    let stderr_reader = drain(Box::new(child.stderr.take().expect("stderr is piped")));

    // Written on its own thread too: a program that doesn't read stdin until it has produced
    // enough stdout/stderr to fill those pipes would otherwise deadlock against the writer.
    if let Some(data) = stdin {
        let mut stdin_pipe = child.stdin.take().expect("stdin is piped when data is given");
        let data = data.to_string();
        thread::spawn(move || {
            let _ = stdin_pipe.write_all(data.as_bytes());
            // stdin_pipe drops here, closing the pipe (EOF) so the child sees end of input.
        });
    }

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // The reader threads end on their own once the pipes close; don't wait for them.
                return Err(DiscoveryError::Timeout { tool });
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                return Err(DiscoveryError::CommandFailed {
                    tool,
                    code: None,
                    stderr: format!("could not wait for the process: {e}"),
                })
            }
        }
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    if !status.success() {
        return Err(DiscoveryError::CommandFailed {
            tool,
            code: status.code(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const T: Duration = Duration::from_secs(5);

    #[test]
    fn returns_stdout_of_a_successful_command() {
        assert_eq!(run("echo", &["hello"], T).unwrap(), "hello\n");
    }

    #[test]
    fn a_missing_program_is_reported_as_tool_missing() {
        match run("hot-stream-no-such-tool", &[], T) {
            Err(DiscoveryError::ToolMissing { tool }) => assert_eq!(tool, "hot-stream-no-such-tool"),
            other => panic!("expected ToolMissing, got {other:?}"),
        }
    }

    #[test]
    fn a_non_zero_exit_reports_code_and_stderr() {
        match run("sh", &["-c", "echo oops >&2; exit 3"], T) {
            Err(DiscoveryError::CommandFailed { tool, code, stderr }) => {
                assert_eq!(tool, "sh");
                assert_eq!(code, Some(3));
                assert!(stderr.contains("oops"), "{stderr:?}");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn a_hung_program_is_killed_after_the_timeout() {
        let started = Instant::now();
        let r = run("sh", &["-c", "sleep 30"], Duration::from_millis(200));
        assert!(matches!(r, Err(DiscoveryError::Timeout { .. })), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    #[test]
    fn output_larger_than_a_pipe_buffer_does_not_deadlock() {
        let out = run("sh", &["-c", "head -c 3000000 /dev/zero | tr '\\0' a"], T).unwrap();
        assert_eq!(out.len(), 3_000_000);
    }

    // ---- run_with_stdin ------------------------------------------------------------

    #[test]
    fn stdin_is_delivered_to_the_program() {
        let out = run_with_stdin("cat", &[], Some("hello from a script\n"), T).unwrap();
        assert_eq!(out, "hello from a script\n");
    }

    #[test]
    fn no_stdin_behaves_exactly_like_run() {
        // `cat` with no input and a closed stdin exits immediately with empty output.
        let out = run_with_stdin("cat", &[], None, T).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn writing_more_stdin_than_a_pipe_buffer_does_not_deadlock() {
        // The child never reads (`sleep 0` then exit), so a naive synchronous write of a large
        // payload before reading stdout/stderr would deadlock once the stdin pipe fills.
        let big = "x".repeat(2_000_000);
        let out = run_with_stdin("sh", &["-c", "true"], Some(&big), T).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn a_program_that_reads_and_echoes_a_large_payload_gets_it_back_whole() {
        let big = "y".repeat(2_000_000);
        let out = run_with_stdin("cat", &[], Some(&big), T).unwrap();
        assert_eq!(out.len(), big.len());
        assert_eq!(out, big);
    }

    #[test]
    fn stdin_errors_still_report_stderr_and_exit_code() {
        match run_with_stdin("sh", &["-c", "echo bad-input >&2; exit 4"], Some("x"), T) {
            Err(DiscoveryError::CommandFailed { code, stderr, .. }) => {
                assert_eq!(code, Some(4));
                assert!(stderr.contains("bad-input"), "{stderr:?}");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }
}
