use std::fmt;

/// Everything that can go wrong while reading hotspot state from the system. Each variant
/// carries enough context to tell the user what to do about it.
#[derive(Debug)]
pub enum DiscoveryError {
    /// The external tool is not installed / not on `PATH`.
    ToolMissing { tool: String },
    /// The tool ran but exited unsuccessfully.
    CommandFailed { tool: String, code: Option<i32>, stderr: String },
    /// The tool did not finish in time and was killed.
    Timeout { tool: String },
    /// The tool's output was not in the expected format.
    Parse { what: &'static str, detail: String },
}

impl DiscoveryError {
    /// `iw` / `ip` report this when the interface vanished (e.g. the hotspot was just stopped).
    pub fn is_no_such_device(&self) -> bool {
        const PHRASES: [&str; 3] = ["No such device", "does not exist", "Cannot find device"];
        matches!(self, DiscoveryError::CommandFailed { stderr, .. }
            if PHRASES.iter().any(|p| stderr.contains(p)))
    }
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::ToolMissing { tool } => write!(
                f,
                "`{tool}` not found in PATH; install the package that provides it \
                 (Hot-Stream needs `iw` and `ip`)"
            ),
            DiscoveryError::CommandFailed { tool, code: Some(code), stderr } => {
                write!(f, "`{tool}` failed (exit code {code}): {stderr}")
            }
            DiscoveryError::CommandFailed { tool, code: None, stderr } => {
                write!(f, "`{tool}` was terminated by a signal: {stderr}")
            }
            DiscoveryError::Timeout { tool } => write!(f, "`{tool}` timed out and was killed"),
            DiscoveryError::Parse { what, detail } => write!(f, "could not parse {what}: {detail}"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_tool_is_named_in_the_message() {
        let msg = DiscoveryError::ToolMissing { tool: "iw".into() }.to_string();
        assert!(msg.contains("`iw`") && msg.contains("not found"), "{msg}");
    }

    #[test]
    fn a_failed_command_reports_exit_code_and_stderr() {
        let msg = DiscoveryError::CommandFailed {
            tool: "ip".into(),
            code: Some(2),
            stderr: "Cannot find device".into(),
        }
        .to_string();
        assert!(msg.contains("`ip`") && msg.contains("2") && msg.contains("Cannot find device"), "{msg}");
    }

    #[test]
    fn the_phrasing_ip_uses_for_a_missing_interface_is_recognised_too() {
        for stderr in ["Device \"wlo1\" does not exist.", "Cannot find device \"wlo1\""] {
            let e = DiscoveryError::CommandFailed {
                tool: "ip".into(),
                code: Some(1),
                stderr: stderr.into(),
            };
            assert!(e.is_no_such_device(), "{stderr}");
        }
    }

    #[test]
    fn a_timeout_names_the_tool() {
        let msg = DiscoveryError::Timeout { tool: "iw".into() }.to_string();
        assert!(msg.contains("`iw`") && msg.contains("timed out"), "{msg}");
    }

    #[test]
    fn no_such_device_is_recognised_only_for_command_failures_that_say_so() {
        let gone = DiscoveryError::CommandFailed {
            tool: "iw".into(),
            code: Some(237),
            stderr: "command failed: No such device (-19)".into(),
        };
        let other = DiscoveryError::CommandFailed {
            tool: "iw".into(),
            code: Some(1),
            stderr: "command failed: Operation not supported (-95)".into(),
        };
        assert!(gone.is_no_such_device());
        assert!(!other.is_no_such_device());
        assert!(!DiscoveryError::Timeout { tool: "iw".into() }.is_no_such_device());
    }
}
