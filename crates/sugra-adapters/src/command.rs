//! Allowlisted platform command boundary.

#[cfg(feature = "local-exec")]
use std::time::Instant;

use async_trait::async_trait;
#[cfg(feature = "local-exec")]
use sugra_core::CommandKind;
use sugra_core::{CommandPort, CommandRequest, CommandResponse, PortError, PortErrorKind};

/// Platform command boundary. Commands are available only with the `local-exec` feature.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommand;

#[cfg(feature = "local-exec")]
#[async_trait]
impl CommandPort for SystemCommand {
    async fn execute(&self, request: CommandRequest) -> Result<CommandResponse, PortError> {
        if !request.scope.allows(&request.target) || !request.scope.active_authorized {
            return Err(PortError::new(
                PortErrorKind::OutOfScope,
                "local command is outside authorized scope",
            ));
        }
        let target = request.target.canonical();
        let (program, arguments): (&str, Vec<&str>) = command_line(request.kind, &target);
        let started = Instant::now();
        let output = tokio::time::timeout(
            request.budget.timeout(),
            tokio::process::Command::new(program)
                .args(arguments)
                .output(),
        )
        .await
        .map_err(|_| PortError::new(PortErrorKind::Timeout, "local command timed out"))?
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "required local command is unavailable",
                )
            } else {
                PortError::new(PortErrorKind::Transport, "local command failed to start")
            }
        })?;
        let limit = request.budget.max_response_bytes;
        Ok(CommandResponse {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(limit)])
                .into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(limit)])
                .into_owned(),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

#[cfg(not(feature = "local-exec"))]
#[async_trait]
impl CommandPort for SystemCommand {
    async fn execute(&self, _request: CommandRequest) -> Result<CommandResponse, PortError> {
        Err(PortError::new(
            PortErrorKind::Unavailable,
            "local command support is disabled at build time",
        ))
    }
}

#[cfg(feature = "local-exec")]
fn command_line(kind: CommandKind, target: &str) -> (&'static str, Vec<&str>) {
    match kind {
        CommandKind::Ping if cfg!(target_os = "windows") => ("ping", vec!["-n", "1", target]),
        CommandKind::Ping => ("ping", vec!["-c", "1", target]),
        CommandKind::Traceroute if cfg!(target_os = "windows") => ("tracert", vec![target]),
        CommandKind::Traceroute => ("traceroute", vec![target]),
        CommandKind::Whois => ("whois", vec![target]),
        CommandKind::SshKeyscan => ("ssh-keyscan", vec![target]),
    }
}
