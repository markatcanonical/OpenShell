//! Navigator Sandbox library.
//!
//! This crate provides process sandboxing and monitoring capabilities.

mod process;

use miette::{IntoDiagnostic, Result};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info};

pub use process::{ProcessHandle, ProcessStatus};

/// Run a command in the sandbox.
///
/// # Errors
///
/// Returns an error if the command fails to start or encounters a fatal error.
pub async fn run_sandbox(
    command: Vec<String>,
    workdir: Option<String>,
    timeout_secs: u64,
    interactive: bool,
    _health_check: bool,
    _health_port: u16,
) -> Result<i32> {
    let (program, args) = command.split_first().ok_or_else(|| {
        miette::miette!("No command specified")
    })?;

    let mut handle = ProcessHandle::spawn(program, args, workdir.as_deref(), interactive)?;

    info!(pid = handle.pid(), "Process started");

    // Wait for process with optional timeout
    let result = if timeout_secs > 0 {
        match timeout(Duration::from_secs(timeout_secs), handle.wait()).await {
            Ok(result) => result,
            Err(_) => {
                error!("Process timed out, killing");
                handle.kill()?;
                return Ok(124); // Standard timeout exit code
            }
        }
    } else {
        handle.wait().await
    };

    let status = result.into_diagnostic()?;

    info!(exit_code = status.code(), "Process exited");

    Ok(status.code())
}
