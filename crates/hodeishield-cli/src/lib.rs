// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! `hodeishield`: read-only command-line client for HodeiShield.
//!
//! The binary is a thin wrapper around [`main`]. The library exists so that repository tools can
//! reach the command-line definition ([`cli::Cli`]), e.g. to generate the man pages; it is not a
//! stable API.

mod auth;
pub mod cli;
mod commands;
mod config;
mod failure;
mod filters;
mod output;
mod update_check;

use std::io::Write;
use std::process::ExitCode;

pub const USER_AGENT: &str = concat!(
    "hodeishield-cli/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Hodeitek/hodeishield-cli)"
);

/// Runs the command line and returns the exit code.
#[must_use]
pub fn main() -> ExitCode {
    let cli = cli::Cli::parse_checked();
    let for_programs = cli.prints_for_programs();
    let verbose = cli.verbose;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(output::Tracked::new(stdout.lock()));
    let result = commands::run(cli, &mut out);
    let flushed = out.flush();
    let stdout_closed = out.get_ref().closed();
    // After the command's own work and output, so it never delays them.
    update_check::notify(for_programs, verbose);
    exit_code(result, flushed, stdout_closed)
}

/// Reports the outcome and maps it to the exit code. `stdout_closed` says that writing to
/// standard output failed with a broken pipe (`hodeishield vendors list | head -1`): that is not
/// an error. A broken pipe from anywhere else is, and the exit code says so.
fn exit_code(
    result: failure::Result<()>,
    flushed: std::io::Result<()>,
    stdout_closed: bool,
) -> ExitCode {
    let result = result.map_err(|failure| {
        if stdout_closed {
            failure.closed_stdout()
        } else {
            failure
        }
    });
    match result {
        Ok(()) => match flushed {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) if stdout_closed => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        // Decided where standard output is written, never on message text (which can come from
        // the API) nor on the kind of an error from somewhere else.
        Err(failure) if failure.closed_pipe => ExitCode::SUCCESS,
        Err(failure) => {
            // Messages can carry text from the API or the app: clean it like any other output.
            eprintln!("error: {}", output::clean(&failure.message));
            if let Some(hint) = &failure.hint {
                eprintln!("hint: {}", output::clean(hint));
            }
            if let Some(id) = &failure.request_id {
                eprintln!("request id: {}", output::clean(id));
            }
            failure.kind.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    fn is_success(code: ExitCode) -> bool {
        format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
    }

    #[test]
    fn a_closed_standard_output_exits_0() {
        let failure = failure::Failure::from(Error::from(ErrorKind::BrokenPipe));
        assert!(is_success(exit_code(Err(failure), Ok(()), true)));
        let flush = Err(Error::from(ErrorKind::BrokenPipe));
        assert!(is_success(exit_code(Ok(()), flush, true)));
    }

    #[test]
    fn a_broken_pipe_from_somewhere_else_is_a_failure() {
        // A socket, a file or a config write failing with a broken pipe is not a closed reader.
        let failure = failure::Failure::from(Error::from(ErrorKind::BrokenPipe));
        assert!(!is_success(exit_code(Err(failure), Ok(()), false)));
        let flush = Err(Error::from(ErrorKind::BrokenPipe));
        assert!(!is_success(exit_code(Ok(()), flush, false)));
    }

    #[test]
    fn tracked_output_notices_only_a_broken_pipe() {
        struct Failing(ErrorKind);
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(Error::from(self.0))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(Error::from(self.0))
            }
        }
        let mut other = output::Tracked::new(Failing(ErrorKind::PermissionDenied));
        assert!(other.write_all(b"x").is_err());
        assert!(!other.closed());
        let mut closed = output::Tracked::new(Failing(ErrorKind::BrokenPipe));
        assert!(closed.write_all(b"x").is_err());
        assert!(closed.closed());
    }
}
