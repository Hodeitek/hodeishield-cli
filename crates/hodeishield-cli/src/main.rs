//! `hodeishield`: read-only command-line client for HodeiShield.

mod auth;
mod cli;
mod commands;
mod config;
mod failure;
mod output;

use clap::Parser;
use std::io::{ErrorKind, Write};
use std::process::ExitCode;

pub const USER_AGENT: &str = concat!(
    "hodeishield-cli/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Hodeitek/hodeishield-cli)"
);

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let result = commands::run(cli, &mut out);
    let flushed = out.flush();
    match result {
        Ok(()) => match flushed {
            Ok(()) => ExitCode::SUCCESS,
            // `hodeishield vendors list | head` closes the pipe early: that is not an error.
            Err(e) if e.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Err(failure) if failure.message.contains("Broken pipe") => ExitCode::SUCCESS,
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
