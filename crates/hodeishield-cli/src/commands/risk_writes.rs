// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! `risks transition`: move a risk along its lifecycle.
//!
//! It follows the alert writes: an API key (a sign-in cannot write), and the person's yes, typed at
//! the prompt or given with `--yes`. Without a terminal and without `--yes`, the command line
//! refuses before it gets here (see `Cli::parse_checked`).

use super::Context;
use super::alert_writes::{confirmed, needs_api_key};
use crate::cli::RiskTransition;
use crate::config::Settings;
use crate::failure::{CredentialSource, Failure, Kind, Result, from_api};
use crate::output::{clean, print_json};
use hodeishield_api::v1::Risk;
use std::io::Write;

pub fn transition(
    ctx: &Context,
    settings: &Settings,
    args: &RiskTransition,
    out: &mut dyn Write,
) -> Result<()> {
    // Before anything is sent: only an API key can write.
    let (_, source) = ctx.api(settings, None)?;
    if source == CredentialSource::OAuth {
        return Err(needs_api_key("a risk", "risks:write"));
    }
    let (client, source) = ctx.single(settings)?;
    let api = ctx.call(source, None);

    if !args.confirm.yes {
        // The risk as it is now, so the person confirms what they are about to change. A key that
        // may write but not read still gets the question, with the id alone.
        let current = match client.get_risk(&args.id) {
            Ok(response) => Some(response.data.data),
            Err(e) => {
                let failure = from_api(e, &api);
                if failure.kind != Kind::Forbidden {
                    return Err(failure);
                }
                None
            }
        };
        let question = question(
            &args.id,
            current.as_ref(),
            &args.to_status,
            args.note.as_deref(),
        );
        let stdin = std::io::stdin();
        if !confirmed(&mut stdin.lock(), &mut std::io::stderr(), &question)? {
            return Err(Failure::general("Cancelled. Nothing was changed."));
        }
    }

    let response = client
        .transition_risk(&args.id, &args.to_status, args.note.as_deref())
        .map_err(|e| from_api(e, &api))?;
    if ctx.json {
        return Ok(print_json(out, &response.raw)?);
    }
    let data = &response.data;
    writeln!(
        out,
        "{}",
        outcome(&data.data.id, &data.data.status, data.changed)
    )?;
    Ok(())
}

/// What the person is asked to confirm.
fn question(id: &str, current: Option<&Risk>, to: &str, note: Option<&str>) -> String {
    let mut text = format!("Risk {}\n", clean(id));
    match current {
        Some(risk) => {
            text.push_str(&format!("  title:  {}\n", clean(&risk.title)));
            text.push_str(&format!("  status: {}\n", clean(&risk.status)));
        }
        None => text.push_str("  (this key cannot read the risk, so its state is not shown)\n"),
    }
    text.push_str(&format!("Change: move it to {}", clean(to)));
    if let Some(note) = note {
        text.push_str(&format!(", note: {}", clean(note)));
    }
    text.push_str("\nProceed? [y/N] ");
    text
}

/// The line that says what the request did.
fn outcome(id: &str, status: &str, changed: bool) -> String {
    let (id, status) = (clean(id), clean(status));
    if changed {
        format!("Moved risk {id} to {status}.")
    } else {
        format!("Risk {id} is already {status}: nothing changed.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_question_names_the_risk_and_the_change() {
        let text = question("r1", None, "assessed", Some("scored"));
        assert!(text.contains("Risk r1"));
        assert!(text.contains("cannot read the risk"));
        assert!(text.contains("move it to assessed, note: scored"));
        assert!(text.ends_with("Proceed? [y/N] "));
    }

    #[test]
    fn the_outcome_says_whether_anything_changed() {
        assert_eq!(
            outcome("r1", "assessed", true),
            "Moved risk r1 to assessed."
        );
        assert_eq!(
            outcome("r1", "assessed", false),
            "Risk r1 is already assessed: nothing changed."
        );
    }
}
