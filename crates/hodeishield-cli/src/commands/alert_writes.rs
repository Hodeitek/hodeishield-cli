// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The two commands that change data: `alerts acknowledge` and `alerts resolve`.
//!
//! A write never happens on a guess. It needs an API key (a sign-in cannot write), and it needs
//! the person's yes, either typed at the prompt or given with `--yes`. Without a terminal and
//! without `--yes`, the command line refuses before it gets here (see `Cli::parse_checked`).

use super::Context;
use crate::cli::{AlertAcknowledge, AlertResolve};
use crate::config::Settings;
use crate::failure::{CredentialSource, Failure, Kind, Result, from_api};
use crate::output::{clean, print_json};
use hodeishield_api::v1::Alert;
use std::io::{BufRead, Write};

/// What the command asks the API to do.
enum Change<'a> {
    Acknowledge { reason: Option<&'a str> },
    Resolve { reason: &'a str },
}

pub fn acknowledge(
    ctx: &Context,
    settings: &Settings,
    args: &AlertAcknowledge,
    out: &mut dyn Write,
) -> Result<()> {
    let change = Change::Acknowledge {
        reason: args.reason.as_deref(),
    };
    apply(ctx, settings, &args.id, &change, args.confirm.yes, out)
}

pub fn resolve(
    ctx: &Context,
    settings: &Settings,
    args: &AlertResolve,
    out: &mut dyn Write,
) -> Result<()> {
    let change = Change::Resolve {
        reason: &args.reason,
    };
    apply(ctx, settings, &args.id, &change, args.confirm.yes, out)
}

fn apply(
    ctx: &Context,
    settings: &Settings,
    id: &str,
    change: &Change<'_>,
    yes: bool,
    out: &mut dyn Write,
) -> Result<()> {
    // Before anything is sent: only an API key can write.
    let (_, source) = ctx.api(settings, None)?;
    if source == CredentialSource::OAuth {
        return Err(needs_api_key("an alert", "alerts:write"));
    }
    let (client, source) = ctx.single(settings)?;
    let api = ctx.call(source, None);

    if !yes {
        // The alert as it is now, so the person confirms what they are about to change. A key that
        // may write but not read still gets the question, with the id alone.
        let current = match client.get_alert(id) {
            Ok(response) => Some(response.data.data),
            Err(e) => {
                let failure = from_api(e, &api);
                if failure.kind != Kind::Forbidden {
                    return Err(failure);
                }
                None
            }
        };
        let question = question(id, current.as_ref(), change);
        let stdin = std::io::stdin();
        let yes = confirmed(&mut stdin.lock(), &mut std::io::stderr(), &question)?;
        if !yes {
            return Err(Failure::general("Cancelled. Nothing was changed."));
        }
    }

    let response = match change {
        Change::Acknowledge { reason } => client.acknowledge_alert(id, *reason),
        Change::Resolve { reason } => client.resolve_alert(id, reason),
    }
    .map_err(|e| from_api(e, &api))?;
    if ctx.json {
        return Ok(print_json(out, &response.raw)?);
    }
    let data = &response.data;
    writeln!(
        out,
        "{}",
        outcome(change, &data.data.id, &data.data.status, data.changed)
    )?;
    Ok(())
}

/// The refusal of a sign-in: the API accepts these writes from a key only.
pub(super) fn needs_api_key(what: &str, scope: &str) -> Failure {
    Failure::new(
        Kind::Forbidden,
        format!(
            "Changing {what} needs an API key. The sign-in made with `hodeishield login` can only read."
        ),
    )
    .hint(format!(
        "Set HODEISHIELD_API_KEY to a tenant API key, or an MSSP portfolio key (and name the client \
         with --tenant), that holds the `{scope}` scope. Nothing was changed."
    ))
}

/// What the person is asked to confirm.
fn question(id: &str, current: Option<&Alert>, change: &Change<'_>) -> String {
    let mut text = format!("Alert {}\n", clean(id));
    match current {
        Some(alert) => {
            text.push_str(&format!("  title:    {}\n", clean(&alert.title)));
            text.push_str(&format!(
                "  severity: {}\n",
                alert
                    .severity
                    .as_deref()
                    .map_or_else(|| "-".to_owned(), clean)
            ));
            text.push_str(&format!("  status:   {}\n", clean(&alert.status)));
        }
        None => text.push_str("  (this key cannot read the alert, so its state is not shown)\n"),
    }
    match change {
        Change::Acknowledge { reason } => {
            text.push_str("Change: mark it as acknowledged (it stays unresolved)");
            if let Some(reason) = reason {
                text.push_str(&format!(", reason: {}", clean(reason)));
            }
        }
        Change::Resolve { reason } => {
            text.push_str(&format!("Change: resolve it, reason: {}", clean(reason)));
        }
    }
    text.push_str("\nProceed? [y/N] ");
    text
}

/// Asks the question and reads one line. Only `y` or `yes` (any case) is a yes; anything else, an
/// empty line and the end of input included, is a no.
pub(super) fn confirmed(
    input: &mut dyn BufRead,
    prompt_to: &mut dyn Write,
    question: &str,
) -> std::io::Result<bool> {
    prompt_to.write_all(question.as_bytes())?;
    prompt_to.flush()?;
    let mut line = String::new();
    input.read_line(&mut line)?;
    let answer = line.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

/// The line that says what the request did.
fn outcome(change: &Change<'_>, id: &str, status: &str, changed: bool) -> String {
    let id = clean(id);
    let status = clean(status);
    match (change, changed) {
        (Change::Acknowledge { .. }, true) => {
            format!("Acknowledged alert {id} (status: {status}).")
        }
        (Change::Resolve { .. }, true) => format!("Resolved alert {id} (status: {status})."),
        (Change::Acknowledge { .. }, false) => {
            format!("Alert {id} is already acknowledged: nothing changed (status: {status}).")
        }
        (Change::Resolve { .. }, false) => {
            format!("Alert {id} is already resolved: nothing changed (status: {status}).")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(answer: &str) -> (bool, String) {
        let mut shown = Vec::new();
        let yes = confirmed(&mut answer.as_bytes(), &mut shown, "Proceed? [y/N] ").expect("io");
        (yes, String::from_utf8(shown).expect("utf-8"))
    }

    #[test]
    fn only_a_clear_yes_confirms() {
        for yes in ["y\n", "Y\n", "yes\n", " YES \r\n"] {
            assert!(ask(yes).0, "{yes:?}");
        }
        for no in [
            "",
            "\n",
            "n\n",
            "no\n",
            "yy\n",
            "ok\n",
            "yes please\n",
            "sure\n",
        ] {
            assert!(!ask(no).0, "{no:?}");
        }
    }

    #[test]
    fn the_question_is_printed_before_the_answer_is_read() {
        assert_eq!(ask("y\n").1, "Proceed? [y/N] ");
    }

    #[test]
    fn the_question_names_the_alert_and_the_change() {
        let change = Change::Resolve { reason: "patched" };
        let text = question("a1", None, &change);
        assert!(text.contains("Alert a1"));
        assert!(text.contains("cannot read the alert"));
        assert!(text.contains("resolve it, reason: patched"));
        assert!(text.ends_with("Proceed? [y/N] "));
    }

    #[test]
    fn the_outcome_says_whether_anything_changed() {
        let ack = Change::Acknowledge { reason: None };
        let res = Change::Resolve { reason: "done" };
        assert_eq!(
            outcome(&ack, "a1", "acknowledged", true),
            "Acknowledged alert a1 (status: acknowledged)."
        );
        assert!(outcome(&ack, "a1", "acknowledged", false).contains("already acknowledged"));
        assert_eq!(
            outcome(&res, "a1", "resolved", true),
            "Resolved alert a1 (status: resolved)."
        );
        assert!(outcome(&res, "a1", "resolved", false).contains("nothing changed"));
    }
}
