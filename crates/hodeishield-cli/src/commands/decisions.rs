// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! `approvals list`, `approvals approve` and `approvals reject`: the proposals waiting for a
//! person's decision.
//!
//! Decisions need a sign-in (an API key cannot make them) that holds `act:decide` and was
//! confirmed in the last 15 minutes; the API says when that is not so, and `failure.rs` turns the
//! answer into a message. Approving only records the approval: the service carries the action out
//! later, with its own checks.
//!
//! Like the other writes, a decision never happens on a guess: it needs the person's yes, typed at
//! the prompt or given with `--yes`. Without a terminal and without `--yes`, the command line
//! refuses before it gets here (see `Cli::parse_checked`).

use super::Context;
use super::alert_writes::confirmed;
use super::resources::list_one;
use crate::cli::{ApprovalDecision, ApprovalsCommand, ApprovalsList};
use crate::config::Settings;
use crate::failure::{CredentialSource, Failure, Kind, Result, from_api};
use crate::output::{Rows, cell, clean, print_json, short_time};
use hodeishield_api::Client;
use hodeishield_api::v1::{ListPendingActProposalsParams, PendingActProposal};
use std::io::Write;

/// Most pages read while looking for one proposal in the list (200 a page).
const MAX_LOOKUP_PAGES: i64 = 50;

pub fn run(
    ctx: &Context,
    settings: &Settings,
    command: ApprovalsCommand,
    out: &mut dyn Write,
) -> Result<()> {
    // Before anything is sent: an API key cannot decide.
    let (_, source) = ctx.api(settings, None)?;
    if source == CredentialSource::ApiKey {
        return Err(needs_sign_in());
    }
    match command {
        ApprovalsCommand::List(args) => list(ctx, settings, &args, out),
        ApprovalsCommand::Approve(args) => decide(ctx, settings, &args, Decision::Approve, out),
        ApprovalsCommand::Reject(args) => decide(ctx, settings, &args, Decision::Reject, out),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decision {
    Approve,
    Reject,
}

/// The refusal of an API key: the API accepts decisions from a sign-in only.
fn needs_sign_in() -> Failure {
    Failure::new(
        Kind::Forbidden,
        "Decisions need a sign-in, not an API key. Nothing was sent.",
    )
    .hint(
        "Unset HODEISHIELD_API_KEY and run `hodeishield login --decide`; an API key cannot see or \
         decide proposals.",
    )
}

fn list(
    ctx: &Context,
    settings: &Settings,
    args: &ApprovalsList,
    out: &mut dyn Write,
) -> Result<()> {
    let (client, source) = ctx.single(settings)?;
    let base = ListPendingActProposalsParams {
        sort: args.sort,
        order: args.paging.order,
        class: args.class,
        module: args.module.clone(),
        expires_before: args.expires_before.clone(),
        ..ListPendingActProposalsParams::default()
    };
    list_one(
        ctx,
        out,
        &args.paging,
        "proposals",
        ctx.call(source, None),
        &mut |page, per_page| {
            client.list_pending_act_proposals(&ListPendingActProposalsParams {
                page,
                per_page,
                ..base.clone()
            })
        },
        |r| (r.data, r.pagination.into()),
        proposal_table,
    )
}

fn proposal_table(items: &[PendingActProposal]) -> Rows {
    Rows::new(
        &[
            "ID",
            "ACTION",
            "MODULE",
            "PROPOSED BY YOU",
            "EXPIRES",
            "WHY",
        ],
        items
            .iter()
            .map(|p| {
                vec![
                    clean(&p.id),
                    cell(p.class.as_deref().or(Some(p.payload_kind.as_str()))),
                    cell(p.module.as_deref()),
                    if p.proposed_by_you { "yes" } else { "no" }.to_owned(),
                    short_time(Some(&p.expires_at)),
                    shorten(&clean(&p.rationale), 60),
                ]
            })
            .collect(),
    )
}

/// `text` cut to `max` characters, with an ellipsis when it was longer.
fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

fn decide(
    ctx: &Context,
    settings: &Settings,
    args: &ApprovalDecision,
    decision: Decision,
    out: &mut dyn Write,
) -> Result<()> {
    let (client, source) = ctx.single(settings)?;
    let api = ctx.call(source, None);

    if !args.confirm.yes {
        // The proposal as it is listed now, so the person reads what it would write before
        // deciding. Any failure to read stops here: nothing has been sent.
        let found = find(&client, &args.id).map_err(|e| from_api(e, &api))?;
        let shown = match (&found, decision) {
            (Some(proposal), _) => Some(proposal),
            // Rejecting is open to more people than approving, so a proposal that is not in the
            // list can still be rejected: the person is asked with the id alone.
            (None, Decision::Reject) => None,
            (None, Decision::Approve) => {
                return Err(Failure::new(
                    Kind::NotFound,
                    format!(
                        "Proposal {} is not in your list of proposals you may approve, so what \
                         it would write cannot be shown. Nothing was sent.",
                        clean(&args.id)
                    ),
                )
                .hint(
                    "It may have been decided or have expired, or you may not be allowed to \
                     approve it. `hodeishield approvals list` shows what you may approve.",
                ));
            }
        };
        let question = question(&args.id, shown, decision, &args.reason);
        let stdin = std::io::stdin();
        if !confirmed(&mut stdin.lock(), &mut std::io::stderr(), &question)? {
            return Err(Failure::general("Cancelled. Nothing was decided."));
        }
    }

    // A decision is sent once: a write is never repeated after a transport or gateway error.
    let response = match decision {
        Decision::Approve => client.approve_act_proposal(&args.id, &args.reason),
        Decision::Reject => client.reject_act_proposal(&args.id, &args.reason),
    }
    .map_err(|e| from_api(e, &api))?;
    if ctx.json {
        return Ok(print_json(out, &response.raw)?);
    }
    let data = &response.data.data;
    writeln!(
        out,
        "{}",
        outcome(
            decision,
            &data.id,
            &data.status,
            data.approval_expires_at.as_deref(),
            &data.ledger_entry_id
        )
    )?;
    Ok(())
}

/// The proposal with this id in the list of what the caller may decide, if it is there.
fn find(
    client: &Client,
    id: &str,
) -> std::result::Result<Option<PendingActProposal>, hodeishield_api::Error> {
    for page in 1..=MAX_LOOKUP_PAGES {
        let response = client.list_pending_act_proposals(&ListPendingActProposalsParams {
            page: Some(page),
            per_page: Some(200),
            ..ListPendingActProposalsParams::default()
        })?;
        let body = response.data;
        if let Some(found) = body.data.into_iter().find(|p| p.id == id) {
            return Ok(Some(found));
        }
        if page >= body.pagination.total_pages {
            break;
        }
    }
    Ok(None)
}

/// What the person is asked to confirm.
fn question(
    id: &str,
    proposal: Option<&PendingActProposal>,
    decision: Decision,
    reason: &str,
) -> String {
    let mut text = format!("Proposal {}\n", clean(id));
    match proposal {
        Some(p) => {
            text.push_str(&format!(
                "  action:          {}\n",
                clean(p.class.as_deref().unwrap_or(&p.payload_kind))
            ));
            if let Some(module) = &p.module {
                text.push_str(&format!("  module:          {}\n", clean(module)));
            }
            text.push_str(&format!(
                "  proposed by you: {}\n",
                if p.proposed_by_you { "yes" } else { "no" }
            ));
            text.push_str(&format!("  proposed via:    {}\n", clean(&p.proposed_via)));
            text.push_str(&format!("  why:             {}\n", clean(&p.rationale)));
            text.push_str(&format!("  expires:         {}\n", clean(&p.expires_at)));
            text.push_str("  it would write:\n");
            let payload = serde_json::to_string_pretty(&p.payload).unwrap_or_default();
            for line in payload.lines() {
                text.push_str(&format!("    {}\n", clean(line)));
            }
        }
        None => text.push_str("  (it is not in your list, so its content is not shown)\n"),
    }
    match decision {
        Decision::Approve => text.push_str(&format!(
            "Change: approve it, reason: {}. This only records your approval; it does not carry \
             the action out.",
            clean(reason)
        )),
        Decision::Reject => text.push_str(&format!(
            "Change: reject it, reason: {}. Nothing will be carried out.",
            clean(reason)
        )),
    }
    text.push_str("\nProceed? [y/N] ");
    text
}

/// The line that says what the request did. An approval never says the action was carried out: the
/// service does that later.
fn outcome(
    decision: Decision,
    id: &str,
    status: &str,
    approval_expires_at: Option<&str>,
    ledger_entry_id: &str,
) -> String {
    let (id, status, ledger) = (clean(id), clean(status), clean(ledger_entry_id));
    match decision {
        Decision::Approve => {
            let until = approval_expires_at.map_or_else(
                || "only while the approval lasts".to_owned(),
                |at| format!("only before {} (the approval lapses after that)", clean(at)),
            );
            format!(
                "Approval recorded for proposal {id} (status: {status}; ledger entry {ledger}).\n\
                 The action has not been carried out: approving only records your decision. The \
                 service carries it out later, with its own checks, {until}."
            )
        }
        Decision::Reject => format!(
            "Rejected proposal {id} (status: {status}; ledger entry {ledger}). Nothing will be \
             carried out."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approval_never_says_the_action_was_carried_out() {
        let text = outcome(
            Decision::Approve,
            "p1",
            "approved",
            Some("2026-11-18T10:15:00Z"),
            "l1",
        );
        assert!(text.starts_with("Approval recorded for proposal p1"));
        assert!(text.contains("has not been carried out"));
        assert!(text.contains("before 2026-11-18T10:15:00Z"));
        for word in ["executed", "applied", "done"] {
            assert!(!text.to_lowercase().contains(word), "{word}: {text}");
        }
    }

    #[test]
    fn a_rejection_says_nothing_will_be_carried_out() {
        let text = outcome(Decision::Reject, "p1", "rejected", None, "l1");
        assert!(text.starts_with("Rejected proposal p1"));
        assert!(text.contains("Nothing will be carried out"));
    }

    #[test]
    fn the_question_without_the_proposal_says_so() {
        let text = question("p1", None, Decision::Reject, "not needed");
        assert!(text.contains("not in your list"));
        assert!(text.contains("reject it, reason: not needed"));
        assert!(text.ends_with("Proceed? [y/N] "));
    }

    #[test]
    fn shorten_cuts_long_text_only() {
        assert_eq!(shorten("short", 10), "short");
        assert_eq!(shorten("abcdefghij", 5), "abcd…");
    }

    fn client(server: &mockito::ServerGuard) -> Client {
        Client::builder(
            server.url().parse().expect("url"),
            secrecy::SecretString::from("at-test"),
        )
        .build()
        .expect("client")
    }

    fn proposal(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","class":"create_task","module":null,"payload_kind":"task","payload":{{"title":"Rotate keys","nested":{{"n":1}}}},"rationale":"Old keys.","confidence":null,"proposed_via":"agent","proposed_by_you":true,"created_at":"2026-11-18T09:00:00Z","expires_at":"2026-11-25T09:00:00Z"}}"#
        )
    }

    #[test]
    fn a_proposal_is_found_on_a_later_page_or_reported_missing() {
        let mut server = mockito::Server::new();
        let page = |page: i64, item: &str| {
            format!(
                r#"{{"data":[{item}],"pagination":{{"page":{page},"per_page":200,"total":2,"total_pages":2}}}}"#
            )
        };
        server
            .mock("GET", "/v1/act/inbox")
            .match_query(mockito::Matcher::UrlEncoded("page".into(), "1".into()))
            .with_body(page(1, &proposal("p1")))
            .create();
        let second = server
            .mock("GET", "/v1/act/inbox")
            .match_query(mockito::Matcher::UrlEncoded("page".into(), "2".into()))
            .with_body(page(2, &proposal("p2")))
            .expect(2)
            .create();
        let found = find(&client(&server), "p2").expect("ok").expect("found");
        assert_eq!(found.id, "p2");
        assert!(find(&client(&server), "p3").expect("ok").is_none());
        second.assert();
    }

    #[test]
    fn the_question_shows_the_payload_the_flag_and_the_reason() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/act/inbox")
            .match_query(mockito::Matcher::Any)
            .with_body(format!(
                r#"{{"data":[{}],"pagination":{{"page":1,"per_page":200,"total":1,"total_pages":1}}}}"#,
                proposal("p1")
            ))
            .create();
        let found = find(&client(&server), "p1").expect("ok").expect("found");
        let text = question("p1", Some(&found), Decision::Approve, "Checked it");
        assert!(text.contains("proposed by you: yes"), "{text}");
        assert!(text.contains("\"title\": \"Rotate keys\""), "{text}");
        assert!(text.contains("why:             Old keys."), "{text}");
        assert!(text.contains("approve it, reason: Checked it"), "{text}");
        assert!(text.contains("does not carry the action out"), "{text}");
        assert!(text.ends_with("Proceed? [y/N] "), "{text}");
    }
}
