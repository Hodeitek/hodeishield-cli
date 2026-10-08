// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The read commands: one per `/v1` collection.

use super::Context;
use crate::cli::{
    AlertsCommand, ComplianceCommand, EndpointsCommand, EvidenceCommand, Paging, RisksCommand,
    VendorsCommand,
};
use crate::failure::{ApiContext, CredentialSource, Result, from_api};
use crate::filters::warn_unknown;
use crate::output::{
    cell, clean, print_csv, print_detail, print_json, print_table, short_time, table,
};
use comfy_table::Table;
use hodeishield_api::v1::{
    Alert, ComplianceControl, Endpoint, Evidence, ListAlertsParams, ListComplianceControlsParams,
    ListEndpointsParams, ListEvidenceParams, ListRisksParams, ListVendorsParams, Pagination, Risk,
    Vendor, operations,
};
use hodeishield_api::{ApiResponse, Error};
use serde::Serialize;
use serde_json::Value;
use std::io::Write;

type Fetch<'a, R> =
    dyn FnMut(Option<i64>, Option<i64>) -> std::result::Result<ApiResponse<R>, Error> + 'a;

/// Most pages `--all` fetches: 200 000 items at the largest page size.
const MAX_PAGES: i64 = 1_000;

/// Most items `--all` collects. The walk keeps every item twice (as received and decoded), so
/// this bounds memory, not just requests; 100 000 is far above any tenant's list and a few
/// hundred MiB at most.
const MAX_ITEMS: usize = 100_000;

/// Prints one page, or every page with `--all`.
#[allow(clippy::too_many_arguments)]
fn list<R, T>(
    ctx: &Context,
    out: &mut dyn Write,
    paging: &Paging,
    noun: &str,
    api: ApiContext<'_>,
    fetch: &mut Fetch<'_, R>,
    split: fn(R) -> (Vec<T>, Pagination),
    render: fn(&[T]) -> Table,
) -> Result<()> {
    if !paging.all {
        let response = fetch(paging.page, paging.per_page).map_err(|e| from_api(e, &api))?;
        if ctx.json {
            return Ok(print_json(out, &response.raw)?);
        }
        let (items, pagination) = split(response.data);
        if items.is_empty() {
            eprintln!("No {noun} found.");
            return Ok(());
        }
        if paging.csv {
            let raw_items = response.raw.get("data").and_then(Value::as_array);
            print_csv(out, raw_items.map_or(&[], Vec::as_slice))?;
        } else {
            print_table(out, &render(&items))?;
        }
        if pagination.total_pages > 1 {
            let next = if pagination.page < pagination.total_pages {
                format!(" Next: --page {}, or --all.", pagination.page + 1)
            } else {
                String::new()
            };
            eprintln!(
                "Page {} of {} ({} {noun}).{next}",
                pagination.page, pagination.total_pages, pagination.total
            );
        }
        return Ok(());
    }

    let per_page = paging.per_page.or(Some(200));
    let (raw_items, items) = collect_pages(noun, &api, per_page, MAX_ITEMS, fetch, split)?;
    if ctx.json {
        return Ok(print_json(out, &Value::Array(raw_items))?);
    }
    if items.is_empty() {
        eprintln!("No {noun} found.");
        return Ok(());
    }
    if paging.csv {
        print_csv(out, &raw_items)?;
    } else {
        print_table(out, &render(&items))?;
    }
    eprintln!("{} {noun}.", items.len());
    Ok(())
}

/// Walks every page, as received and decoded, stopping with an error past `max_items` items.
fn collect_pages<R, T>(
    noun: &str,
    api: &ApiContext<'_>,
    per_page: Option<i64>,
    max_items: usize,
    fetch: &mut Fetch<'_, R>,
    split: fn(R) -> (Vec<T>, Pagination),
) -> Result<(Vec<Value>, Vec<T>)> {
    let mut raw_items = Vec::new();
    let mut items = Vec::new();
    let mut page = 1;
    loop {
        let response = fetch(Some(page), per_page).map_err(|e| from_api(e, api))?;
        if let Some(Value::Array(batch)) = response.raw.get("data") {
            raw_items.extend(batch.iter().cloned());
        }
        let (mut batch, pagination) = split(response.data);
        // Stop on whichever says "last page" first, and never trust the server to end the walk.
        let done = batch.is_empty()
            || page >= pagination.total_pages
            || pagination.page != page
            || page.saturating_mul(pagination.per_page.max(1)) >= pagination.total;
        items.append(&mut batch);
        if items.len() > max_items {
            return Err(crate::failure::Failure::general(format!(
                "Stopped after {} {noun}; --all collects at most {max_items}, so the rest was not fetched.",
                items.len()
            ))
            .hint("Narrow the list with filters, or walk it with --page."));
        }
        if done {
            break;
        }
        if page >= MAX_PAGES {
            return Err(crate::failure::Failure::general(format!(
                "Stopped after {MAX_PAGES} pages ({} {noun}); the rest was not fetched.",
                items.len()
            ))
            .hint("Narrow the list with filters, or walk it with --page."));
        }
        page += 1;
    }
    Ok((raw_items, items))
}

/// Prints one resource: the API's JSON, or its fields one per line.
fn show<R, T: Serialize>(
    ctx: &Context,
    out: &mut dyn Write,
    api: ApiContext<'_>,
    response: std::result::Result<ApiResponse<R>, Error>,
    data: fn(&R) -> &T,
) -> Result<()> {
    let response = response.map_err(|e| from_api(e, &api))?;
    if ctx.json {
        return Ok(print_json(out, &response.raw)?);
    }
    let value = serde_json::to_value(data(&response.data))
        .map_err(|e| crate::failure::Failure::general(e.to_string()))?;
    Ok(print_detail(out, &value)?)
}

fn plain(source: CredentialSource) -> ApiContext<'static> {
    ApiContext {
        source,
        framework: None,
    }
}

pub fn vendors(ctx: &Context, command: VendorsCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        VendorsCommand::List(args) => {
            let base = ListVendorsParams {
                q: args.query,
                category: args.category,
                active: args.active.map(|a| a.to_string()),
                business_criticality: args.criticality,
                sort: args.sort,
                order: args.paging.order,
                ..ListVendorsParams::default()
            };
            list(
                ctx,
                out,
                &args.paging,
                "vendors",
                plain(source),
                &mut |page, per_page| {
                    client.list_vendors(&ListVendorsParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                vendor_table,
            )
        }
        VendorsCommand::Get { id } => {
            show(ctx, out, plain(source), client.get_vendor(&id), |r| &r.data)
        }
    }
}

fn vendor_table(items: &[Vendor]) -> Table {
    table(
        &["ID", "NAME", "DOMAIN", "CRITICALITY", "ACTIVE", "LAST SCAN"],
        items
            .iter()
            .map(|v| {
                vec![
                    clean(&v.id),
                    clean(&v.name),
                    cell(v.domain.as_deref()),
                    cell(v.business_criticality.as_deref()),
                    if v.active { "yes" } else { "no" }.to_owned(),
                    short_time(v.last_scan_at.as_deref()),
                ]
            })
            .collect(),
    )
}

pub fn alerts(ctx: &Context, command: AlertsCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        AlertsCommand::List(args) => {
            warn_unknown(
                &operations::LIST_ALERTS,
                &[("severity", args.severity.as_deref())],
            );
            let base = ListAlertsParams {
                status: args.status,
                severity: args.severity,
                vendor_id: args.vendor,
                since: args.since,
                sort: args.sort,
                order: args.paging.order,
                ..ListAlertsParams::default()
            };
            list(
                ctx,
                out,
                &args.paging,
                "alerts",
                plain(source),
                &mut |page, per_page| {
                    client.list_alerts(&ListAlertsParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                alert_table,
            )
        }
        AlertsCommand::Get { id } => {
            show(ctx, out, plain(source), client.get_alert(&id), |r| &r.data)
        }
    }
}

fn alert_table(items: &[Alert]) -> Table {
    table(
        &["ID", "SEVERITY", "STATUS", "TYPE", "TITLE", "CREATED"],
        items
            .iter()
            .map(|a| {
                vec![
                    clean(&a.id),
                    cell(a.severity.as_deref()),
                    clean(&a.status),
                    clean(&a.r#type),
                    clean(&a.title),
                    short_time(Some(&a.created_at)),
                ]
            })
            .collect(),
    )
}

pub fn risks(ctx: &Context, command: RisksCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        RisksCommand::List(args) => {
            warn_unknown(
                &operations::LIST_RISKS,
                &[
                    ("status", args.status.as_deref()),
                    ("domain", args.domain.as_deref()),
                ],
            );
            let base = ListRisksParams {
                status: args.status,
                domain: args.domain,
                vendor_id: args.vendor,
                min_inherent_score: args.min_inherent_score,
                sort: args.sort,
                order: args.paging.order,
                ..ListRisksParams::default()
            };
            list(
                ctx,
                out,
                &args.paging,
                "risks",
                plain(source),
                &mut |page, per_page| {
                    client.list_risks(&ListRisksParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                risk_table,
            )
        }
        RisksCommand::Get { id } => {
            show(ctx, out, plain(source), client.get_risk(&id), |r| &r.data)
        }
    }
}

fn risk_table(items: &[Risk]) -> Table {
    table(
        &["ID", "TITLE", "DOMAIN", "STATUS", "INHERENT", "RESIDUAL"],
        items
            .iter()
            .map(|r| {
                vec![
                    clean(&r.id),
                    clean(&r.title),
                    clean(&r.domain),
                    clean(&r.status),
                    r.inherent_score.to_string(),
                    r.residual_score
                        .map_or_else(|| "-".to_owned(), |s| s.to_string()),
                ]
            })
            .collect(),
    )
}

pub fn compliance(ctx: &Context, command: ComplianceCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        ComplianceCommand::Controls(args) => {
            warn_unknown(
                &operations::LIST_COMPLIANCE_CONTROLS,
                &[("status", args.status.as_deref())],
            );
            let api = ApiContext {
                source,
                framework: Some(&args.framework),
            };
            let mut base = ListComplianceControlsParams::new(args.framework.clone());
            base.status = args.status;
            base.sort = args.sort;
            base.order = args.paging.order;
            list(
                ctx,
                out,
                &args.paging,
                "controls",
                api,
                &mut |page, per_page| {
                    client.list_compliance_controls(&ListComplianceControlsParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                control_table,
            )
        }
        ComplianceCommand::Posture { framework } => {
            let api = ApiContext {
                source,
                framework: Some(&framework),
            };
            let response = client
                .get_framework_posture(&framework)
                .map_err(|e| from_api(e, &api))?;
            if ctx.json {
                return Ok(print_json(out, &response.raw)?);
            }
            let posture = &response.data.data;
            writeln!(out, "framework          {}", clean(&posture.framework))?;
            writeln!(out, "controls_total     {}", posture.controls_total)?;
            writeln!(out, "evidence_total     {}", posture.evidence_total)?;
            writeln!(
                out,
                "last_evaluated_at  {}",
                short_time(posture.last_evaluated_at.as_deref())
            )?;
            if !posture.by_status.is_empty() {
                writeln!(out)?;
                let rows = posture
                    .by_status
                    .iter()
                    .map(|(status, count)| vec![clean(status), count.to_string()])
                    .collect();
                print_table(out, &table(&["STATUS", "CONTROLS"], rows))?;
            }
            Ok(())
        }
    }
}

fn control_table(items: &[ComplianceControl]) -> Table {
    table(
        &["CONTROL", "STATUS", "EVIDENCE", "LAST EVALUATED"],
        items
            .iter()
            .map(|c| {
                vec![
                    clean(&c.control_code),
                    clean(&c.status),
                    c.evidence_count.to_string(),
                    short_time(c.last_evaluated_at.as_deref()),
                ]
            })
            .collect(),
    )
}

pub fn evidence(ctx: &Context, command: EvidenceCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        EvidenceCommand::List(args) => {
            let base = ListEvidenceParams {
                evidence_type: args.evidence_type,
                source_type: args.source_type,
                vendor_id: args.vendor,
                expiring_before: args.expiring_before,
                sort: args.sort,
                order: args.paging.order,
                ..ListEvidenceParams::default()
            };
            list(
                ctx,
                out,
                &args.paging,
                "evidence items",
                plain(source),
                &mut |page, per_page| {
                    client.list_evidence(&ListEvidenceParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                evidence_table,
            )
        }
        EvidenceCommand::Get { id } => {
            show(ctx, out, plain(source), client.get_evidence(&id), |r| {
                &r.data
            })
        }
    }
}

fn evidence_table(items: &[Evidence]) -> Table {
    table(
        &["ID", "TYPE", "SOURCE", "TITLE", "VALID UNTIL"],
        items
            .iter()
            .map(|e| {
                vec![
                    clean(&e.id),
                    clean(&e.evidence_type),
                    clean(&e.source_type),
                    clean(&e.title),
                    short_time(e.valid_until.as_deref()),
                ]
            })
            .collect(),
    )
}

pub fn endpoints(ctx: &Context, command: EndpointsCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings)?;
    match command {
        EndpointsCommand::List(args) => {
            let base = ListEndpointsParams {
                status: args.status,
                silent_since: args.silent_since,
                sort: args.sort,
                order: args.paging.order,
                ..ListEndpointsParams::default()
            };
            list(
                ctx,
                out,
                &args.paging,
                "endpoints",
                plain(source),
                &mut |page, per_page| {
                    client.list_endpoints(&ListEndpointsParams {
                        page,
                        per_page,
                        ..base.clone()
                    })
                },
                |r| (r.data, r.pagination),
                endpoint_table,
            )
        }
    }
}

fn endpoint_table(items: &[Endpoint]) -> Table {
    table(
        &[
            "ID",
            "HOSTNAME",
            "STATUS",
            "PRODUCER",
            "VERSION",
            "LAST SEEN",
        ],
        items
            .iter()
            .map(|e| {
                vec![
                    clean(&e.id),
                    cell(e.hostname.as_deref()),
                    clean(&e.status),
                    clean(&e.producer),
                    cell(e.agent_version.as_deref()),
                    short_time(e.last_seen_at.as_deref()),
                ]
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::CredentialSource;

    /// Serves `total` items, `per_page` at a time, as numbers.
    fn walk(total: i64, per_page: i64, max_items: usize) -> Result<(Vec<Value>, Vec<i64>)> {
        let api = ApiContext {
            source: CredentialSource::ApiKey,
            framework: None,
        };
        let total_pages = (total + per_page - 1) / per_page;
        collect_pages(
            "things",
            &api,
            Some(per_page),
            max_items,
            &mut |page, _| {
                let page = page.unwrap_or(1);
                let first = (page - 1) * per_page;
                let batch: Vec<i64> = (first..(first + per_page).min(total)).collect();
                Ok(ApiResponse {
                    raw: serde_json::json!({ "data": batch }),
                    data: (
                        batch,
                        Pagination {
                            page,
                            per_page,
                            total,
                            total_pages,
                        },
                    ),
                    meta: Default::default(),
                })
            },
            |r: (Vec<i64>, Pagination)| r,
        )
    }

    #[test]
    fn a_walk_within_the_item_limit_collects_everything() {
        let (raw, items) = walk(10, 4, 10).expect("within the limit");
        assert_eq!((raw.len(), items.len()), (10, 10));
    }

    #[test]
    fn a_walk_past_the_item_limit_stops_with_a_hint() {
        let failure = walk(11, 4, 10).expect_err("over the limit");
        assert!(
            failure.message.contains("at most 10"),
            "{}",
            failure.message
        );
        assert!(failure.hint.is_some_and(|h| h.contains("--page")));
    }
}
