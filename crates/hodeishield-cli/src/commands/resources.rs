// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The read commands: one per `/v1` collection.

use super::Context;
use super::tenants::{Selection, Target};
use crate::cli::{
    AlertsCommand, ComplianceCommand, EndpointsCommand, EvidenceCommand, Paging, RisksCommand,
    VendorsCommand,
};
use crate::failure::{ApiContext, CredentialSource, Failure, Kind, Result, from_api};
use crate::filters::warn_unknown;
use crate::output::{
    Rows, cell, clean, print_csv, print_detail, print_json, print_table, short_time, table,
    tenant_table,
};
use hodeishield_api::Client;
use hodeishield_api::portfolio::Tenant;
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

/// A fetch that still has to be told which client to ask.
type FetchFrom<'a, R> =
    dyn FnMut(&Client, Option<i64>, Option<i64>) -> std::result::Result<ApiResponse<R>, Error> + 'a;

/// Most pages `--all` fetches: 200 000 items at the largest page size.
const MAX_PAGES: i64 = 1_000;

/// Most items `--all` collects. The walk keeps every item twice (as received and decoded), so
/// this bounds memory, not just requests; 100 000 is far above any tenant's list and a few
/// hundred MiB at most.
const MAX_ITEMS: usize = 100_000;

/// Prints a list for the selected client, or for every client with `--all-tenants`.
#[allow(clippy::too_many_arguments)]
fn list<R, T>(
    ctx: &Context,
    out: &mut dyn Write,
    paging: &Paging,
    noun: &str,
    api: ApiContext<'_>,
    targets: &[Target],
    fetch: &mut FetchFrom<'_, R>,
    split: fn(R) -> (Vec<T>, Pagination),
    render: fn(&[T]) -> Rows,
) -> Result<()> {
    if matches!(ctx.selection, Selection::All) {
        return list_across(ctx, out, paging, noun, api, targets, fetch, split, render);
    }
    let client = &targets[0].client;
    list_one(
        ctx,
        out,
        paging,
        noun,
        api,
        &mut |page, per_page| fetch(client, page, per_page),
        split,
        render,
    )
}

/// Prints one page, or every page with `--all`, of one tenant's list.
#[allow(clippy::too_many_arguments)]
pub(super) fn list_one<R, T>(
    ctx: &Context,
    out: &mut dyn Write,
    paging: &Paging,
    noun: &str,
    api: ApiContext<'_>,
    fetch: &mut Fetch<'_, R>,
    split: fn(R) -> (Vec<T>, Pagination),
    render: fn(&[T]) -> Rows,
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
            print_table(out, &render(&items).into_table())?;
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
        print_table(out, &render(&items).into_table())?;
    }
    eprintln!("{} {noun}.", items.len());
    Ok(())
}

/// Every page of every client tenant, each row labelled with the tenant whose request produced it.
///
/// A tenant that cannot be read for its own reasons (no licence, left the portfolio) is reported
/// and skipped, and the command still fails at the end, so a script never takes a partial result
/// for a complete one. Any other failure stops the walk: tenants are asked one after the other, and
/// a rate limit (after the client has waited out the short ones) or a missing scope is not retried
/// against the next tenant.
#[allow(clippy::too_many_arguments)]
fn list_across<R, T>(
    ctx: &Context,
    out: &mut dyn Write,
    paging: &Paging,
    noun: &str,
    api: ApiContext<'_>,
    targets: &[Target],
    fetch: &mut FetchFrom<'_, R>,
    split: fn(R) -> (Vec<T>, Pagination),
    render: fn(&[T]) -> Rows,
) -> Result<()> {
    let per_page = paging.per_page.or(Some(200));
    let mut collected: Vec<(&Tenant, Vec<Value>, Vec<T>)> = Vec::new();
    let mut failures: Vec<Failure> = Vec::new();
    let mut total = 0_usize;
    for target in targets {
        let Some(tenant) = &target.tenant else {
            continue;
        };
        if target.unknown_licence {
            // The licence vocabulary is open. Not read, but not silently dropped either.
            eprintln!(
                "warning: client tenant {}: licence status `{}` is not known to this version; not read",
                clean(&tenant.slug),
                clean(&tenant.licence_status)
            );
            failures.push(Failure::general("licence status not known"));
            continue;
        }
        let walked = collect_pages(
            noun,
            &api,
            per_page,
            MAX_ITEMS.saturating_sub(total),
            &mut |page, per_page| fetch(&target.client, page, per_page),
            split,
        );
        match walked {
            Ok((raw_items, items)) => {
                total += items.len();
                collected.push((tenant, raw_items, items));
            }
            Err(failure) if matches!(failure.kind, Kind::NotFound | Kind::LicenceInactive) => {
                eprintln!(
                    "warning: client tenant {}: {}",
                    clean(&tenant.slug),
                    clean(&failure.message)
                );
                failures.push(failure);
            }
            Err(failure) => return Err(failure),
        }
    }

    if ctx.json || paging.csv {
        let mut labelled = Vec::new();
        for (tenant, raw_items, _) in &collected {
            for item in raw_items {
                labelled.push(with_tenant(item, tenant)?);
            }
        }
        if ctx.json {
            print_json(out, &Value::Array(labelled))?;
        } else {
            print_csv(out, &labelled)?;
        }
    } else {
        let mut headers = None;
        let mut groups = Vec::new();
        for (tenant, _, items) in &collected {
            if items.is_empty() {
                continue;
            }
            let rows = render(items);
            headers.get_or_insert(rows.headers);
            groups.push((tenant.slug.clone(), tenant.id.clone(), rows.rows));
        }
        if let Some(headers) = headers {
            print_table(out, &tenant_table(headers, groups))?;
        }
    }
    if total == 0 {
        eprintln!("No {noun} found.");
    } else {
        eprintln!("{total} {noun} across {} client tenants.", collected.len());
    }
    match failures.first() {
        None => Ok(()),
        Some(first) => Err(Failure::new(
            first.kind,
            format!(
                "Could not read {} of {} client tenants (see the warnings above); the output covers the others.",
                failures.len(),
                targets.len()
            ),
        )),
    }
}

/// The item with the tenant whose request returned it in front: `tenant_id`, `tenant_slug` and
/// `tenant_name`. An item that already has such a field is refused rather than overwritten.
fn with_tenant(item: &Value, tenant: &Tenant) -> Result<Value> {
    let Value::Object(fields) = item else {
        return Err(Failure::general(
            "An item of the answer is not an object, so it cannot be labelled with its tenant.",
        ));
    };
    let mut labelled = serde_json::Map::new();
    labelled.insert("tenant_id".to_owned(), Value::String(tenant.id.clone()));
    labelled.insert("tenant_slug".to_owned(), Value::String(tenant.slug.clone()));
    labelled.insert("tenant_name".to_owned(), Value::String(tenant.name.clone()));
    for (key, value) in fields {
        if labelled.contains_key(key) {
            return Err(Failure::general(format!(
                "An item already has a field named {}, which the tenant label would overwrite.",
                clean(key)
            )));
        }
        labelled.insert(key.clone(), value.clone());
    }
    Ok(Value::Object(labelled))
}

/// Walks every page, as received and decoded, stopping with an error past `max_items` items.
pub(super) fn collect_pages<R, T>(
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

fn plain(ctx: &Context, source: CredentialSource) -> ApiContext<'static> {
    ctx.call(source, None)
}

pub fn vendors(ctx: &Context, command: VendorsCommand, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    match command {
        VendorsCommand::List(args) => {
            let (targets, source) = ctx.targets(&settings)?;
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
                plain(ctx, source),
                &targets,
                &mut |client, page, per_page| {
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
            let (client, source) = ctx.single(&settings)?;
            show(ctx, out, plain(ctx, source), client.get_vendor(&id), |r| {
                &r.data
            })
        }
    }
}

fn vendor_table(items: &[Vendor]) -> Rows {
    Rows::new(
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
    match command {
        AlertsCommand::List(args) => {
            warn_unknown(
                &operations::LIST_ALERTS,
                &[("severity", args.severity.as_deref())],
            );
            let (targets, source) = ctx.targets(&settings)?;
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
                plain(ctx, source),
                &targets,
                &mut |client, page, per_page| {
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
            let (client, source) = ctx.single(&settings)?;
            show(ctx, out, plain(ctx, source), client.get_alert(&id), |r| {
                &r.data
            })
        }
    }
}

fn alert_table(items: &[Alert]) -> Rows {
    Rows::new(
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
    match command {
        RisksCommand::List(args) => {
            warn_unknown(
                &operations::LIST_RISKS,
                &[
                    ("status", args.status.as_deref()),
                    ("domain", args.domain.as_deref()),
                ],
            );
            let (targets, source) = ctx.targets(&settings)?;
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
                plain(ctx, source),
                &targets,
                &mut |client, page, per_page| {
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
            let (client, source) = ctx.single(&settings)?;
            show(ctx, out, plain(ctx, source), client.get_risk(&id), |r| {
                &r.data
            })
        }
    }
}

fn risk_table(items: &[Risk]) -> Rows {
    Rows::new(
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
    match command {
        ComplianceCommand::Controls(args) => {
            warn_unknown(
                &operations::LIST_COMPLIANCE_CONTROLS,
                &[("status", args.status.as_deref())],
            );
            let (targets, source) = ctx.targets(&settings)?;
            let api = ctx.call(source, Some(&args.framework));
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
                &targets,
                &mut |client, page, per_page| {
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
            let (client, source) = ctx.single(&settings)?;
            let api = ctx.call(source, Some(&framework));
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

fn control_table(items: &[ComplianceControl]) -> Rows {
    Rows::new(
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
    match command {
        EvidenceCommand::List(args) => {
            let (targets, source) = ctx.targets(&settings)?;
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
                plain(ctx, source),
                &targets,
                &mut |client, page, per_page| {
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
            let (client, source) = ctx.single(&settings)?;
            show(
                ctx,
                out,
                plain(ctx, source),
                client.get_evidence(&id),
                |r| &r.data,
            )
        }
    }
}

fn evidence_table(items: &[Evidence]) -> Rows {
    Rows::new(
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
    match command {
        EndpointsCommand::List(args) => {
            let (targets, source) = ctx.targets(&settings)?;
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
                plain(ctx, source),
                &targets,
                &mut |client, page, per_page| {
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

fn endpoint_table(items: &[Endpoint]) -> Rows {
    Rows::new(
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
            tenant_selected: false,
            is_portfolio_key: false,
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
