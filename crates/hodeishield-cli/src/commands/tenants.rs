// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Client tenants: the `tenants` command and the selection of which client a read command reads.
//!
//! The CLI depends on the interface of `hodeishield_api::portfolio` only: it lists tenants and builds
//! a client bound to one of them. How the selection travels on the wire is not known here.

use super::Context;
use super::resources::{collect_pages, list_one};
use crate::cli::TenantsCommand;
use crate::config::Settings;
use crate::failure::{ApiContext, CredentialSource, Failure, Kind, Result};
use crate::output::{Rows, clean, count};
use hodeishield_api::Client;
use hodeishield_api::portfolio::{
    ListTenantsParams, ListTenantsResponse, Readability, Tenant, is_uuid,
};
use std::collections::HashSet;
use std::io::Write;

/// Which client tenant the read commands read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The credential's own tenant: what the CLI did before portfolios, with no tenant label.
    Own,
    /// One client, by slug or id.
    Tenant(String),
    /// Every client of the portfolio.
    All,
}

/// A client to ask, and the tenant it is bound to. `tenant` is `None` only for [`Selection::Own`].
/// Each target has its own client, so a request for one tenant can never carry another's selection.
#[derive(Debug)]
pub struct Target {
    pub client: Client,
    pub tenant: Option<Tenant>,
    /// Set for a tenant of `--all-tenants` whose licence status this version does not know: it is
    /// not read, and the walk reports it and fails at the end.
    pub unknown_licence: bool,
}

impl Context {
    /// The clients to read for the selection. For [`Selection::Own`] this is one client and no
    /// request is made; otherwise the portfolio is listed first.
    pub fn targets(&self, settings: &Settings) -> Result<(Vec<Target>, CredentialSource)> {
        let selected = match &self.selection {
            Selection::Own => {
                let (client, source) = self.api(settings, None)?;
                return Ok((
                    vec![Target {
                        client,
                        tenant: None,
                        unknown_licence: false,
                    }],
                    source,
                ));
            }
            selected => selected,
        };
        let (lister, source) = self.api(settings, None)?;
        let is_portfolio = self.is_portfolio_key.get().unwrap_or(false);
        let portfolio = list_portfolio(&lister, source, is_portfolio)?;
        let tenants = match selected {
            Selection::Tenant(wanted) => {
                let tenant = find(&portfolio, wanted)?;
                eprintln!(
                    "Client tenant: {} ({})",
                    clean(&tenant.slug),
                    clean(&tenant.id)
                );
                vec![tenant]
            }
            _ => {
                // Inactive tenants are skipped on purpose. A tenant whose licence status this
                // version does not know is not read either, but it stays in the list so the walk
                // can report it and fail: nothing is silently missing.
                let idle = portfolio
                    .iter()
                    .filter(|t| t.readability() == Readability::Inactive)
                    .count();
                if idle > 0 {
                    eprintln!(
                        "Skipping {} (see `hodeishield tenants list`).",
                        count(idle, "inactive client tenants")
                    );
                }
                portfolio
                    .into_iter()
                    .filter(|t| t.readability() != Readability::Inactive)
                    .collect()
            }
        };
        let targets = tenants
            .into_iter()
            .map(|tenant| {
                let (client, _) = self.api(settings, Some(&tenant.id))?;
                let unknown_licence = matches!(selected, Selection::All)
                    && tenant.readability() == Readability::Unknown;
                Ok(Target {
                    client,
                    tenant: Some(tenant),
                    unknown_licence,
                })
            })
            .collect::<Result<_>>()?;
        Ok((targets, source))
    }

    /// The one client a single-item command reads.
    pub fn single(&self, settings: &Settings) -> Result<(Client, CredentialSource)> {
        let (mut targets, source) = self.targets(settings)?;
        match (targets.pop(), targets.is_empty()) {
            (Some(target), true) => Ok((target.client, source)),
            _ => Err(
                Failure::general("This command reads one client tenant at a time.")
                    .hint("Use --tenant <slug|id>; --all-tenants works on list commands."),
            ),
        }
    }
}

/// Every client tenant of the portfolio.
fn list_portfolio(
    lister: &Client,
    source: CredentialSource,
    is_portfolio_key: bool,
) -> Result<Vec<Tenant>> {
    let api = ApiContext {
        source,
        framework: None,
        tenant_selected: false,
        is_portfolio_key,
    };
    let mut totals: Vec<i64> = Vec::new();
    let (_, mut tenants) = collect_pages(
        "client tenants",
        &api,
        Some(200),
        100_000,
        &mut |page, per_page| {
            let response = lister.list_tenants(&ListTenantsParams::alphabetical(page, per_page))?;
            totals.push(response.data.pagination.total);
            Ok(response)
        },
        |r: ListTenantsResponse| (r.data, r.pagination),
    )
    .map_err(|failure| {
        if failure.kind == Kind::Forbidden {
            failure.hint(
                "--tenant and --all-tenants need a portfolio credential. Without them the CLI \
                 reads the credential's own tenant.",
            )
        } else {
            failure
        }
    })?;
    // The portfolio can change while it is walked: a tenant may then appear on two pages, or on
    // none. Each tenant is read once, and the change is said out loud.
    if totals.windows(2).any(|pair| pair[0] != pair[1]) {
        eprintln!(
            "warning: the number of client tenants changed while they were listed ({}); a tenant \
             may be missing. Run the command again.",
            totals
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", then ")
        );
    }
    let mut seen = HashSet::new();
    tenants.retain(|tenant| seen.insert(tenant.id.to_ascii_lowercase()));
    Ok(tenants)
}

/// The tenant the user named, by id or slug. One that is not in the portfolio is reported the way
/// the API reports it: not found, with no hint about whether it exists elsewhere.
fn find(portfolio: &[Tenant], wanted: &str) -> Result<Tenant> {
    // An input shaped like a UUID may be an id, but a slug can have that shape too: if it matches
    // an id of one tenant and the slug of another, it is ambiguous, never resolved to one of them.
    let by_id = is_uuid(wanted);
    let mut matches = portfolio.iter().filter(|t| {
        t.slug.eq_ignore_ascii_case(wanted) || (by_id && t.id.eq_ignore_ascii_case(wanted))
    });
    match (matches.next(), matches.next()) {
        (Some(tenant), None) => Ok(tenant.clone()),
        (Some(_), Some(_)) => Err(Failure::general(format!(
            "More than one client tenant is called {}.",
            clean(wanted)
        ))
        .hint("Use its id: see `hodeishield tenants list`.")),
        _ => Err(Failure::new(
            Kind::NotFound,
            format!(
                "No client tenant {} in this credential's portfolio.",
                clean(wanted)
            ),
        )
        .hint("List the client tenants you may read with `hodeishield tenants list`.")),
    }
}

pub fn run(ctx: &Context, command: TenantsCommand, out: &mut dyn Write) -> Result<()> {
    let TenantsCommand::List(args) = command;
    let settings = ctx.settings()?;
    let (client, source) = ctx.api(&settings, None)?;
    let is_portfolio = ctx.is_portfolio_key.get().unwrap_or(false);
    list_one(
        ctx,
        out,
        &args.paging,
        "client tenants",
        ApiContext {
            source,
            framework: None,
            tenant_selected: false,
            is_portfolio_key: is_portfolio,
        },
        &mut |page, per_page| client.list_tenants(&ListTenantsParams::alphabetical(page, per_page)),
        |r| (r.data, r.pagination),
        tenant_rows,
    )
    .map_err(|failure| {
        if failure.kind == Kind::Forbidden {
            failure.hint("Listing client tenants needs a portfolio credential.")
        } else {
            failure
        }
    })
}

fn tenant_rows(items: &[Tenant]) -> Rows {
    Rows::new(
        &[
            "SLUG",
            "NAME",
            "ORGANISATION",
            "TYPE",
            "STATUS",
            "LICENCE",
            "ID",
        ],
        items
            .iter()
            .map(|t| {
                vec![
                    clean(&t.slug),
                    clean(&t.name),
                    clean(&t.organization.name),
                    if t.internal { "own" } else { "client" }.to_owned(),
                    if t.active { "active" } else { "inactive" }.to_owned(),
                    clean(&t.licence_status),
                    clean(&t.id),
                ]
            })
            .collect(),
    )
}
