// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Command dispatch and what every command shares.

mod config;
mod resources;
mod save;
mod session;
mod tenants;

use crate::auth::{self, TokenStore};
use crate::cli::{Cli, Command};
use crate::config::{Overrides, Settings};
use crate::failure::{ApiContext, CredentialSource, Result, from_api};
use hodeishield_api::Client;
use std::cell::Cell;
use std::io::Write;
use std::sync::Arc;
use tenants::Selection;

pub struct Context {
    pub overrides: Overrides,
    pub json: bool,
    pub verbose: bool,
    pub selection: Selection,
    pub store: Arc<dyn TokenStore + Send + Sync>,
    /// Cached information about whether the credential is a portfolio key, set on first API call.
    is_portfolio_key: Cell<Option<bool>>,
}

impl Context {
    pub fn settings(&self) -> Result<Settings> {
        crate::config::resolve(&self.overrides)
    }

    /// A `/v1` client with the credential in effect, reading `tenant` (a client tenant's id) when
    /// one is given and the credential's own tenant otherwise.
    pub fn api(
        &self,
        settings: &Settings,
        tenant: Option<&str>,
    ) -> Result<(Client, CredentialSource)> {
        let (credential, source) = auth::credential_for_api(settings, self.store.as_ref())?;
        let is_portfolio =
            source == CredentialSource::ApiKey && auth::is_portfolio_key(&credential);
        self.is_portfolio_key.set(Some(is_portfolio));
        let mut builder =
            Client::builder(settings.api_url.clone(), credential).user_agent(crate::USER_AGENT);
        if source == CredentialSource::OAuth {
            let (settings, store) = (settings.clone(), Arc::clone(&self.store));
            builder = builder.renew_credential(move || auth::renew(&settings, store.as_ref()));
        }
        if let Some(tenant) = tenant {
            builder = builder.tenant(tenant).map_err(|e| {
                from_api(
                    e,
                    &ApiContext {
                        source,
                        framework: None,
                        tenant_selected: true,
                        is_portfolio_key: is_portfolio,
                    },
                )
            })?;
        }
        if self.verbose {
            builder = builder.observer(|event| {
                eprintln!(
                    "{} {} → {} ({} ms{})",
                    event.method,
                    event.url,
                    event.status,
                    event.elapsed.as_millis(),
                    event
                        .request_id
                        .map_or_else(String::new, |id| format!(", request id {id}"))
                );
            });
            builder = builder.retry_observer(|event| {
                eprintln!(
                    "retrying GET {} in {} ms ({}, retry {})",
                    event.url,
                    event.wait.as_millis(),
                    event.reason,
                    event.attempt,
                );
            });
        }
        let client = builder.build().map_err(|e| {
            from_api(
                e,
                &ApiContext {
                    source,
                    framework: None,
                    tenant_selected: tenant.is_some(),
                    is_portfolio_key: is_portfolio,
                },
            )
        })?;
        Ok((client, source))
    }

    /// What a failure message needs to know about a call made with this context's selection.
    pub fn call<'a>(&self, source: CredentialSource, framework: Option<&'a str>) -> ApiContext<'a> {
        ApiContext {
            source,
            framework,
            tenant_selected: !matches!(self.selection, Selection::Own),
            is_portfolio_key: self.is_portfolio_key.get().unwrap_or(false),
        }
    }
}

pub fn run(cli: Cli, out: &mut dyn Write) -> Result<()> {
    let ctx = Context {
        overrides: Overrides {
            profile: cli.profile,
            api_url: cli.api_url,
        },
        json: cli.json,
        verbose: cli.verbose,
        selection: match (cli.tenant, cli.all_tenants) {
            (Some(tenant), _) => Selection::Tenant(tenant),
            (None, true) => Selection::All,
            (None, false) => Selection::Own,
        },
        store: Arc::new(auth::store::Configured::default()),
        is_portfolio_key: Cell::new(None),
    };
    match cli.command {
        Command::Vendors(command) => resources::vendors(&ctx, command, out),
        Command::Alerts(command) => resources::alerts(&ctx, command, out),
        Command::Risks(command) => resources::risks(&ctx, command, out),
        Command::Compliance(command) => resources::compliance(&ctx, command, out),
        Command::Evidence(command) => resources::evidence(&ctx, command, out),
        Command::Endpoints(command) => resources::endpoints(&ctx, command, out),
        Command::Reports(command) => resources::reports(&ctx, command, out),
        Command::Tenants(command) => tenants::run(&ctx, command, out),
        Command::Login(args) => session::login(&ctx, &args),
        Command::Logout => session::logout(&ctx),
        Command::Whoami => session::whoami(&ctx, out),
        Command::Config(command) => config::run(&ctx, command, out),
        Command::Completions { shell } => {
            let mut command = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(shell, &mut command, "hodeishield", out);
            Ok(())
        }
    }
}
