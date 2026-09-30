// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Command dispatch and what every command shares.

mod config;
mod resources;
mod session;

use crate::auth::{self, TokenStore};
use crate::cli::{Cli, Command};
use crate::config::{Overrides, Settings};
use crate::failure::{ApiContext, CredentialSource, Result, from_api};
use hodeishield_api::Client;
use std::io::Write;
use std::sync::Arc;

pub struct Context {
    pub overrides: Overrides,
    pub json: bool,
    pub verbose: bool,
    pub store: Arc<dyn TokenStore + Send + Sync>,
}

impl Context {
    pub fn settings(&self) -> Result<Settings> {
        crate::config::resolve(&self.overrides)
    }

    /// A `/v1` client with the credential in effect.
    pub fn api(&self, settings: &Settings) -> Result<(Client, CredentialSource)> {
        let (credential, source) = auth::credential_for_api(settings, self.store.as_ref())?;
        let mut builder =
            Client::builder(settings.api_url.clone(), credential).user_agent(crate::USER_AGENT);
        if source == CredentialSource::OAuth {
            let (settings, store) = (settings.clone(), Arc::clone(&self.store));
            builder = builder.renew_credential(move || auth::renew(&settings, store.as_ref()));
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
        }
        let client = builder.build().map_err(|e| {
            from_api(
                e,
                &ApiContext {
                    source,
                    framework: None,
                },
            )
        })?;
        Ok((client, source))
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
        store: Arc::new(auth::store::Keychain),
    };
    match cli.command {
        Command::Vendors(command) => resources::vendors(&ctx, command, out),
        Command::Alerts(command) => resources::alerts(&ctx, command, out),
        Command::Risks(command) => resources::risks(&ctx, command, out),
        Command::Compliance(command) => resources::compliance(&ctx, command, out),
        Command::Evidence(command) => resources::evidence(&ctx, command, out),
        Command::Endpoints(command) => resources::endpoints(&ctx, command, out),
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
