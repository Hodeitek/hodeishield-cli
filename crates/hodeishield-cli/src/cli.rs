// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Command-line surface.

use crate::filters;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Args, CommandFactory, Parser, Subcommand};
use hodeishield_api::ParseEnumError;
use hodeishield_api::v1::operations;
use hodeishield_api::v1::{
    AlertSort, AlertStatus, BusinessCriticality, ComplianceControlSort, EndpointSort,
    EndpointStatus, EvidenceSort, Order, RiskSort, VendorSort,
};
use std::str::FromStr;

const AFTER_HELP: &str = "\
Credentials:
  HODEISHIELD_API_KEY   A tenant API key. When set, it is used for every API call.
  hodeishield login     Otherwise, sign in to the app; the token is kept in the system keychain.

Exit codes:
  0 ok · 1 error · 2 usage · 3 not authenticated · 4 missing scope · 5 not found
  6 rate limited · 7 API unreachable or failing · 8 tenant licence not in force";

/// Read-only command-line client for HodeiShield.
///
/// Every command reads; nothing here can change data in your organisation.
#[derive(Debug, Parser)]
#[command(name = "hodeishield", version, propagate_version = true, after_help = AFTER_HELP)]
pub struct Cli {
    /// Configuration profile to use.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        env = "HODEISHIELD_PROFILE",
        value_name = "NAME"
    )]
    pub profile: Option<String>,

    /// Base URL of the API, overriding the profile.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        env = "HODEISHIELD_API_URL",
        value_name = "URL"
    )]
    pub api_url: Option<String>,

    /// Print the API's JSON instead of a table.
    #[arg(long, global = true, help_heading = "Global options")]
    pub json: bool,

    /// Log each request (method, URL, status, request id) and each retry to stderr. Never logs
    /// credentials.
    #[arg(short, long, global = true, help_heading = "Global options")]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Third parties in your inventory.
    #[command(subcommand)]
    Vendors(VendorsCommand),
    /// Supply-chain alerts raised against your vendors.
    #[command(subcommand)]
    Alerts(AlertsCommand),
    /// Entries of the risk register.
    #[command(subcommand)]
    Risks(RisksCommand),
    /// Control status and posture per framework.
    #[command(subcommand)]
    Compliance(ComplianceCommand),
    /// Security evidence.
    #[command(subcommand)]
    Evidence(EvidenceCommand),
    /// Enrolled endpoint agents.
    #[command(subcommand)]
    Endpoints(EndpointsCommand),
    /// Sign in to the app (browser, or --device without one).
    #[command(long_about = LOGIN_ABOUT)]
    Login(LoginArgs),
    /// Sign out: revoke the sign-in token and remove it from the keychain.
    Logout,
    /// Show which profile, API and credential are in use.
    Whoami,
    /// Read and change the configuration file.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Print a shell completion script.
    Completions {
        /// The shell to complete for.
        shell: clap_complete::Shell,
    },
}

const LOGIN_ABOUT: &str = "\
Sign in to the HodeiShield app. The token is kept in the system keychain (macOS Keychain, Windows \
Credential Manager, Secret Service on Linux), never in a file, and is refreshed when it expires.

By default a browser window opens and the app redirects back to a one-shot listener on 127.0.0.1. \
With --device, you get a short code to type in on any other device instead.

On the consent screen you choose the one tenant the CLI may read; the token covers only that \
tenant, and only reads. The scopes asked for are the ones the CLI's commands need (see \
`config set oauth_scopes` to ask for fewer). Revoke the access with `hodeishield logout`, or in the \
app under Account → Application access.";

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Sign in with a code approved on another device (RFC 8628), without a local browser.
    #[arg(long)]
    pub device: bool,
    /// Print the sign-in URL instead of opening a browser.
    #[arg(long, conflicts_with = "device")]
    pub no_browser: bool,
}

impl Cli {
    /// Parses the command line. `--csv` declares its conflict with `--json`, but clap does not see
    /// it when the global `--json` comes before the subcommand, so it is checked here too.
    pub fn parse_checked() -> Self {
        let cli = Self::parse();
        if cli.json && cli.command.paging().is_some_and(|paging| paging.csv) {
            Self::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "the argument '--json' cannot be used with '--csv'",
                )
                .exit();
        }
        cli
    }
}

impl Command {
    /// The paging options, for the commands that list.
    fn paging(&self) -> Option<&Paging> {
        match self {
            Self::Vendors(VendorsCommand::List(list)) => Some(&list.paging),
            Self::Alerts(AlertsCommand::List(list)) => Some(&list.paging),
            Self::Risks(RisksCommand::List(list)) => Some(&list.paging),
            Self::Compliance(ComplianceCommand::Controls(list)) => Some(&list.paging),
            Self::Evidence(EvidenceCommand::List(list)) => Some(&list.paging),
            Self::Endpoints(EndpointsCommand::List(list)) => Some(&list.paging),
            _ => None,
        }
    }
}

/// Paging shared by every list.
#[derive(Debug, Args)]
pub struct Paging {
    /// Page to fetch, from 1.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..), conflicts_with = "all")]
    pub page: Option<i64>,
    /// Items per page, 1 to 200.
    #[arg(long, value_parser = clap::value_parser!(i64).range(1..=200))]
    pub per_page: Option<i64>,
    /// Fetch every page, up to 100000 items. With --json, prints one JSON array of all items.
    #[arg(long)]
    pub all: bool,
    /// Sort direction.
    #[arg(long, value_parser = choice::<Order>(Order::VALUES))]
    pub order: Option<Order>,
    /// Print the items as CSV (RFC 4180) instead of a table. Works with --all.
    #[arg(long, conflicts_with = "json")]
    pub csv: bool,
}

/// A clap parser that accepts exactly the values the OpenAPI document lists.
fn choice<T>(values: &'static [&'static str]) -> impl TypedValueParser<Value = T>
where
    T: FromStr<Err = ParseEnumError> + Clone + Send + Sync + 'static,
{
    PossibleValuesParser::new(values).try_map(|value| T::from_str(&value))
}

#[derive(Debug, Subcommand)]
pub enum VendorsCommand {
    /// List vendors.
    List(VendorsList),
    /// Show one vendor.
    Get {
        /// Vendor id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct VendorsList {
    /// Case-insensitive search in the name or domain.
    #[arg(long, short)]
    pub query: Option<String>,
    /// Exact category.
    #[arg(long)]
    pub category: Option<String>,
    /// Only active (true) or inactive (false) vendors.
    #[arg(long)]
    pub active: Option<bool>,
    /// Exact business criticality.
    #[arg(long, value_parser = choice::<BusinessCriticality>(BusinessCriticality::VALUES))]
    pub criticality: Option<BusinessCriticality>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<VendorSort>(VendorSort::VALUES))]
    pub sort: Option<VendorSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum AlertsCommand {
    /// List alerts.
    List(AlertsList),
    /// Show one alert.
    Get {
        /// Alert id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct AlertsList {
    /// Only alerts in this state.
    #[arg(long, value_parser = choice::<AlertStatus>(AlertStatus::VALUES))]
    pub status: Option<AlertStatus>,
    /// Exact severity.
    #[arg(long, help = filters::help("Exact severity.", &operations::LIST_ALERTS, "severity"))]
    pub severity: Option<String>,
    /// Only alerts about this vendor id.
    #[arg(long)]
    pub vendor: Option<String>,
    /// Only alerts created at or after this RFC 3339 instant, e.g. 2026-01-31T00:00:00Z.
    #[arg(long, value_name = "INSTANT")]
    pub since: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<AlertSort>(AlertSort::VALUES))]
    pub sort: Option<AlertSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum RisksCommand {
    /// List risk-register entries.
    List(RisksList),
    /// Show one risk-register entry.
    Get {
        /// Risk id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct RisksList {
    /// Exact status.
    #[arg(long, help = filters::help("Exact status.", &operations::LIST_RISKS, "status"))]
    pub status: Option<String>,
    /// Exact risk domain.
    #[arg(long, help = filters::help("Exact risk domain.", &operations::LIST_RISKS, "domain"))]
    pub domain: Option<String>,
    /// Only risks linked to this vendor id.
    #[arg(long)]
    pub vendor: Option<String>,
    /// Only risks with at least this inherent score.
    #[arg(long, value_name = "SCORE")]
    pub min_inherent_score: Option<i64>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<RiskSort>(RiskSort::VALUES))]
    pub sort: Option<RiskSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum ComplianceCommand {
    /// List the status of each control of a framework.
    Controls(ControlsList),
    /// Show the posture summary of a framework.
    Posture {
        /// Framework slug, e.g. nis2, ens, iso27001, dora.
        framework: String,
    },
}

#[derive(Debug, Args)]
pub struct ControlsList {
    /// Framework slug, e.g. nis2, ens, iso27001, dora.
    #[arg(long, short)]
    pub framework: String,
    /// Exact control status.
    #[arg(
        long,
        help = filters::help("Exact control status.", &operations::LIST_COMPLIANCE_CONTROLS, "status")
    )]
    pub status: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<ComplianceControlSort>(ComplianceControlSort::VALUES))]
    pub sort: Option<ComplianceControlSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// List evidence.
    List(EvidenceList),
    /// Show one evidence item.
    Get {
        /// Evidence id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct EvidenceList {
    /// Exact evidence type.
    #[arg(long = "type", value_name = "TYPE")]
    pub evidence_type: Option<String>,
    /// Exact source type.
    #[arg(long)]
    pub source_type: Option<String>,
    /// Only evidence about this vendor id.
    #[arg(long)]
    pub vendor: Option<String>,
    /// Only evidence that stops being valid before this RFC 3339 instant.
    #[arg(long, value_name = "INSTANT")]
    pub expiring_before: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<EvidenceSort>(EvidenceSort::VALUES))]
    pub sort: Option<EvidenceSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum EndpointsCommand {
    /// List enrolled endpoint agents.
    List(EndpointsList),
}

#[derive(Debug, Args)]
pub struct EndpointsList {
    /// Only agents in this state.
    #[arg(long, value_parser = choice::<EndpointStatus>(EndpointStatus::VALUES))]
    pub status: Option<EndpointStatus>,
    /// Only agents not seen since this RFC 3339 instant.
    #[arg(long, value_name = "INSTANT")]
    pub silent_since: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<EndpointSort>(EndpointSort::VALUES))]
    pub sort: Option<EndpointSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the path of the configuration file.
    Path,
    /// Show the settings in effect for the profile.
    Show,
    /// Set a key of the profile: api_url, app_url, oauth_client_id, oauth_scopes.
    Set {
        /// The key to set.
        #[arg(value_parser = PossibleValuesParser::new(crate::config::KEYS))]
        key: String,
        /// The value. For oauth_scopes, a space-separated list.
        value: String,
    },
    /// Remove a key from the profile, going back to the default.
    Unset {
        /// The key to remove.
        #[arg(value_parser = PossibleValuesParser::new(crate::config::KEYS))]
        key: String,
    },
    /// Make a profile the default one.
    Use {
        /// The profile name.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn enum_flags_accept_only_documented_values() {
        let cli = Cli::try_parse_from([
            "hodeishield",
            "vendors",
            "list",
            "--sort",
            "name",
            "--order",
            "asc",
        ])
        .expect("valid");
        match cli.command {
            Command::Vendors(VendorsCommand::List(list)) => {
                assert_eq!(list.sort, Some(VendorSort::Name));
                assert_eq!(list.paging.order, Some(Order::Asc));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["hodeishield", "vendors", "list", "--sort", "bogus"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["hodeishield", "vendors", "list", "--per-page", "201"]).is_err()
        );
    }
}
