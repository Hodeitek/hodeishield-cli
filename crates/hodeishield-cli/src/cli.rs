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
    EndpointStatus, EvidenceSort, Format, Locale, Order, ReportSort, RiskSort, VendorSort,
};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;

const AFTER_HELP: &str = "\
Credentials:
  HODEISHIELD_API_KEY   A tenant API key, or an MSSP portfolio key (hsp_…). When set, it is used for every API call.
  hodeishield login     Otherwise, sign in to the app; the token is kept in the system keychain
                        (or, only if you opt in, in a plain-text file).

Several client tenants (portfolio credential):
  hodeishield tenants list                       The client tenants you may read.
  hodeishield --tenant <slug|id> vendors list    One client.
  hodeishield --all-tenants vendors list         Every client, with a tenant column.

Exit codes:
  0 ok · 1 error · 2 usage · 3 not authenticated · 4 missing scope · 5 not found
  6 rate limited · 7 API unreachable, failing or without portfolio access · 8 tenant licence not in force";

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

    /// Read this client tenant (its slug or id) instead of the credential's own. Needs a
    /// portfolio credential; see `hodeishield tenants list`.
    #[arg(
        long,
        global = true,
        help_heading = "Client selection (MSSP)",
        value_name = "SLUG|ID",
        conflicts_with = "all_tenants"
    )]
    pub tenant: Option<String>,

    /// On a list command, read every client tenant of the portfolio and add a tenant column (or
    /// `tenant_*` fields) to each row. Fetches every page of each tenant.
    #[arg(
        long,
        global = true,
        help_heading = "Client selection (MSSP)",
        conflicts_with = "tenant"
    )]
    pub all_tenants: bool,

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
    /// Reports generated for the tenant, and their files.
    #[command(subcommand)]
    Reports(ReportsCommand),
    /// Client tenants a portfolio (MSSP) credential may read.
    #[command(subcommand)]
    Tenants(TenantsCommand),
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
Credential Manager, Secret Service on Linux) and is refreshed when it expires. Only if you opt in \
with HODEISHIELD_TOKEN_STORE=plaintext-file (Linux and macOS), it is kept instead in a file in your \
state directory, unencrypted and readable only by you. The CLI never switches between the two on \
its own.

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
        if let Some(message) = cli.selection_error() {
            Self::command()
                .error(clap::error::ErrorKind::ArgumentConflict, message)
                .exit();
        }
        if cli.command.downloads_to_stdout() && std::io::stdout().is_terminal() {
            Self::command()
                .error(
                    clap::error::ErrorKind::InvalidValue,
                    "'--output -' writes the file to standard output, which is a terminal here; \
                     redirect it to a file or a pipe, or give a path",
                )
                .exit();
        }
        cli
    }

    /// Why the client selection cannot go with this command, if it cannot. It is refused rather
    /// than ignored: a command that does not read the selected client must not look as if it did.
    fn selection_error(&self) -> Option<&'static str> {
        if self.tenant.is_some() && self.all_tenants {
            return Some("the argument '--tenant' cannot be used with '--all-tenants'");
        }
        if self.tenant.is_none() && !self.all_tenants {
            return None;
        }
        if !self.command.reads_tenant_data() {
            return Some(
                "'--tenant' and '--all-tenants' only apply to the commands that read tenant data",
            );
        }
        if self.all_tenants {
            match self.command.paging() {
                None => {
                    return Some(
                        "'--all-tenants' applies to list commands; use '--tenant' to read one \
                         client",
                    );
                }
                Some(paging) if paging.page.is_some() => {
                    return Some(
                        "the argument '--all-tenants' cannot be used with '--page': it fetches \
                         every page of each tenant",
                    );
                }
                Some(_) => {}
            }
        }
        None
    }
}

impl Cli {
    /// Whether this invocation prints something a program reads: `--json`, `--csv` or the
    /// completion script. Nothing but that output may be added to such a run.
    #[must_use]
    pub(crate) fn prints_for_programs(&self) -> bool {
        self.json
            || matches!(self.command, Command::Completions { .. })
            || self.command.paging().is_some_and(|paging| paging.csv)
            || self.command.downloads_to_stdout()
    }
}

impl Command {
    /// The commands that read a tenant's data, and so can read a selected client's.
    fn reads_tenant_data(&self) -> bool {
        matches!(
            self,
            Self::Vendors(_)
                | Self::Alerts(_)
                | Self::Risks(_)
                | Self::Compliance(_)
                | Self::Evidence(_)
                | Self::Endpoints(_)
                | Self::Reports(_)
        )
    }

    /// Whether this is a download whose file goes to standard output (`--output -`).
    fn downloads_to_stdout(&self) -> bool {
        matches!(self, Self::Reports(ReportsCommand::Download(download)) if download.to_stdout())
    }

    /// The paging options, for the commands that list.
    fn paging(&self) -> Option<&Paging> {
        match self {
            Self::Vendors(VendorsCommand::List(list)) => Some(&list.paging),
            Self::Alerts(AlertsCommand::List(list)) => Some(&list.paging),
            Self::Risks(RisksCommand::List(list)) => Some(&list.paging),
            Self::Compliance(ComplianceCommand::Controls(list)) => Some(&list.paging),
            Self::Evidence(EvidenceCommand::List(list)) => Some(&list.paging),
            Self::Endpoints(EndpointsCommand::List(list)) => Some(&list.paging),
            Self::Reports(ReportsCommand::List(list)) => Some(&list.paging),
            Self::Tenants(TenantsCommand::List(list)) => Some(&list.paging),
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
pub enum TenantsCommand {
    /// List the client tenants this credential may read.
    List(TenantsList),
}

#[derive(Debug, Args)]
pub struct TenantsList {
    #[command(flatten)]
    pub paging: Paging,
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
pub enum ReportsCommand {
    /// List generated reports, newest first.
    List(ReportsList),
    /// Show one report, with the formats it can be downloaded in.
    Get {
        /// Report id.
        id: String,
    },
    /// Download a report's file (PDF or XLSX).
    #[command(long_about = DOWNLOAD_ABOUT)]
    Download(ReportsDownload),
}

const DOWNLOAD_ABOUT: &str = "\
Download a report's file (PDF or XLSX). Only a completed report has one; `reports get` lists the \
formats it can be downloaded in.

By default the file is saved in the current directory under the name the API suggests, reduced to \
letters, digits, `.`, `_` and `-` (or report-<id>.<format> when nothing usable is left). An existing \
file is never replaced without --force, and the file appears in full or not at all.";

#[derive(Debug, Args)]
pub struct ReportsList {
    /// Exact report type.
    #[arg(
        long = "type",
        visible_alias = "report-type",
        value_name = "TYPE",
        help = filters::help("Exact report type.", &operations::LIST_REPORTS, "report_type")
    )]
    pub report_type: Option<String>,
    /// Exact status.
    #[arg(long, help = filters::help("Exact status.", &operations::LIST_REPORTS, "status"))]
    pub status: Option<String>,
    /// Only reports created at or after this RFC 3339 instant, e.g. 2026-01-31T00:00:00Z.
    #[arg(long, value_name = "INSTANT")]
    pub since: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<ReportSort>(ReportSort::VALUES))]
    pub sort: Option<ReportSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Args)]
pub struct ReportsDownload {
    /// Report id.
    pub id: String,
    /// File format; the API sends pdf when it is not given.
    #[arg(long, value_parser = choice::<Format>(Format::VALUES))]
    pub format: Option<Format>,
    /// Language of the file; the API uses en when it is not given.
    #[arg(long, value_parser = choice::<Locale>(Locale::VALUES))]
    pub locale: Option<Locale>,
    /// Where to save the file: a file path, a directory to save it in under the suggested name, or
    /// `-` for standard output (not a terminal).
    #[arg(long, short, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Replace the file if it exists.
    #[arg(long)]
    pub force: bool,
}

impl ReportsDownload {
    /// Whether the file goes to standard output (`--output -`).
    pub fn to_stdout(&self) -> bool {
        self.output.as_deref() == Some(std::path::Path::new("-"))
    }
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the path of the configuration file.
    Path,
    /// Show the settings in effect for the profile.
    Show,
    /// Set a key: api_url, app_url, oauth_client_id, oauth_scopes (per profile), update_check, token_store (global).
    Set {
        /// The key to set.
        #[arg(value_parser = PossibleValuesParser::new(crate::config::KEYS))]
        key: String,
        /// The value. For oauth_scopes, a space-separated list; update_check takes true or false; token_store takes keychain or plaintext-file.
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
