// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Command-line surface.

use crate::filters;
use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::{Args, CommandFactory, Parser, Subcommand};
use hodeishield_api::ParseEnumError;
use hodeishield_api::v1::Class as ActClass;
use hodeishield_api::v1::operations;
use hodeishield_api::v1::{
    AiSystemSort, AlertSort, AlertStatus, BusinessCriticality, ChangeCategory, ChangeSort,
    ChangeStatus, ChangeType, ComplianceControlSort, EndpointSort, EndpointStatus, EvidenceSort,
    Format, IncidentSort, Locale, Order, PendingActProposalSort, ReportSort, RiskSort, VendorSort,
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

Changing data (the only commands that write):
  hodeishield alerts acknowledge <id>             Mark an open alert as taken.
  hodeishield alerts resolve <id> --reason TEXT   Close an alert, with the reason.
  hodeishield risks transition <id> --to STATUS   Move a risk along its lifecycle.
  These need HODEISHIELD_API_KEY with the `alerts:write` or `risks:write` scope. A sign-in cannot
  write them.

Deciding proposals (needs a sign-in, never an API key):
  hodeishield login --decide                      Sign in with permission to decide; it asks you to
                                                  confirm your identity again.
  hodeishield approvals list                      The proposals you may approve.
  hodeishield approvals approve <id> --reason TEXT   Record your approval. It does not carry the
                                                  action out: the service does that later.
  hodeishield approvals reject <id> --reason TEXT    Reject a proposal, with the reason.
  Decisions need a sign-in confirmed in the last 15 minutes.

Every command that changes data or decides asks you to confirm first (--yes skips the question;
without a terminal and without --yes it refuses and sends nothing).

Exit codes:
  0 ok · 1 error · 2 usage · 3 not authenticated · 4 missing scope · 5 not found
  6 rate limited · 7 API unreachable, failing or without portfolio access · 8 tenant licence not in force";

/// Command-line client for HodeiShield.
///
/// Every command reads, except those that change an alert (`alerts acknowledge`, `alerts resolve`)
/// or a risk (`risks transition`), which need an API key with the `alerts:write` or `risks:write`
/// scope, and the decisions on proposals (`approvals approve`, `approvals reject`), which need a
/// sign-in made with `hodeishield login --decide`. Each asks for confirmation (or `--yes`) before
/// it writes.
#[derive(Debug, Parser)]
#[command(name = "hodeishield", version, propagate_version = true, after_help = AFTER_HELP)]
pub struct Cli {
    /// Configuration profile to use. [env: HODEISHIELD_PROFILE]
    // Read from the environment in `commands::run`, not by clap: clap would list the flag in every
    // usage line while the variable is set.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        value_name = "NAME"
    )]
    pub profile: Option<String>,

    /// Base URL of the API, overriding the profile. [env: HODEISHIELD_API_URL]
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
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
    /// Entries of the incident register, with their notification deadlines.
    #[command(subcommand)]
    Incidents(IncidentsCommand),
    /// Entries of the AI system register.
    #[command(name = "ai-systems", subcommand)]
    AiSystems(AiSystemsCommand),
    /// Proposals waiting for a person's decision: list, approve, reject.
    #[command(subcommand)]
    Approvals(ApprovalsCommand),
    /// Change requests of the change-management register.
    #[command(subcommand)]
    Changes(ChangesCommand),
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
app under Account → Applications.

With --decide the sign-in also asks for permission to see and decide the proposals waiting for \
approval (`hodeishield approvals`). A plain login never asks for it. The sign-in asks you to \
confirm your identity again (your second factor or password), and decisions work only for 15 \
minutes after that confirmation: refreshing the sign-in does not extend it, so run `login --decide` \
again when it lapses. If the server does not grant the permission (decisions can be switched off), \
the command says so and exits 4.";

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Sign in with a code approved on another device (RFC 8628), without a local browser.
    #[arg(long)]
    pub device: bool,
    /// Print the sign-in URL instead of opening a browser.
    #[arg(long, conflicts_with = "device")]
    pub no_browser: bool,
    /// Also ask for permission to see and decide proposals waiting for approval (`approvals`).
    /// The sign-in asks you to confirm your identity again.
    #[arg(long)]
    pub decide: bool,
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
        if let Some((kind, message)) = cli.command.framework_error() {
            Self::command().error(kind, message).exit();
        }
        if cli.command.asks_confirmation() && !std::io::stdin().is_terminal() {
            Self::command()
                .error(
                    clap::error::ErrorKind::InvalidValue,
                    "refusing to change data or decide without confirmation: standard input is not a \
                     terminal, so there is nobody to ask; pass --yes to confirm",
                )
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
                | Self::Incidents(_)
                | Self::AiSystems(_)
                | Self::Changes(_)
                | Self::Compliance(_)
                | Self::Evidence(_)
                | Self::Endpoints(_)
                | Self::Reports(_)
        )
    }

    /// Whether this is a write that has to ask before it changes anything (no `--yes`).
    fn asks_confirmation(&self) -> bool {
        match self {
            Self::Alerts(AlertsCommand::Acknowledge(args)) => !args.confirm.yes,
            Self::Alerts(AlertsCommand::Resolve(args)) => !args.confirm.yes,
            Self::Risks(RisksCommand::Transition(args)) => !args.confirm.yes,
            Self::Approvals(ApprovalsCommand::Approve(args) | ApprovalsCommand::Reject(args)) => {
                !args.confirm.yes
            }
            _ => false,
        }
    }

    /// Whether this is a download whose file goes to standard output (`--output -`).
    fn downloads_to_stdout(&self) -> bool {
        matches!(self, Self::Reports(ReportsCommand::Download(download)) if download.to_stdout())
    }

    /// The usage error of a compliance command whose framework is missing or given twice differently.
    fn framework_error(&self) -> Option<(clap::error::ErrorKind, String)> {
        match self {
            Self::Compliance(ComplianceCommand::Controls(list)) => list.framework.check().err(),
            Self::Compliance(ComplianceCommand::Posture(args)) => args.framework.check().err(),
            _ => None,
        }
    }

    /// The paging options, for the commands that list.
    fn paging(&self) -> Option<&Paging> {
        match self {
            Self::Vendors(VendorsCommand::List(list)) => Some(&list.paging),
            Self::Alerts(AlertsCommand::List(list)) => Some(&list.paging),
            Self::Risks(RisksCommand::List(list)) => Some(&list.paging),
            Self::Incidents(IncidentsCommand::List(list)) => Some(&list.paging),
            Self::AiSystems(AiSystemsCommand::List(list)) => Some(&list.paging),
            Self::Changes(ChangesCommand::List(list)) => Some(&list.paging),
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
    /// Mark an open alert as taken. Writes: asks for confirmation, needs an API key.
    #[command(long_about = ACKNOWLEDGE_ABOUT)]
    Acknowledge(AlertAcknowledge),
    /// Close an alert, with the reason. Writes: asks for confirmation, needs an API key.
    #[command(long_about = RESOLVE_ABOUT)]
    Resolve(AlertResolve),
}

const ACKNOWLEDGE_ABOUT: &str = "\
Mark an open alert as taken (\"someone is on it\"). It stays unresolved. Repeating it on an alert \
that is already acknowledged changes nothing.

This command writes. It first shows the alert (its title, severity and status) and the change, and \
asks you to confirm; --yes skips the question. With no terminal on standard input and no --yes it \
refuses and sends nothing.

It needs HODEISHIELD_API_KEY: a tenant API key, or an MSSP portfolio key (with --tenant), that holds \
the `alerts:write` scope. A sign-in made with `hodeishield login` cannot write. The key acts with \
the role of the user who created it, and every change is written to the tenant's audit trail.";

const RESOLVE_ABOUT: &str = "\
Close an alert, with the reason why (2 to 500 characters, kept in the audit trail). Repeating it on \
an alert that is already resolved changes nothing, and the first reason stays.

This command writes. It first shows the alert (its title, severity and status) and the change, and \
asks you to confirm; --yes skips the question. With no terminal on standard input and no --yes it \
refuses and sends nothing.

It needs HODEISHIELD_API_KEY: a tenant API key, or an MSSP portfolio key (with --tenant), that holds \
the `alerts:write` scope. A sign-in made with `hodeishield login` cannot write. The key acts with \
the role of the user who created it; an MSSP analyst's key closes medium and low alerts only.";

/// The confirmation every write asks for.
#[derive(Debug, Args)]
pub struct Confirm {
    /// Do not ask for confirmation: go ahead straight away. Needed when standard input is not a
    /// terminal.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct AlertAcknowledge {
    /// Alert id.
    pub id: String,
    /// Why, kept in the audit trail (at most 500 characters).
    #[arg(long, value_name = "TEXT", value_parser = acknowledge_reason)]
    pub reason: Option<String>,
    #[command(flatten)]
    pub confirm: Confirm,
}

#[derive(Debug, Args)]
pub struct AlertResolve {
    /// Alert id.
    pub id: String,
    /// Why the alert is closed: 2 to 500 characters, kept in the audit trail.
    #[arg(long, required = true, value_name = "TEXT", value_parser = resolve_reason)]
    pub reason: String,
    #[command(flatten)]
    pub confirm: Confirm,
}

/// The longest reason the API takes.
const REASON_MAX_CHARS: usize = 500;

fn acknowledge_reason(text: &str) -> Result<String, String> {
    if text.chars().count() > REASON_MAX_CHARS {
        return Err(format!("at most {REASON_MAX_CHARS} characters"));
    }
    Ok(text.to_owned())
}

fn resolve_reason(text: &str) -> Result<String, String> {
    if text.chars().filter(|c| !c.is_whitespace()).count() < 2 {
        return Err("at least two characters that are not blank".to_owned());
    }
    acknowledge_reason(text)
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
    /// Move a risk to another lifecycle status. Writes: asks for confirmation, needs an API key.
    #[command(long_about = TRANSITION_ABOUT)]
    Transition(RiskTransition),
}

const TRANSITION_ABOUT: &str = "\
Move a risk-register entry to another lifecycle status, with an optional note. The lifecycle allows \
identified -> assessed -> treatment_planned -> treatment_implemented -> closed, and closed -> \
assessed; any other move is refused and nothing changes. Asking for the status the entry already \
has changes nothing.

This command writes. It first shows the risk (its title and status) and the change, and asks you to \
confirm; --yes skips the question. With no terminal on standard input and no --yes it refuses and \
sends nothing.

It needs HODEISHIELD_API_KEY: a tenant API key, or an MSSP portfolio key (with --tenant), that holds \
the `risks:write` scope. A sign-in made with `hodeishield login` cannot write. The key acts with the \
role of the user who created it; only an administrator role of the tenant may move a risk. Every \
change is written to the risk's history and to the tenant's audit trail.";

/// The statuses a risk can be moved to, as the API document lists them.
const RISK_STATUSES: &[&str] = &[
    "identified",
    "assessed",
    "treatment_planned",
    "treatment_implemented",
    "closed",
];

#[derive(Debug, Args)]
pub struct RiskTransition {
    /// Risk id.
    pub id: String,
    /// The status to move the risk to.
    #[arg(long = "to", value_name = "STATUS", required = true, value_parser = PossibleValuesParser::new(RISK_STATUSES))]
    pub to_status: String,
    /// Why, kept in the risk's history and the audit trail (at most 2000 characters).
    #[arg(long, value_name = "TEXT", value_parser = risk_note)]
    pub note: Option<String>,
    #[command(flatten)]
    pub confirm: Confirm,
}

fn risk_note(text: &str) -> Result<String, String> {
    if text.chars().count() > 2000 {
        return Err("at most 2000 characters".to_owned());
    }
    Ok(text.to_owned())
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// List the proposals waiting for you to decide. Needs `login --decide`.
    #[command(long_about = APPROVALS_LIST_ABOUT)]
    List(ApprovalsList),
    /// Record your approval of a proposal. It does not carry the action out. Needs `login --decide`.
    #[command(long_about = APPROVE_ABOUT)]
    Approve(ApprovalDecision),
    /// Reject a proposal, with the reason. Needs `login --decide`.
    #[command(long_about = REJECT_ABOUT)]
    Reject(ApprovalDecision),
}

const APPROVALS_LIST_ABOUT: &str = "\
List the proposals of the tenant that you may approve and that are still waiting for a decision, \
the one that expires first on top. The server decides what is listed: a proposal you could not \
approve is not shown. `proposed by you` says the proposal was made for you. With --json you get \
what each proposal would write (its payload) and why it was proposed.

Needs a sign-in made with `hodeishield login --decide`, confirmed in the last 15 minutes; an API \
key cannot decide.";

const APPROVE_ABOUT: &str = "\
Record your approval of one proposal. This only records the approval: it does not carry the \
action out. The service carries it out later, with its own checks, and only before the approval \
lapses (15 minutes).

This command decides. It first shows the proposal from your list (what it would write and why it \
was proposed) and asks you to confirm; --yes skips the question. With no terminal on standard input \
and no --yes it refuses and sends nothing.

Needs a sign-in made with `hodeishield login --decide`, confirmed in the last 15 minutes (refreshing \
it does not extend that); an API key cannot decide. The decision is written to the tenant's audit \
trail with your name and the reason.";

const REJECT_ABOUT: &str = "\
Reject one proposal, with the reason why. Nothing is carried out.

This command decides. It first shows the proposal when it is in your list and asks you to confirm; \
--yes skips the question. With no terminal on standard input and no --yes it refuses and sends \
nothing.

Needs a sign-in made with `hodeishield login --decide`, confirmed in the last 15 minutes (refreshing \
it does not extend that); an API key cannot decide. The decision is written to the tenant's audit \
trail with your name and the reason.";

#[derive(Debug, Args)]
pub struct ApprovalsList {
    /// Only proposals of this action class.
    #[arg(long, value_parser = choice::<ActClass>(ActClass::VALUES))]
    pub class: Option<ActClass>,
    /// Only proposals whose action class needs this module.
    #[arg(long)]
    pub module: Option<String>,
    /// Only proposals that stop being decidable before this instant (RFC 3339).
    #[arg(long, value_name = "WHEN")]
    pub expires_before: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<PendingActProposalSort>(PendingActProposalSort::VALUES))]
    pub sort: Option<PendingActProposalSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Args)]
pub struct ApprovalDecision {
    /// Proposal id, from `approvals list`.
    pub id: String,
    /// Why: 1 to 1000 characters, kept in the audit trail.
    #[arg(long, required = true, value_name = "TEXT", value_parser = decision_reason)]
    pub reason: String,
    #[command(flatten)]
    pub confirm: Confirm,
}

fn decision_reason(text: &str) -> Result<String, String> {
    if text.trim().is_empty() {
        return Err("a reason is required".to_owned());
    }
    if text.chars().count() > 1000 {
        return Err("at most 1000 characters".to_owned());
    }
    Ok(text.to_owned())
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
pub enum IncidentsCommand {
    /// List incidents, with their regulatory notification deadlines.
    List(IncidentsList),
    /// Show one incident, with its notification deadlines.
    Get {
        /// Incident id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct IncidentsList {
    /// Exact status.
    #[arg(long, help = filters::help("Exact status.", &operations::LIST_INCIDENTS, "status"))]
    pub status: Option<String>,
    /// Exact severity.
    #[arg(long, help = filters::help("Exact severity.", &operations::LIST_INCIDENTS, "severity"))]
    pub severity: Option<String>,
    /// Exact incident type.
    #[arg(long = "type", value_name = "TYPE", help = filters::help("Exact incident type.", &operations::LIST_INCIDENTS, "type"))]
    pub incident_type: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<IncidentSort>(IncidentSort::VALUES))]
    pub sort: Option<IncidentSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum AiSystemsCommand {
    /// List AI systems of the register.
    List(AiSystemsList),
    /// Show one AI system.
    Get {
        /// AI system id.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct AiSystemsList {
    /// Exact risk class.
    #[arg(long, help = filters::help("Exact risk class.", &operations::LIST_AI_SYSTEMS, "risk_class"))]
    pub risk_class: Option<String>,
    /// Exact lifecycle status.
    #[arg(long, help = filters::help("Exact lifecycle status.", &operations::LIST_AI_SYSTEMS, "lifecycle_status"))]
    pub lifecycle_status: Option<String>,
    /// Only systems provided by this vendor id.
    #[arg(long)]
    pub vendor: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<AiSystemSort>(AiSystemSort::VALUES))]
    pub sort: Option<AiSystemSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum ChangesCommand {
    /// List change requests.
    List(ChangesList),
}

#[derive(Debug, Args)]
pub struct ChangesList {
    /// Exact status.
    #[arg(long, value_parser = choice::<ChangeStatus>(ChangeStatus::VALUES))]
    pub status: Option<ChangeStatus>,
    /// Exact change type.
    #[arg(long = "type", value_name = "TYPE", value_parser = choice::<ChangeType>(ChangeType::VALUES))]
    pub change_type: Option<ChangeType>,
    /// Exact category.
    #[arg(long, value_parser = choice::<ChangeCategory>(ChangeCategory::VALUES))]
    pub category: Option<ChangeCategory>,
    /// Only changes created on or after this date (UTC), as YYYY-MM-DD.
    #[arg(long, value_name = "DATE")]
    pub created_from: Option<String>,
    /// Only changes created on or before this date (UTC), as YYYY-MM-DD.
    #[arg(long, value_name = "DATE")]
    pub created_to: Option<String>,
    /// Field to order by.
    #[arg(long, value_parser = choice::<ChangeSort>(ChangeSort::VALUES))]
    pub sort: Option<ChangeSort>,
    #[command(flatten)]
    pub paging: Paging,
}

#[derive(Debug, Subcommand)]
pub enum ComplianceCommand {
    /// List the status of each control of a framework.
    Controls(ControlsList),
    /// Show the posture summary of a framework.
    Posture(PostureArgs),
}

/// The framework of a compliance command, given as a positional or as `--framework`.
#[derive(Debug, Args)]
pub struct FrameworkArg {
    /// Framework slug, e.g. nis2, ens, iso27001, dora. Give it here or with `--framework`.
    #[arg(value_name = "FRAMEWORK")]
    positional: Option<String>,
    /// Framework slug, the same as the positional form.
    #[arg(long = "framework", short = 'f', value_name = "FRAMEWORK")]
    flag: Option<String>,
}

impl FrameworkArg {
    /// The framework slug, or the message of the usage error when it is missing or the two forms
    /// disagree.
    fn check(&self) -> Result<&str, (clap::error::ErrorKind, String)> {
        match (self.positional.as_deref(), self.flag.as_deref()) {
            (Some(a), Some(b)) if a != b => Err((
                clap::error::ErrorKind::ArgumentConflict,
                format!("the framework is given twice with different values ('{a}' and '--framework {b}'); give it once"),
            )),
            (Some(a), _) | (None, Some(a)) => Ok(a),
            (None, None) => Err((
                clap::error::ErrorKind::MissingRequiredArgument,
                "the following required arguments were not provided:\n  <FRAMEWORK> or --framework <FRAMEWORK>".into(),
            )),
        }
    }

    /// The framework slug. `Cli::parse_checked` has already refused a missing one.
    pub fn get(&self) -> &str {
        self.check().unwrap_or_default()
    }
}

#[derive(Debug, Args)]
pub struct PostureArgs {
    #[command(flatten)]
    pub framework: FrameworkArg,
}

#[derive(Debug, Args)]
pub struct ControlsList {
    #[command(flatten)]
    pub framework: FrameworkArg,
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
