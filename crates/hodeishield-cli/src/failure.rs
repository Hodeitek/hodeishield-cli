// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The one error type the commands return, and the exit code each kind maps to.

use std::fmt;
use std::process::ExitCode;

/// Why a command failed, which decides the exit code. Scripts can branch on these; the numbers are
/// documented in the README and do not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Anything not listed below. Exit code 1.
    General,
    /// No usable credential, or the API rejected it (401). Exit code 3.
    NotAuthenticated,
    /// The credential lacks the scope the operation needs (403). Exit code 4.
    Forbidden,
    /// The resource does not exist, or not in this tenant (404). Exit code 5.
    NotFound,
    /// A rate limit is exhausted (429). Exit code 6.
    RateLimited,
    /// The API could not be reached, failed (network, 5xx), or lacks a feature the command needs
    /// (no portfolio listing). Exit code 7.
    Unavailable,
    /// The tenant holds no licence in force, or is deactivated (403 `LICENCE_INACTIVE`). Exit code 8.
    LicenceInactive,
}

impl Kind {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::General => 1,
            Self::NotAuthenticated => 3,
            Self::Forbidden => 4,
            Self::NotFound => 5,
            Self::RateLimited => 6,
            Self::Unavailable => 7,
            Self::LicenceInactive => 8,
        })
    }
}

/// A failure to report: what happened, optionally what to do about it, and a request id for
/// support. It never carries a credential.
#[derive(Debug)]
pub struct Failure {
    pub kind: Kind,
    pub message: String,
    pub hint: Option<String>,
    pub request_id: Option<String>,
    /// Whether this failure is the reader of standard output going away
    /// (`hodeishield ... | head -1`). Only [`Failure::closed_stdout`] sets it, and the caller does
    /// that only for an `io::Error` of kind [`std::io::ErrorKind::BrokenPipe`] seen while writing
    /// to standard output (see `output::Tracked`). The conversion from [`std::io::Error`] never
    /// sets it: a broken pipe on a socket, a file or a config write is a real failure, and so is
    /// message text, which can come from the API.
    pub closed_pipe: bool,
    /// Whether this failure was converted from an `io::Error` of kind
    /// [`std::io::ErrorKind::BrokenPipe`], wherever it came from. On its own it means nothing:
    /// `main` treats the failure as a closed reader only when standard output also saw the
    /// broken pipe, so an unrelated failure after the reader went away still fails.
    pub(crate) broken_pipe: bool,
}

impl Failure {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            request_id: None,
            closed_pipe: false,
            broken_pipe: false,
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(Kind::General, message)
    }

    /// Marks this failure as the reader of standard output having gone away.
    #[must_use]
    pub fn closed_stdout(mut self) -> Self {
        self.closed_pipe = true;
        self
    }

    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        let mut failure = Self::general(error.to_string());
        failure.broken_pipe = error.kind() == std::io::ErrorKind::BrokenPipe;
        failure
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

/// Turns an API client error into a failure a person can act on.
pub fn from_api(error: hodeishield_api::Error, context: &ApiContext<'_>) -> Failure {
    use hodeishield_api::Error;
    match error {
        Error::Api(api) => {
            let code = api.code().unwrap_or("").to_owned();
            let server_message = api.body.as_ref().map(|b| b.message.clone());
            let request_id = api.request_id().map(str::to_owned);
            let mut failure = match api.status {
                401 => Failure::new(
                    Kind::NotAuthenticated,
                    "The API did not accept the credential.",
                )
                .hint(match context.source {
                    CredentialSource::ApiKey => {
                        "Check HODEISHIELD_API_KEY: the key may be revoked, expired or mistyped."
                    }
                    CredentialSource::OAuth => {
                        "Run `hodeishield login` again: the sign-in was revoked, has expired, or no \
                         longer covers its tenant."
                    }
                }),
                403 if detail(&api, "code") == Some("LICENCE_INACTIVE") => {
                    // The state is a short token (none, suspended…); anything else is not shown.
                    let state = detail(&api, "licence")
                        .filter(|s| {
                            !s.is_empty()
                                && s.len() <= 32
                                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                        })
                        .map_or_else(String::new, |s| format!(" (licence: {s})"));
                    let message = if detail(&api, "licence") == Some("tenant_inactive") {
                        "The tenant is deactivated.".to_owned()
                    } else if is_write(&api) {
                        // A write is also refused while the licence is in its grace period.
                        format!(
                            "The tenant's licence is not in force{state}, so {} cannot be {}.",
                            write_noun(&api),
                            if api.operation.ends_with("ActProposal") { "decided" } else { "changed" }
                        )
                    } else {
                        format!("The tenant's licence is not in force{state}.")
                    };
                    Failure::new(Kind::LicenceInactive, message)
                    .hint(
                        "Ask a tenant administrator to renew or reactivate it. Signing in again or \
                         using another key of this tenant will not help.",
                    )
                }
                403 if detail(&api, "code") == Some("MODULE_NOT_ENTITLED") => {
                    // The scopes name the module (or `compliance.<framework>`); only short tokens
                    // are shown.
                    let scopes = entitlement_list(&api, "scopes");
                    // A newer server names the cause. When a framework is not enabled it also lists
                    // `compliance` as a module, but the module is in the plan, so that entry is
                    // not shown.
                    let frameworks = entitlement_list(&api, "frameworks");
                    let mut modules = entitlement_list(&api, "modules");
                    if !frameworks.is_empty() {
                        modules.retain(|m| m != "compliance");
                    }
                    let compliance = scopes.iter().any(|s| s.starts_with("compliance."));
                    let what = match (modules.is_empty(), frameworks.is_empty()) {
                        (false, true) => format!(
                            "The tenant's plan does not include the {} {}",
                            if modules.len() == 1 { "module" } else { "modules" },
                            modules.join(", ")
                        ),
                        (true, false) => format!(
                            "The compliance {} {} not enabled for the tenant",
                            if frameworks.len() == 1 { "framework" } else { "frameworks" },
                            frameworks.join(", ") + if frameworks.len() == 1 { " is" } else { " are" }
                        ),
                        (false, false) => format!(
                            "The tenant's plan does not include the {} {}, and the compliance {} {} \
                             not enabled for the tenant",
                            if modules.len() == 1 { "module" } else { "modules" },
                            modules.join(", "),
                            if frameworks.len() == 1 { "framework" } else { "frameworks" },
                            frameworks.join(", ") + if frameworks.len() == 1 { " is" } else { " are" }
                        ),
                        (true, true) if compliance => "The tenant's plan does not include this \
                             module, or the compliance framework is not enabled for the tenant"
                            .to_owned(),
                        (true, true) => {
                            "The tenant's plan does not include the module this needs".to_owned()
                        }
                    };
                    let shown = if scopes.is_empty() {
                        String::new()
                    } else {
                        format!(" (scope: {})", scopes.join(", "))
                    };
                    let ask = match (modules.is_empty(), frameworks.is_empty()) {
                        (false, true) => "Ask a tenant administrator to add the module to the plan.",
                        (true, false) => "Ask a tenant administrator to enable the framework for the tenant.",
                        (false, false) => {
                            "Ask a tenant administrator to add the module to the plan and to enable \
                             the framework for the tenant."
                        }
                        (true, true) => {
                            "Ask a tenant administrator to add the module to the plan, or to enable \
                             the framework."
                        }
                    };
                    Failure::new(Kind::Forbidden, format!("{what}{shown}."))
                    .hint(format!(
                        "{ask} Signing in again or using another key of this tenant will not help."
                    ))
                }
                403 if detail(&api, "code") == Some("IP_NOT_ALLOWED") => Failure::new(
                    Kind::Forbidden,
                    "The request comes from an IP address that is not allowed for this \
                     credential or organisation.",
                )
                .hint(
                    "Ask an administrator to add this machine's public IP address to the \
                     allowlist, or run the command from an allowed network. Signing in again \
                     will not help.",
                ),
                403 if detail(&api, "code") == Some("PLAN_WITHOUT_API") => {
                    plan_without_api(Kind::Forbidden)
                }
                403 if detail(&api, "code") == Some("STEP_UP_REQUIRED") => {
                    // The window is the server's: `max_grant_age_seconds`, 900 today.
                    let minutes = detail_u64(&api, "max_grant_age_seconds")
                        .filter(|s| (60..=86_400).contains(s))
                        .map_or(15, |s| s.div_ceil(60));
                    Failure::new(
                        Kind::Forbidden,
                        format!(
                            "Decisions need a sign-in confirmed in the last {minutes} minutes. \
                             Run `hodeishield login --decide` and try again."
                        ),
                    )
                    .hint(
                        "The sign-in asks you to confirm your identity again. Refreshing the \
                         sign-in does not extend the window. Nothing was decided.",
                    )
                }
                403 if detail(&api, "code") == Some("CREDENTIAL_NOT_ALLOWED") => Failure::new(
                    Kind::Forbidden,
                    "Decisions need a sign-in made with the CLI, not an API key or another \
                     application's token. Nothing was decided.",
                )
                .hint(
                    "Unset HODEISHIELD_API_KEY if it is set, and run `hodeishield login --decide`.",
                ),
                403 if detail(&api, "code") == Some("OWN_PROPOSAL") => Failure::new(
                    Kind::Forbidden,
                    "This proposal was made for you, and the tenant's rules do not let you approve \
                     your own proposal. Nothing was decided.",
                )
                .hint("Another person with the right role has to approve it."),
                403 if detail(&api, "code") == Some("ROLE_NOT_PERMITTED") => {
                    let decision = api.operation.ends_with("ActProposal");
                    Failure::new(
                        Kind::Forbidden,
                        match api.operation {
                            "resolveAlert" => "The role this key acts with may not close this alert. Nothing was changed.",
                            "transitionRisk" => "The role this key acts with may not move risks. Nothing was changed.",
                            "approveActProposal" => "Your role may not approve this proposal. Nothing was decided.",
                            "rejectActProposal" => "Your role may not reject this proposal. Nothing was decided.",
                            _ => "The role this key acts with may not acknowledge alerts. Nothing was changed.",
                        },
                    )
                    .hint(if decision {
                        "The role an action class and the tenant's policy require decides who may \
                         approve it. Ask a person with that role."
                    } else if api.operation == "transitionRisk" {
                        "A key acts with the role of the user who created it, and only an \
                         administrator role of the tenant may move a risk. Use a key created by \
                         such a user."
                    } else {
                        "A key acts with the role of the user who created it. An MSSP analyst's key \
                         closes medium and low alerts only. Use a key created by a user whose role \
                         may do this in the app."
                    })
                }
                403 if detail(&api, "code") == Some("WRITE_ACTOR_UNRESOLVED") => Failure::new(
                    Kind::Forbidden,
                    if api.operation.ends_with("ActProposal") {
                        "Your account no longer exists, is not active or no longer reaches the \
                         tenant. Nothing was decided."
                    } else {
                        "The user who created this key no longer exists, is not active or no longer \
                         reaches the tenant. Nothing was changed."
                    },
                )
                .hint(if api.operation == "transitionRisk" {
                    "Ask for a new key, created by an administrator of the tenant."
                } else if api.operation.ends_with("ActProposal") {
                    "Ask a tenant administrator to check your access."
                } else {
                    "Ask for a new key, created by a user who can triage alerts."
                }),
                403 if detail(&api, "code") == Some("MFA_ENROLLMENT_REQUIRED") => Failure::new(
                    Kind::Forbidden,
                    "This account must enrol multi-factor authentication before it can use the API.",
                )
                .hint(
                    "Sign in to the web app, enrol MFA in the account settings, then run \
                     `hodeishield login` again.",
                ),
                // A reason code this CLI does not know (the vocabulary is open): the server's own
                // message says what is wrong. The exit code stays the one of every 403.
                403 if matches!(
                    detail(&api, "code"),
                    Some(reason) if reason != "INSUFFICIENT_SCOPE" && reason != "CREDENTIAL_NOT_ALLOWED"
                ) =>
                {
                    Failure::new(
                        Kind::Forbidden,
                        format!(
                            "The API refused the request: {}.",
                            server_message.as_deref().map_or("forbidden", sentence_body)
                        ),
                    )
                }
                403 => {
                    let scopes: Vec<String> = api
                        .required_scopes
                        .iter()
                        .map(|s| context.fill_scope(s))
                        .collect();
                    let hint = if scopes.iter().any(|s| s == "act:decide") {
                        "This sign-in was not given permission to decide. Run \
                         `hodeishield login --decide`."
                    } else if context.is_portfolio_key {
                        "Ask an organisation administrator of your MSSP organisation for a key or \
                         access with that scope."
                    } else {
                        "Ask a tenant administrator for a key or access with that scope."
                    };
                    let message = if scopes.is_empty() {
                        "The credential is valid but is not allowed to do this.".to_owned()
                    } else {
                        format!(
                            "The credential is valid but lacks the scope this needs: {}.",
                            scopes.join(", ")
                        )
                    };
                    Failure::new(Kind::Forbidden, message).hint(hint)
                }
                404 => {
                    let failure = Failure::new(
                        Kind::NotFound,
                        server_message.unwrap_or_else(|| "Not found.".to_owned()),
                    );
                    if detail(&api, "code") == Some("TENANT_NOT_FOUND") {
                        failure.hint(
                            "The client tenant is not in this credential's portfolio (or it left \
                             it). `hodeishield tenants list` shows the ones you may read.",
                        )
                    } else {
                        failure
                    }
                }
                429 => {
                    let wait = api
                        .meta
                        .retry_after
                        .map_or_else(String::new, |s| format!(" Try again in {s} s."));
                    let scope = detail(&api, "scope").map_or_else(String::new, |s| format!(" (limit: {s})"));
                    let hint = match detail(&api, "scope") {
                        Some("portfolio_key") => Some(
                            "This portfolio key has used its requests for the minute. A script \
                             that reads many client tenants should pause between runs.",
                        ),
                        Some("portfolio_org") => Some(
                            "All portfolio keys of your organisation share this limit; another key \
                             or script may be using it.",
                        ),
                        Some("portfolio_tenant") => Some(
                            "This client tenant's own limit is used up; other client tenants are \
                             not affected.",
                        ),
                        // The plain `tenant` limit is also what a single-tenant key hits: the
                        // client wording fits only when a client tenant was selected.
                        Some("write_key") => Some(
                            "This key has used its allowance of changes for the minute; reads are \
                             counted apart. Space out the changes a script makes.",
                        ),
                        Some("decision_user") => Some(
                            "You have made as many decisions as are allowed for the minute. Wait \
                             before the next one.",
                        ),
                        Some("tenant") if context.tenant_selected => Some(
                            "This client tenant's own limit is used up; other client tenants are \
                             not affected.",
                        ),
                        _ => None,
                    };
                    let failure = Failure::new(
                        Kind::RateLimited,
                        format!("Rate limit exhausted{scope}.{wait}"),
                    );
                    match hint {
                        Some(hint) => failure.hint(hint),
                        None => failure,
                    }
                }
                400 => {
                    let failure = Failure::general(format!(
                        "The API rejected the request: {}.",
                        server_message.as_deref().map_or("invalid request", sentence_body)
                    ));
                    match detail(&api, "code") {
                        Some("TENANT_REQUIRED") => failure.hint(
                            "This credential covers several client tenants: pick one with \
                             --tenant <slug|id>, or every one with --all-tenants on a list. \
                             `hodeishield tenants list` shows them.",
                        ),
                        Some("TENANT_SELECTOR_NOT_SUPPORTED") => failure.hint(
                            "This credential reads one tenant only; leave out --tenant and \
                             --all-tenants.",
                        ),
                        Some("UNKNOWN_QUERY_PARAMETER") => {
                            let unknown = name_list(&api, "unknown", 10);
                            let allowed = name_list(&api, "allowed", 40);
                            let mut failure = Failure::general(if unknown.is_empty() {
                                "The API does not know a query parameter this command sent."
                                    .to_owned()
                            } else {
                                format!(
                                    "The API does not know the query {} {}.",
                                    if unknown.len() == 1 { "parameter" } else { "parameters" },
                                    unknown.join(", ")
                                )
                            });
                            if !allowed.is_empty() {
                                failure = failure.hint(format!(
                                    "The API accepts: {}. Check for a newer release of the CLI; \
                                     if it persists, please report it.",
                                    allowed.join(", ")
                                ));
                            }
                            failure
                        }
                        Some("TENANT_HEADER_INVALID") => failure.hint(
                            "The CLI sent a tenant selection the API could not read. This is a \
                             bug: please report it.",
                        ),
                        _ => failure,
                    }
                }
                409 => conflict(&api, server_message.as_deref()),
                status if status >= 500 => Failure::new(
                    Kind::Unavailable,
                    format!(
                        "The API failed ({status}{}). Try again later.",
                        if code.is_empty() { String::new() } else { format!(" {code}") }
                    ),
                ),
                status => Failure::general(format!(
                    "Unexpected answer from the API: HTTP {status}{}.",
                    server_message.map_or_else(String::new, |m| format!(": {}", sentence_body(&m)))
                )),
            };
            failure.request_id = request_id;
            failure
        }
        Error::Transport(e) => {
            let chain = error_chain(&e);
            ca_hint(Failure::new(Kind::Unavailable, format!("Could not reach the API: {chain}.")), &chain)
        }
        Error::Decode { operation, source } => Failure::general(format!(
            "The answer to {operation} does not match the API description this CLI was built from: {source}."
        ))
        .hint("Your CLI may be older than the API. Check for a newer release."),
        hodeishield_api::Error::PortfolioNotOffered { .. } => Failure::new(
            Kind::Unavailable,
            "This API does not offer portfolio access yet.",
        )
        .hint(
            "Reading several client tenants with one credential needs a newer API, or the API URL \
             is not the HodeiShield /v1 API. Without --tenant and --all-tenants the CLI reads the \
             credential's own tenant as before.",
        ),
        other @ hodeishield_api::Error::TenantMismatch { .. } => Failure::general(other.to_string())
            .hint(
                "Nothing was shown, so that no client's data appears under another's name. Check \
                 the API URL and try again; if it persists, contact support.",
            ),
        other => Failure::general(other.to_string()),
    }
}

/// Why a file cannot be served as asked (409), from `error.details.code`. Only the documented
/// codes get their own wording; the values shown are short tokens, anything else is left out.
fn conflict(api: &hodeishield_api::ApiError, server_message: Option<&str>) -> Failure {
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 16
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    let details = api.body.as_ref().and_then(|b| b.details.as_ref());
    match detail(api, "code") {
        Some("ALERT_RESOLVED") => Failure::general(
            "The alert is already resolved, so it cannot be acknowledged. Nothing was changed.",
        ),
        Some("ALERT_STATE_CHANGED") => Failure::general(
            "The alert changed while this request was being applied. Nothing was changed.",
        )
        .hint("Read it again with `hodeishield alerts get <id>`, and repeat the command if it is still needed."),
        Some("TRANSITION_NOT_ALLOWED") => {
            let word = |s: &str| {
                !s.is_empty()
                    && s.len() <= 32
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            };
            let current = detail(api, "status").filter(|s| word(s));
            let allowed: Vec<&str> = details
                .and_then(|d| d.get("allowed"))
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| word(s))
                        .collect()
                })
                .unwrap_or_default();
            let failure = Failure::general(match current {
                Some(status) => format!(
                    "The risk's lifecycle does not allow that move from `{status}`. Nothing was changed."
                ),
                None => "The risk's lifecycle does not allow that move. Nothing was changed."
                    .to_owned(),
            });
            if allowed.is_empty() {
                failure
            } else {
                failure.hint(format!("From there it may move to: {}.", allowed.join(", ")))
            }
        }
        Some("PROPOSAL_EXPIRED") => Failure::general(
            "The proposal expired, so nobody can decide it any more. Nothing was decided.",
        )
        .hint("`hodeishield approvals list` shows what is still waiting."),
        Some("ALREADY_DECIDED") => Failure::general(
            "The proposal is no longer waiting for a decision: it was already approved, rejected, \
             carried out or ended. Nothing was decided.",
        )
        .hint("`hodeishield approvals list` shows what is still waiting."),
        Some("ACTIONS_PAUSED") => Failure::general(
            "Actions are paused for this tenant or for the whole service, so a proposal cannot be \
             decided now. Nothing was decided.",
        )
        .hint("Try again when actions are switched on again."),
        Some("NOT_DECIDABLE") => {
            let reason = detail(api, "reason")
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 48
                        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
                .map_or_else(String::new, |r| format!(" (reason: {r})"));
            Failure::general(format!(
                "The proposal cannot be decided{reason}. Nothing was decided."
            ))
            .hint("`hodeishield approvals list` shows what is still waiting.")
        }
        Some("REPORT_NOT_READY") if detail(api, "status") == Some("failed") => {
            Failure::general("The report failed to generate, so it has no file.")
                .hint("Generate it again in the app.")
        }
        Some("REPORT_NOT_READY") => {
            Failure::general("The report is still being generated, so it has no file yet.")
                .hint("Try again later; `hodeishield reports get <id>` shows its status.")
        }
        Some("FORMAT_UNSUPPORTED") => {
            let formats: Vec<&str> = details
                .and_then(|d| d.get("formats"))
                .and_then(serde_json::Value::as_array)
                .map(|f| {
                    f.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| token(s))
                        .collect()
                })
                .unwrap_or_default();
            let failure = Failure::general("The report cannot be downloaded in that format.");
            if formats.is_empty() {
                failure.hint(
                    "It has no format the API can render; `hodeishield reports get <id>` lists \
                     the formats it can be downloaded in.",
                )
            } else {
                failure.hint(format!(
                    "Choose one of its formats with --format: {}.",
                    formats.join(", ")
                ))
            }
        }
        Some("FILE_TOO_LARGE") => {
            let limit = details
                .and_then(|d| d.get("limit_bytes"))
                .and_then(serde_json::Value::as_u64)
                .map_or_else(String::new, |b| format!(" ({b} bytes)"));
            Failure::general(format!(
                "The report's file is larger than the API serves{limit}, so it was not sent."
            ))
        }
        _ => Failure::general(format!(
            "The API refused the request: {}.",
            server_message.map_or("conflict", sentence_body)
        )),
    }
}

/// A string member of `error.details`.
/// The server's message without its closing punctuation, for a sentence the CLI ends itself, so
/// that "Bad value." does not become "Bad value..".
fn sentence_body(message: &str) -> &str {
    message.trim_end().trim_end_matches(['.', '!', '?'])
}

/// Whether the call that failed was one of the writes (alerts, risks, decisions).
fn is_write(api: &hodeishield_api::ApiError) -> bool {
    matches!(
        api.operation,
        "acknowledgeAlert"
            | "resolveAlert"
            | "transitionRisk"
            | "approveActProposal"
            | "rejectActProposal"
    )
}

/// What a refused write was going to change, for the licence message.
fn write_noun(api: &hodeishield_api::ApiError) -> &'static str {
    match api.operation {
        "transitionRisk" => "risks",
        "approveActProposal" | "rejectActProposal" => "proposals",
        _ => "alerts",
    }
}

/// A non-negative whole number member of `error.details`.
fn detail_u64(api: &hodeishield_api::ApiError, key: &str) -> Option<u64> {
    api.body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .and_then(|d| d.get(key))
        .and_then(serde_json::Value::as_u64)
}

fn detail<'a>(api: &'a hodeishield_api::ApiError, key: &str) -> Option<&'a str> {
    api.body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_str())
}

/// A list of parameter names in `error.details` (`unknown`, `allowed`): at most `max` short
/// names, anything else is dropped.
fn name_list(api: &hodeishield_api::ApiError, key: &str, max: usize) -> Vec<String> {
    api.body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']')
                        })
                })
                .take(max)
                .map(|s| format!("`{s}`"))
                .collect()
        })
        .unwrap_or_default()
}

/// A list a `MODULE_NOT_ENTITLED` answer sends in `details` (`scopes`, `modules` or `frameworks`):
/// at most 5 short tokens, anything else is dropped.
fn entitlement_list(api: &hodeishield_api::ApiError, key: &str) -> Vec<String> {
    api.body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
                        })
                })
                .take(5)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The error and its causes on one line: `reqwest` puts the useful part (DNS, TLS, refused) in the
/// source chain.
pub fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// Adds the hint for a machine with no CA certificates, which the HTTP client reports only as
/// "No CA certificates were loaded from the system".
pub fn ca_hint(failure: Failure, chain: &str) -> Failure {
    if chain.contains("No CA certificates were loaded") {
        failure.hint("Install the system CA certificates package (for example `ca-certificates`).")
    } else {
        failure
    }
}

/// Where the credential of a call came from, for the hint on a 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    ApiKey,
    OAuth,
}

/// What a failure message needs to know about the call.
#[derive(Debug, Clone, Copy)]
pub struct ApiContext<'a> {
    pub source: CredentialSource,
    /// The framework of a compliance call, to fill `compliance.<framework>:read`.
    pub framework: Option<&'a str>,
    /// Whether the call reads a selected client tenant (`--tenant` or `--all-tenants`).
    pub tenant_selected: bool,
    /// Whether the credential is a portfolio key (starts with `hsp_`).
    pub is_portfolio_key: bool,
}

impl ApiContext<'_> {
    fn fill_scope(&self, scope: &str) -> String {
        match self.framework {
            Some(framework) => scope.replace("<framework>", framework),
            None => scope.to_owned(),
        }
    }
}

/// The tenant's plan has no API or CLI access (`PLAN_WITHOUT_API`). Shared by the API refusal (exit
/// code 4) and the refused device sign-in, which keeps its own kind.
pub fn plan_without_api(kind: Kind) -> Failure {
    Failure::new(
        kind,
        "This tenant's plan does not include API or CLI access.",
    )
    .hint(
        "API and CLI access is included in every plan from Comply up, except AI Governance, and \
         also during a trial. The plan can be changed from the plan page in the web console.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn converting_an_io_error_never_marks_a_closed_pipe() {
        assert!(!Failure::from(Error::from(ErrorKind::BrokenPipe)).closed_pipe);
        assert!(!Failure::from(Error::from(ErrorKind::NotFound)).closed_pipe);
        assert!(
            Failure::from(Error::from(ErrorKind::BrokenPipe))
                .closed_stdout()
                .closed_pipe
        );
    }

    #[test]
    fn a_sentence_body_drops_only_the_closing_punctuation() {
        assert_eq!(sentence_body("Bad value."), "Bad value");
        assert_eq!(sentence_body("Bad value!  "), "Bad value");
        assert_eq!(sentence_body("send X-HS-Tenant.."), "send X-HS-Tenant");
        assert_eq!(sentence_body("version 1.2 is old"), "version 1.2 is old");
    }

    #[test]
    fn a_missing_ca_bundle_gets_a_hint_and_other_errors_do_not() {
        let chain =
            "builder error: unexpected error: No CA certificates were loaded from the system";
        let hinted = ca_hint(Failure::general("x"), chain);
        assert!(
            hinted
                .hint
                .as_deref()
                .is_some_and(|h| h.contains("ca-certificates"))
        );
        assert!(ca_hint(Failure::general("x"), "dns error").hint.is_none());
    }

    fn forbidden(details: &str) -> hodeishield_api::Error {
        let body = format!(
            r#"{{"code":"forbidden","message":"no","request_id":"r","details":{details}}}"#
        );
        hodeishield_api::Error::Api(Box::new(hodeishield_api::ApiError {
            status: 403,
            operation: "test",
            required_scopes: &[],
            body: Some(serde_json::from_str(&body).expect("body")),
            meta: hodeishield_api::ResponseMeta::default(),
        }))
    }

    fn context() -> ApiContext<'static> {
        ApiContext {
            source: CredentialSource::ApiKey,
            framework: None,
            tenant_selected: false,
            is_portfolio_key: false,
        }
    }

    #[test]
    fn a_module_not_entitled_answer_names_the_scope_and_exits_4() {
        let f = from_api(
            forbidden(r#"{"code":"MODULE_NOT_ENTITLED","scopes":["supply_risk:read"]}"#),
            &context(),
        );
        assert_eq!(f.kind, Kind::Forbidden);
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module this needs (scope: supply_risk:read)."
        );
        let hint = f.hint.as_deref().expect("hint");
        assert!(hint.contains("tenant administrator"), "{hint}");
        assert!(hint.contains("will not help"), "{hint}");
    }

    #[test]
    fn a_compliance_scope_mentions_the_framework_being_enabled() {
        let f = from_api(
            forbidden(r#"{"code":"MODULE_NOT_ENTITLED","scopes":["compliance.nis2:read"]}"#),
            &context(),
        );
        assert_eq!(f.kind, Kind::Forbidden);
        assert!(
            f.message.contains("framework is not enabled"),
            "{}",
            f.message
        );
        assert!(f.message.contains("compliance.nis2:read"), "{}", f.message);
    }

    #[test]
    fn a_module_not_entitled_answer_without_scopes_names_nothing() {
        let f = from_api(forbidden(r#"{"code":"MODULE_NOT_ENTITLED"}"#), &context());
        assert_eq!(f.kind, Kind::Forbidden);
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module this needs."
        );
    }

    #[test]
    fn odd_or_long_scope_values_are_not_shown() {
        let long = "a".repeat(65);
        let details = format!(
            r#"{{"code":"MODULE_NOT_ENTITLED","scopes":["{long}","\u001b[31mred","bad scope",7]}}"#
        );
        let f = from_api(forbidden(&details), &context());
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module this needs."
        );
    }

    #[test]
    fn a_missing_module_is_named_with_a_hint_to_add_it_to_the_plan() {
        let f = from_api(
            forbidden(
                r#"{"code":"MODULE_NOT_ENTITLED","scopes":["supply_risk:read"],"modules":["supply_risk"]}"#,
            ),
            &context(),
        );
        assert_eq!(f.kind, Kind::Forbidden);
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module supply_risk (scope: supply_risk:read)."
        );
        assert_eq!(
            f.hint.as_deref(),
            Some(
                "Ask a tenant administrator to add the module to the plan. Signing in again or \
                 using another key of this tenant will not help."
            )
        );
    }

    #[test]
    fn a_framework_that_is_not_enabled_is_named_and_not_reported_as_a_module() {
        let f = from_api(
            forbidden(
                r#"{"code":"MODULE_NOT_ENTITLED","scopes":["compliance.nis2:read"],"modules":["compliance"],"frameworks":["nis2"]}"#,
            ),
            &context(),
        );
        assert_eq!(f.kind, Kind::Forbidden);
        assert_eq!(
            f.message,
            "The compliance framework nis2 is not enabled for the tenant (scope: compliance.nis2:read)."
        );
        assert!(!f.message.contains("module"), "{}", f.message);
        assert_eq!(
            f.hint.as_deref(),
            Some(
                "Ask a tenant administrator to enable the framework for the tenant. Signing in \
                 again or using another key of this tenant will not help."
            )
        );
    }

    #[test]
    fn a_missing_module_and_a_framework_that_is_not_enabled_are_both_named() {
        let f = from_api(
            forbidden(
                r#"{"code":"MODULE_NOT_ENTITLED","modules":["supply_risk","compliance"],"frameworks":["nis2","dora"]}"#,
            ),
            &context(),
        );
        assert_eq!(f.kind, Kind::Forbidden);
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module supply_risk, and the compliance \
             frameworks nis2, dora are not enabled for the tenant."
        );
        let hint = f.hint.as_deref().expect("hint");
        assert!(
            hint.contains("add the module to the plan and to enable the framework"),
            "{hint}"
        );
    }

    #[test]
    fn an_old_server_without_modules_or_frameworks_gets_the_earlier_message() {
        let f = from_api(
            forbidden(
                r#"{"code":"MODULE_NOT_ENTITLED","scopes":["compliance.nis2:read"],"modules":"x","frameworks":[7,null]}"#,
            ),
            &context(),
        );
        assert_eq!(
            f.message,
            "The tenant's plan does not include this module, or the compliance framework is not \
             enabled for the tenant (scope: compliance.nis2:read)."
        );
        assert_eq!(
            f.hint.as_deref(),
            Some(
                "Ask a tenant administrator to add the module to the plan, or to enable the \
                 framework. Signing in again or using another key of this tenant will not help."
            )
        );
    }

    #[test]
    fn odd_long_or_control_character_modules_and_frameworks_are_not_shown() {
        let long = "a".repeat(65);
        let details = format!(
            r#"{{"code":"MODULE_NOT_ENTITLED","modules":["{long}","\u001b[31mred","bad module",7,"ok_module"],"frameworks":["{long}","nis2\n","\u0007"]}}"#
        );
        let f = from_api(forbidden(&details), &context());
        assert_eq!(
            f.message,
            "The tenant's plan does not include the module ok_module."
        );
        assert!(!f.message.contains('\u{1b}') && !f.message.contains('\u{7}'));
    }

    #[test]
    fn a_generic_403_without_scopes_does_not_end_in_an_empty_list() {
        let f = from_api(forbidden("{}"), &context());
        assert_eq!(f.kind, Kind::Forbidden);
        assert!(!f.message.contains("needs:"), "{}", f.message);
        assert!(f.message.ends_with('.'), "{}", f.message);
    }

    #[test]
    fn message_text_never_marks_a_closed_pipe() {
        assert!(!Failure::general("Broken pipe").closed_pipe);
        assert!(!Failure::from(Error::other("Broken pipe")).closed_pipe);
    }
}
