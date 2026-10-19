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
                    } else {
                        format!("The tenant's licence is not in force{state}.")
                    };
                    Failure::new(Kind::LicenceInactive, message)
                    .hint(
                        "Ask a tenant administrator to renew or reactivate it. Signing in again or \
                         using another key of this tenant will not help.",
                    )
                }
                403 => {
                    let scopes: Vec<String> = api
                        .required_scopes
                        .iter()
                        .map(|s| context.fill_scope(s))
                        .collect();
                    let hint = if context.is_portfolio_key {
                        "Ask an organisation administrator of your MSSP organisation for a key or \
                         access with that scope."
                    } else {
                        "Ask a tenant administrator for a key or access with that scope."
                    };
                    Failure::new(
                        Kind::Forbidden,
                        format!(
                            "The credential is valid but lacks the scope this needs: {}.",
                            scopes.join(", ")
                        ),
                    )
                    .hint(hint)
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

fn detail<'a>(api: &'a hodeishield_api::ApiError, key: &str) -> Option<&'a str> {
    api.body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_str())
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

    #[test]
    fn message_text_never_marks_a_closed_pipe() {
        assert!(!Failure::general("Broken pipe").closed_pipe);
        assert!(!Failure::from(Error::other("Broken pipe")).closed_pipe);
    }
}
