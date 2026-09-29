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
    /// The API could not be reached or failed (network, 5xx). Exit code 7.
    Unavailable,
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
}

impl Failure {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            request_id: None,
        }
    }

    pub fn general(message: impl Into<String>) -> Self {
        Self::new(Kind::General, message)
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
        Self::general(error.to_string())
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
                403 => {
                    let scopes: Vec<String> = api
                        .required_scopes
                        .iter()
                        .map(|s| context.fill_scope(s))
                        .collect();
                    Failure::new(
                        Kind::Forbidden,
                        format!(
                            "The credential is valid but lacks the scope this needs: {}.",
                            scopes.join(", ")
                        ),
                    )
                    .hint("Ask a tenant administrator for a key or access with that scope.")
                }
                404 => Failure::new(
                    Kind::NotFound,
                    server_message.unwrap_or_else(|| "Not found.".to_owned()),
                ),
                429 => {
                    let wait = api
                        .meta
                        .retry_after
                        .map_or_else(String::new, |s| format!(" Try again in {s} s."));
                    let scope = api
                        .body
                        .as_ref()
                        .and_then(|b| b.details.as_ref())
                        .and_then(|d| d.get("scope"))
                        .and_then(|s| s.as_str())
                        .map_or_else(String::new, |s| format!(" (limit: {s})"));
                    Failure::new(
                        Kind::RateLimited,
                        format!("Rate limit exhausted{scope}.{wait}"),
                    )
                }
                400 => Failure::general(format!(
                    "The API rejected the request: {}.",
                    server_message.unwrap_or_else(|| "invalid request".to_owned())
                )),
                status if status >= 500 => Failure::new(
                    Kind::Unavailable,
                    format!(
                        "The API failed ({status}{}). Try again later.",
                        if code.is_empty() { String::new() } else { format!(" {code}") }
                    ),
                ),
                status => Failure::general(format!(
                    "Unexpected answer from the API: HTTP {status}{}.",
                    server_message.map_or_else(String::new, |m| format!(": {m}"))
                )),
            };
            failure.request_id = request_id;
            failure
        }
        Error::Transport(e) => Failure::new(Kind::Unavailable, format!("Could not reach the API: {}.", error_chain(&e))),
        Error::Decode { operation, source } => Failure::general(format!(
            "The answer to {operation} does not match the API description this CLI was built from: {source}."
        ))
        .hint("Your CLI may be older than the API. Check for a newer release."),
        other => Failure::general(other.to_string()),
    }
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
}

impl ApiContext<'_> {
    fn fill_scope(&self, scope: &str) -> String {
        match self.framework {
            Some(framework) => scope.replace("<framework>", framework),
            None => scope.to_owned(),
        }
    }
}
