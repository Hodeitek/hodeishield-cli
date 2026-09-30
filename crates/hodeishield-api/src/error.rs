use crate::client::{Operation, ResponseMeta};
use crate::v1::ErrorEnvelope;
use std::fmt;

/// The `error` object of a `/v1` error answer.
pub use crate::v1::ErrorBody as ApiErrorBody;

/// An error answer from `/v1`.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status.
    pub status: u16,
    /// `operationId` of the call.
    pub operation: &'static str,
    /// Scopes the operation requires, as documented.
    pub required_scopes: &'static [&'static str],
    /// The error envelope, when the body was one.
    pub body: Option<ApiErrorBody>,
    /// Request id, rate-limit and `Retry-After` headers.
    pub meta: ResponseMeta,
}

impl ApiError {
    /// `error.code`. Branch on this, not on the message.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        self.body.as_ref().map(|b| b.code.as_str())
    }

    /// Request id, from the body or the `X-Request-Id` header.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.body
            .as_ref()
            .map(|b| b.request_id.as_str())
            .filter(|id| !id.is_empty())
            .or(self.meta.request_id.as_deref())
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.body {
            Some(body) => write!(f, "{} {}: {}", self.status, body.code, body.message),
            None => write!(f, "HTTP {}", self.status),
        }
    }
}

/// Everything that can go wrong calling `/v1`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The API answered with an error status.
    #[error("{0}")]
    Api(Box<ApiError>),
    /// The request could not be sent or the answer could not be read.
    #[error("could not reach the API: {0}")]
    Transport(#[source] reqwest::Error),
    /// The answer's body could not be read, or was larger than the client accepts.
    #[error("could not read the API's answer: {0}")]
    Body(#[source] std::io::Error),
    /// A successful answer did not match the OpenAPI document.
    #[error("the answer to {operation} does not match the published API description: {source}")]
    Decode {
        /// `operationId` of the call.
        operation: &'static str,
        /// What did not match.
        #[source]
        source: serde_json::Error,
    },
    /// The base URL is not `https` and not a loopback host.
    #[error(
        "refusing to send credentials to {0}: the API URL must use https \
         (plain http is accepted only for localhost)"
    )]
    InsecureBaseUrl(String),
    /// The base URL cannot be used.
    #[error("invalid API URL: {0}")]
    InvalidBaseUrl(String),
    /// The credential cannot travel in an HTTP header.
    #[error("the credential contains characters that cannot be sent in an HTTP header")]
    InvalidCredential,
    /// An id or slug that would change which resource the path addresses.
    #[error("{0:?} is not a valid identifier")]
    InvalidPathArgument(String),
}

impl Error {
    pub(crate) fn from_response(
        operation: &'static Operation,
        meta: ResponseMeta,
        body: &[u8],
    ) -> Self {
        let body = serde_json::from_slice::<ErrorEnvelope>(body)
            .ok()
            .map(|envelope| envelope.error);
        Self::Api(Box::new(ApiError {
            status: meta.status,
            operation: operation.id,
            required_scopes: operation.scopes,
            body,
            meta,
        }))
    }

    /// The error answer, when the API gave one.
    #[must_use]
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Self::Api(error) => Some(error),
            _ => None,
        }
    }
}

/// A value that is not one of a query parameter's accepted values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    /// The value given.
    pub value: String,
    /// The accepted values.
    pub expected: &'static [&'static str],
}

impl ParseEnumError {
    pub(crate) fn new(value: &str, expected: &'static [&'static str]) -> Self {
        Self {
            value: value.to_owned(),
            expected,
        }
    }
}

impl fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not one of: {}",
            self.value,
            self.expected.join(", ")
        )
    }
}

impl std::error::Error for ParseEnumError {}
