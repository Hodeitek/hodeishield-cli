// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

use crate::error::Error;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use std::fmt;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

/// One `/v1` operation, as the OpenAPI document describes it. The generated constants live in
/// [`crate::v1::operations`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    /// `operationId`, e.g. `listVendors`.
    pub id: &'static str,
    /// Always `GET`: `/v1` is read-only.
    pub method: &'static str,
    /// Path template, e.g. `/v1/vendors/{id}`.
    pub path: &'static str,
    /// One-line summary.
    pub summary: &'static str,
    /// Scopes the credential needs. A template such as `compliance.<framework>:read` stands for the
    /// scope of the framework being read.
    pub scopes: &'static [&'static str],
}

/// A successful answer: the typed body, the body exactly as received (for `--json`, so fields this
/// client does not know yet are not lost), and what the headers said.
#[derive(Debug, Clone)]
pub struct ApiResponse<T> {
    /// The body, decoded into the generated type.
    pub data: T,
    /// The body as received.
    pub raw: serde_json::Value,
    /// Status, request id and rate-limit headers.
    pub meta: ResponseMeta,
}

/// What an answer's status line and headers said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseMeta {
    /// HTTP status.
    pub status: u16,
    /// `X-Request-Id`: what support asks for.
    pub request_id: Option<String>,
    /// `RateLimit-*` headers, when the request got past authentication.
    pub rate_limit: Option<RateLimit>,
    /// `Retry-After`, in seconds.
    pub retry_after: Option<u64>,
}

/// The `RateLimit-*` headers of an answer: the limit closest to being exhausted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    /// `RateLimit-Limit`: requests allowed in the window.
    pub limit: u64,
    /// `RateLimit-Remaining`: requests left in the window.
    pub remaining: u64,
    /// `RateLimit-Reset`: seconds until the window renews.
    pub reset_seconds: u64,
    /// `RateLimit-Policy`, e.g. `100;w=60`.
    pub policy: Option<String>,
}

impl ResponseMeta {
    fn from_headers(status: StatusCode, headers: &HeaderMap) -> Self {
        let text = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let number = |name: &str| text(name).and_then(|v| v.parse::<u64>().ok());
        let rate_limit = match (
            number("ratelimit-limit"),
            number("ratelimit-remaining"),
            number("ratelimit-reset"),
        ) {
            (Some(limit), Some(remaining), Some(reset_seconds)) => Some(RateLimit {
                limit,
                remaining,
                reset_seconds,
                policy: text("ratelimit-policy"),
            }),
            _ => None,
        };
        Self {
            status: status.as_u16(),
            request_id: text("x-request-id"),
            rate_limit,
            retry_after: number("retry-after"),
        }
    }
}

/// What the client reports about each request it sends, for `--verbose`. It carries no header and
/// no credential.
#[derive(Debug, Clone)]
pub struct RequestEvent<'a> {
    /// Always `GET`.
    pub method: &'static str,
    /// The URL, which never contains a credential.
    pub url: &'a Url,
    /// HTTP status of the answer.
    pub status: u16,
    /// `X-Request-Id` of the answer.
    pub request_id: Option<&'a str>,
    /// Time to the response headers.
    pub elapsed: Duration,
}

type Observer = Arc<dyn Fn(&RequestEvent<'_>) + Send + Sync>;
type Renew = Arc<dyn Fn() -> Option<SecretString> + Send + Sync>;

/// Builds a [`Client`].
pub struct ClientBuilder {
    base_url: Url,
    credential: SecretString,
    user_agent: String,
    timeout: Duration,
    max_rate_limit_retries: u32,
    max_retry_wait: Duration,
    observer: Option<Observer>,
    renew: Option<Renew>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url.as_str())
            .field("credential", &"[REDACTED]")
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// The `User-Agent` header. Defaults to `hodeishield-api/<version>`.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Timeout of each request. Defaults to 30 s.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many times a `429` is retried after its `Retry-After`, and the longest wait accepted.
    /// Defaults to 2 retries of at most 60 s. A longer `Retry-After` is returned as an error.
    #[must_use]
    pub fn rate_limit_retries(mut self, retries: u32, max_wait: Duration) -> Self {
        self.max_rate_limit_retries = retries;
        self.max_retry_wait = max_wait;
        self
    }

    /// Called after every request, including retried ones.
    #[must_use]
    pub fn observer(
        mut self,
        observer: impl Fn(&RequestEvent<'_>) + Send + Sync + 'static,
    ) -> Self {
        self.observer = Some(Arc::new(observer));
        self
    }

    /// Called at most once per request, when the API answers `401`: a credential it returns
    /// replaces the refused one for this and later requests, and the request is sent again. For an
    /// OAuth access token the app ended before it expired; a refresh gives a new one.
    #[must_use]
    pub fn renew_credential(
        mut self,
        renew: impl Fn() -> Option<SecretString> + Send + Sync + 'static,
    ) -> Self {
        self.renew = Some(Arc::new(renew));
        self
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`Error::InsecureBaseUrl`] when the base URL is not `https` (plain `http` is accepted only for
    /// a loopback host), [`Error::InvalidBaseUrl`] when it cannot carry a path, and
    /// [`Error::Transport`] when the HTTP stack cannot be initialised.
    pub fn build(self) -> Result<Client, Error> {
        check_base_url(&self.base_url)?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut http = reqwest::blocking::Client::builder();
        if is_loopback_host(&self.base_url) {
            // Plain http is accepted for loopback only because it never leaves the machine; a
            // proxy from the environment would carry the credential elsewhere in clear.
            http = http.no_proxy();
        }
        let http = http
            .user_agent(self.user_agent)
            .default_headers(headers)
            .timeout(self.timeout)
            .connect_timeout(Duration::from_secs(10))
            // `/v1` does not redirect. Refusing to follow means a credential is never replayed to
            // wherever a redirect points.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!is_loopback_host(&self.base_url))
            .build()
            .map_err(Error::Transport)?;
        Ok(Client {
            http,
            base_url: self.base_url,
            credential: Mutex::new(self.credential),
            max_rate_limit_retries: self.max_rate_limit_retries,
            max_retry_wait: self.max_retry_wait,
            observer: self.observer,
            renew: self.renew,
        })
    }
}

/// A `/v1` client bound to one base URL and one credential (a tenant API key or an OAuth access
/// token). The operations are generated: see the methods documented on this type.
pub struct Client {
    http: reqwest::blocking::Client,
    base_url: Url,
    credential: Mutex<SecretString>,
    max_rate_limit_retries: u32,
    max_retry_wait: Duration,
    observer: Option<Observer>,
    renew: Option<Renew>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url.as_str())
            .field("credential", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client with the default settings.
    ///
    /// # Errors
    ///
    /// See [`ClientBuilder::build`].
    pub fn new(base_url: Url, credential: SecretString) -> Result<Self, Error> {
        Self::builder(base_url, credential).build()
    }

    /// A builder, to change the defaults.
    #[must_use]
    pub fn builder(base_url: Url, credential: SecretString) -> ClientBuilder {
        ClientBuilder {
            base_url,
            credential,
            user_agent: concat!("hodeishield-api/", env!("CARGO_PKG_VERSION")).to_owned(),
            timeout: Duration::from_secs(30),
            max_rate_limit_retries: 2,
            max_retry_wait: Duration::from_secs(60),
            observer: None,
            renew: None,
        }
    }

    /// The base URL requests are sent to.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn url(&self, path: &str, query: &[(&'static str, String)]) -> Url {
        let mut url = self.base_url.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}{path}"));
        url.set_query(None);
        url.set_fragment(None);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        url
    }

    fn authorization(&self) -> Result<HeaderValue, Error> {
        let credential = self
            .credential
            .lock()
            .map_err(|_| Error::InvalidCredential)?;
        let mut value = HeaderValue::from_str(&format!("Bearer {}", credential.expose_secret()))
            .map_err(|_| Error::InvalidCredential)?;
        // Keeps the value out of `Debug` output of the request and out of HTTP/2 header compression
        // tables.
        value.set_sensitive(true);
        Ok(value)
    }

    pub(crate) fn get<T: DeserializeOwned>(
        &self,
        operation: &'static Operation,
        path: String,
        query: Vec<(&'static str, String)>,
    ) -> Result<ApiResponse<T>, Error> {
        let url = self.url(&path, &query);
        let mut retries = 0;
        let mut renewed = false;
        loop {
            let started = Instant::now();
            let response = self
                .http
                .get(url.clone())
                .header(AUTHORIZATION, self.authorization()?)
                .send()
                .map_err(Error::Transport)?;
            let status = response.status();
            let meta = ResponseMeta::from_headers(status, response.headers());
            if let Some(observer) = &self.observer {
                observer(&RequestEvent {
                    method: "GET",
                    url: &url,
                    status: meta.status,
                    request_id: meta.request_id.as_deref(),
                    elapsed: started.elapsed(),
                });
            }
            let body = read_body(response, MAX_RESPONSE_BYTES).map_err(Error::Body)?;
            if status.is_success() {
                let raw: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|source| Error::Decode {
                        operation: operation.id,
                        source,
                    })?;
                let data = T::deserialize(&raw).map_err(|source| Error::Decode {
                    operation: operation.id,
                    source,
                })?;
                return Ok(ApiResponse { data, raw, meta });
            }
            if status == StatusCode::TOO_MANY_REQUESTS
                && retries < self.max_rate_limit_retries
                && let Some(wait) = meta.retry_after.map(Duration::from_secs)
                && wait <= self.max_retry_wait
            {
                retries += 1;
                std::thread::sleep(wait);
                continue;
            }
            if status == StatusCode::UNAUTHORIZED
                && !renewed
                && let Some(renew) = &self.renew
            {
                renewed = true;
                if let Some(credential) = renew()
                    && let Ok(mut current) = self.credential.lock()
                {
                    *current = credential;
                    continue;
                }
            }
            return Err(Error::from_response(operation, meta, &body));
        }
    }
}

/// Largest answer body this client reads: far above any `/v1` page, well below what would strain
/// memory.
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Reads the body of `response`, failing once it is larger than `limit` bytes instead of buffering
/// the rest.
///
/// # Errors
/// An [`std::io::Error`] when the body cannot be read, or is larger than `limit`.
pub fn read_body(
    response: reqwest::blocking::Response,
    limit: u64,
) -> Result<Vec<u8>, std::io::Error> {
    let too_large = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the answer is larger than {limit} bytes"),
        )
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    response
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(body)
}

/// Whether the URL's host is `localhost` or a loopback address: the only hosts plain `http` is
/// accepted for.
#[must_use]
pub fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn check_base_url(url: &Url) -> Result<(), Error> {
    if url.cannot_be_a_base() || url.host().is_none() {
        return Err(Error::InvalidBaseUrl(url.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidBaseUrl(
            "the URL must not carry a user name or password".to_owned(),
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        _ => Err(Error::InsecureBaseUrl(url.to_string())),
    }
}

/// Percent-encodes one path segment (an id or a framework slug). Segments that URL parsers would
/// read as `.` or `..`, and empty ones, are refused rather than encoded: they would change which
/// resource is addressed.
///
/// # Errors
///
/// [`Error::InvalidPathArgument`] for an empty segment or one that is only dots.
pub fn encode_path_segment(segment: &str) -> Result<String, Error> {
    if segment.is_empty() || segment.chars().all(|c| c == '.') {
        return Err(Error::InvalidPathArgument(segment.to_owned()));
    }
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> Client {
        Client::new(base.parse().expect("url"), SecretString::from("hsk_test")).expect("client")
    }

    #[test]
    fn builds_urls_under_the_base_path() {
        let c = client("https://api.example.test/prefix/");
        let url = c.url(
            "/v1/vendors",
            &[("page", "2".to_owned()), ("q", "a b&c".to_owned())],
        );
        assert_eq!(
            url.as_str(),
            "https://api.example.test/prefix/v1/vendors?page=2&q=a+b%26c"
        );
        let url = client("https://api.example.test").url("/v1/vendors", &[]);
        assert_eq!(url.as_str(), "https://api.example.test/v1/vendors");
    }

    #[test]
    fn refuses_plain_http_except_loopback() {
        for insecure in ["http://api.example.test", "ftp://api.example.test"] {
            let err = Client::new(insecure.parse().expect("url"), SecretString::from("k"))
                .expect_err("insecure");
            assert!(matches!(err, Error::InsecureBaseUrl(_)), "{insecure}");
        }
        for loopback in [
            "http://localhost:8080",
            "http://127.0.0.1:1",
            "http://[::1]:2",
        ] {
            assert!(
                Client::new(loopback.parse().expect("url"), SecretString::from("k")).is_ok(),
                "{loopback}"
            );
        }
        let err = Client::new(
            "https://user:pw@api.example.test".parse().expect("url"),
            SecretString::from("k"),
        )
        .expect_err("userinfo");
        assert!(matches!(err, Error::InvalidBaseUrl(_)));
    }

    #[test]
    fn encodes_path_segments_and_refuses_dot_segments() {
        assert_eq!(
            encode_path_segment("9b2c-AF_~x").expect("plain"),
            "9b2c-AF_~x"
        );
        assert_eq!(
            encode_path_segment("a/b?c#d").expect("reserved"),
            "a%2Fb%3Fc%23d"
        );
        assert_eq!(encode_path_segment("a.b").expect("dot inside"), "a.b");
        for bad in ["", ".", "..", "..."] {
            assert!(encode_path_segment(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn debug_never_shows_the_credential() {
        let c = client("https://api.example.test");
        let shown = format!("{c:?}");
        assert!(!shown.contains("hsk_test"), "{shown}");
    }
}
