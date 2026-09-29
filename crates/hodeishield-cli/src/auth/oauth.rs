//! OAuth 2.0 client for signing in to the app: discovery (RFC 8414, with OpenID Connect discovery as
//! fallback), authorization code with PKCE (RFC 7636) over a loopback redirect (RFC 8252), device
//! authorization (RFC 8628), refresh, and revocation (RFC 7009).
//!
//! No endpoint is written here: every URL comes from the metadata the app publishes.

use crate::failure::{Failure, Kind, Result, error_chain};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

/// The parts of the authorization server metadata this client uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Url,
    #[serde(default)]
    pub device_authorization_endpoint: Option<Url>,
    #[serde(default)]
    pub revocation_endpoint: Option<Url>,
    #[serde(default)]
    pub userinfo_endpoint: Option<Url>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
}

/// Asks for a refresh token, so a sign-in outlives its short access token.
const OFFLINE_ACCESS: &str = "offline_access";

/// The scopes to ask for when the profile names none: the ones the `/v1` operations this CLI calls
/// need, with a template such as `compliance.<framework>:read` standing for every scope of that
/// shape the app offers, plus a refresh token. An app that publishes no list gets the fixed ones.
/// Asking explicitly matters: an app may grant a request without scopes nothing at all.
pub fn default_scopes(metadata: &Metadata) -> Vec<String> {
    let offered = metadata.scopes_supported.as_deref();
    let mut scopes: Vec<String> = Vec::new();
    let needed = hodeishield_api::v1::operations::ALL
        .iter()
        .flat_map(|operation| operation.scopes.iter().copied())
        .chain([OFFLINE_ACCESS]);
    for scope in needed {
        let matches: Vec<String> = match (scope.split_once('<'), offered) {
            (Some((prefix, rest)), Some(offered)) => {
                let suffix = rest.split_once('>').map_or("", |(_, suffix)| suffix);
                // Only a slug fills the template: the app's list must not be able to slip another
                // scope (a write one, say) into the space-separated request.
                offered
                    .iter()
                    .filter(|s| {
                        s.len() > prefix.len() + suffix.len()
                            && s.starts_with(prefix)
                            && s.ends_with(suffix)
                            && s[prefix.len()..s.len() - suffix.len()]
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    })
                    .cloned()
                    .collect()
            }
            // A template means nothing to an app that does not say what it offers.
            (Some(_), None) => Vec::new(),
            (None, Some(offered)) if !offered.iter().any(|s| s == scope) => Vec::new(),
            (None, _) => vec![scope.to_owned()],
        };
        for s in matches {
            if !scopes.contains(&s) {
                scopes.push(s);
            }
        }
    }
    scopes
}

/// HTTP client for the app: no redirects, https only unless the app is on loopback.
pub fn http_client(app_url: &Url) -> Result<reqwest::blocking::Client> {
    let mut builder = reqwest::blocking::Client::builder();
    if hodeishield_api::is_loopback_host(app_url) {
        // Loopback over plain http must stay on this machine, not go through a proxy.
        builder = builder.no_proxy();
    }
    builder
        .user_agent(crate::USER_AGENT)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!hodeishield_api::is_loopback_host(app_url))
        .build()
        .map_err(|e| {
            Failure::general(format!(
                "Cannot start the HTTP client: {}.",
                error_chain(&e)
            ))
        })
}

fn unreachable(what: &str, error: &reqwest::Error) -> Failure {
    Failure::new(
        Kind::Unavailable,
        format!(
            "Could not reach the app for {what}: {}.",
            error_chain(error)
        ),
    )
}

/// The well-known URL for `suffix` under `issuer` (RFC 8414 §3.1: inserted after the host, before
/// any path of the issuer).
fn well_known(issuer: &Url, suffix: &str) -> Url {
    let mut url = issuer.clone();
    let path = issuer.path().trim_end_matches('/');
    url.set_path(&format!("/.well-known/{suffix}{path}"));
    url.set_query(None);
    url.set_fragment(None);
    url
}

/// The parts of the protected resource metadata (RFC 9728) this client uses.
#[derive(Debug, Deserialize)]
struct ResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// The issuer of the tokens `api_url` accepts: the first authorization server its protected
/// resource metadata (RFC 9728) names on the app's origin. The API says where on the app sign-in
/// lives; the profile's `app_url` decides which server the CLI is willing to sign in to at all.
/// Without that document, the app itself is the issuer.
pub fn authorization_server(
    http: &reqwest::blocking::Client,
    api_url: &Url,
    app_url: &Url,
) -> Result<Url> {
    let url = well_known(api_url, "oauth-protected-resource");
    let response = http
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|e| unreachable("sign-in", &e))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(app_url.clone());
    }
    if !status.is_success() {
        return Err(Failure::new(
            Kind::Unavailable,
            format!("The API answered {status} to {url}."),
        ));
    }
    let metadata: ResourceMetadata = response.json().map_err(|e| {
        Failure::general(format!(
            "The API's resource metadata at {url} is not valid: {e}."
        ))
    })?;
    // RFC 9728 §3.3: the resource must be the one the metadata was fetched for.
    let resource = Url::parse(&metadata.resource)
        .map_err(|_| Failure::general("The API's resource metadata names an invalid resource."))?;
    if !same_url(&resource, api_url) {
        return Err(Failure::general(format!(
            "The API's resource metadata is for {} but was fetched from {api_url}.",
            metadata.resource
        )));
    }
    metadata
        .authorization_servers
        .iter()
        .filter_map(|server| Url::parse(server).ok())
        .find(|server| {
            same_origin(server, app_url)
                && server.username().is_empty()
                && server.password().is_none()
        })
        .ok_or_else(|| {
            Failure::general(format!(
                "The API at {api_url} does not name a sign-in server on {app_url}.",
            ))
            .hint("Check `api_url` and `app_url` with `hodeishield config show`.")
        })
}

/// Reads the authorization server metadata of `issuer`.
pub fn discover(http: &reqwest::blocking::Client, app_url: &Url) -> Result<Metadata> {
    let mut not_published = Vec::new();
    for suffix in ["oauth-authorization-server", "openid-configuration"] {
        let url = well_known(app_url, suffix);
        let response = http
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(|e| unreachable("sign-in", &e))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            not_published.push(url.to_string());
            continue;
        }
        if !status.is_success() {
            return Err(Failure::new(
                Kind::Unavailable,
                format!("The app answered {status} to {url}."),
            ));
        }
        let metadata: Metadata = response.json().map_err(|e| {
            Failure::general(format!(
                "The app's sign-in metadata at {url} is not valid: {e}."
            ))
        })?;
        validate(&metadata, app_url)?;
        return Ok(metadata);
    }
    Err(Failure::general(format!(
        "{} does not offer sign-in for the CLI yet (no OAuth metadata at {}).",
        app_url.host_str().unwrap_or("the app"),
        not_published.join(" or ")
    ))
    .hint("Use a tenant API key meanwhile: export HODEISHIELD_API_KEY=<key>."))
}

fn validate(metadata: &Metadata, app_url: &Url) -> Result<()> {
    // RFC 8414 §3.3: the issuer must be the URL the metadata was fetched for. Anything else could be
    // metadata of another server replayed here.
    let issuer = Url::parse(&metadata.issuer)
        .map_err(|_| Failure::general("The app's sign-in metadata has an invalid issuer."))?;
    if !same_url(&issuer, app_url) {
        return Err(Failure::general(format!(
            "The app's sign-in metadata names issuer {} but was fetched from {app_url}.",
            metadata.issuer
        )));
    }
    let loopback = hodeishield_api::is_loopback_host(app_url);
    let endpoints = [
        metadata.authorization_endpoint.as_ref(),
        Some(&metadata.token_endpoint),
        metadata.device_authorization_endpoint.as_ref(),
        metadata.revocation_endpoint.as_ref(),
        metadata.userinfo_endpoint.as_ref(),
    ];
    for endpoint in endpoints.into_iter().flatten() {
        let secure = endpoint.scheme() == "https"
            || (loopback
                && endpoint.scheme() == "http"
                && hodeishield_api::is_loopback_host(endpoint));
        if !secure {
            return Err(Failure::general(format!(
                "The app's sign-in metadata lists an endpoint that is not https: {endpoint}."
            )));
        }
    }
    if let Some(methods) = &metadata.code_challenge_methods_supported
        && !methods.iter().any(|m| m == "S256")
    {
        return Err(Failure::general(
            "The app does not support PKCE with S256, which this CLI requires.",
        ));
    }
    Ok(())
}

fn same_url(a: &Url, b: &Url) -> bool {
    same_origin(a, b) && a.path().trim_end_matches('/') == b.path().trim_end_matches('/')
}

pub fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Random URL-safe string from `bytes` bytes of the operating system's generator.
pub fn random_token(bytes: usize) -> Result<String> {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|e| Failure::general(format!("No secure random source: {e}.")))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// A PKCE verifier and its S256 challenge.
#[derive(Debug)]
pub struct Pkce {
    pub verifier: SecretString,
    pub challenge: String,
}

impl Pkce {
    pub fn new() -> Result<Self> {
        // 32 bytes → 43 characters, the minimum RFC 7636 allows and plenty of entropy.
        let verifier = random_token(32)?;
        Ok(Self::from_verifier(verifier))
    }

    pub fn from_verifier(verifier: String) -> Self {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Self {
            verifier: SecretString::from(verifier),
            challenge,
        }
    }
}

/// A token endpoint answer.
#[derive(Debug)]
pub struct TokenSet {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl OAuthError {
    fn describe(&self) -> String {
        match &self.error_description {
            Some(d) if !d.is_empty() => format!("{} ({d})", self.error),
            _ => self.error.clone(),
        }
    }
}

/// What the token endpoint said: tokens, or a protocol error the caller may want to branch on
/// (`authorization_pending`, `slow_down`, `invalid_grant`, …).
pub enum TokenOutcome {
    Tokens(TokenSet),
    Error(OAuthError),
}

pub fn token_request(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    form: &[(&str, &str)],
) -> Result<TokenOutcome> {
    let response = http
        .post(metadata.token_endpoint.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .map_err(|e| unreachable("sign-in", &e))?;
    let status = response.status();
    let body = response.bytes().map_err(|e| unreachable("sign-in", &e))?;
    if status.is_success() {
        let wire: TokenWire = serde_json::from_slice(&body)
            .map_err(|_| Failure::general("The app's token answer is not valid."))?;
        if !wire.token_type.eq_ignore_ascii_case("bearer") {
            return Err(Failure::general(format!(
                "The app issued a `{}` token; this CLI only uses bearer tokens.",
                wire.token_type
            )));
        }
        return Ok(TokenOutcome::Tokens(TokenSet {
            access_token: SecretString::from(wire.access_token),
            refresh_token: wire.refresh_token.map(SecretString::from),
            expires_in: wire.expires_in,
            scope: wire.scope,
        }));
    }
    match serde_json::from_slice::<OAuthError>(&body) {
        Ok(error) => Ok(TokenOutcome::Error(error)),
        Err(_) => Err(Failure::new(
            if status.is_server_error() {
                Kind::Unavailable
            } else {
                Kind::General
            },
            format!("The app's token endpoint answered {status}."),
        )),
    }
}

fn expect_tokens(outcome: TokenOutcome, what: &str) -> Result<TokenSet> {
    match outcome {
        TokenOutcome::Tokens(tokens) => Ok(tokens),
        TokenOutcome::Error(error) => Err(Failure::new(
            Kind::NotAuthenticated,
            format!("{what} failed: {}.", error.describe()),
        )),
    }
}

/// The URL to send the browser to, for an authorization code with PKCE.
pub fn authorization_url(
    metadata: &Metadata,
    client_id: &str,
    redirect_uri: &str,
    scopes: Option<&[String]>,
    state: &str,
    pkce: &Pkce,
) -> Result<Url> {
    let mut url = metadata.authorization_endpoint.clone().ok_or_else(|| {
        Failure::general("The app does not offer browser sign-in.")
            .hint("Try `hodeishield login --device`.")
    })?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(scopes) = scopes {
            query.append_pair("scope", &scopes.join(" "));
        }
    }
    Ok(url)
}

pub fn exchange_code(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    client_id: &str,
    code: &SecretString,
    redirect_uri: &str,
    pkce: &Pkce,
) -> Result<TokenSet> {
    let outcome = token_request(
        http,
        metadata,
        &[
            ("grant_type", "authorization_code"),
            ("code", code.expose_secret()),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", pkce.verifier.expose_secret()),
        ],
    )?;
    expect_tokens(outcome, "Signing in")
}

/// Refreshes an access token. `Ok(None)` means the refresh token is no longer valid
/// (`invalid_grant`): the session is over and a new sign-in is needed.
pub fn refresh(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    client_id: &str,
    refresh_token: &SecretString,
) -> Result<Option<TokenSet>> {
    let outcome = token_request(
        http,
        metadata,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
            ("client_id", client_id),
        ],
    )?;
    match outcome {
        TokenOutcome::Tokens(tokens) => Ok(Some(tokens)),
        TokenOutcome::Error(error) if error.error == "invalid_grant" => Ok(None),
        TokenOutcome::Error(error) => Err(Failure::new(
            Kind::NotAuthenticated,
            format!("Refreshing the sign-in failed: {}.", error.describe()),
        )),
    }
}

/// What the app said to a revocation.
#[derive(Debug, PartialEq, Eq)]
pub enum Revocation {
    Revoked,
    /// The app does not know the token: already ended, or never its. RFC 7009 answers 200 for that;
    /// some apps answer 400 `invalid_request` or `invalid_token`. The detail says which.
    Unknown(String),
}

/// Revokes a token (RFC 7009).
pub fn revoke(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    client_id: &str,
    token: &SecretString,
    hint: &str,
) -> Result<Revocation> {
    let Some(endpoint) = metadata.revocation_endpoint.clone() else {
        return Err(Failure::general("The app does not offer token revocation."));
    };
    let response = http
        .post(endpoint)
        .form(&[
            ("token", token.expose_secret()),
            ("token_type_hint", hint),
            ("client_id", client_id),
        ])
        .send()
        .map_err(|e| unreachable("revocation", &e))?;
    let status = response.status();
    if status.is_success() {
        return Ok(Revocation::Revoked);
    }
    let error = response
        .bytes()
        .ok()
        .and_then(|body| serde_json::from_slice::<OAuthError>(&body).ok());
    let what = hint.replace('_', " ");
    match error {
        Some(error)
            if status == reqwest::StatusCode::BAD_REQUEST
                && matches!(error.error.as_str(), "invalid_request" | "invalid_token") =>
        {
            Ok(Revocation::Unknown(format!(
                "the app does not know the {what}: {}",
                error.describe()
            )))
        }
        error => Err(Failure::general(format!(
            "the app refused to revoke the {what}: {}",
            error.map_or_else(|| format!("HTTP {status}"), |e| e.describe())
        ))),
    }
}

/// Device authorization answer (RFC 8628 §3.2).
#[derive(Debug, Deserialize)]
pub struct DeviceAuthorization {
    device_code: SecretString,
    pub user_code: String,
    pub verification_uri: Url,
    #[serde(default)]
    pub verification_uri_complete: Option<Url>,
    pub expires_in: u64,
    #[serde(default)]
    pub interval: Option<u64>,
}

pub fn start_device(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    client_id: &str,
    scopes: Option<&[String]>,
) -> Result<DeviceAuthorization> {
    let endpoint = metadata
        .device_authorization_endpoint
        .clone()
        .ok_or_else(|| {
            Failure::general("The app does not offer sign-in with a device code.")
                .hint("Run `hodeishield login` without --device on a machine with a browser.")
        })?;
    let joined = scopes.map(|s| s.join(" "));
    let mut form = vec![("client_id", client_id)];
    if let Some(scope) = joined.as_deref() {
        form.push(("scope", scope));
    }
    let response = http
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .map_err(|e| unreachable("sign-in", &e))?;
    let status = response.status();
    let body = response.bytes().map_err(|e| unreachable("sign-in", &e))?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<OAuthError>(&body)
            .map_or_else(|_| format!("HTTP {status}"), |e| e.describe());
        return Err(Failure::general(format!(
            "The app refused a device code: {detail}."
        )));
    }
    let authorization: DeviceAuthorization = serde_json::from_slice(&body)
        .map_err(|_| Failure::general("The app's device code answer is not valid."))?;
    for uri in [
        Some(&authorization.verification_uri),
        authorization.verification_uri_complete.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if uri.scheme() != "https" && !hodeishield_api::is_loopback_host(uri) {
            return Err(Failure::general(format!(
                "The app gave a verification address that is not https: {uri}."
            )));
        }
    }
    Ok(authorization)
}

/// Longest a device code is waited for, whatever the server says.
const MAX_DEVICE_LIFETIME: u64 = 3_600;

/// Polls the token endpoint until the user approves or denies the device code, or it expires.
pub fn poll_device(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    client_id: &str,
    authorization: &DeviceAuthorization,
    sleep: &mut dyn FnMut(Duration),
    now: &dyn Fn() -> std::time::Instant,
) -> Result<TokenSet> {
    // The server's numbers are bounded: a code lives at most an hour, and polling is between once a
    // second and once a minute, so a hostile answer can neither overflow the clock nor hang the CLI.
    let deadline = now() + Duration::from_secs(authorization.expires_in.min(MAX_DEVICE_LIFETIME));
    let mut interval = Duration::from_secs(authorization.interval.unwrap_or(5).clamp(1, 60));
    loop {
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            return Err(expired());
        }
        sleep(interval.min(remaining));
        let outcome = token_request(
            http,
            metadata,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", authorization.device_code.expose_secret()),
                ("client_id", client_id),
            ],
        )?;
        match outcome {
            TokenOutcome::Tokens(tokens) => return Ok(tokens),
            TokenOutcome::Error(error) => match error.error.as_str() {
                "authorization_pending" => {}
                // RFC 8628 §3.5: add 5 seconds to the interval for this and every later request.
                "slow_down" => {
                    interval = (interval + Duration::from_secs(5)).min(Duration::from_secs(60));
                }
                "access_denied" => {
                    return Err(Failure::new(
                        Kind::NotAuthenticated,
                        "Sign-in was denied in the browser.",
                    ));
                }
                "expired_token" => return Err(expired()),
                _ => {
                    return Err(Failure::new(
                        Kind::NotAuthenticated,
                        format!("Sign-in failed: {}.", error.describe()),
                    ));
                }
            },
        }
    }
}

fn expired() -> Failure {
    Failure::new(
        Kind::NotAuthenticated,
        "The device code expired before it was approved.",
    )
    .hint("Run `hodeishield login --device` again and approve the new code in time.")
}

/// The signed-in user, when the app offers OpenID Connect `userinfo`.
pub fn userinfo(
    http: &reqwest::blocking::Client,
    metadata: &Metadata,
    access_token: &SecretString,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let Some(endpoint) = metadata.userinfo_endpoint.clone() else {
        return Ok(None);
    };
    let response = http
        .get(endpoint)
        .bearer_auth(access_token.expose_secret())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .map_err(|e| unreachable("the user profile", &e))?;
    if !response.status().is_success() {
        return Ok(None);
    }
    Ok(response.json().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc_7636_appendix_b() {
        let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned());
        assert_eq!(
            pkce.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let fresh = Pkce::new().expect("pkce");
        assert_eq!(fresh.verifier.expose_secret().len(), 43);
    }

    #[test]
    fn well_known_goes_before_the_issuer_path() {
        let root: Url = "https://app.example.test".parse().expect("url");
        assert_eq!(
            well_known(&root, "oauth-authorization-server").as_str(),
            "https://app.example.test/.well-known/oauth-authorization-server"
        );
        let tenant: Url = "https://app.example.test/auth/".parse().expect("url");
        assert_eq!(
            well_known(&tenant, "openid-configuration").as_str(),
            "https://app.example.test/.well-known/openid-configuration/auth"
        );
    }

    fn metadata(issuer: &str) -> Metadata {
        serde_json::from_value(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": "https://app.example.test/oauth/authorize",
            "token_endpoint": "https://app.example.test/oauth/token",
        }))
        .expect("metadata")
    }

    fn resource_metadata(api: &mut mockito::ServerGuard, body: serde_json::Value) {
        api.mock("GET", "/.well-known/oauth-protected-resource")
            .with_body(body.to_string())
            .create();
    }

    #[test]
    fn the_api_names_where_on_the_app_to_sign_in() {
        let mut api = mockito::Server::new();
        let app: Url = "https://app.example.test".parse().expect("url");
        let api_url: Url = api.url().parse().expect("url");
        resource_metadata(
            &mut api,
            serde_json::json!({
                "resource": api_url.as_str(),
                "authorization_servers": ["https://other.example.test/auth", "https://app.example.test/api/auth"],
            }),
        );
        let http = http_client(&api_url).expect("http");
        let issuer = authorization_server(&http, &api_url, &app).expect("issuer");
        assert_eq!(issuer.as_str(), "https://app.example.test/api/auth");
    }

    #[test]
    fn without_resource_metadata_the_app_is_the_issuer() {
        let mut api = mockito::Server::new();
        api.mock("GET", "/.well-known/oauth-protected-resource")
            .with_status(404)
            .create();
        let app: Url = "https://app.example.test".parse().expect("url");
        let api_url: Url = api.url().parse().expect("url");
        let http = http_client(&api_url).expect("http");
        assert_eq!(
            authorization_server(&http, &api_url, &app).expect("issuer"),
            app
        );
    }

    #[test]
    fn resource_metadata_of_another_resource_or_server_is_refused() {
        let app: Url = "https://app.example.test".parse().expect("url");

        let mut replayed = mockito::Server::new();
        resource_metadata(
            &mut replayed,
            serde_json::json!({
                "resource": "https://api.example.test",
                "authorization_servers": ["https://app.example.test/api/auth"],
            }),
        );
        let api_url: Url = replayed.url().parse().expect("url");
        let http = http_client(&api_url).expect("http");
        let err = authorization_server(&http, &api_url, &app).expect_err("other resource");
        assert!(err.message.contains("was fetched from"), "{}", err.message);

        let mut elsewhere = mockito::Server::new();
        let elsewhere_url = elsewhere.url();
        resource_metadata(
            &mut elsewhere,
            serde_json::json!({
                "resource": elsewhere_url,
                "authorization_servers": ["https://app.evil.example.test/api/auth"],
            }),
        );
        let api_url: Url = elsewhere.url().parse().expect("url");
        let err = authorization_server(&http, &api_url, &app).expect_err("other server");
        assert!(
            err.message.contains("does not name a sign-in server"),
            "{}",
            err.message
        );

        // Credentials in the server's URL would travel to the app as a Basic header.
        let mut with_credentials = mockito::Server::new();
        let with_credentials_url = with_credentials.url();
        resource_metadata(
            &mut with_credentials,
            serde_json::json!({
                "resource": with_credentials_url,
                "authorization_servers": ["https://user:pass@app.example.test/api/auth"],
            }),
        );
        let api_url: Url = with_credentials_url.parse().expect("url");
        assert!(authorization_server(&http, &api_url, &app).is_err());
    }

    #[test]
    fn default_scopes_are_what_the_commands_need_among_what_the_app_offers() {
        let mut offered = metadata("https://app.example.test");
        offered.scopes_supported = Some(
            [
                "supply_risk:read",
                "compliance.nis2:read",
                "compliance.ens:read",
                "radar:read",
                "evidence:read",
                "endpoints:read",
                "management:read",
                "offline_access",
            ]
            .map(str::to_owned)
            .to_vec(),
        );
        assert_eq!(
            default_scopes(&offered),
            [
                "supply_risk:read",
                "compliance.nis2:read",
                "compliance.ens:read",
                "evidence:read",
                "endpoints:read",
                "offline_access",
            ]
        );

        // Only a slug fills a template: an offered entry cannot smuggle more scopes into the request.
        let mut hostile = metadata("https://app.example.test");
        hostile.scopes_supported = Some(
            [
                "compliance.x:read management:write radar:read",
                "compliance.:read",
                "compliance.a.b:read",
                "compliance.ok_1-2:read",
            ]
            .map(str::to_owned)
            .to_vec(),
        );
        assert_eq!(default_scopes(&hostile), ["compliance.ok_1-2:read"]);

        // An app that does not publish its scopes gets the fixed ones; a template stands for none.
        assert_eq!(
            default_scopes(&metadata("https://app.example.test")),
            [
                "supply_risk:read",
                "evidence:read",
                "endpoints:read",
                "offline_access"
            ]
        );
    }

    #[test]
    fn validation_checks_issuer_scheme_and_pkce() {
        let app: Url = "https://app.example.test".parse().expect("url");
        assert!(validate(&metadata("https://app.example.test/"), &app).is_ok());
        assert!(validate(&metadata("https://evil.example.test"), &app).is_err());

        let mut insecure = metadata("https://app.example.test");
        insecure.token_endpoint = "http://app.example.test/token".parse().expect("url");
        assert!(validate(&insecure, &app).is_err());

        let mut plain_only = metadata("https://app.example.test");
        plain_only.code_challenge_methods_supported = Some(vec!["plain".to_owned()]);
        assert!(validate(&plain_only, &app).is_err());
    }

    #[test]
    fn the_authorization_url_carries_pkce_and_state() {
        let pkce = Pkce::from_verifier("v".repeat(43));
        let url = authorization_url(
            &metadata("https://app.example.test"),
            "cli",
            "http://127.0.0.1:5000/callback",
            Some(&["a:read".to_owned(), "b:read".to_owned()]),
            "st",
            &pkce,
        )
        .expect("url");
        let pairs: std::collections::BTreeMap<String, String> =
            url.query_pairs().into_owned().collect();
        assert_eq!(pairs["response_type"], "code");
        assert_eq!(pairs["code_challenge_method"], "S256");
        assert_eq!(pairs["code_challenge"], pkce.challenge);
        assert_eq!(pairs["state"], "st");
        assert_eq!(pairs["scope"], "a:read b:read");
        assert!(
            !url.as_str().contains(&"v".repeat(43)),
            "the verifier never leaves the machine"
        );
    }

    fn app_metadata(server: &mockito::Server) -> Metadata {
        serde_json::from_value(serde_json::json!({
            "issuer": server.url(),
            "token_endpoint": format!("{}/token", server.url()),
            "device_authorization_endpoint": format!("{}/device", server.url()),
        }))
        .expect("metadata")
    }

    #[test]
    fn device_flow_waits_slows_down_and_gets_tokens() {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/device")
            .match_body(mockito::Matcher::UrlEncoded("client_id".into(), "cli".into()))
            .with_body(r#"{"device_code":"dc_secret","user_code":"ABCD-EFGH","verification_uri":"https://app.example.test/device","expires_in":600,"interval":2}"#)
            .create();
        let device_grant = mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded(
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
            ),
            mockito::Matcher::UrlEncoded("device_code".into(), "dc_secret".into()),
        ]);
        let pending = server
            .mock("POST", "/token")
            .match_body(device_grant.clone())
            .with_status(400)
            .with_body(r#"{"error":"authorization_pending"}"#)
            .expect(1)
            .create();
        let http = http_client(&server.url().parse().expect("url")).expect("http");
        let metadata = app_metadata(&server);
        let authorization = start_device(&http, &metadata, "cli", None).expect("device");
        assert_eq!(authorization.user_code, "ABCD-EFGH");
        assert!(!format!("{authorization:?}").contains("dc_secret"));

        let mut waits = Vec::new();
        let mut calls = 0;
        let clock = std::time::Instant::now();
        // The mocks are swapped from inside the sleep, which runs before each poll.
        let mut server_ref = Some(server);
        let mut later = Vec::new();
        let result = poll_device(
            &http,
            &metadata,
            "cli",
            &authorization,
            &mut |d| {
                waits.push(d.as_secs());
                calls += 1;
                let server = server_ref.as_mut().expect("server");
                if calls == 2 {
                    pending.remove();
                    later.push(
                        server
                            .mock("POST", "/token")
                            .match_body(device_grant.clone())
                            .with_status(400)
                            .with_body(r#"{"error":"slow_down"}"#)
                            .expect(1)
                            .create(),
                    );
                }
                if calls == 3 {
                    for m in later.drain(..) {
                        m.remove();
                    }
                    server
                        .mock("POST", "/token")
                        .with_body(r#"{"access_token":"at","token_type":"bearer","refresh_token":"rt","expires_in":900}"#)
                        .create();
                }
            },
            &|| clock,
        )
        .expect("tokens");
        assert_eq!(waits, [2, 2, 7], "slow_down adds five seconds");
        assert_eq!(result.access_token.expose_secret(), "at");
        assert_eq!(result.expires_in, Some(900));
    }

    #[test]
    fn device_flow_reports_denial_and_expiry() {
        let mut server = mockito::Server::new();
        let http = http_client(&server.url().parse().expect("url")).expect("http");
        let metadata = app_metadata(&server);
        let authorization: DeviceAuthorization = serde_json::from_str(
            r#"{"device_code":"d","user_code":"U","verification_uri":"https://app.example.test/d","expires_in":60}"#,
        )
        .expect("authorization");
        for (error, expected) in [("access_denied", "denied"), ("expired_token", "expired")] {
            let mock = server
                .mock("POST", "/token")
                .with_status(400)
                .with_body(format!(r#"{{"error":"{error}"}}"#))
                .create();
            let clock = std::time::Instant::now();
            let err = poll_device(
                &http,
                &metadata,
                "cli",
                &authorization,
                &mut |_| {},
                &|| clock,
            )
            .expect_err("fails");
            assert!(err.message.contains(expected), "{}", err.message);
            mock.remove();
        }
        // A deadline already past: no request at all.
        let clock = std::time::Instant::now();
        let never = server.mock("POST", "/token").expect(0).create();
        let expired: DeviceAuthorization = serde_json::from_str(
            r#"{"device_code":"d","user_code":"U","verification_uri":"https://app.example.test/d","expires_in":0}"#,
        )
        .expect("authorization");
        assert!(poll_device(&http, &metadata, "cli", &expired, &mut |_| {}, &|| clock).is_err());
        never.assert();
    }

    #[test]
    fn a_non_bearer_token_is_refused() {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/token")
            .with_body(r#"{"access_token":"at","token_type":"mac"}"#)
            .create();
        let http = http_client(&server.url().parse().expect("url")).expect("http");
        let pkce = Pkce::from_verifier("v".repeat(43));
        let err = exchange_code(
            &http,
            &app_metadata(&server),
            "cli",
            &SecretString::from("code"),
            "http://127.0.0.1:1/callback",
            &pkce,
        )
        .expect_err("mac token");
        assert!(err.message.contains("bearer"));
    }

    #[test]
    fn hostile_device_timings_are_bounded() {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"authorization_pending"}"#)
            .create();
        let http = http_client(&server.url().parse().expect("url")).expect("http");
        let metadata = app_metadata(&server);
        let authorization: DeviceAuthorization = serde_json::from_str(&format!(
            r#"{{"device_code":"d","user_code":"U","verification_uri":"https://app.example.test/d","expires_in":{},"interval":{}}}"#,
            u64::MAX,
            u64::MAX
        ))
        .expect("authorization");
        let start = std::time::Instant::now();
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let mut waits = Vec::new();
        let err = poll_device(
            &http,
            &metadata,
            "cli",
            &authorization,
            &mut |d| {
                waits.push(d);
                elapsed.set(elapsed.get() + d);
            },
            &|| start + elapsed.get(),
        )
        .expect_err("expires");
        assert!(err.message.contains("expired"), "{}", err.message);
        assert!(waits.iter().all(|w| *w <= Duration::from_secs(60)));
        assert!(elapsed.get() <= Duration::from_secs(MAX_DEVICE_LIFETIME));
    }
}
