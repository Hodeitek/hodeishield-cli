// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! `login`, `logout` and `whoami`.

use super::Context;
use crate::auth::oauth::{self, Pkce, Revocation};
use crate::auth::{self, StoredToken, loopback::Loopback};
use crate::cli::LoginArgs;
use crate::failure::{CredentialSource, Failure, Result};
use crate::output::{clean, print_json, unix_to_rfc3339};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::time::{Duration, Instant};

const BROWSER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub fn login(ctx: &Context, args: &LoginArgs) -> Result<()> {
    login_with(&ctx.settings()?, ctx.store.as_ref(), args)
}

fn login_with(
    settings: &crate::config::Settings,
    store: &dyn auth::TokenStore,
    args: &LoginArgs,
) -> Result<()> {
    // Before anything is asked of the person or the app: a session that cannot be kept is not
    // worth approving.
    store.check_available(&settings.profile)?;
    let client_id = settings.oauth_client_id.clone();
    let issuer = oauth::authorization_server(
        &oauth::http_client(&settings.api_url)?,
        &settings.api_url,
        &settings.app_url,
    )?;
    let http = oauth::http_client(&issuer)?;
    let metadata = oauth::discover(&http, &issuer)?;
    let scopes = settings
        .oauth_scopes
        .clone()
        .unwrap_or_else(|| oauth::default_scopes(&metadata));
    let scopes = Some(scopes.as_slice()).filter(|s| !s.is_empty());

    let tokens = if args.device {
        let authorization = oauth::start_device(&http, &metadata, &client_id, scopes)?;
        eprintln!(
            "To sign in, open {} and enter the code:\n\n    {}\n",
            authorization.verification_uri,
            clean(&authorization.user_code)
        );
        eprintln!(
            "Waiting for approval (the code expires in {} min)…",
            authorization.expires_in.div_ceil(60)
        );
        oauth::poll_device(
            &http,
            &metadata,
            &client_id,
            &authorization,
            &mut std::thread::sleep,
            &Instant::now,
        )?
    } else {
        let loopback = Loopback::bind()?;
        let pkce = Pkce::new()?;
        let state = oauth::random_token(24)?;
        let url = oauth::authorization_url(
            &metadata,
            &client_id,
            loopback.redirect_uri(),
            scopes,
            &state,
            &pkce,
        )?;
        let opened = !args.no_browser && webbrowser::open(url.as_str()).is_ok();
        if opened {
            eprintln!("Opened your browser to sign in. If nothing happened, open:\n\n    {url}\n");
        } else {
            eprintln!("Open this address in a browser on this machine to sign in:\n\n    {url}\n");
        }
        eprintln!(
            "Waiting for the browser (up to {} min)…",
            BROWSER_TIMEOUT.as_secs() / 60
        );
        let callback = loopback.wait(
            &state,
            &metadata.issuer,
            metadata.authorization_response_iss_parameter_supported == Some(true),
            BROWSER_TIMEOUT,
        )?;
        oauth::exchange_code(
            &http,
            &metadata,
            &client_id,
            &callback.code,
            loopback.redirect_uri(),
            &pkce,
        )?
    };

    let token = StoredToken {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_in.map(|s| auth::now().saturating_add(s)),
        scope: tokens.scope,
        issuer: issuer.as_str().trim_end_matches('/').to_owned(),
        api_url: settings.api_url.as_str().trim_end_matches('/').to_owned(),
        client_id,
    };
    if let Err(failure) = store.save(&settings.profile, &token) {
        // The grant exists at the app although nothing holds it: end it before reporting.
        let revoked = revoke_tokens(
            &http,
            &metadata,
            &token.client_id,
            &token.access_token,
            token.refresh_token.as_ref(),
        );
        eprintln!("{}", unstored_notice(&revoked));
        return Err(if failure.hint.is_some() {
            failure
        } else {
            failure.hint(format!(
                "Use a tenant API key instead: export {}=<key>.",
                auth::API_KEY_ENV
            ))
        });
    }
    let who = oauth::userinfo(&http, &metadata, &token.access_token)
        .ok()
        .flatten()
        .and_then(|info| user_label(&info));
    eprintln!(
        "Signed in to {}{} (profile {}).",
        settings.app_url.host_str().unwrap_or("the app"),
        who.map_or_else(String::new, |w| format!(" as {w}")),
        settings.profile
    );
    if auth::api_key_from_env().is_some() {
        eprintln!(
            "Note: {} is set in this shell and takes precedence for API calls.",
            auth::API_KEY_ENV
        );
    }
    Ok(())
}

/// What to tell the person when the session could not be kept, given how revoking it went.
fn unstored_notice(revoked: &Result<()>) -> String {
    match revoked {
        Ok(()) => "The session could not be stored on this machine; the tokens issued for it were \
                   revoked."
            .to_owned(),
        Err(revocation) => format!(
            "The session could not be stored on this machine, and the app did not confirm \
             revoking the tokens issued for it ({}). Revoke the CLI's access in the app under \
             \"Application access\".",
            clean(&revocation.message)
        ),
    }
}

pub fn logout(ctx: &Context) -> Result<()> {
    logout_with(&ctx.settings()?, ctx.store.as_ref())
}

fn logout_with(settings: &crate::config::Settings, store: &dyn auth::TokenStore) -> Result<()> {
    let Some(token) = store.load(&settings.profile)? else {
        eprintln!("Not signed in (profile {}).", settings.profile);
        return Ok(());
    };
    // Revoke at the app first, so a copy of the token elsewhere stops working too; then forget it
    // here whatever the app said.
    let revoked = revoke_at_issuer(&token);
    store.delete(&settings.profile)?;
    eprintln!(
        "Signed out (profile {}); the token is removed from this machine.",
        settings.profile
    );
    if let Err(failure) = revoked {
        eprintln!(
            "Warning: the app did not confirm the revocation ({}). Revoke the CLI's access from \
             the app's settings if you need it cut off now.",
            clean(&failure.message)
        );
    }
    if auth::api_key_from_env().is_some() {
        eprintln!("Note: {} is still set in this shell.", auth::API_KEY_ENV);
    }
    Ok(())
}

pub fn whoami(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    whoami_with(
        &settings,
        auth::api_key_from_env().is_some(),
        ctx.store.as_ref(),
        ctx.json,
        out,
    )
}

/// `whoami` with the settings and whether an API key is set given, so it can be tested without the
/// process environment. With a key, the store is not read.
fn whoami_with(
    settings: &crate::config::Settings,
    has_api_key: bool,
    store: &dyn auth::TokenStore,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let mut info = Map::new();
    info.insert("profile".into(), json!(settings.profile));
    info.insert("api_url".into(), json!(settings.api_url.as_str()));
    info.insert("app_url".into(), json!(settings.app_url.as_str()));

    let source = if has_api_key {
        Some(CredentialSource::ApiKey)
    } else {
        let existing = auth::current_token(settings, store).map_err(auth::explain_store_failure)?;
        match existing {
            Some(token) => {
                info.insert("issuer".into(), json!(token.issuer));
                info.insert(
                    "expires_at".into(),
                    token
                        .expires_at
                        .map_or(Value::Null, |t| json!(unix_to_rfc3339(t))),
                );
                info.insert("scope".into(), json!(token.scope));
                let user = auth::issuer_url(&token)
                    .and_then(|issuer| {
                        let http = oauth::http_client(&issuer)?;
                        let metadata = oauth::discover(&http, &issuer)?;
                        oauth::userinfo(&http, &metadata, &token.access_token)
                    })
                    .ok()
                    .flatten()
                    .and_then(|u| user_label(&u));
                info.insert("user".into(), json!(user));
                Some(CredentialSource::OAuth)
            }
            None => None,
        }
    };
    info.insert(
        "credential".into(),
        json!(source.map(|s| match s {
            CredentialSource::ApiKey => "api_key",
            CredentialSource::OAuth => "oauth",
        })),
    );

    if json {
        print_json(out, &Value::Object(info))?;
    } else {
        let mut rows = vec![
            ("Profile", settings.profile.clone()),
            ("API", settings.api_url.to_string()),
            ("App", settings.app_url.to_string()),
            (
                "Credential",
                source.map_or_else(
                    || "none".to_owned(),
                    |s| auth::describe_source(s).to_owned(),
                ),
            ),
        ];
        for (label, key) in [
            ("Issuer", "issuer"),
            ("Expires", "expires_at"),
            ("Scopes", "scope"),
            ("User", "user"),
        ] {
            if let Some(Value::String(value)) = info.get(key) {
                rows.push((label, clean(value)));
            }
        }
        for (label, value) in rows {
            writeln!(out, "{label:<11} {value}")?;
        }
    }
    match source {
        Some(_) => Ok(()),
        None => Err(auth::not_signed_in(settings)),
    }
}

/// Revokes a stored sign-in at the app that issued it, never at whatever the profile points to
/// now: the tokens themselves travel in the requests.
///
/// The refresh token first, then the access token, each whatever happened to the other. An access
/// token the app no longer knows (one that already expired, say) is not a failure; a refresh token it
/// does not know, or any other refusal, is reported.
fn revoke_at_issuer(token: &StoredToken) -> Result<()> {
    let issuer = auth::issuer_url(token)?;
    let http = oauth::http_client(&issuer)?;
    let metadata = oauth::discover(&http, &issuer)?;
    revoke_tokens(
        &http,
        &metadata,
        &token.client_id,
        &token.access_token,
        token.refresh_token.as_ref(),
    )
}

/// The revocation requests themselves (RFC 7009), refresh token first so it cannot mint another
/// access token while the first is being ended.
fn revoke_tokens(
    http: &reqwest::blocking::Client,
    metadata: &oauth::Metadata,
    client_id: &str,
    access_token: &secrecy::SecretString,
    refresh_token: Option<&secrecy::SecretString>,
) -> Result<()> {
    let refresh = refresh_token
        .map(|refresh| oauth::revoke(http, metadata, client_id, refresh, "refresh_token"));
    let access = oauth::revoke(http, metadata, client_id, access_token, "access_token");
    // In request order (refresh token, then access token); the same text twice is said once, which
    // is what a missing revocation endpoint produces.
    let mut problems: Vec<String> = Vec::new();
    let mut report = |problem: String| {
        if !problems.contains(&problem) {
            problems.push(problem);
        }
    };
    match refresh {
        Some(Ok(Revocation::Unknown(detail))) => report(detail),
        Some(Err(failure)) => report(failure.message),
        Some(Ok(Revocation::Revoked)) | None => {}
    }
    if let Err(failure) = access {
        report(failure.message);
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(Failure::general(problems.join("; ")))
    }
}

/// `Name <email>`, or whichever of them the app gave, or the subject.
fn user_label(info: &Map<String, Value>) -> Option<String> {
    let get = |key: &str| {
        info.get(key)
            .and_then(Value::as_str)
            .map(clean)
            .filter(|s| !s.is_empty())
    };
    match (get("name"), get("email")) {
        (Some(name), Some(email)) => Some(format!("{name} <{email}>")),
        (name, email) => name.or(email).or_else(|| get("sub")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenStore;
    use crate::auth::store::MemoryStore;
    use crate::cli::LoginArgs;
    use crate::config::{ConfigFile, Overrides, resolve_with};
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn logout_revokes_at_the_issuer_not_at_the_app_configured_now() {
        let mut issuer = mockito::Server::new();
        let mut elsewhere = mockito::Server::new();
        issuer
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(
                json!({
                    "issuer": issuer.url(),
                    "token_endpoint": format!("{}/token", issuer.url()),
                    "revocation_endpoint": format!("{}/revoke", issuer.url()),
                })
                .to_string(),
            )
            .create();
        let revoked = issuer.mock("POST", "/revoke").expect(2).create();
        let never = elsewhere
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create();
        let never_post = elsewhere
            .mock("POST", mockito::Matcher::Any)
            .expect(0)
            .create();

        let app_now = elsewhere.url();
        let env = |name: &str| (name == "HODEISHIELD_APP_URL").then(|| app_now.clone());
        let settings = resolve_with(
            &ConfigFile::default(),
            std::path::PathBuf::new(),
            &Overrides::default(),
            env,
        )
        .expect("settings");
        let store = MemoryStore::default();
        store
            .save(
                "default",
                &StoredToken {
                    access_token: SecretString::from("at"),
                    refresh_token: Some(SecretString::from("rt")),
                    expires_at: None,
                    scope: None,
                    issuer: issuer.url(),
                    api_url: "https://api.hodeishield.com".to_owned(),
                    client_id: "cli".to_owned(),
                },
            )
            .expect("save");
        logout_with(&settings, &store).expect("logout");
        revoked.assert();
        never.assert();
        never_post.assert();
        assert!(store.load("default").expect("load").is_none());
    }

    #[test]
    fn logout_revokes_only_the_profile_s_own_tokens() {
        let mut issuer = mockito::Server::new();
        issuer
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(
                json!({
                    "issuer": issuer.url(),
                    "token_endpoint": format!("{}/token", issuer.url()),
                    "revocation_endpoint": format!("{}/revoke", issuer.url()),
                })
                .to_string(),
            )
            .create();
        let mut revocations = Vec::new();
        for (hint, token) in [("access_token", "at-a"), ("refresh_token", "rt-a")] {
            revocations.push(
                issuer
                    .mock("POST", "/revoke")
                    .match_body(mockito::Matcher::AllOf(vec![
                        mockito::Matcher::UrlEncoded("token_type_hint".into(), hint.into()),
                        mockito::Matcher::UrlEncoded("token".into(), token.into()),
                    ]))
                    .expect(1)
                    .create(),
            );
        }
        // Anything else, such as the other profile's tokens, would land here.
        let other = issuer
            .mock("POST", "/revoke")
            .with_status(500)
            .expect(0)
            .create();

        let mut config = ConfigFile::default();
        for name in ["client-a", "client-b"] {
            config.profiles.insert(name.to_owned(), Default::default());
        }
        let overrides = Overrides {
            profile: Some("client-a".to_owned()),
            api_url: None,
        };
        let settings = resolve_with(&config, std::path::PathBuf::new(), &overrides, |_| None)
            .expect("settings");
        let store = MemoryStore::default();
        for (profile, suffix) in [("client-a", "a"), ("client-b", "b")] {
            let mut token = signed_in(&issuer, Some(&format!("rt-{suffix}")));
            token.access_token = SecretString::from(format!("at-{suffix}"));
            store.save(profile, &token).expect("save");
        }

        logout_with(&settings, &store).expect("logout");
        for revocation in &revocations {
            revocation.assert();
        }
        other.assert();
        assert!(store.load("client-a").expect("load").is_none());
        let kept = store
            .load("client-b")
            .expect("load")
            .expect("still signed in");
        assert_eq!(kept.access_token.expose_secret(), "at-b");
    }

    fn signed_in(issuer: &mockito::ServerGuard, refresh: Option<&str>) -> StoredToken {
        StoredToken {
            access_token: SecretString::from("at"),
            refresh_token: refresh.map(|r| SecretString::from(r.to_owned())),
            expires_at: None,
            scope: None,
            issuer: issuer.url(),
            api_url: "https://api.hodeishield.com".to_owned(),
            client_id: "cli".to_owned(),
        }
    }

    fn revocation_server(access_status: usize, refresh_status: usize) -> mockito::ServerGuard {
        let mut issuer = mockito::Server::new();
        issuer
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(
                json!({
                    "issuer": issuer.url(),
                    "token_endpoint": format!("{}/token", issuer.url()),
                    "revocation_endpoint": format!("{}/revoke", issuer.url()),
                })
                .to_string(),
            )
            .create();
        for (hint, status) in [
            ("access_token", access_status),
            ("refresh_token", refresh_status),
        ] {
            issuer
                .mock("POST", "/revoke")
                .match_body(mockito::Matcher::UrlEncoded(
                    "token_type_hint".into(),
                    hint.into(),
                ))
                .with_status(status)
                .with_body(
                    r#"{"error":"invalid_request","error_description":"Invalid access token"}"#,
                )
                .expect(1)
                .create();
        }
        issuer
    }

    #[test]
    fn an_access_token_already_gone_does_not_fail_a_revoked_sign_in() {
        // The app answers 400 for an access token it already ended; revoking the refresh token is
        // what cuts the sign-in, and it succeeded.
        let issuer = revocation_server(400, 200);
        revoke_at_issuer(&signed_in(&issuer, Some("rt"))).expect("revoked");
    }

    #[test]
    fn a_refused_refresh_token_revocation_is_reported_with_the_app_s_reason() {
        let issuer = revocation_server(200, 400);
        let err = revoke_at_issuer(&signed_in(&issuer, Some("rt"))).expect_err("refused");
        assert!(
            err.message.contains("refresh token") && err.message.contains("invalid_request"),
            "{}",
            err.message
        );
    }

    #[test]
    fn an_access_token_revocation_that_failed_is_reported_even_if_the_refresh_one_worked() {
        let issuer = revocation_server(500, 200);
        let err = revoke_at_issuer(&signed_in(&issuer, Some("rt"))).expect_err("reported");
        assert!(err.message.contains("access token"), "{}", err.message);
    }

    #[test]
    fn without_a_refresh_token_the_access_token_revocation_decides() {
        let mut issuer = mockito::Server::new();
        issuer
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(
                json!({
                    "issuer": issuer.url(),
                    "token_endpoint": format!("{}/token", issuer.url()),
                    "revocation_endpoint": format!("{}/revoke", issuer.url()),
                })
                .to_string(),
            )
            .create();
        issuer.mock("POST", "/revoke").with_status(400).create();
        assert!(revoke_at_issuer(&signed_in(&issuer, None)).is_err());
    }

    #[test]
    fn a_missing_revocation_endpoint_is_reported_once_in_request_order() {
        let mut issuer = mockito::Server::new();
        issuer
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(
                json!({
                    "issuer": issuer.url(),
                    "token_endpoint": format!("{}/token", issuer.url()),
                })
                .to_string(),
            )
            .create();
        let err = revoke_at_issuer(&signed_in(&issuer, Some("rt"))).expect_err("no endpoint");
        assert_eq!(err.message, "The app does not offer token revocation.");

        // Different problems keep the order of the requests: refresh token first.
        let issuer = revocation_server(500, 500);
        let err = revoke_at_issuer(&signed_in(&issuer, Some("rt"))).expect_err("refused");
        let refresh = err.message.find("refresh token").expect("refresh");
        let access = err.message.find("access token").expect("access");
        assert!(refresh < access, "{}", err.message);
    }

    /// A store for the sign-in tests: it can be unreachable from the start, or fail on save.
    struct BrokenStore {
        available: bool,
    }

    impl TokenStore for BrokenStore {
        fn load(&self, _profile: &str) -> Result<Option<StoredToken>> {
            Ok(None)
        }

        fn save(&self, _profile: &str, _token: &StoredToken) -> Result<()> {
            Err(Failure::general("system keychain: cannot write"))
        }

        fn delete(&self, _profile: &str) -> Result<bool> {
            Ok(false)
        }

        fn check_available(&self, _profile: &str) -> Result<()> {
            if self.available {
                Ok(())
            } else {
                Err(Failure::general(format!(
                    "{}: no Secret Service",
                    crate::auth::store::KEYCHAIN_UNAVAILABLE
                ))
                .hint("use HODEISHIELD_API_KEY"))
            }
        }
    }

    fn settings_for(
        api: &mockito::ServerGuard,
        app: &mockito::ServerGuard,
    ) -> crate::config::Settings {
        let app = app.url();
        let env = |name: &str| (name == "HODEISHIELD_APP_URL").then(|| app.clone());
        let overrides = Overrides {
            profile: None,
            api_url: Some(api.url()),
        };
        resolve_with(
            &ConfigFile::default(),
            std::path::PathBuf::new(),
            &overrides,
            env,
        )
        .expect("settings")
    }

    /// A store whose keychain cannot be reached from this session; reading is the only thing it does.
    struct UnreachableStore;

    impl TokenStore for UnreachableStore {
        fn load(&self, _profile: &str) -> Result<Option<StoredToken>> {
            Err(crate::auth::store::read_failure(
                keyring_core::Error::NoStorageAccess("Windows ERROR_NO_SUCH_LOGON_SESSION".into()),
            ))
        }
        fn save(&self, _: &str, _: &StoredToken) -> Result<()> {
            unreachable!()
        }
        fn delete(&self, _: &str) -> Result<bool> {
            unreachable!()
        }
        fn check_available(&self, _: &str) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn whoami_with_an_unreachable_keychain_is_not_authenticated() {
        let (api, app) = (mockito::Server::new(), mockito::Server::new());
        let settings = settings_for(&api, &app);
        let mut out = Vec::new();
        let err = whoami_with(&settings, false, &UnreachableStore, false, &mut out)
            .expect_err("no credential");
        assert_eq!(err.kind, crate::failure::Kind::NotAuthenticated);
        assert!(
            err.message
                .starts_with("The system keychain is not available in this session"),
            "{}",
            err.message
        );
        assert!(
            err.hint.as_deref().is_some_and(
                |h| h.ends_with("In remote or automated sessions, set HODEISHIELD_API_KEY.")
            ),
            "{:?}",
            err.hint
        );
        assert!(out.is_empty(), "nothing is printed before the failure");
    }

    #[test]
    fn whoami_with_an_api_key_does_not_read_the_store() {
        let (api, app) = (mockito::Server::new(), mockito::Server::new());
        let settings = settings_for(&api, &app);
        let mut out = Vec::new();
        whoami_with(&settings, true, &UnreachableStore, true, &mut out).expect("key set");
        assert!(String::from_utf8(out).expect("utf8").contains("api_key"));
    }

    const DEVICE: LoginArgs = LoginArgs {
        device: true,
        no_browser: false,
    };

    /// An app that offers the device flow, issues `at-new` / `rt-new`, and revokes whatever it is
    /// asked to; the hints of the revocation requests are recorded in the order they arrive.
    fn device_app(
        api: &mut mockito::ServerGuard,
        app: &mut mockito::ServerGuard,
        revoke_status: usize,
    ) -> (
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        Vec<mockito::Mock>,
    ) {
        let revoked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&revoked);
        let url = app.url();
        let mocks = vec![
            api.mock("GET", "/.well-known/oauth-protected-resource")
                .with_status(404)
                .create(),
            app.mock("GET", "/.well-known/oauth-authorization-server")
                .with_body(
                    json!({
                        "issuer": url,
                        "token_endpoint": format!("{url}/token"),
                        "device_authorization_endpoint": format!("{url}/device/code"),
                        "revocation_endpoint": format!("{url}/revoke"),
                        "scopes_supported": ["offline_access"],
                    })
                    .to_string(),
                )
                .create(),
            app.mock("POST", "/device/code")
                .with_body(
                    json!({
                        "device_code": "dc", "user_code": "ABCD-EFGH",
                        "verification_uri": format!("{url}/device"),
                        "expires_in": 600, "interval": 1,
                    })
                    .to_string(),
                )
                .expect(1)
                .create(),
            app.mock("POST", "/token")
                .with_body(
                    json!({
                        "access_token": "at-new", "refresh_token": "rt-new",
                        "token_type": "Bearer", "expires_in": 3600,
                    })
                    .to_string(),
                )
                .expect(1)
                .create(),
            app.mock("POST", "/revoke")
                .with_body_from_request(move |request| {
                    let form: Vec<(String, String)> =
                        url::form_urlencoded::parse(request.body().expect("body"))
                            .into_owned()
                            .collect();
                    let get = |key: &str| {
                        form.iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default()
                    };
                    seen.lock().expect("lock").push(format!(
                        "{}={}",
                        get("token_type_hint"),
                        get("token")
                    ));
                    Vec::new()
                })
                .with_status(revoke_status)
                .expect(2)
                .create(),
        ];
        (revoked, mocks)
    }

    #[test]
    fn an_unavailable_store_stops_login_before_the_app_is_asked_for_anything() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let calls: Vec<_> = [&mut api, &mut app]
            .into_iter()
            .flat_map(|server| {
                ["GET", "POST"].map(|method| {
                    server
                        .mock(method, mockito::Matcher::Any)
                        .expect(0)
                        .create()
                })
            })
            .collect();
        let settings = settings_for(&api, &app);
        let err =
            login_with(&settings, &BrokenStore { available: false }, &DEVICE).expect_err("refused");
        assert!(
            err.message
                .starts_with(crate::auth::store::KEYCHAIN_UNAVAILABLE),
            "{}",
            err.message
        );
        assert!(err.hint.as_deref().is_some_and(|h| h.contains("API_KEY")));
        assert_eq!(format!("{:?}", err.kind), "General");
        for call in &calls {
            call.assert();
        }
    }

    #[test]
    fn tokens_that_cannot_be_stored_are_revoked_refresh_token_first() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let (revoked, mocks) = device_app(&mut api, &mut app, 200);
        let settings = settings_for(&api, &app);
        let err = login_with(&settings, &BrokenStore { available: true }, &DEVICE)
            .expect_err("save fails");
        assert_eq!(err.message, "system keychain: cannot write");
        assert!(err.hint.as_deref().is_some_and(|h| h.contains("API_KEY")));
        assert_eq!(
            *revoked.lock().expect("lock"),
            ["refresh_token=rt-new", "access_token=at-new"]
        );
        for mock in &mocks {
            mock.assert();
        }
        // Nothing the person sees carries a token.
        let notice = unstored_notice(&Ok(()));
        assert!(notice.contains("revoked"), "{notice}");
        let all = format!("{err:?} {notice}");
        assert!(!all.contains("-new"), "{all}");
    }

    #[test]
    fn a_failed_revocation_is_said_without_showing_any_token() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let (revoked, mocks) = device_app(&mut api, &mut app, 500);
        let settings = settings_for(&api, &app);
        let err = login_with(&settings, &BrokenStore { available: true }, &DEVICE)
            .expect_err("save fails");
        assert_eq!(err.message, "system keychain: cannot write");
        assert_eq!(revoked.lock().expect("lock").len(), 2);
        for mock in &mocks {
            mock.assert();
        }
        // The notice login prints is built from the same revocation result.
        let token = StoredToken {
            access_token: SecretString::from("at-new"),
            refresh_token: Some(SecretString::from("rt-new")),
            ..signed_in(&app, None)
        };
        let revocation = revoke_at_issuer(&token).expect_err("the app answered 500");
        let notice = unstored_notice(&Err(revocation));
        assert!(notice.contains("did not confirm"), "{notice}");
        let all = format!("{err:?} {} {notice}", err.message);
        for secret in ["at-new", "rt-new"] {
            assert!(!all.contains(secret), "{all}");
        }
    }

    #[test]
    fn the_notice_for_unrevoked_tokens_points_to_the_app() {
        let notice = unstored_notice(&Err(Failure::general("the app refused to revoke")));
        assert!(
            notice.contains("did not confirm") && notice.contains("Application access"),
            "{notice}"
        );
    }

    #[test]
    fn a_store_that_works_keeps_the_session_and_revokes_nothing() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let (revoked, mocks) = device_app(&mut api, &mut app, 200);
        let settings = settings_for(&api, &app);
        let store = MemoryStore::default();
        login_with(&settings, &store, &DEVICE).expect("signed in");
        let kept = store.load("default").expect("load").expect("stored");
        assert_eq!(kept.access_token.expose_secret(), "at-new");
        assert!(revoked.lock().expect("lock").is_empty());
        // The revocation mock is the last one: it was never reached.
        for mock in &mocks[..4] {
            mock.assert();
        }
    }

    #[test]
    fn login_finds_the_sign_in_server_through_the_api_and_asks_for_the_scopes_it_needs() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let issuer = format!("{}/api/auth", app.url());
        let resource = api
            .mock("GET", "/.well-known/oauth-protected-resource")
            .with_body(
                json!({ "resource": api.url(), "authorization_servers": [issuer] }).to_string(),
            )
            .expect(1)
            .create();
        // RFC 8414 §3.1: the issuer's path goes after the well-known segment.
        app.mock("GET", "/.well-known/oauth-authorization-server/api/auth")
            .with_body(
                json!({
                    "issuer": issuer,
                    "token_endpoint": format!("{issuer}/oauth2/token"),
                    "device_authorization_endpoint": format!("{issuer}/device/code"),
                    "scopes_supported": ["supply_risk:read", "compliance.nis2:read", "radar:read", "offline_access"],
                })
                .to_string(),
            )
            .create();
        let device = app
            .mock("POST", "/api/auth/device/code")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("client_id".into(), "hodeishield-cli".into()),
                mockito::Matcher::UrlEncoded(
                    "scope".into(),
                    "supply_risk:read compliance.nis2:read offline_access".into(),
                ),
            ]))
            .with_body(
                json!({
                    "device_code": "dc", "user_code": "ABCD-EFGH",
                    "verification_uri": format!("{}/device", app.url()),
                    "expires_in": 600, "interval": 1,
                })
                .to_string(),
            )
            .expect(1)
            .create();
        // Denied at the end, so nothing is stored.
        let token = app
            .mock("POST", "/api/auth/oauth2/token")
            .match_body(mockito::Matcher::UrlEncoded(
                "client_id".into(),
                "hodeishield-cli".into(),
            ))
            .with_status(400)
            .with_body(r#"{"error":"access_denied"}"#)
            .expect(1)
            .create();
        let settings = settings_for(&api, &app);
        let store = MemoryStore::default();
        let err = login_with(&settings, &store, &DEVICE).expect_err("denied");
        assert!(err.message.contains("denied"), "{}", err.message);
        assert_eq!(
            err.kind.exit_code(),
            crate::failure::Kind::NotAuthenticated.exit_code()
        );
        assert!(store.load("default").expect("load").is_none());
        resource.assert();
        device.assert();
        token.assert();
    }

    #[test]
    fn login_says_clearly_when_the_app_does_not_offer_it() {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        api.mock("GET", "/.well-known/oauth-protected-resource")
            .with_status(404)
            .create();
        app.mock("GET", mockito::Matcher::Regex("^/.well-known/".into()))
            .with_status(404)
            .expect(2)
            .create();
        let settings = settings_for(&api, &app);
        let err = login_with(&settings, &MemoryStore::default(), &DEVICE).expect_err("none");
        assert!(
            err.message
                .contains("does not offer sign-in for the CLI yet"),
            "{}",
            err.message
        );
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("HODEISHIELD_API_KEY"))
        );
        assert_eq!(err.kind, crate::failure::Kind::General);
    }
}
