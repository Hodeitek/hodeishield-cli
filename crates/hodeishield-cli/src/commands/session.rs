//! `login`, `logout` and `whoami`.

use super::Context;
use crate::auth::oauth::{self, Pkce};
use crate::auth::{self, StoredToken, loopback::Loopback};
use crate::cli::LoginArgs;
use crate::config::DEFAULT_OAUTH_CLIENT_ID;
use crate::failure::{CredentialSource, Failure, Result};
use crate::output::{clean, print_json, unix_to_rfc3339};
use serde_json::{Map, Value, json};
use std::io::Write;
use std::time::{Duration, Instant};

const BROWSER_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub fn login(ctx: &Context, args: &LoginArgs) -> Result<()> {
    let settings = ctx.settings()?;
    let Some(client_id) = settings.oauth_client_id.clone() else {
        return Err(Failure::general(
            "Signing in from the CLI is not available yet: the app has not published the CLI's OAuth client.",
        )
        .hint(
            "Use a tenant API key meanwhile: export HODEISHIELD_API_KEY=<key>. If you were given a \
             client id for a preview, set it with `hodeishield config set oauth_client_id <id>`.",
        ));
    };
    if DEFAULT_OAUTH_CLIENT_ID.is_none() {
        eprintln!(
            "Preview: CLI sign-in depends on OAuth support in the app that is still being rolled \
             out. The API may not accept the resulting token yet."
        );
    }
    let http = oauth::http_client(&settings.app_url)?;
    let metadata = oauth::discover(&http, &settings.app_url)?;
    let scopes = settings.oauth_scopes.as_deref();

    let tokens = if args.device {
        let authorization = oauth::start_device(&http, &metadata, &client_id, scopes)?;
        eprintln!(
            "To sign in, open {} and enter the code:\n\n    {}\n",
            authorization.verification_uri,
            clean(&authorization.user_code)
        );
        if let Some(complete) = &authorization.verification_uri_complete {
            eprintln!("Or open this address, which carries the code: {complete}");
        }
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
        issuer: settings.app_url.as_str().trim_end_matches('/').to_owned(),
        api_url: settings.api_url.as_str().trim_end_matches('/').to_owned(),
        client_id,
    };
    ctx.store.save(&settings.profile, &token)?;
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
    // Revoke at the app that issued the token, never at whatever the profile points to now: the
    // tokens themselves travel in the revocation request.
    let revoked = (|| -> Result<()> {
        let issuer = url::Url::parse(&token.issuer)
            .map_err(|_| Failure::general("The stored sign-in names an invalid issuer."))?;
        let http = oauth::http_client(&issuer)?;
        let metadata = oauth::discover(&http, &issuer)?;
        if let Some(refresh) = &token.refresh_token {
            oauth::revoke(&http, &metadata, &token.client_id, refresh, "refresh_token")?;
        }
        oauth::revoke(
            &http,
            &metadata,
            &token.client_id,
            &token.access_token,
            "access_token",
        )
    })();
    store.delete(&settings.profile)?;
    eprintln!(
        "Signed out (profile {}); the token is removed from this machine.",
        settings.profile
    );
    if let Err(failure) = revoked {
        eprintln!(
            "Warning: the app did not confirm the revocation ({}). Revoke the CLI's access from \
             the app's settings if you need it cut off now.",
            failure.message
        );
    }
    if auth::api_key_from_env().is_some() {
        eprintln!("Note: {} is still set in this shell.", auth::API_KEY_ENV);
    }
    Ok(())
}

pub fn whoami(ctx: &Context, out: &mut dyn Write) -> Result<()> {
    let settings = ctx.settings()?;
    let mut info = Map::new();
    info.insert("profile".into(), json!(settings.profile));
    info.insert("api_url".into(), json!(settings.api_url.as_str()));
    info.insert("app_url".into(), json!(settings.app_url.as_str()));

    let source = if auth::api_key_from_env().is_some() {
        Some(CredentialSource::ApiKey)
    } else {
        let existing = auth::current_token(&settings, ctx.store.as_ref())
            .map_err(|failure| auth::explain_store_failure(failure, &settings))?;
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
                let user = oauth::http_client(&settings.app_url)
                    .and_then(|http| {
                        let metadata = oauth::discover(&http, &settings.app_url)?;
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

    if ctx.json {
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
        None => Err(auth::not_signed_in(&settings)),
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
    use crate::config::{ConfigFile, Overrides, resolve_with};
    use secrecy::SecretString;

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
}
