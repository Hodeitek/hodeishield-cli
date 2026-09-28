//! Credentials: a tenant API key from the environment, or a sign-in token from the keychain.

pub mod loopback;
pub mod oauth;
pub mod store;

use crate::config::Settings;
use crate::failure::{CredentialSource, Failure, Kind, Result};
use secrecy::SecretString;
use std::time::{SystemTime, UNIX_EPOCH};
pub use store::{StoredToken, TokenStore};

pub const API_KEY_ENV: &str = "HODEISHIELD_API_KEY";

/// Refresh this many seconds before the access token expires, so it does not expire in flight.
const EXPIRY_MARGIN: u64 = 60;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The tenant API key in `HODEISHIELD_API_KEY`, if set.
pub fn api_key_from_env() -> Option<SecretString> {
    std::env::var(API_KEY_ENV)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .map(SecretString::from)
}

/// The credential for an API call: the environment's API key, else the profile's sign-in token,
/// refreshed if it is about to expire.
pub fn credential_for_api(
    settings: &Settings,
    store: &dyn TokenStore,
) -> Result<(SecretString, CredentialSource)> {
    if let Some(key) = api_key_from_env() {
        return Ok((key, CredentialSource::ApiKey));
    }
    let token = match current_token(settings, store) {
        Ok(Some(token)) => token,
        Ok(None) => return Err(not_signed_in(settings)),
        Err(failure) => return Err(explain_store_failure(failure, settings)),
    };
    // A sign-in token only goes to the API it was obtained for: a changed profile, environment or
    // `--api-url` must not be able to send it elsewhere.
    let api = settings.api_url.as_str().trim_end_matches('/');
    if token.api_url.trim_end_matches('/') != api {
        return Err(Failure::new(
            Kind::NotAuthenticated,
            format!(
                "This profile's sign-in is for {}, not {api}, and is not sent anywhere else.",
                token.api_url
            ),
        )
        .hint(format!(
            "Use {API_KEY_ENV} for that API, or sign in again with it configured: \
             `hodeishield logout`, then `hodeishield login`."
        )));
    }
    Ok((token.access_token, CredentialSource::OAuth))
}

pub fn not_signed_in(settings: &Settings) -> Failure {
    let profile = if settings.profile == crate::config::DEFAULT_PROFILE {
        String::new()
    } else {
        format!(" --profile {}", settings.profile)
    };
    Failure::new(
        Kind::NotAuthenticated,
        "No credential: not signed in and HODEISHIELD_API_KEY is not set.",
    )
    .hint(format!(
        "Set a tenant API key (export {API_KEY_ENV}=<key>) or run `hodeishield{profile} login`."
    ))
}

/// Turns a raw store failure into words about what to do, when the underlying reason is that this
/// machine has no keychain to sign in to. Any other store failure (a corrupt entry, say) passes
/// through unchanged: it already says what happened.
pub fn explain_store_failure(failure: Failure, settings: &Settings) -> Failure {
    if failure.message.starts_with(store::KEYCHAIN_UNAVAILABLE) {
        not_signed_in(settings).hint(format!(
            "Set a tenant API key: export {API_KEY_ENV}=<key>. Signing in is not possible on \
             this machine: {}.",
            failure.message
        ))
    } else {
        failure
    }
}

/// The profile's sign-in token, refreshed when needed. `None` when not signed in.
pub fn current_token(settings: &Settings, store: &dyn TokenStore) -> Result<Option<StoredToken>> {
    let Some(token) = store.load(&settings.profile)? else {
        return Ok(None);
    };
    let app = settings.app_url.as_str().trim_end_matches('/');
    if token.issuer.trim_end_matches('/') != app {
        return Err(Failure::new(
            Kind::NotAuthenticated,
            format!(
                "This profile is signed in to {}, but now points to {app}.",
                token.issuer
            ),
        )
        .hint("Run `hodeishield logout` and `hodeishield login` again."));
    }
    if !token.expires_within(now(), EXPIRY_MARGIN) {
        return Ok(Some(token));
    }
    refresh_stored(settings, store, token).map(Some)
}

fn refresh_stored(
    settings: &Settings,
    store: &dyn TokenStore,
    token: StoredToken,
) -> Result<StoredToken> {
    let expired = || {
        Failure::new(
            Kind::NotAuthenticated,
            "Your sign-in has expired or was revoked.",
        )
        .hint("Run `hodeishield login` again.")
    };
    let Some(refresh_token) = token.refresh_token.clone() else {
        store.delete(&settings.profile)?;
        return Err(expired());
    };
    let http = oauth::http_client(&settings.app_url)?;
    let metadata = oauth::discover(&http, &settings.app_url)?;
    match oauth::refresh(&http, &metadata, &token.client_id, &refresh_token)? {
        Some(tokens) => {
            let renewed = StoredToken {
                access_token: tokens.access_token,
                // A server that does not rotate refresh tokens keeps the old one valid.
                refresh_token: tokens.refresh_token.or(Some(refresh_token)),
                expires_at: tokens.expires_in.map(|s| now().saturating_add(s)),
                scope: tokens.scope.or(token.scope),
                issuer: token.issuer,
                api_url: token.api_url,
                client_id: token.client_id,
            };
            store.save(&settings.profile, &renewed)?;
            Ok(renewed)
        }
        None => {
            store.delete(&settings.profile)?;
            Err(expired())
        }
    }
}

/// Whether a stored token is the one that would be sent, for `whoami`.
pub fn describe_source(source: CredentialSource) -> &'static str {
    match source {
        CredentialSource::ApiKey => "tenant API key (HODEISHIELD_API_KEY)",
        CredentialSource::OAuth => "sign-in token in the system keychain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::store::MemoryStore;
    use crate::config::{ConfigFile, Overrides, resolve_with};
    use secrecy::ExposeSecret;

    fn settings(app: &str) -> Settings {
        let env = |name: &str| (name == "HODEISHIELD_APP_URL").then(|| app.to_owned());
        resolve_with(
            &ConfigFile::default(),
            std::path::PathBuf::new(),
            &Overrides::default(),
            env,
        )
        .expect("settings")
    }

    fn token(issuer: &str, expires_at: Option<u64>, refresh: Option<&str>) -> StoredToken {
        StoredToken {
            access_token: SecretString::from("at_old"),
            refresh_token: refresh.map(|r| SecretString::from(r.to_owned())),
            expires_at,
            scope: None,
            issuer: issuer.to_owned(),
            api_url: "https://api.hodeishield.com".to_owned(),
            client_id: "cli".to_owned(),
        }
    }

    fn metadata_body(server: &mockito::Server) -> String {
        serde_json::json!({
            "issuer": server.url(),
            "authorization_endpoint": format!("{}/oauth/authorize", server.url()),
            "token_endpoint": format!("{}/oauth/token", server.url()),
        })
        .to_string()
    }

    #[test]
    fn a_fresh_token_is_used_without_calling_the_app() {
        let store = MemoryStore::default();
        let s = settings("https://app.example.test");
        store
            .save(
                "default",
                &token("https://app.example.test/", Some(now() + 3_600), None),
            )
            .expect("save");
        let t = current_token(&s, &store).expect("ok").expect("token");
        assert_eq!(t.access_token.expose_secret(), "at_old");
    }

    #[test]
    fn a_token_is_only_sent_to_the_api_it_was_obtained_for() {
        let store = MemoryStore::default();
        store
            .save(
                "default",
                &token("https://app.example.test", Some(now() + 3_600), None),
            )
            .expect("save");
        let good = settings("https://app.example.test");
        assert!(credential_for_api(&good, &store).is_ok());
        let mut elsewhere = good.clone();
        elsewhere.api_url = "https://api.evil.example.test".parse().expect("url");
        let err = credential_for_api(&elsewhere, &store).expect_err("other api");
        assert_eq!(err.kind, Kind::NotAuthenticated);
    }

    #[test]
    fn a_token_for_another_app_is_refused() {
        let store = MemoryStore::default();
        store
            .save("default", &token("https://other.example.test", None, None))
            .expect("save");
        let err =
            current_token(&settings("https://app.example.test"), &store).expect_err("mismatch");
        assert_eq!(err.kind, Kind::NotAuthenticated);
    }

    #[test]
    fn an_expiring_token_is_refreshed_and_saved() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(metadata_body(&server))
            .create();
        let refresh = server
            .mock("POST", "/oauth/token")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("grant_type".into(), "refresh_token".into()),
                mockito::Matcher::UrlEncoded("refresh_token".into(), "rt_1".into()),
                mockito::Matcher::UrlEncoded("client_id".into(), "cli".into()),
            ]))
            .with_body(r#"{"access_token":"at_new","token_type":"Bearer","expires_in":600}"#)
            .create();
        let s = settings(&server.url());
        let store = MemoryStore::default();
        store
            .save(
                "default",
                &token(&server.url(), Some(now() + 10), Some("rt_1")),
            )
            .expect("save");
        let t = current_token(&s, &store).expect("ok").expect("token");
        refresh.assert();
        assert_eq!(t.access_token.expose_secret(), "at_new");
        let saved = store.load("default").expect("load").expect("saved");
        assert_eq!(saved.access_token.expose_secret(), "at_new");
        assert_eq!(
            saved
                .refresh_token
                .map(|r| r.expose_secret().to_owned())
                .as_deref(),
            Some("rt_1")
        );
    }

    #[test]
    fn a_revoked_refresh_token_signs_out() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/.well-known/oauth-authorization-server")
            .with_body(metadata_body(&server))
            .create();
        server
            .mock("POST", "/oauth/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant"}"#)
            .create();
        let s = settings(&server.url());
        let store = MemoryStore::default();
        store
            .save(
                "default",
                &token(&server.url(), Some(1), Some("rt_revoked")),
            )
            .expect("save");
        let err = current_token(&s, &store).expect_err("revoked");
        assert_eq!(err.kind, Kind::NotAuthenticated);
        assert!(
            store.load("default").expect("load").is_none(),
            "the dead token is removed"
        );
    }
}
