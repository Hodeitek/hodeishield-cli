// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Where sign-in tokens are kept: the system keychain, and nowhere else.
//!
//! macOS Keychain, Windows Credential Manager, or the Secret Service on Linux and the BSDs (GNOME
//! Keyring, KWallet). If none is available, signing in fails: there is no fallback to a file.

use crate::failure::{Failure, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const SERVICE: &str = "hodeishield-cli";

/// Start of the message when there is no keychain to use.
pub const KEYCHAIN_UNAVAILABLE: &str = "the system keychain is not available";

/// A signed-in session for one profile.
#[derive(Debug, Clone)]
pub struct StoredToken {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    /// Unix seconds; `None` when the server did not say.
    pub expires_at: Option<u64>,
    pub scope: Option<String>,
    /// The authorization server that issued it (the app).
    pub issuer: String,
    /// The API it was obtained for. It is only ever sent there, whatever the profile says later.
    pub api_url: String,
    pub client_id: String,
}

/// The keychain payload. Plain strings live only for the instant of (de)serialisation.
#[derive(Serialize, Deserialize)]
struct Payload {
    v: u32,
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    issuer: String,
    api_url: String,
    client_id: String,
}

impl StoredToken {
    fn to_payload(&self) -> Payload {
        Payload {
            v: 1,
            access_token: self.access_token.expose_secret().to_owned(),
            refresh_token: self
                .refresh_token
                .as_ref()
                .map(|t| t.expose_secret().to_owned()),
            expires_at: self.expires_at,
            scope: self.scope.clone(),
            issuer: self.issuer.clone(),
            api_url: self.api_url.clone(),
            client_id: self.client_id.clone(),
        }
    }

    fn from_payload(payload: Payload) -> Self {
        Self {
            access_token: SecretString::from(payload.access_token),
            refresh_token: payload.refresh_token.map(SecretString::from),
            expires_at: payload.expires_at,
            scope: payload.scope,
            issuer: payload.issuer,
            api_url: payload.api_url,
            client_id: payload.client_id,
        }
    }

    /// Whether the access token is expired or will be within `margin` seconds.
    pub fn expires_within(&self, now: u64, margin: u64) -> bool {
        self.expires_at
            .is_some_and(|at| at <= now.saturating_add(margin))
    }
}

/// Storage for sign-in tokens, one per profile.
pub trait TokenStore {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>>;
    fn save(&self, profile: &str, token: &StoredToken) -> Result<()>;
    /// Whether there was something to delete.
    fn delete(&self, profile: &str) -> Result<bool>;
    /// Whether tokens can be kept for this profile, without writing anything. Sign-in checks it
    /// before it asks the person to approve anything.
    fn check_available(&self, profile: &str) -> Result<()>;
}

/// The system keychain.
#[derive(Debug, Default)]
pub struct Keychain;

static STORE_READY: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn ensure_store() -> Result<()> {
    STORE_READY
        .get_or_init(|| native_store().map(keyring_core::set_default_store))
        .clone()
        .map_err(|reason| unavailable(&reason))
}

fn unavailable(reason: &str) -> Failure {
    Failure::general(format!("{KEYCHAIN_UNAVAILABLE}: {reason}")).hint(unavailable_hint())
}

/// What to do about a missing keychain, for the platform this build runs on.
fn unavailable_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "Sign-in tokens are only kept in the system keychain. Allow access when the Keychain \
         prompt appears (or in Keychain Access), or use a tenant API key in HODEISHIELD_API_KEY \
         instead."
    } else if cfg!(windows) {
        "Sign-in tokens are only kept in the system keychain. Check that Windows Credential \
         Manager is available, or use a tenant API key in HODEISHIELD_API_KEY instead."
    } else {
        "Sign-in tokens are only kept in the system keychain. Start a Secret Service \
         (GNOME Keyring or KWallet); on a server without one, use a tenant API key in \
         HODEISHIELD_API_KEY instead."
    }
}

#[cfg(target_os = "macos")]
fn native_store() -> std::result::Result<std::sync::Arc<keyring_core::CredentialStore>, String> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
        .map_err(|e| e.to_string())
}

#[cfg(windows)]
fn native_store() -> std::result::Result<std::sync::Arc<keyring_core::CredentialStore>, String> {
    windows_native_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
        .map_err(|e| e.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn native_store() -> std::result::Result<std::sync::Arc<keyring_core::CredentialStore>, String> {
    zbus_secret_service_keyring_store::Store::new()
        .map(|s| s as std::sync::Arc<keyring_core::CredentialStore>)
        .map_err(|e| e.to_string())
}

#[cfg(not(any(unix, windows)))]
fn native_store() -> std::result::Result<std::sync::Arc<keyring_core::CredentialStore>, String> {
    Err("this platform has no supported keychain".to_owned())
}

fn entry(profile: &str) -> Result<keyring_core::Entry> {
    ensure_store()?;
    keyring_core::Entry::new(SERVICE, profile).map_err(keychain_failure)
}

fn keychain_failure(error: keyring_core::Error) -> Failure {
    // keyring errors describe the store, never the secret.
    Failure::general(format!("system keychain: {error}"))
}

impl TokenStore for Keychain {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        let entry = entry(profile)?;
        match entry.get_password() {
            Ok(text) => {
                let payload: Payload = serde_json::from_str(&text).map_err(|_| {
                    Failure::general("the sign-in stored in the system keychain is unreadable")
                        .hint("Run `hodeishield logout` and sign in again.")
                })?;
                Ok(Some(StoredToken::from_payload(payload)))
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(keychain_failure(e)),
        }
    }

    fn save(&self, profile: &str, token: &StoredToken) -> Result<()> {
        let text = serde_json::to_string(&token.to_payload())
            .map_err(|e| Failure::general(format!("cannot encode the sign-in: {e}")))?;
        entry(profile)?
            .set_password(&text)
            .map_err(keychain_failure)
    }

    fn delete(&self, profile: &str) -> Result<bool> {
        match entry(profile)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(e) => Err(keychain_failure(e)),
        }
    }

    /// Reads the profile's entry, which proves the backend answers without writing a secret: an
    /// entry that does not exist, or that cannot be decoded, still means the keychain works.
    ///
    /// Reading the stored entry and discarding it is deliberate: keyring-core 1.0 has no cheaper
    /// probe that works everywhere. `get_attributes` is not implemented on macOS, and treating
    /// `NotSupportedByStore` as unavailable would lock macOS users out. The value is dropped
    /// at once; `zeroize` is not a direct dependency and is not added for this.
    fn check_available(&self, profile: &str) -> Result<()> {
        match entry(profile)?.get_password() {
            Err(
                e @ (keyring_core::Error::PlatformFailure(_)
                | keyring_core::Error::NoStorageAccess(_)
                | keyring_core::Error::NoDefaultStore
                | keyring_core::Error::NotSupportedByStore(_)),
            ) => Err(unavailable(&e.to_string())),
            _ => Ok(()),
        }
    }
}

/// In-memory store for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemoryStore(std::sync::Mutex<std::collections::BTreeMap<String, String>>);

#[cfg(test)]
impl TokenStore for MemoryStore {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        let map = self.0.lock().map_err(|_| Failure::general("poisoned"))?;
        Ok(map.get(profile).map(|text| {
            StoredToken::from_payload(serde_json::from_str(text).expect("valid payload"))
        }))
    }

    fn save(&self, profile: &str, token: &StoredToken) -> Result<()> {
        let text = serde_json::to_string(&token.to_payload()).expect("encodes");
        self.0
            .lock()
            .map_err(|_| Failure::general("poisoned"))?
            .insert(profile.to_owned(), text);
        Ok(())
    }

    fn delete(&self, profile: &str) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Failure::general("poisoned"))?
            .remove(profile)
            .is_some())
    }

    fn check_available(&self, _profile: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> StoredToken {
        StoredToken {
            access_token: SecretString::from("at_secret"),
            refresh_token: Some(SecretString::from("rt_secret")),
            expires_at: Some(1_000),
            scope: Some("read".to_owned()),
            issuer: "https://app.example.test".to_owned(),
            api_url: "https://api.example.test".to_owned(),
            client_id: "cli".to_owned(),
        }
    }

    #[test]
    fn debug_never_shows_tokens() {
        let shown = format!("{:?}", token());
        assert!(
            !shown.contains("at_secret") && !shown.contains("rt_secret"),
            "{shown}"
        );
    }

    #[test]
    fn expiry_margin() {
        let t = token();
        assert!(!t.expires_within(900, 60));
        assert!(t.expires_within(940, 60));
        assert!(t.expires_within(2_000, 0));
        let forever = StoredToken {
            expires_at: None,
            ..token()
        };
        assert!(!forever.expires_within(u64::MAX, 60));
    }

    #[test]
    fn the_keychain_payload_round_trips() {
        let text = serde_json::to_string(&token().to_payload()).expect("encode");
        let back = StoredToken::from_payload(serde_json::from_str(&text).expect("decode"));
        assert_eq!(back.access_token.expose_secret(), "at_secret");
        assert_eq!(
            back.refresh_token
                .map(|t| t.expose_secret().to_owned())
                .as_deref(),
            Some("rt_secret")
        );
        assert_eq!(
            (back.expires_at, back.issuer.as_str()),
            (Some(1_000), "https://app.example.test")
        );
    }

    #[test]
    fn the_memory_store_behaves_like_a_store() {
        let store = MemoryStore::default();
        assert!(store.load("p").expect("load").is_none());
        store.save("p", &token()).expect("save");
        assert!(store.load("p").expect("load").is_some());
        assert!(store.delete("p").expect("delete"));
        assert!(!store.delete("p").expect("delete again"));
    }
}
