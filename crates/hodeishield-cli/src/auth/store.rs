// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Where sign-in tokens are kept: the system keychain, or, only when the person opts in, a
//! plain-text file.
//!
//! The keychain is the default: macOS Keychain, Windows Credential Manager, or the Secret Service
//! on Linux and the BSDs (GNOME Keyring, KWallet). The other store is
//! [`file_store`](super::file_store), chosen by `HODEISHIELD_TOKEN_STORE=plaintext-file` or the
//! `token_store` setting. Neither is ever used as a fallback for the other: if the chosen one is
//! not available, signing in fails.

use crate::failure::{Failure, Result};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const SERVICE: &str = "hodeishield-cli";

/// Start of the message when there is no keychain to use.
pub const KEYCHAIN_UNAVAILABLE: &str = "the system keychain is not available";

/// The message when the profile's entry exists but cannot be decoded.
const UNREADABLE: &str = "the sign-in stored in the system keychain is unreadable";

/// Decodes a stored entry. An entry that cannot be decoded fails with a message that
/// [`is_unreadable`] recognises, so `logout` can still remove it.
fn decode(text: &str) -> Result<StoredToken> {
    let payload: Payload = serde_json::from_str(text).map_err(|_| {
        Failure::general(UNREADABLE).hint("Run `hodeishield logout` and sign in again.")
    })?;
    Ok(StoredToken::from_payload(payload))
}

/// Whether `failure` is a profile's entry that exists but cannot be decoded.
pub fn is_unreadable(failure: &Failure) -> bool {
    failure.message == UNREADABLE
}

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
pub(super) struct Payload {
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
    pub(super) fn to_payload(&self) -> Payload {
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

    pub(super) fn from_payload(payload: Payload) -> Self {
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
    /// The file that holds the profile's tokens, for stores that are files. `None` for the
    /// keychain.
    fn location(&self, _profile: &str) -> Option<std::path::PathBuf> {
        None
    }
}

/// The system keychain.
#[derive(Debug, Default)]
pub struct Keychain;

/// The store the settings choose. The choice is made at the first use and kept for the rest of
/// the process, so one command checks, reads and saves in the same store even if the environment
/// or the configuration file changed meanwhile. The environment and the configuration file are
/// read at that point, so a command that never needs a token never fails on them. A value that is
/// not a store, or a platform that cannot have it, is an error at the first use, and nothing
/// falls back to the other store.
#[derive(Debug, Default)]
pub struct Configured {
    kind: OnceLock<crate::config::TokenStoreKind>,
}

impl Configured {
    fn chosen(&self) -> Result<Box<dyn TokenStore>> {
        let kind = match self.kind.get() {
            Some(kind) => *kind,
            None => {
                let chosen = crate::config::token_store()?;
                *self.kind.get_or_init(|| chosen)
            }
        };
        Ok(match kind {
            crate::config::TokenStoreKind::Keychain => Box::new(Keychain),
            crate::config::TokenStoreKind::PlaintextFile => {
                Box::new(super::file_store::FileStore::platform()?)
            }
        })
    }
}

impl TokenStore for Configured {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        self.chosen()?.load(profile)
    }
    fn save(&self, profile: &str, token: &StoredToken) -> Result<()> {
        self.chosen()?.save(profile, token)
    }
    fn delete(&self, profile: &str) -> Result<bool> {
        self.chosen()?.delete(profile)
    }
    fn check_available(&self, profile: &str) -> Result<()> {
        self.chosen()?.check_available(profile)
    }
    fn location(&self, profile: &str) -> Option<std::path::PathBuf> {
        self.chosen().ok()?.location(profile)
    }
}

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
        "Sign-in tokens are kept in the system keychain. Allow access when the Keychain prompt \
         appears (or in Keychain Access), or use a tenant API key in HODEISHIELD_API_KEY \
         instead, or opt in to a plain-text token file with \
         HODEISHIELD_TOKEN_STORE=plaintext-file (tokens are then stored unencrypted in a file \
         only you can read)."
    } else if cfg!(windows) {
        "Sign-in tokens are kept in the system keychain. Check that Windows Credential Manager \
         is available, or use a tenant API key in HODEISHIELD_API_KEY instead."
    } else {
        "Sign-in tokens are kept in the system keychain. Start a Secret Service (GNOME Keyring \
         or KWallet); on a server without one, use a tenant API key in HODEISHIELD_API_KEY \
         instead, or opt in to a plain-text token file with \
         HODEISHIELD_TOKEN_STORE=plaintext-file (tokens are then stored unencrypted in a file \
         only you can read)."
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

/// The failure for a keychain read that did not find an entry. When the platform store cannot be
/// reached from this session (Windows ERROR_NO_SUCH_LOGON_SESSION over SSH, no Secret Service on
/// Linux), it is worded as an unavailable keychain, which `explain_store_failure` turns into "not
/// authenticated"; anything else is a plain keychain failure.
pub(crate) fn read_failure(error: keyring_core::Error) -> Failure {
    match error {
        keyring_core::Error::PlatformFailure(_) | keyring_core::Error::NoStorageAccess(_) => {
            unavailable(&error.to_string())
        }
        other => keychain_failure(other),
    }
}

impl TokenStore for Keychain {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        let entry = entry(profile)?;
        match entry.get_password() {
            Ok(text) => decode(&text).map(Some),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(read_failure(e)),
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
impl MemoryStore {
    /// Stores `text` as the profile's entry as it is, like a keychain entry written by something
    /// else.
    pub fn put_raw(&self, profile: &str, text: &str) {
        self.0
            .lock()
            .expect("not poisoned")
            .insert(profile.to_owned(), text.to_owned());
    }
}

#[cfg(test)]
impl TokenStore for MemoryStore {
    fn load(&self, profile: &str) -> Result<Option<StoredToken>> {
        let map = self.0.lock().map_err(|_| Failure::general("poisoned"))?;
        map.get(profile).map(|text| decode(text)).transpose()
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

    #[test]
    fn an_entry_that_cannot_be_decoded_is_recognised_as_unreadable() {
        let store = MemoryStore::default();
        store.put_raw("p", "not a sign-in");
        let err = store.load("p").expect_err("unreadable");
        assert!(is_unreadable(&err));
        assert_eq!(
            err.hint.as_deref(),
            Some("Run `hodeishield logout` and sign in again.")
        );
        assert!(!is_unreadable(&unavailable("no session")));
        assert!(!is_unreadable(&Failure::general("anything else")));
    }
}
