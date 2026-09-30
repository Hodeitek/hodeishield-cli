// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Configuration file and profiles.
//!
//! The file holds URLs and OAuth client settings per profile. It never holds a credential: tokens
//! live in the system keychain and API keys in the environment.

use crate::failure::{Failure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use url::Url;

pub const DEFAULT_PROFILE: &str = "default";
pub const DEFAULT_APP_URL: &str = "https://app.hodeishield.com";

/// The OAuth client id of this CLI, pre-registered in the app as a public client. A profile or
/// `HODEISHIELD_OAUTH_CLIENT_ID` can name another one, for an app that registers it differently.
pub const DEFAULT_OAUTH_CLIENT_ID: &str = "hodeishield-cli";

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// Profile used when neither `--profile` nor `HODEISHIELD_PROFILE` names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Base URL of the `/v1` API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// Base URL of the app, which signs you in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_url: Option<String>,
    /// OAuth client id of the CLI in the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    /// OAuth scopes to request. Unset: the ones the CLI's commands need, among those the app offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_scopes: Option<Vec<String>>,
}

/// The keys `config set` and `config unset` accept.
pub const KEYS: &[&str] = &["api_url", "app_url", "oauth_client_id", "oauth_scopes"];

impl Profile {
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "api_url" => self.api_url = Some(parse_url(value, key)?.to_string()),
            "app_url" => self.app_url = Some(parse_url(value, key)?.to_string()),
            "oauth_client_id" => {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Failure::general("oauth_client_id cannot be empty."));
                }
                self.oauth_client_id = Some(value.to_owned());
            }
            "oauth_scopes" => {
                let scopes: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
                if scopes.is_empty() {
                    return Err(Failure::general(
                        "oauth_scopes needs at least one scope; use `config unset` to let the app decide.",
                    ));
                }
                self.oauth_scopes = Some(scopes);
            }
            other => return Err(unknown_key(other)),
        }
        Ok(())
    }

    pub fn unset(&mut self, key: &str) -> Result<()> {
        match key {
            "api_url" => self.api_url = None,
            "app_url" => self.app_url = None,
            "oauth_client_id" => self.oauth_client_id = None,
            "oauth_scopes" => self.oauth_scopes = None,
            other => return Err(unknown_key(other)),
        }
        Ok(())
    }
}

fn unknown_key(key: &str) -> Failure {
    Failure::general(format!("Unknown key `{key}`."))
        .hint(format!("Known keys: {}.", KEYS.join(", ")))
}

/// Parses a base URL and refuses anything credentials must not be sent to.
pub fn parse_url(value: &str, what: &str) -> Result<Url> {
    let url = Url::parse(value.trim())
        .map_err(|e| Failure::general(format!("{what}: `{value}` is not a URL ({e}).")))?;
    if url.host().is_none() {
        return Err(Failure::general(format!("{what}: `{value}` has no host.")));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Failure::general(format!(
            "{what}: the URL must not contain a user name or password."
        )));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if hodeishield_api::is_loopback_host(&url) => Ok(url),
        _ => Err(Failure::general(format!(
            "{what}: `{value}` must use https (plain http is accepted only for localhost)."
        ))),
    }
}

/// Where the configuration file is: `HODEISHIELD_CONFIG`, or the platform's configuration directory.
pub fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("HODEISHIELD_CONFIG").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    directories::ProjectDirs::from("com", "Hodeitek", "HodeiShield")
        .map(|dirs| dirs.config_dir().join("config.toml"))
        .ok_or_else(|| {
            Failure::general("Cannot find a configuration directory for this user.")
                .hint("Set HODEISHIELD_CONFIG to the path of a configuration file.")
        })
}

pub fn load(path: &Path) -> Result<ConfigFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| {
            Failure::general(format!(
                "{} is not a valid configuration file: {e}.",
                path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConfigFile::default()),
        Err(e) => Err(Failure::general(format!(
            "Cannot read {}: {e}.",
            path.display()
        ))),
    }
}

pub fn save(path: &Path, config: &ConfigFile) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| Failure::general(format!("Cannot create {}: {e}.", dir.display())))?;
    }
    let text = toml::to_string_pretty(config)
        .map_err(|e| Failure::general(format!("Cannot write the configuration: {e}.")))?;
    let body = format!(
        "# HodeiShield CLI configuration. It holds no credential: tokens live in the system\n\
         # keychain and API keys in HODEISHIELD_API_KEY.\n\n{text}"
    );
    write_private(path, body.as_bytes())
        .map_err(|e| Failure::general(format!("Cannot write {}: {e}.", path.display())))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Everything a command needs to know about where it talks to, resolved from flags, environment,
/// profile and defaults, in that order.
#[derive(Debug, Clone)]
pub struct Settings {
    pub profile: String,
    pub api_url: Url,
    pub app_url: Url,
    pub oauth_client_id: String,
    pub oauth_scopes: Option<Vec<String>>,
    pub config_path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Overrides {
    pub profile: Option<String>,
    pub api_url: Option<String>,
}

pub fn resolve(overrides: &Overrides) -> Result<Settings> {
    let config_path = path()?;
    let config = load(&config_path)?;
    resolve_with(&config, config_path, overrides, |name| {
        std::env::var(name).ok()
    })
}

pub fn resolve_with(
    config: &ConfigFile,
    config_path: PathBuf,
    overrides: &Overrides,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Settings> {
    let env = |name: &str| env(name).filter(|v| !v.trim().is_empty());
    let named = overrides.profile.clone();
    let profile_name = named
        .clone()
        .or_else(|| config.default_profile.clone())
        .unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    let profile = match config.profiles.get(&profile_name) {
        Some(profile) => profile.clone(),
        None if profile_name == DEFAULT_PROFILE => Profile::default(),
        None => {
            return Err(Failure::general(format!("Profile `{profile_name}` is not defined."))
                .hint(format!(
                    "Create it with `hodeishield config set --profile {profile_name} api_url <URL>`."
                )));
        }
    };
    let api_url = match overrides
        .api_url
        .clone()
        .or_else(|| profile.api_url.clone())
    {
        Some(url) => parse_url(&url, "api_url")?,
        None => parse_url(hodeishield_api::v1::DEFAULT_SERVER, "api_url")?,
    };
    let app_url = match env("HODEISHIELD_APP_URL").or_else(|| profile.app_url.clone()) {
        Some(url) => parse_url(&url, "app_url")?,
        None => parse_url(DEFAULT_APP_URL, "app_url")?,
    };
    let oauth_client_id = env("HODEISHIELD_OAUTH_CLIENT_ID")
        .or_else(|| profile.oauth_client_id.clone())
        .unwrap_or_else(|| DEFAULT_OAUTH_CLIENT_ID.to_owned());
    Ok(Settings {
        profile: profile_name,
        api_url,
        app_url,
        oauth_client_id,
        oauth_scopes: profile.oauth_scopes,
        config_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn defaults_without_a_file() {
        let s = resolve_with(
            &ConfigFile::default(),
            PathBuf::from("c.toml"),
            &Overrides::default(),
            no_env,
        )
        .expect("defaults");
        assert_eq!(s.profile, "default");
        assert_eq!(s.api_url.as_str(), "https://api.hodeishield.com/");
        assert_eq!(s.app_url.as_str(), "https://app.hodeishield.com/");
        assert_eq!(s.oauth_client_id, "hodeishield-cli");
    }

    #[test]
    fn flags_beat_profile_and_env_beats_profile() {
        let mut config = ConfigFile::default();
        let mut staging = Profile::default();
        staging
            .set("api_url", "https://api.staging.example.test")
            .expect("set");
        staging
            .set("app_url", "https://app.staging.example.test")
            .expect("set");
        staging.set("oauth_client_id", "from-profile").expect("set");
        config.profiles.insert("staging".to_owned(), staging);
        config.default_profile = Some("staging".to_owned());

        let s =
            resolve_with(&config, PathBuf::new(), &Overrides::default(), no_env).expect("profile");
        assert_eq!(s.profile, "staging");
        assert_eq!(s.api_url.host_str(), Some("api.staging.example.test"));
        assert_eq!(s.oauth_client_id, "from-profile");

        let overrides = Overrides {
            api_url: Some("http://localhost:4000".to_owned()),
            ..Overrides::default()
        };
        let env = |name: &str| match name {
            "HODEISHIELD_OAUTH_CLIENT_ID" => Some("from-env".to_owned()),
            "HODEISHIELD_APP_URL" => Some("http://127.0.0.1:3000".to_owned()),
            _ => None,
        };
        let s = resolve_with(&config, PathBuf::new(), &overrides, env).expect("overrides");
        assert_eq!(s.api_url.as_str(), "http://localhost:4000/");
        assert_eq!(s.app_url.as_str(), "http://127.0.0.1:3000/");
        assert_eq!(s.oauth_client_id, "from-env");
    }

    #[test]
    fn an_unknown_named_profile_is_an_error() {
        let overrides = Overrides {
            profile: Some("nope".to_owned()),
            ..Overrides::default()
        };
        let err = resolve_with(&ConfigFile::default(), PathBuf::new(), &overrides, no_env)
            .expect_err("unknown profile");
        assert!(err.message.contains("nope"));
    }

    #[test]
    fn refuses_urls_credentials_must_not_go_to() {
        for bad in [
            "http://api.example.test",
            "ftp://api.example.test",
            "https://user:pw@api.example.test",
            "not a url",
        ] {
            assert!(parse_url(bad, "api_url").is_err(), "{bad}");
        }
        assert!(parse_url("http://[::1]:8080", "api_url").is_ok());
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("config.toml");
        let mut config = ConfigFile::default();
        let mut profile = Profile::default();
        profile
            .set("oauth_scopes", "a:read  b:read")
            .expect("scopes");
        config.profiles.insert("default".to_owned(), profile);
        save(&path, &config).expect("save");
        assert_eq!(load(&path).expect("load"), config);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn unknown_keys_are_refused() {
        let mut profile = Profile::default();
        assert!(profile.set("token", "x").is_err());
        assert!(toml::from_str::<ConfigFile>("[profiles.default]\ntoken = \"x\"\n").is_err());
    }
}
