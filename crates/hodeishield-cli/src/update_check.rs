// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The notice that a newer release exists.
//!
//! The interface is one function, [`notify`], called once after a command has finished and its
//! output has been flushed. It decides, asks and prints; the caller learns nothing and nothing can
//! fail: every error is dropped (logged with `--verbose`).
//!
//! What it does, and the conditions that bound it:
//!
//! - one unauthenticated `GET` to GitHub's public "latest release" endpoint of this repository,
//!   with a 2 second limit and only the `User-Agent` (`hodeishield-cli/<version>`) and `Accept`
//!   headers: no API key, token, profile, tenant or machine identifier;
//! - at most once in 24 hours, remembered in `update-check.json` next to the configuration file
//!   (the attempt is recorded even when it fails, so a slow network costs the 2 seconds once a day);
//! - only when standard error is a terminal, the run prints nothing for programs (`--json`,
//!   `--csv`, `completions`), `CI` is unset, and neither `HODEISHIELD_NO_UPDATE_CHECK` nor
//!   `update_check = false` in the configuration file opts out;
//! - the notice is one line on standard error, shown on the run that made the query.
//!
//! Two variables exist for the test suite and are not documented to users:
//! `HODEISHIELD_UPDATE_CHECK_URL` replaces the endpoint (honoured only for a loopback address, so
//! it can never send the request anywhere else) and `HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL`
//! stands in for a terminal on standard error.

use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const LATEST_RELEASE: &str =
    "https://api.github.com/repos/Hodeitek/hodeishield-cli/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/Hodeitek/hodeishield-cli/releases";
const INTERVAL_SECS: u64 = 24 * 60 * 60;
const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_BODY_BYTES: u64 = 1024 * 1024;
const CACHE_FILE: &str = "update-check.json";

/// What is remembered between runs.
#[derive(Debug, Serialize, Deserialize)]
struct Cache {
    /// Seconds since the Unix epoch of the last query, successful or not.
    checked_at: u64,
    /// The version the last successful query reported.
    #[serde(default)]
    latest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
}

/// Prints the new-version notice when it is due and wanted. `for_programs` is true when this run
/// printed machine-readable output.
pub fn notify(for_programs: bool, verbose: bool) {
    let log = |message: &str| {
        if verbose {
            eprintln!("update check: {message}");
        }
    };
    if for_programs || !wanted() {
        return;
    }
    let Ok(config_path) = crate::config::path() else {
        return;
    };
    match crate::config::load(&config_path) {
        Ok(config) if config.update_check != Some(false) => {}
        _ => return,
    }
    let cache_path = config_path.with_file_name(CACHE_FILE);
    let now = unix_now();
    if read_cache(&cache_path).is_some_and(|c| now.saturating_sub(c.checked_at) < INTERVAL_SECS) {
        log("checked less than 24 hours ago");
        return;
    }
    let latest = match fetch_latest() {
        Ok(version) => Some(version),
        Err(reason) => {
            log(&reason);
            None
        }
    };
    if let Err(e) = write_cache(
        &cache_path,
        &Cache {
            checked_at: now,
            latest: latest.clone(),
        },
    ) {
        log(&format!("cannot write {}: {e}", cache_path.display()));
    }
    if let Some(latest) = latest.filter(|l| is_newer(l, env!("CARGO_PKG_VERSION"))) {
        eprintln!(
            "A newer version of hodeishield is available: {latest} (you have {}). See {RELEASES_PAGE}",
            env!("CARGO_PKG_VERSION")
        );
    }
}

/// Interactive, not CI and not opted out by the environment.
fn wanted() -> bool {
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    let terminal =
        std::io::stderr().is_terminal() || set("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL");
    terminal && std::env::var_os("CI").is_none() && !set("HODEISHIELD_NO_UPDATE_CHECK")
}

fn endpoint() -> Url {
    endpoint_for(
        std::env::var("HODEISHIELD_UPDATE_CHECK_URL")
            .ok()
            .as_deref(),
    )
}

fn endpoint_for(override_url: Option<&str>) -> Url {
    override_url
        .and_then(|v| Url::parse(v).ok())
        .filter(hodeishield_api::is_loopback_host)
        .unwrap_or_else(|| Url::parse(LATEST_RELEASE).expect("constant URL"))
}

fn fetch_latest() -> Result<String, String> {
    let url = endpoint();
    let mut builder = reqwest::blocking::Client::builder();
    if hodeishield_api::is_loopback_host(&url) {
        builder = builder.no_proxy();
    }
    let http = builder
        .user_agent(format!("hodeishield-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!hodeishield_api::is_loopback_host(&url))
        .build()
        .map_err(|e| format!("cannot start the HTTP client: {e}"))?;
    let response = http
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| format!("request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("the answer was HTTP {}", response.status()));
    }
    let body = hodeishield_api::read_body(response, MAX_BODY_BYTES).map_err(|e| e.to_string())?;
    let release: Release = serde_json::from_slice(&body).map_err(|e| format!("bad answer: {e}"))?;
    parse_version(&release.tag_name)
        .map(|_| release.tag_name.trim_start_matches('v').to_owned())
        .ok_or_else(|| "the release tag is not a plain version".to_owned())
}

/// `1.2.3` or `v1.2.3` as numbers. Pre-releases (`1.2.3-rc.1`) are not versions to announce, so
/// they are refused; build metadata (`+abc`) is ignored.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let text = text.trim().trim_start_matches('v');
    let text = text.split('+').next()?;
    let mut parts = text.split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn read_cache(path: &Path) -> Option<Cache> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_cache(path: &Path, cache: &Cache) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_vec(cache)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_numbers() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1.0.0", "0.3.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("0.2.9", "0.3.0"));
    }

    #[test]
    fn only_a_loopback_address_can_replace_the_endpoint() {
        assert_eq!(endpoint_for(None).as_str(), LATEST_RELEASE);
        assert_eq!(
            endpoint_for(Some("https://example.test/latest")).as_str(),
            LATEST_RELEASE
        );
        assert_eq!(
            endpoint_for(Some("http://127.0.0.1:8080/latest")).as_str(),
            "http://127.0.0.1:8080/latest"
        );
    }

    #[test]
    fn prereleases_and_junk_are_not_announced() {
        assert!(!is_newer("0.4.0-rc.1", "0.3.0"));
        assert!(!is_newer("nightly", "0.3.0"));
        assert!(!is_newer("0.4", "0.3.0"));
        assert!(!is_newer("0.4.0.1", "0.3.0"));
        assert_eq!(parse_version("0.4.0+build5"), Some((0, 4, 0)));
    }
}
