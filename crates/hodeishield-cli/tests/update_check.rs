// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The new-version notice: when it appears, when it stays silent, and that it never costs a
//! command its output or its exit code.
//!
//! The release endpoint is a mock on loopback (`HODEISHIELD_UPDATE_CHECK_URL`) and a terminal on
//! standard error is simulated (`HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL`); both exist for these
//! tests. The binary under test is version 0.x of this workspace, so `v99.0.0` is always newer.

use assert_cmd::Command;
use mockito::{Mock, Server};
use std::path::PathBuf;
use std::process::Output;

const NOTICE: &str = "A newer version of hodeishield is available: 99.0.0";

struct Env {
    _dir: tempfile::TempDir,
    config: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        Self { _dir: dir, config }
    }

    fn cache(&self) -> PathBuf {
        self.config.with_file_name("update-check.json")
    }

    /// A run that is not on a terminal, so it never asks: for changing the configuration.
    fn quiet(&self, args: &[&str]) -> Output {
        Command::cargo_bin("hodeishield")
            .expect("binary")
            .env("HODEISHIELD_CONFIG", &self.config)
            .args(args)
            .output()
            .expect("run")
    }

    /// A run on an interactive terminal, against `release_url`.
    fn run(&self, release_url: &str, args: &[&str]) -> Output {
        let mut cmd = Command::cargo_bin("hodeishield").expect("binary");
        for var in [
            "CI",
            "HODEISHIELD_NO_UPDATE_CHECK",
            "HODEISHIELD_API_KEY",
            "HODEISHIELD_API_URL",
            "HODEISHIELD_PROFILE",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("HODEISHIELD_CONFIG", &self.config)
            .env("HODEISHIELD_UPDATE_CHECK_URL", release_url)
            .env("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL", "1")
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .expect("run")
    }
}

fn release(server: &mut Server, tag: &str) -> Mock {
    server
        .mock("GET", "/latest")
        .match_header(
            "user-agent",
            concat!("hodeishield-cli/", env!("CARGO_PKG_VERSION")),
        )
        .with_body(format!(r#"{{"tag_name":"{tag}","draft":false}}"#))
        .create()
}

fn url(server: &Server) -> String {
    format!("{}/latest", server.url())
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_newer_release_is_announced_on_stderr_only() {
    let env = Env::new();
    let mut server = Server::new();
    let mock = release(&mut server, "v99.0.0").expect(1).create();
    let output = env.run(&url(&server), &["config", "path"]);
    assert!(output.status.success());
    assert!(stderr(&output).contains(NOTICE), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("you have 0."),
        "{}",
        stderr(&output)
    );
    assert!(!stdout(&output).contains("newer version"));
    mock.assert();
}

#[test]
fn the_same_or_an_older_release_says_nothing() {
    for tag in [
        concat!("v", env!("CARGO_PKG_VERSION")),
        "v0.0.1",
        "v99.0.0-rc.1",
    ] {
        let env = Env::new();
        let mut server = Server::new();
        let mock = release(&mut server, tag).expect(1).create();
        let output = env.run(&url(&server), &["config", "path"]);
        assert!(output.status.success());
        assert!(!stderr(&output).contains("newer version"), "{tag}");
        mock.assert();
    }
}

#[test]
fn it_asks_at_most_once_a_day() {
    let env = Env::new();
    let mut server = Server::new();
    let mock = release(&mut server, "v99.0.0").expect(1).create();
    let first = env.run(&url(&server), &["config", "path"]);
    let second = env.run(&url(&server), &["config", "path"]);
    assert!(stderr(&first).contains(NOTICE));
    assert!(!stderr(&second).contains("newer version"));
    mock.assert();

    // A check older than a day is made again.
    std::fs::write(env.cache(), r#"{"checked_at":1,"latest":"0.1.0"}"#).expect("age the cache");
    let third = env.run(&url(&server), &["config", "path"]);
    assert!(stderr(&third).contains(NOTICE));
}

#[test]
fn json_and_csv_and_completions_stay_clean_and_make_no_request() {
    let env = Env::new();
    let mut server = Server::new();
    let mock = release(&mut server, "v99.0.0").expect(0).create();
    let mut api = Server::new();
    api.mock("GET", mockito::Matcher::Any)
        .with_header("content-type", "application/json")
        .with_body(r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":0}}"#)
        .create();
    let release_url = url(&server);
    let api_url = api.url();
    for args in [
        vec!["--json", "config", "show"],
        vec!["vendors", "list", "--csv"],
        vec!["completions", "bash"],
    ] {
        let mut cmd_args = vec!["--api-url", api_url.as_str()];
        cmd_args.extend(&args);
        let output = {
            let mut cmd = Command::cargo_bin("hodeishield").expect("binary");
            cmd.env_remove("CI")
                .env_remove("HODEISHIELD_NO_UPDATE_CHECK")
                .env("HODEISHIELD_CONFIG", &env.config)
                .env("HODEISHIELD_API_KEY", "hsk_test_0123456789abcdef")
                .env("HODEISHIELD_UPDATE_CHECK_URL", &release_url)
                .env("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL", "1")
                .args(&cmd_args)
                .output()
                .expect("run")
        };
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert!(!stderr(&output).contains("newer version"), "{args:?}");
    }
    mock.assert();
}

#[test]
fn without_a_terminal_ci_or_with_an_opt_out_nothing_is_asked() {
    let mut server = Server::new();
    let mock = release(&mut server, "v99.0.0").expect(0).create();
    let release_url = url(&server);

    // Standard error is not a terminal (the test harness pipes it).
    let env = Env::new();
    let output = Command::cargo_bin("hodeishield")
        .expect("binary")
        .env_remove("CI")
        .env_remove("HODEISHIELD_NO_UPDATE_CHECK")
        .env_remove("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL")
        .env("HODEISHIELD_CONFIG", &env.config)
        .env("HODEISHIELD_UPDATE_CHECK_URL", &release_url)
        .args(["config", "path"])
        .output()
        .expect("run");
    assert!(!stderr(&output).contains("newer version"));

    // CI, with any value.
    for ci in ["true", "0", "false"] {
        let env = Env::new();
        let mut cmd = Command::cargo_bin("hodeishield").expect("binary");
        let output = cmd
            .env("HODEISHIELD_CONFIG", &env.config)
            .env("HODEISHIELD_UPDATE_CHECK_URL", &release_url)
            .env("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL", "1")
            .env("CI", ci)
            .args(["config", "path"])
            .output()
            .expect("run");
        assert!(!stderr(&output).contains("newer version"), "CI={ci}");
    }

    // The environment opt-out.
    let env = Env::new();
    let output = Command::cargo_bin("hodeishield")
        .expect("binary")
        .env_remove("CI")
        .env("HODEISHIELD_CONFIG", &env.config)
        .env("HODEISHIELD_UPDATE_CHECK_URL", &release_url)
        .env("HODEISHIELD_UPDATE_CHECK_ASSUME_TERMINAL", "1")
        .env("HODEISHIELD_NO_UPDATE_CHECK", "1")
        .args(["config", "path"])
        .output()
        .expect("run");
    assert!(!stderr(&output).contains("newer version"));

    // The configuration opt-out, set the way a user sets it.
    let env = Env::new();
    let set = env.quiet(&["config", "set", "update_check", "false"]);
    assert!(set.status.success(), "{}", stderr(&set));
    let output = env.run(&release_url, &["config", "path"]);
    assert!(!stderr(&output).contains("newer version"));
    let shown = env.quiet(&["--json", "config", "show"]);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).expect("json");
    assert_eq!(shown["update_check"], false);

    // Unsetting it brings the default back.
    env.quiet(&["config", "unset", "update_check"]);
    let shown = env.quiet(&["--json", "config", "show"]);
    let shown: serde_json::Value = serde_json::from_slice(&shown.stdout).expect("json");
    assert_eq!(shown["update_check"], true);

    mock.assert();
}

#[test]
fn update_check_must_be_a_boolean() {
    let env = Env::new();
    let output = env.run(
        "http://127.0.0.1:9/",
        &["config", "set", "update_check", "maybe"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not true or false"));
}

#[test]
fn failures_are_silent_and_do_not_change_the_exit_code() {
    let mut server = Server::new();
    let bodies: [(usize, &str); 3] = [
        (500, "oops"),
        (200, "not json"),
        (200, r#"{"tag_name":"nightly"}"#),
    ];
    for (status, body) in bodies {
        let env = Env::new();
        server.reset();
        server
            .mock("GET", "/latest")
            .with_status(status)
            .with_body(body)
            .create();
        let ok = env.run(&url(&server), &["config", "path"]);
        assert!(ok.status.success());
        assert_eq!(stderr(&ok), "");
        // The failed attempt is remembered, so it is not repeated at once.
        assert!(env.cache().exists());

        let failing = env.run(&url(&server), &["--profile", "missing", "config", "show"]);
        assert_eq!(failing.status.code(), Some(1));
    }

    // Nothing listens: the connection is refused.
    let env = Env::new();
    let output = env.run("http://127.0.0.1:9/latest", &["config", "path"]);
    assert!(output.status.success());
    assert_eq!(stderr(&output), "");
}

#[test]
fn an_unwritable_cache_never_fails_the_command() {
    let env = Env::new();
    // A directory where the cache file should be.
    std::fs::create_dir(env.cache()).expect("dir");
    let mut server = Server::new();
    let _mock = release(&mut server, "v99.0.0").create();
    let output = env.run(&url(&server), &["config", "path"]);
    assert!(output.status.success());
}

#[test]
fn verbose_explains_why_it_stayed_quiet() {
    let env = Env::new();
    let mut server = Server::new();
    server.mock("GET", "/latest").with_status(500).create();
    let output = env.run(&url(&server), &["--verbose", "config", "path"]);
    assert!(
        stderr(&output).contains("update check:"),
        "{}",
        stderr(&output)
    );
}
