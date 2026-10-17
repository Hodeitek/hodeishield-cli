// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The `hodeishield` binary end to end, against a mock `/v1` and a mock app.
//!
//! Every test runs with a throw-away configuration file and, on Linux, with the Secret Service
//! unreachable, so no test ever reads or writes the real keychain.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

const KEY: &str = "hsk_test_0123456789abcdef";

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

    /// The binary with an isolated environment: no inherited HodeiShield variables.
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("hodeishield").expect("binary");
        for var in [
            "HODEISHIELD_API_KEY",
            "HODEISHIELD_API_URL",
            "HODEISHIELD_APP_URL",
            "HODEISHIELD_PROFILE",
            "HODEISHIELD_OAUTH_CLIENT_ID",
            "HODEISHIELD_TOKEN_STORE",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("HODEISHIELD_CONFIG", &self.config)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/hodeishield-test",
            )
            .env("XDG_STATE_HOME", self.state())
            .env("NO_COLOR", "1");
        cmd
    }

    /// Where the state directory is for this test.
    fn state(&self) -> PathBuf {
        self._dir.path().join("state")
    }

    /// The binary with the opt-in plain-text token store, and a home that is the test's own, so
    /// the platform's state directory is inside the test's directory on every system.
    #[cfg(unix)]
    fn cmd_file(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.env("HODEISHIELD_TOKEN_STORE", "plaintext-file")
            .env("HOME", self._dir.path().join("home"));
        cmd
    }

    /// The sessions directory of the opt-in store, where the platform keeps it.
    #[cfg(unix)]
    fn sessions(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self._dir
                .path()
                .join("home/Library/Application Support/com.Hodeitek.HodeiShield.sessions")
        } else {
            self.state().join("hodeishield/sessions")
        }
    }

    fn api(&self, server: &mockito::Server) -> Command {
        let mut cmd = self.cmd();
        cmd.env("HODEISHIELD_API_KEY", KEY)
            .env("HODEISHIELD_API_URL", server.url());
        cmd
    }
}

fn vendor(id: &str, name: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","legal_name":null,"domain":"example.com","category":null,"vendor_type":null,"access_level":null,"business_criticality":"high","data_sensitivity":null,"economic_impact":null,"active":true,"monitoring_status":null,"last_scan_at":"2026-03-04T05:06:07.000Z","lei":null,"hq_country":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","added_later":1}}"#
    )
}

fn page(items: &[String], page: i64, total: i64, total_pages: i64) -> String {
    format!(
        r#"{{"data":[{}],"pagination":{{"page":{page},"per_page":50,"total":{total},"total_pages":{total_pages}}}}}"#,
        items.join(",")
    )
}

/// The key must never be printed, whatever happens.
fn assert_no_key(output: &std::process::Output) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains(KEY),
        "the API key leaked into the output:\n{all}"
    );
}

/// `--help` names the variables but never prints their values, which end up in terminals and CI logs.
#[test]
fn help_does_not_print_the_values_of_the_environment() {
    let env = Env::new();
    let output = env
        .cmd()
        .env("HODEISHIELD_API_URL", "https://api-from-env.example.test")
        .env("HODEISHIELD_PROFILE", "profile-from-env")
        .env("HODEISHIELD_API_KEY", KEY)
        .arg("--help")
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("[env: HODEISHIELD_API_URL]"), "{text}");
    assert!(
        !text.contains("api-from-env") && !text.contains("profile-from-env"),
        "{text}"
    );
    assert_no_key(&output);
}

#[test]
fn vendors_list_prints_a_table_and_the_next_page() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_header("authorization", format!("Bearer {KEY}").as_str())
        .with_body(page(&[vendor("v1", "Example Hosting")], 1, 60, 2))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("ID"), "{stdout}");
    assert!(
        stdout.contains("Example Hosting") && stdout.contains("2026-03-04 05:06Z"),
        "{stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Page 1 of 2 (60 vendors). Next: --page 2, or --all."),
        "{stderr}"
    );
    assert_no_key(&output);
}

#[test]
fn json_is_the_api_body_unchanged() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::UrlEncoded(
            "business_criticality".into(),
            "critical".into(),
        ))
        .with_body(page(&[vendor("v1", "A")], 1, 1, 1))
        .create();
    let output = env
        .api(&server)
        .args(["--json", "vendors", "list", "--criticality", "critical"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(body["data"][0]["added_later"], 1, "unknown fields survive");
    assert_eq!(body["pagination"]["total"], 1);
}

#[test]
fn all_walks_every_page() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    for (n, name) in [(1, "First"), (2, "Second")] {
        server
            .mock("GET", "/v1/alerts")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("page".into(), n.to_string()),
                mockito::Matcher::UrlEncoded("per_page".into(), "200".into()),
            ]))
            .with_body(format!(
                r#"{{"data":[{{"id":"a{n}","vendor_id":"v","type":"cve","severity":null,"title":"{name}","description":null,"source_url":null,"economic_impact":null,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z"}}],"pagination":{{"page":{n},"per_page":1,"total":2,"total_pages":2}}}}"#
            ))
            .expect(1)
            .create();
    }
    let output = env
        .api(&server)
        .args(["alerts", "list", "--all", "--json"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let items: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let titles: Vec<&str> = items
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|i| i["title"].as_str())
        .collect();
    assert_eq!(titles, ["First", "Second"]);
}

#[test]
fn a_missing_scope_exits_4_and_names_the_framework_scope() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/controls")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_header("x-request-id", "req_abc")
        .with_body(r#"{"error":{"code":"forbidden","message":"no","request_id":"req_abc"}}"#)
        .create();
    env.api(&server)
        .args(["compliance", "controls", "--framework", "nis2"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("compliance.nis2:read"))
        .stderr(predicate::str::contains("request id: req_abc"));
}

#[test]
fn an_api_message_that_says_broken_pipe_still_fails() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/risks/r1")
        .with_status(404)
        .with_body(
            r#"{"error":{"code":"not_found","message":"Broken pipe","request_id":"req_bp"}}"#,
        )
        .create();
    env.api(&server)
        .args(["risks", "get", "r1"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("error: Broken pipe"));
}

/// Unix only: the child gets a plain pipe and sees `EPIPE` once the reader is gone. Windows reports
/// a closed pipe with other codes, and this suite cannot confirm that mapping there.
#[cfg(unix)]
#[test]
fn a_closed_output_pipe_exits_0_silently() {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let env = Env::new();
    let mut server = mockito::Server::new();
    let filler = "x".repeat(1000);
    let items: Vec<String> = (0..1000)
        .map(|i| vendor(&format!("v{i}"), &filler))
        .collect();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(page(&items, 1, 1000, 1))
        .create();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("hodeishield"))
        .args(["--json", "vendors", "list"])
        .env_clear()
        .env("HODEISHIELD_CONFIG", &env.config)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/hodeishield-test",
        )
        .env("HODEISHIELD_API_KEY", KEY)
        .env("HODEISHIELD_API_URL", server.url())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Read a little, then hang up while about a megabyte is still to come.
    let mut stdout = child.stdout.take().expect("stdout");
    let mut first = [0_u8; 16];
    stdout.read_exact(&mut first).expect("first bytes");
    drop(stdout);
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn an_inactive_licence_exits_8_without_blaming_a_scope() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_header("x-request-id", "req_lic")
        .with_body(
            r#"{"error":{"code":"forbidden","message":"no licence","request_id":"req_lic","details":{"code":"LICENCE_INACTIVE","licence":"suspended"}}}"#,
        )
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(8), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("licence is not in force (licence: suspended)"),
        "{stderr}"
    );
    assert!(stderr.contains("tenant administrator"), "{stderr}");
    assert!(stderr.contains("request id: req_lic"), "{stderr}");
    assert!(!stderr.contains("scope"), "no scope is blamed: {stderr}");
    assert_no_key(&output);
}

#[test]
fn an_unexpected_licence_state_is_not_echoed() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(
            r#"{"error":{"code":"forbidden","message":"no","request_id":"r","details":{"code":"LICENCE_INACTIVE","licence":"\u001b[31mred"}}}"#,
        )
        .create();
    env.api(&server)
        .args(["vendors", "list"])
        .assert()
        .code(8)
        .stderr(predicate::str::contains("licence is not in force."))
        .stderr(predicate::str::contains("red").not());
}

#[test]
fn a_rejected_key_exits_3_without_printing_it() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/endpoints")
        .with_status(401)
        .with_body(r#"{"error":{"code":"unauthorized","message":"bad key","request_id":"r"}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["--verbose", "endpoints", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HODEISHIELD_API_KEY"), "{stderr}");
    assert!(
        stderr.contains("GET http://127.0.0.1:"),
        "verbose logs the request: {stderr}"
    );
    assert_no_key(&output);
}

#[test]
fn not_found_exits_5_and_dot_segments_are_refused_locally() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/risks/nope")
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"Risk not found.","request_id":"r"}}"#)
        .create();
    env.api(&server)
        .args(["risks", "get", "nope"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("Risk not found."));
    env.api(&server)
        .args(["risks", "get", ".."])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not a valid identifier"));
}

#[test]
fn control_characters_from_the_api_do_not_reach_the_terminal() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors/v1")
        .with_body(format!(
            r#"{{"data":{}}}"#,
            vendor("v1", "Evil\\u001b]0;pwned\\u0007")
        ))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "get", "v1"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    assert!(!output.stdout.contains(&0x1b) && !output.stdout.contains(&0x07));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Evil\u{fffd}]0;pwned\u{fffd}"));
}

#[test]
fn the_key_is_never_sent_over_plain_http_to_a_remote_host() {
    let env = Env::new();
    env.cmd()
        .env("HODEISHIELD_API_KEY", KEY)
        .args(["--api-url", "http://api.example.test", "vendors", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must use https"));
}

#[test]
fn without_any_credential_it_exits_3_and_says_how_to_get_one() {
    let env = Env::new();
    env.cmd()
        .args(["--api-url", "http://127.0.0.1:9", "vendors", "list"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("HODEISHIELD_API_KEY"));
}

#[test]
fn whoami_names_the_source_but_never_the_key() {
    let env = Env::new();
    let server = mockito::Server::new();
    let output = env.api(&server).args(["whoami"]).output().expect("run");
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("tenant API key (HODEISHIELD_API_KEY)")
    );
    assert_no_key(&output);
    let output = env
        .api(&server)
        .args(["--json", "whoami"])
        .output()
        .expect("run");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(body["credential"], "api_key");
    assert_no_key(&output);
}

#[test]
fn config_profiles_round_trip() {
    let env = Env::new();
    env.cmd()
        .args([
            "--profile",
            "staging",
            "config",
            "set",
            "api_url",
            "https://api.staging.example.test",
        ])
        .assert()
        .success();
    env.cmd()
        .args(["config", "use", "staging"])
        .assert()
        .success();
    let output = env
        .cmd()
        .args(["--json", "config", "show"])
        .output()
        .expect("run");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(body["profile"], "staging");
    assert_eq!(body["api_url"], "https://api.staging.example.test/");
    env.cmd()
        .args(["config", "set", "api_url", "http://api.example.test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must use https"));
    env.cmd()
        .args(["--profile", "missing", "vendors", "list"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Profile `missing` is not defined.",
        ));
    let text = std::fs::read_to_string(&env.config).expect("config written");
    assert!(text.contains("default_profile = \"staging\""), "{text}");
}

/// Without a reachable Secret Service (as in every test here) signing in is refused before the app
/// is asked for anything. Only on Linux: elsewhere the real keychain would be consulted.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn login_is_refused_up_front_when_there_is_no_keychain_to_keep_the_session_in() {
    for args in [&["login"][..], &["login", "--device"][..]] {
        let env = Env::new();
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let untouched: Vec<_> = [&mut api, &mut app]
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
        env.cmd()
            .env("HODEISHIELD_API_URL", api.url())
            .env("HODEISHIELD_APP_URL", app.url())
            .args(args)
            .assert()
            .code(1)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("system keychain is not available"))
            .stderr(predicate::str::contains("HODEISHIELD_API_KEY"));
        for mock in &untouched {
            mock.assert();
        }
    }
}

#[test]
fn completions_are_generated() {
    Env::new()
        .cmd()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hodeishield"));
}

#[test]
fn only_get_is_ever_sent() {
    // The generated client exposes no other method; this pins it at the binary level too. The
    // mock answers GET only: any other method would get mockito's 501 and fail the command.
    let env = Env::new();
    let mut server = mockito::Server::new();
    let gets = server
        .mock("GET", mockito::Matcher::Any)
        .with_body(page(&[], 1, 0, 0))
        .expect(7)
        .create();
    for args in [
        vec!["vendors", "list"],
        vec!["alerts", "list"],
        vec!["risks", "list"],
        vec!["evidence", "list"],
        vec!["endpoints", "list"],
        vec!["reports", "list"],
        vec!["compliance", "controls", "-f", "ens"],
    ] {
        env.api(&server).args(&args).assert().success();
    }
    gets.assert();
}

#[test]
fn server_text_in_error_messages_is_cleaned() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_status(400)
        .with_body(r#"{"error":{"code":"invalid_request","message":"bad \u001b]52;c;cHduZWQ=\u0007 \u202e","request_id":"r\u001b[5m"}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    for byte in [0x1b_u8, 0x07] {
        assert!(
            !output.stderr.contains(&byte),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!String::from_utf8_lossy(&output.stderr).contains('\u{202e}'));
}

#[test]
fn a_proxy_from_the_environment_is_not_used_for_loopback() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let mut proxy = mockito::Server::new();
    let never = proxy.mock("GET", mockito::Matcher::Any).expect(0).create();
    server
        .mock("GET", "/v1/endpoints")
        .with_body(page(&[], 1, 0, 0))
        .create();
    env.api(&server)
        .env("HTTP_PROXY", proxy.url())
        .env("http_proxy", proxy.url())
        .env("ALL_PROXY", proxy.url())
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .args(["endpoints", "list"])
        .assert()
        .success();
    never.assert();
}

#[test]
fn vendors_list_csv_single_page() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_body(page(
            &[
                vendor("v1", "Example Hosting"),
                vendor("v2", "Second Vendor"),
            ],
            1,
            60,
            2,
        ))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list", "--csv"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "Command failed: status={:?}, stdout={}, stderr={}",
        output.status,
        stdout,
        stderr
    );
    // Header should be present
    assert!(stdout.contains("id"), "Missing 'id' in stdout: {}", stdout);
    assert!(
        stdout.contains("name"),
        "Missing 'name' in stdout: {}",
        stdout
    );
    // Rows should be present
    assert!(
        stdout.contains("Example Hosting"),
        "Missing 'Example Hosting' in stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("Second Vendor"),
        "Missing 'Second Vendor' in stdout: {}",
        stdout
    );
    // Should have CRLF line endings (RFC 4180)
    assert!(stdout.contains("\r\n"), "CSV should use CRLF: {}", stdout);
    // Stderr should have paging info, not mixed into stdout (we set total_pages=2)
    assert!(
        stderr.contains("Page 1 of 2 (60 vendors)") && stderr.contains("Next: --page 2, or --all."),
        "Missing paging info in stderr: {}",
        stderr
    );
    assert_no_key(&output);
}

#[test]
fn csv_with_all_prints_one_header_and_every_page() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    for (n, title) in [(1, "=cmd()"), (2, "Second, with a comma")] {
        server
            .mock("GET", "/v1/alerts")
            .match_query(mockito::Matcher::UrlEncoded("page".into(), n.to_string()))
            .with_body(format!(
                r#"{{"data":[{{"id":"a{n}","vendor_id":"v","type":"cve","severity":null,"title":"{title}","description":null,"source_url":null,"economic_impact":-5,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z"}}],"pagination":{{"page":{n},"per_page":1,"total":2,"total_pages":2}}}}"#
            ))
            .expect(1)
            .create();
    }
    let output = env
        .api(&server)
        .args(["alerts", "list", "--all", "--csv"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "id,vendor_id,type,severity,title,description,source_url,economic_impact,status,\
         acknowledged_at,resolved_at,resolution_reason,created_at\r\n\
         a1,v,cve,,'=cmd(),,,-5,open,,,,2026-01-01T00:00:00Z\r\n\
         a2,v,cve,,\"Second, with a comma\",,,-5,open,,,,2026-01-01T00:00:00Z\r\n"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("2 alerts."));
}

#[test]
fn csv_empty_list_prints_nothing_to_stdout() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_body(page(&[], 1, 0, 1))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list", "--csv"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.is_empty(),
        "stdout should be empty for empty list: {stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No vendors found."), "{stderr}");
}

#[test]
fn json_and_csv_conflict() {
    let env = Env::new();
    for args in [
        ["vendors", "list", "--json", "--csv"],
        ["vendors", "list", "--csv", "--json"],
        ["--json", "vendors", "list", "--csv"],
    ] {
        let output = env.cmd().args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    }
}

#[test]
fn compliance_controls_csv() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/controls")
        .match_query(mockito::Matcher::UrlEncoded("framework".into(), "nis2".into()))
        .with_body(
            r#"{"data":[{"id":"c1","control_code":"1.1","control_id":"1.1","framework":"nis2","description":"First","status":"passing","evidence_count":5},{"id":"c2","control_code":"1.2","control_id":"1.2","framework":"nis2","description":"Second","status":"failing","evidence_count":0}],"pagination":{"page":1,"per_page":50,"total":2,"total_pages":1}}"#,
        )
        .create();
    let output = env
        .api(&server)
        .args(["compliance", "controls", "-f", "nis2", "--csv"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("id"), "{stdout}");
    assert!(stdout.contains("c1"), "{stdout}");
    assert!(stdout.contains("c2"), "{stdout}");
    assert!(stdout.contains("passing"), "{stdout}");
    assert!(stdout.contains("failing"), "{stdout}");
    assert_no_key(&output);
}

/// The vendors `category` filter is free text with no list in the document, so it is sent exactly
/// as typed, without a warning, and the command succeeds.
#[test]
fn a_free_form_filter_is_sent_as_typed_without_a_warning() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::UrlEncoded(
            "category".into(),
            "Cloud Host".into(),
        ))
        .with_body(page(&[], 1, 0, 1))
        .expect(1)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list", "--category", "Cloud Host"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("warning:"), "{stderr}");
    mock.assert();
}

/// The document lists values for the risks `domain` and `status` filters and the compliance
/// controls `status` filter: a listed value goes through silently, another one gets a warning and
/// is still sent exactly as typed.
#[test]
fn listed_risk_and_control_filters_warn_and_are_sent_as_typed() {
    let controls = |status: &'static str| -> Vec<&'static str> {
        vec![
            "compliance",
            "controls",
            "--framework",
            "nis2",
            "--status",
            status,
        ]
    };
    for (args, path, param, value, expected) in [
        (
            vec!["risks", "list", "--domain", "cyber"],
            "/v1/risks",
            "domain",
            "cyber",
            None,
        ),
        (
            vec!["risks", "list", "--domain", "Cyber"],
            "/v1/risks",
            "domain",
            "Cyber",
            Some(
                "for --domain (vendor, cyber, data, operational, compliance, concentration, strategic, legal, financial, reputational); did you mean `cyber`? Sending it anyway.",
            ),
        ),
        (
            vec!["risks", "list", "--status", "closed"],
            "/v1/risks",
            "status",
            "closed",
            None,
        ),
        (
            vec!["risks", "list", "--status", "open"],
            "/v1/risks",
            "status",
            "open",
            Some(
                "warning: `open` is not one of the values the API lists for --status (identified, assessed, treatment_planned, treatment_implemented, closed); sending it anyway.",
            ),
        ),
        (
            controls("covered"),
            "/v1/compliance/controls",
            "status",
            "covered",
            None,
        ),
        (
            controls("Covered"),
            "/v1/compliance/controls",
            "status",
            "Covered",
            Some(
                "for --status (covered, partial, missing); did you mean `covered`? Sending it anyway.",
            ),
        ),
    ] {
        let env = Env::new();
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", path)
            .match_query(mockito::Matcher::UrlEncoded(param.into(), value.into()))
            .with_body(page(&[], 1, 0, 1))
            .expect(1)
            .create();
        let output = env.api(&server).args(&args).output().expect("run");
        assert!(output.status.success(), "{args:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected {
            Some(warning) => assert!(stderr.contains(warning), "{args:?}: {stderr}"),
            None => assert!(!stderr.contains("warning:"), "{args:?}: {stderr}"),
        }
        mock.assert();
    }
}

/// The opt-in plain-text token store, end to end. Unix only: Windows refuses it (last test).
#[cfg(unix)]
mod file_store {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Mutex};

    /// An app that offers the device flow and issues `at-new` / `rt-new`; revocation requests are
    /// recorded in arrival order.
    struct App {
        api: mockito::ServerGuard,
        app: mockito::ServerGuard,
        revoked: Arc<Mutex<Vec<String>>>,
        _mocks: Vec<mockito::Mock>,
    }

    fn app() -> App {
        let mut api = mockito::Server::new();
        let mut app = mockito::Server::new();
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&revoked);
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
                .create(),
            app.mock("POST", "/token")
                .with_body(
                    json!({
                        "access_token": "at-new", "refresh_token": "rt-new",
                        "token_type": "Bearer", "expires_in": 3600,
                    })
                    .to_string(),
                )
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
                .create(),
        ];
        App {
            api,
            app,
            revoked,
            _mocks: mocks,
        }
    }

    impl App {
        fn with(&self, mut cmd: Command) -> Command {
            cmd.env("HODEISHIELD_API_URL", self.api.url())
                .env("HODEISHIELD_APP_URL", self.app.url());
            cmd
        }
    }

    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).expect("metadata").mode() & 0o777
    }

    /// The files in the sessions directory.
    fn kept(env: &Env) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(env.sessions())
            .map(|dir| dir.map(|e| e.expect("entry").path()).collect())
            .unwrap_or_default();
        found.sort();
        found
    }

    fn signed_in(env: &Env, app: &App) -> PathBuf {
        app.with(env.cmd_file())
            .args(["login", "--device"])
            .assert()
            .success();
        let files = kept(env);
        assert_eq!(files.len(), 1, "{files:?}");
        files[0].clone()
    }

    fn all_output(output: &std::process::Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    fn login_whoami_and_logout_use_a_private_file_and_never_show_a_token() {
        let env = Env::new();
        let app = app();
        let login = app
            .with(env.cmd_file())
            .args(["login", "--device"])
            .output()
            .expect("run");
        assert!(login.status.success(), "{}", all_output(&login));
        assert!(login.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&login.stderr).contains("stored unencrypted"),
            "{}",
            all_output(&login)
        );

        let files = kept(&env);
        assert_eq!(files.len(), 1, "{files:?}");
        let file = &files[0];
        assert_eq!(mode(file), 0o600);
        assert_eq!(mode(&env.sessions()), 0o700);
        assert!(file.to_string_lossy().ends_with(".json"));
        let text = std::fs::read_to_string(file).expect("file");
        assert!(text.contains("at-new") && text.contains("rt-new"));

        let whoami = app
            .with(env.cmd_file())
            .arg("whoami")
            .output()
            .expect("run");
        assert!(whoami.status.success(), "{}", all_output(&whoami));
        let shown = all_output(&whoami);
        assert!(shown.contains("plain-text file"), "{shown}");
        assert!(
            !shown.contains("at-new") && !shown.contains("rt-new"),
            "{shown}"
        );

        let logout = app
            .with(env.cmd_file())
            .arg("logout")
            .output()
            .expect("run");
        assert!(logout.status.success(), "{}", all_output(&logout));
        assert_eq!(
            *app.revoked.lock().expect("lock"),
            ["refresh_token=rt-new", "access_token=at-new"]
        );
        assert!(kept(&env).is_empty());
        assert!(!all_output(&logout).contains("-new"));
    }

    #[test]
    fn two_profiles_are_kept_in_two_files() {
        let env = Env::new();
        let app = app();
        env.cmd()
            .args(["config", "set", "--profile", "client-b", "api_url"])
            .arg(app.api.url())
            .assert()
            .success();
        signed_in(&env, &app);
        app.with(env.cmd_file())
            .args(["--profile", "client-b", "login", "--device"])
            .assert()
            .success();
        assert_eq!(kept(&env).len(), 2);
        app.with(env.cmd_file())
            .args(["--profile", "client-b", "logout"])
            .assert()
            .success();
        assert_eq!(kept(&env).len(), 1);
        app.with(env.cmd_file()).arg("whoami").assert().success();
    }

    #[test]
    fn a_corrupt_file_is_an_error_that_names_it() {
        let env = Env::new();
        let app = app();
        let file = signed_in(&env, &app);
        std::fs::write(&file, "{ not json").expect("corrupt it");
        for args in [&["whoami"][..], &["vendors", "list"][..]] {
            app.with(env.cmd_file())
                .args(args)
                .assert()
                .code(1)
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::contains("is unreadable"))
                .stderr(predicate::str::contains(file.to_string_lossy().as_ref()));
        }
    }

    /// Every way the store refuses a file or directory: signing in is refused before the app is
    /// asked for anything (exit 1), commands that need a credential are "not authenticated"
    /// (exit 3), and nothing is repaired or deleted.
    fn assert_refused(env: &Env, app: &App, reason: &str) {
        let before = snapshot(env);
        let mut login_api = mockito::Server::new();
        let mut login_app = mockito::Server::new();
        let calls: Vec<_> = [&mut login_api, &mut login_app]
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
        env.cmd_file()
            .env("HODEISHIELD_API_URL", login_api.url())
            .env("HODEISHIELD_APP_URL", login_app.url())
            .args(["login", "--device"])
            .assert()
            .code(1)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(
                "plain-text token store cannot be used",
            ))
            .stderr(predicate::str::contains(reason));
        for call in &calls {
            call.assert();
        }
        for args in [&["whoami"][..], &["vendors", "list"][..]] {
            app.with(env.cmd_file())
                .args(args)
                .assert()
                .code(3)
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::contains(reason));
        }
        // Nothing was sent to the app that signed in, and logout does not revoke what it cannot
        // trust.
        app.revoked.lock().expect("lock").clear();
        app.with(env.cmd_file())
            .arg("logout")
            .assert()
            .code(1)
            .stderr(predicate::str::contains(reason));
        assert!(app.revoked.lock().expect("lock").is_empty());
        assert_eq!(snapshot(env), before, "a refused file is never touched");
    }

    /// Every file in the sessions directory with its bytes.
    fn snapshot(env: &Env) -> Vec<(PathBuf, Vec<u8>)> {
        kept(env)
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path).expect("read");
                (path, bytes)
            })
            .collect()
    }

    #[test]
    fn a_file_open_to_group_or_others_is_refused_and_left_alone() {
        for bits in [0o644, 0o640] {
            let env = Env::new();
            let app = app();
            let file = signed_in(&env, &app);
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(bits)).expect("chmod");
            assert_refused(&env, &app, "accessible to other users");
            assert_eq!(mode(&file), bits);
        }
    }

    #[test]
    fn a_directory_open_to_group_or_others_is_refused_and_left_alone() {
        let env = Env::new();
        let app = app();
        signed_in(&env, &app);
        std::fs::set_permissions(env.sessions(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        assert_refused(&env, &app, "accessible to other users");
        assert_eq!(mode(&env.sessions()), 0o755);
    }

    #[test]
    fn a_symlinked_file_is_refused_and_left_alone() {
        let env = Env::new();
        let app = app();
        let file = signed_in(&env, &app);
        let real = env.sessions().join("elsewhere");
        std::fs::rename(&file, &real).expect("move");
        symlink(&real, &file).expect("link");
        assert_refused(&env, &app, "symbolic link");
        assert!(std::fs::symlink_metadata(&file).expect("meta").is_symlink());
        assert!(real.exists());
    }

    #[test]
    fn a_symlinked_directory_is_refused_and_left_alone() {
        let env = Env::new();
        let app = app();
        signed_in(&env, &app);
        // Next to the sessions directory, which exists on every platform (the state directory is
        // not used on macOS).
        let moved = env.sessions().parent().expect("parent").join("moved");
        std::fs::rename(env.sessions(), &moved).expect("move");
        symlink(&moved, env.sessions()).expect("link");
        assert_refused(&env, &app, "symbolic link");
        assert!(
            std::fs::symlink_metadata(env.sessions())
                .expect("meta")
                .is_symlink()
        );
        assert_eq!(std::fs::read_dir(&moved).expect("dir").count(), 1);
    }

    #[test]
    fn an_invalid_setting_is_an_error_before_anything_else_happens() {
        let env = Env::new();
        let mut server = mockito::Server::new();
        let calls = server.mock("GET", mockito::Matcher::Any).expect(0).create();
        // Even with an API key, which would otherwise never look at the token store.
        for value in ["file", "Keychain", "plaintext"] {
            env.api(&server)
                .env("HODEISHIELD_TOKEN_STORE", value)
                .args(["vendors", "list"])
                .assert()
                .code(1)
                .stderr(predicate::str::contains("not a token store"))
                .stderr(predicate::str::contains("plaintext-file"));
        }
        env.cmd()
            .args(["config", "set", "token_store", "file"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("not a token store"));
        std::fs::write(&env.config, "token_store = \"nope\"\n").expect("config");
        env.api(&server)
            .args(["vendors", "list"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains(
                "token_store: `nope` is not a token store",
            ));
        calls.assert();
        assert!(!env.sessions().exists());
    }

    #[test]
    fn the_setting_can_come_from_the_configuration_file_and_the_environment_wins() {
        let env = Env::new();
        env.cmd()
            .args(["config", "set", "token_store", "plaintext-file"])
            .assert()
            .success();
        env.cmd()
            .args(["config", "show"])
            .assert()
            .success()
            .stdout(predicate::str::contains("token_store      plaintext-file"));
        env.cmd()
            .env("HODEISHIELD_TOKEN_STORE", "keychain")
            .args(["config", "show"])
            .assert()
            .success()
            .stdout(predicate::str::contains("token_store      keychain"));
        let app = app();
        // From the file alone, and without the environment variable, the file store is used.
        app.with(env.cmd())
            .env("HOME", env._dir.path().join("home"))
            .args(["login", "--device"])
            .assert()
            .success();
        assert_eq!(kept(&env).len(), 1);
        env.cmd()
            .args(["config", "unset", "token_store"])
            .assert()
            .success();
        env.cmd()
            .args(["config", "show"])
            .assert()
            .success()
            .stdout(predicate::str::contains("token_store      keychain"));
    }

    /// Only on Linux, where the tests make the Secret Service unreachable.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn there_is_no_fallback_to_a_file_without_the_opt_in() {
        let env = Env::new();
        let app = app();
        app.with(env.cmd())
            .args(["login", "--device"])
            .assert()
            .code(1)
            .stderr(predicate::str::contains("system keychain is not available"))
            .stderr(predicate::str::contains(
                "HODEISHIELD_TOKEN_STORE=plaintext-file",
            ))
            .stderr(predicate::str::contains("HODEISHIELD_API_KEY"));
        assert!(!env.state().exists(), "no file or directory is made");
        // And the other way round: with the opt-in the keychain is never asked, which here would
        // be an error.
        signed_in(&env, &app);
    }

    /// The other direction of "no fallback": a valid session file is not used by the default store.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_session_file_is_not_used_when_the_keychain_is_selected() {
        let env = Env::new();
        let app = app();
        let file = signed_in(&env, &app);
        let before = std::fs::read(&file).expect("read");
        app.with(env.cmd())
            .arg("whoami")
            .assert()
            .code(3)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("keychain is not available"));
        app.with(env.cmd())
            .args(["vendors", "list"])
            .assert()
            .code(3);
        assert_eq!(std::fs::read(&file).expect("read"), before);
    }
}

/// Windows has no mode bits to check, so the opt-in is refused there, before the app is asked for
/// anything.
#[cfg(windows)]
#[test]
fn the_plain_text_token_store_is_refused_on_windows() {
    let env = Env::new();
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
    for args in [&["login"][..], &["login", "--device"][..]] {
        env.cmd()
            .env("HODEISHIELD_TOKEN_STORE", "plaintext-file")
            .env("HODEISHIELD_API_URL", api.url())
            .env("HODEISHIELD_APP_URL", app.url())
            .args(args)
            .assert()
            .code(1)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("not supported on Windows"));
    }
    for call in &calls {
        call.assert();
    }
}

/// The vendored document lists the alert severities and deprecates some older ones: a value that
/// is not listed, or a deprecated one, gets a warning and is still sent exactly as typed.
#[test]
fn listed_and_deprecated_severities_warn_and_are_sent_as_typed() {
    for (value, expected) in [
        ("high", None),
        ("High", Some("did you mean `high`? Sending it anyway.")),
        (
            "alto",
            Some(
                "warning: `alto` is a deprecated value for --severity, accepted by the API until \
                 2027-01-14; use `high`. Sending it as typed.",
            ),
        ),
    ] {
        let env = Env::new();
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/v1/alerts")
            .match_query(mockito::Matcher::UrlEncoded(
                "severity".into(),
                value.into(),
            ))
            .with_body(page(&[], 1, 0, 1))
            .expect(1)
            .create();
        let output = env
            .api(&server)
            .args(["alerts", "list", "--severity", value])
            .output()
            .expect("run");
        assert!(output.status.success(), "{value}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected {
            Some(warning) => assert!(stderr.contains(warning), "{value}: {stderr}"),
            None => assert!(!stderr.contains("warning:"), "{value}: {stderr}"),
        }
        mock.assert();
    }
}

// Client tenants, against a mock of the published portfolio contract (version 2026-10-16).

/// The shape of a portfolio key: `hsp_`, 12 hex, `_`, 64 hex. Its secret part must never be shown.
const PORTFOLIO_KEY: &str =
    "hsp_3f2a9c0d1b4e_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const ACME: &str = "11111111-1111-4111-8111-111111111111";
const BETA: &str = "22222222-2222-4222-8222-222222222222";
const OLD: &str = "33333333-3333-4333-8333-333333333333";

fn tenant(id: &str, slug: &str, active: bool, licence: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{slug} S.L.","slug":"{slug}","organization":{{"id":"o-{slug}","name":"{slug} Group"}},"internal":false,"active":{active},"licence_status":"{licence}"}}"#
    )
}

fn portfolio(tenants: &[String]) -> String {
    page(tenants, 1, tenants.len() as i64, 1)
}

fn mock_portfolio(server: &mut mockito::Server, tenants: &[String]) -> mockito::Mock {
    server
        .mock("GET", "/v1/portfolio/tenants")
        // The API's default order is descending; the CLI asks for alphabetical.
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("sort".into(), "name".into()),
            mockito::Matcher::UrlEncoded("order".into(), "asc".into()),
        ]))
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_body(portfolio(tenants))
        .create()
}

/// A vendor list for one tenant, confirmed the way the API confirms a selection.
fn mock_vendors(server: &mut mockito::Server, tenant_id: &str, names: &[&str]) -> mockito::Mock {
    let items: Vec<String> = names.iter().map(|n| vendor(&format!("v-{n}"), n)).collect();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", tenant_id)
        .with_header("x-hs-tenant", tenant_id)
        .with_body(page(&items, 1, items.len() as i64, 1))
        .create()
}

fn two_clients() -> [String; 2] {
    [
        tenant(ACME, "acme", true, "in_force"),
        tenant(BETA, "beta", true, "grace"),
    ]
}

#[test]
fn tenants_list_prints_the_portfolio_as_table_json_and_csv() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let listing = mock_portfolio(&mut server, &two_clients());
    let table = env
        .api(&server)
        .args(["tenants", "list"])
        .output()
        .expect("run");
    assert!(table.status.success(), "{table:?}");
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert!(stdout.starts_with("SLUG"), "{stdout}");
    assert!(
        stdout.contains("acme") && stdout.contains(BETA) && stdout.contains("grace"),
        "{stdout}"
    );

    let json = env
        .api(&server)
        .args(["tenants", "list", "--json"])
        .output()
        .expect("run");
    let body: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    assert_eq!(body["data"][1]["slug"], "beta");

    let csv = env
        .api(&server)
        .args(["tenants", "list", "--csv"])
        .output()
        .expect("run");
    assert!(String::from_utf8_lossy(&csv.stdout).starts_with("id,name,slug,"));
    listing.expect_at_least(3).assert();
}

#[test]
fn a_tenant_is_selected_by_slug_or_id_and_the_table_stays_as_it_was() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let beta = mock_vendors(&mut server, BETA, &["Beta Hosting"]);
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    for selector in ["beta", "BETA", BETA] {
        let output = env
            .api(&server)
            .args(["--tenant", selector, "vendors", "list"])
            .output()
            .expect("run");
        assert!(output.status.success(), "{selector}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with("ID") && stdout.contains("Beta Hosting"),
            "{stdout}"
        );
        assert!(
            !stdout.contains("TENANT") && !stdout.contains("Acme"),
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("Client tenant: beta ({BETA})")),
            "{stderr}"
        );
        assert_no_key(&output);
    }
    beta.expect(3).assert();
    acme.expect(0).assert();
}

#[test]
fn a_selected_tenant_with_json_is_the_api_body_unchanged() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let body = format!(r#"{{"data":{}}}"#, vendor("v-1", "Acme Hosting"));
    server
        .mock("GET", "/v1/vendors/v-1")
        .match_header("x-hs-tenant", ACME)
        .with_header("x-hs-tenant", ACME)
        .with_body(&body)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "get", "v-1", "--json", "--tenant", "acme"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let shown: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(
        shown,
        serde_json::from_str::<serde_json::Value>(&body).expect("json")
    );
}

#[test]
fn all_tenants_labels_every_row_with_the_tenant_that_returned_it() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    mock_vendors(&mut server, ACME, &["Acme Hosting", "Shared Name"]);
    mock_vendors(&mut server, BETA, &["Beta Hosting", "Shared Name"]);

    let table = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(table.status.success(), "{table:?}");
    let stdout = String::from_utf8_lossy(&table.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines[0].starts_with("TENANT") && lines[0].contains("ID"),
        "{stdout}"
    );
    assert_eq!(lines.len(), 5, "{stdout}");
    let row = |name: &str, slug: &str| {
        lines
            .iter()
            .any(|l| l.starts_with(slug) && l.contains(name))
    };
    assert!(
        row("Acme Hosting", "acme") && row("Beta Hosting", "beta"),
        "{stdout}"
    );
    assert!(
        !row("Acme Hosting", "beta") && !row("Beta Hosting", "acme"),
        "{stdout}"
    );
    assert!(String::from_utf8_lossy(&table.stderr).contains("4 vendors across 2 client tenants."));

    let json = env
        .api(&server)
        .args(["--json", "vendors", "list", "--all-tenants"])
        .output()
        .expect("run");
    let items: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    let items = items.as_array().expect("array");
    assert_eq!(items.len(), 4);
    assert_eq!(items[0]["tenant_id"], ACME);
    assert_eq!(items[0]["tenant_slug"], "acme");
    assert_eq!(items[0]["name"], "Acme Hosting");
    assert_eq!(items[0]["added_later"], 1, "unknown fields are kept");
    assert_eq!(items[3]["tenant_slug"], "beta");

    let csv = env
        .api(&server)
        .args(["vendors", "list", "--all-tenants", "--csv"])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&csv.stdout);
    assert!(
        text.starts_with("tenant_id,tenant_slug,tenant_name,id,"),
        "{text}"
    );
    assert!(
        text.contains(&format!("{BETA},beta,beta S.L.,v-Beta Hosting,")),
        "{text}"
    );
}

#[test]
fn all_tenants_skips_inactive_clients_and_says_so() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant(ACME, "acme", true, "in_force"),
            tenant(OLD, "old", false, "inactive"),
        ],
    );
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Skipping 1 inactive client tenant (")
    );
}

#[test]
fn a_tenant_that_cannot_be_read_is_reported_and_the_command_still_fails() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", BETA)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r1","details":{"code":"LICENCE_INACTIVE","licence":"expired"}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(8), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Acme Hosting"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning: client tenant beta"), "{stderr}");
    assert!(
        stderr.contains("Could not read 1 of 2 client tenants"),
        "{stderr}"
    );
}

#[test]
fn a_client_outside_the_portfolio_fails_clearly_without_reading_any_data() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let data = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .expect(0)
        .create();
    for selector in ["stranger", "44444444-4444-4444-8444-444444444444"] {
        let output = env
            .api(&server)
            .args(["vendors", "list", "--tenant", selector])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(5), "{selector}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "No client tenant {selector} in this credential's portfolio."
            )),
            "{stderr}"
        );
        assert!(output.stdout.is_empty());
    }
    data.assert();
}

#[test]
fn the_server_refusing_a_selected_client_is_not_found_too() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"No such tenant in this credential's portfolio.","request_id":"r2"}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list", "--tenant", "acme"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("No such tenant"));
}

#[test]
fn an_answer_that_does_not_confirm_the_client_prints_nothing() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    // The server answers with the other client's confirmation.
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_header("x-hs-tenant", BETA)
        .with_body(page(&[vendor("v1", "Beta Hosting")], 1, 1, 1))
        .create();
    for args in [&["--tenant", "acme"][..], &["--all-tenants"][..]] {
        let output = env
            .api(&server)
            .args(args)
            .args(["vendors", "list"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("did not confirm the client tenant")
        );
    }
}

#[test]
fn without_a_selection_nothing_changes_for_a_single_tenant_credential() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let listing = server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .expect(0)
        .create();
    let vendors = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_body(page(&[vendor("v1", "Example Hosting")], 1, 1, 1))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("ID") && !stdout.contains("TENANT"),
        "{stdout}"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Client tenant"));
    listing.assert();
    vendors.assert();
}

#[test]
fn selecting_a_client_with_a_single_tenant_credential_explains_what_is_missing() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r3"}}"#)
        .create();
    for args in [&["--tenant", "acme"][..], &["--all-tenants"][..]] {
        let output = env
            .api(&server)
            .args(args)
            .args(["vendors", "list"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(4), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("portfolio:read"), "{stderr}");
        assert!(stderr.contains("need a portfolio credential"), "{stderr}");
    }
    let output = env
        .api(&server)
        .args(["tenants", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(4), "{output:?}");
}

#[test]
fn a_portfolio_credential_without_a_selection_is_told_how_to_select() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(400)
        .with_body(r#"{"error":{"code":"invalid_request","message":"X-HS-Tenant is required","request_id":"r4","details":{"code":"TENANT_REQUIRED"}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--all-tenants"));
}

#[test]
fn a_server_message_that_ends_a_sentence_gets_one_full_stop() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(400)
        .with_body(r#"{"error":{"code":"invalid_request","message":"Bad filter value.","request_id":"r5"}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("The API rejected the request: Bad filter value.\n"),
        "{stderr}"
    );
    assert!(!stderr.contains(".."), "{stderr}");
}

#[test]
fn one_item_across_the_clients_is_counted_in_the_singular() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant(ACME, "acme", true, "in_force"),
            tenant(BETA, "beta", true, "in_force"),
        ],
    );
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    mock_vendors(&mut server, BETA, &[]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 vendor across 2 client tenants."),
        "{stderr}"
    );
}

#[test]
fn tenant_names_from_the_server_cannot_drive_the_terminal() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[tenant(ACME, "ac\\u001b[2Jme", true, "in_force")],
    );
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!all.contains('\u{1b}'), "{all:?}");
    assert!(all.contains("ac\u{fffd}[2Jme"), "{all:?}");
}

#[test]
fn the_selection_is_refused_where_it_cannot_apply() {
    let env = Env::new();
    for args in [
        &["--tenant", "acme", "--all-tenants", "vendors", "list"][..],
        &["--tenant", "acme", "whoami"][..],
        &["--all-tenants", "tenants", "list"][..],
        &["--all-tenants", "vendors", "get", "v1"][..],
        &["--all-tenants", "reports", "get", "r1"][..],
        &["--all-tenants", "reports", "download", "r1"][..],
        &["--all-tenants", "compliance", "posture", "nis2"][..],
        &["--all-tenants", "vendors", "list", "--page", "2"][..],
    ] {
        let output = env.cmd().args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    }
}

/// Runs the CLI with a real-shaped portfolio key, so a leak of the secret part would show.
fn portfolio_cmd(env: &Env, server: &mockito::Server) -> Command {
    let mut cmd = env.cmd();
    cmd.env("HODEISHIELD_API_KEY", PORTFOLIO_KEY)
        .env("HODEISHIELD_API_URL", server.url());
    cmd
}

fn assert_no_portfolio_secret(output: &std::process::Output) {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let secret = PORTFOLIO_KEY.rsplit('_').next().expect("secret part");
    assert!(
        !all.contains(secret),
        "the key's secret part leaked:\n{all}"
    );
    assert!(!all.contains(PORTFOLIO_KEY), "the key leaked:\n{all}");
}

#[test]
fn a_portfolio_key_in_its_published_format_is_sent_as_a_bearer_and_never_shown() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let bearer = format!("Bearer {PORTFOLIO_KEY}");
    let listing = server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", bearer.as_str())
        .with_body(portfolio(&two_clients()))
        .create();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", bearer.as_str())
        .match_header("x-hs-tenant", ACME)
        .with_header("x-hs-tenant", ACME)
        .with_body(page(&[vendor("v1", "Acme Hosting")], 1, 1, 1))
        .create();
    for args in [
        &["tenants", "list"][..],
        &["--tenant", "acme", "vendors", "list"][..],
    ] {
        let output = portfolio_cmd(&env, &server)
            .args(args)
            .output()
            .expect("run");
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert_no_portfolio_secret(&output);
    }
    // A refused key is reported without echoing it either.
    let mut rejected = mockito::Server::new();
    rejected
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .with_status(401)
        .with_body(
            r#"{"error":{"code":"unauthorized","message":"Invalid API key","request_id":"r"}}"#,
        )
        .create();
    let output = portfolio_cmd(&env, &rejected)
        .args(["tenants", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_no_portfolio_secret(&output);
    listing.expect_at_least(2).assert();
}

#[test]
fn all_tenants_skips_what_is_not_readable_by_the_contract_rule() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let off = "55555555-5555-4555-8555-555555555555";
    mock_portfolio(
        &mut server,
        &[
            tenant(ACME, "acme", true, "in_force"),
            tenant(BETA, "beta", true, "grace"),
            // Listed by the server, but a client reading them would get a 403.
            tenant(OLD, "old", true, "inactive"),
            tenant(off, "off", false, "in_force"),
        ],
    );
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let beta = mock_vendors(&mut server, BETA, &["Beta Hosting"]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Skipping 2 inactive client tenants"),
        "{stderr}"
    );
    assert!(
        stderr.contains("2 vendors across 2 client tenants."),
        "{stderr}"
    );
    acme.assert();
    beta.assert();
}

#[test]
fn an_api_that_does_not_offer_the_portfolio_says_so_with_its_own_exit_code() {
    let env = Env::new();
    for status in [404, 405] {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/portfolio/tenants")
            .match_query(mockito::Matcher::Any)
            .with_status(status)
            .with_body(r#"{"error":{"code":"not_found","message":"Not found","request_id":"r"}}"#)
            .create();
        let data = server
            .mock("GET", "/v1/vendors")
            .match_query(mockito::Matcher::Any)
            .expect(0)
            .create();
        for args in [
            &["tenants", "list"][..],
            &["--tenant", "acme", "vendors", "list"][..],
            &["--all-tenants", "vendors", "list"][..],
        ] {
            let output = env.api(&server).args(args).output().expect("run");
            assert_eq!(
                output.status.code(),
                Some(7),
                "{status} {args:?}: {output:?}"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("does not offer portfolio access yet"),
                "{stderr}"
            );
            assert!(output.stdout.is_empty());
        }
        data.assert();
    }
}

#[test]
fn a_rate_limit_stops_an_all_tenants_walk_and_names_its_scope() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    // A wait too long to sit out: the walk ends, and the second client is never asked.
    let limited = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", ACME)
        .with_status(429)
        .with_header("retry-after", "600")
        .with_body(r#"{"error":{"code":"rate_limited","message":"x","request_id":"r9","details":{"scope":"portfolio_key","limit":100,"window_seconds":60,"retry_after_seconds":600}}}"#)
        .expect(1)
        .create();
    let second = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", BETA)
        .expect(0)
        .create();
    let output = portfolio_cmd(&env, &server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("(limit: portfolio_key)"), "{stderr}");
    assert!(stderr.contains("Try again in 600 s."), "{stderr}");
    assert_no_portfolio_secret(&output);
    limited.assert();
    second.assert();
}

#[test]
fn a_short_rate_limit_is_waited_out_and_the_walk_goes_on() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let limited = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", ACME)
        .with_status(429)
        .with_header("retry-after", "1")
        .with_body(r#"{"error":{"code":"rate_limited","message":"x","request_id":"r9","details":{"scope":"portfolio_tenant","limit":60,"window_seconds":60,"retry_after_seconds":1}}}"#)
        .expect(1)
        .create();
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let beta = mock_vendors(&mut server, BETA, &["Beta Hosting"]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    limited.assert();
    acme.assert();
    beta.assert();
}

#[test]
fn a_missing_data_scope_stops_the_walk_instead_of_failing_once_per_tenant() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let refused = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"INSUFFICIENT_SCOPE","missing":["supply_risk:read"]}}}"#)
        .expect(1)
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("supply_risk:read"));
    refused.assert();
}

#[test]
fn a_missing_scope_with_a_portfolio_key_hints_organisation_administrator() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"INSUFFICIENT_SCOPE","missing":["supply_risk:read"]}}}"#)
        .create();
    let output = portfolio_cmd(&env, &server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(stderr.contains("organisation administrator"), "{stderr}");
    assert!(!stderr.contains("tenant administrator"), "{stderr}");
}

#[test]
fn a_missing_scope_with_a_regular_key_hints_tenant_administrator() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"INSUFFICIENT_SCOPE","missing":["supply_risk:read"]}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(stderr.contains("tenant administrator"), "{stderr}");
    assert!(!stderr.contains("organisation administrator"), "{stderr}");
}

#[test]
fn a_deactivated_client_is_a_licence_refusal_not_a_missing_resource() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"LICENCE_INACTIVE","licence":"tenant_inactive"}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(8), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("The tenant is deactivated."));
}

#[test]
fn a_tenant_the_server_does_not_know_gets_the_same_answer_as_one_it_hides() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"No such tenant in this credential's portfolio.","request_id":"r2","details":{"code":"TENANT_NOT_FOUND"}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No such tenant in this credential's portfolio."),
        "{stderr}"
    );
    assert!(stderr.contains("tenants list"), "{stderr}");
}

#[test]
fn the_selector_errors_of_the_contract_are_explained() {
    let env = Env::new();
    for (code, expected) in [
        ("TENANT_SELECTOR_NOT_SUPPORTED", "leave out --tenant"),
        ("TENANT_HEADER_INVALID", "please report it"),
    ] {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/vendors")
            .match_query(mockito::Matcher::Any)
            .with_status(400)
            .with_body(format!(
                r#"{{"error":{{"code":"invalid_request","message":"x","request_id":"r","details":{{"code":"{code}","parameter":"X-HS-Tenant"}}}}}}"#
            ))
            .create();
        let output = env
            .api(&server)
            .args(["vendors", "list"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{code}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{code}"
        );
    }
}

#[test]
fn an_echo_in_the_wrong_form_prints_nothing() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let mixed = "0B8F2A52-6A0E-4D5C-9D3E-1F2A3B4C5D6E";
    mock_portfolio(&mut server, &[tenant(mixed, "acme", true, "in_force")]);
    // The contract's echo is lowercase; capitals are not what an honest server sends.
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", mixed.to_ascii_lowercase().as_str())
        .with_header("x-hs-tenant", mixed)
        .with_body(page(&[vendor("v1", "Acme Hosting")], 1, 1, 1))
        .create();
    let output = env
        .api(&server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
}

// Review follow-ups.

const STRANGE: &str = "44444444-4444-4444-8444-444444444444";

/// A tenant with a free-form name and slug (quotes and non-ASCII letters included).
fn tenant_named(id: &str, slug: &str, name: &str) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "slug": slug,
        "organization": {"id": "o", "name": "Group"},
        "internal": false,
        "active": true,
        "licence_status": "in_force",
    })
    .to_string()
}

fn never_read(server: &mut mockito::Server) -> mockito::Mock {
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .expect(0)
        .create()
}

#[test]
fn an_unknown_licence_status_is_not_read_is_named_and_fails_the_command() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant(ACME, "acme", true, "in_force"),
            tenant(OLD, "old", true, "inactive"),
            tenant(STRANGE, "strange", true, "a_status_from_the_future"),
        ],
    );
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let strange = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", STRANGE)
        .expect(0)
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Acme Hosting"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // "inactive" is said of the inactive tenant only.
    assert!(
        stderr.contains("Skipping 1 inactive client tenant ("),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "warning: client tenant strange: licence status `a_status_from_the_future` is not known to this version; not read"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("Could not read 1 of 2 client tenants"),
        "{stderr}"
    );
    acme.assert();
    strange.assert();
}

#[test]
fn a_walk_where_one_tenant_is_mismatched_prints_nothing() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    // Beta is asked for and answers with Acme's confirmation.
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", BETA)
        .with_header("x-hs-tenant", ACME)
        .with_body(page(&[vendor("v9", "Acme Hosting")], 1, 1, 1))
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}

#[test]
fn a_second_page_that_is_not_confirmed_prints_nothing() {
    let env = Env::new();
    for args in [
        &["--tenant", "acme", "vendors", "list", "--all"][..],
        &["--all-tenants", "vendors", "list", "--all"][..],
    ] {
        let mut server = mockito::Server::new();
        mock_portfolio(&mut server, &[tenant(ACME, "acme", true, "in_force")]);
        let page_of = |n: i64, name: &str| page(&[vendor(&format!("v{n}"), name)], n, 120, 3);
        for (n, echo) in [(1_i64, ACME), (2, BETA)] {
            server
                .mock("GET", "/v1/vendors")
                .match_query(mockito::Matcher::UrlEncoded("page".into(), n.to_string()))
                .match_header("x-hs-tenant", ACME)
                .with_header("x-hs-tenant", echo)
                .with_body(page_of(n, &format!("Item {n}")))
                .create();
        }
        let output = env.api(&server).args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn a_walk_stops_with_nothing_on_stdout_when_a_later_tenant_fails() {
    let env = Env::new();
    let scope = r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"INSUFFICIENT_SCOPE","missing":["supply_risk:read"]}}}"#;
    let unauthorised = r#"{"error":{"code":"unauthorized","message":"x","request_id":"r"}}"#;
    let down = r#"{"error":{"code":"unavailable","message":"x","request_id":"r"}}"#;
    for (status, body, expected) in [(401, unauthorised, 3), (503, down, 7), (403, scope, 4)] {
        let mut server = mockito::Server::new();
        mock_portfolio(&mut server, &two_clients());
        mock_vendors(&mut server, ACME, &["Acme Hosting"]);
        server
            .mock("GET", "/v1/vendors")
            .match_query(mockito::Matcher::Any)
            .match_header("x-hs-tenant", BETA)
            .with_status(status)
            // A zero wait keeps the retries of the 503 quick.
            .with_header("retry-after", "0")
            .with_body(body)
            .create();
        let output = env
            .api(&server)
            .args(["--all-tenants", "vendors", "list"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(expected), "{status}: {output:?}");
        assert!(output.stdout.is_empty(), "{status}: {output:?}");
    }
}

#[test]
fn tenant_labels_in_csv_cannot_run_as_formulas() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant_named(ACME, "+cmd", r#"=HYPERLINK("http://example.invalid","x")"#),
            tenant_named(BETA, "beta", "-2+3"),
        ],
    );
    mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    mock_vendors(&mut server, BETA, &["Beta Hosting"]);
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list", "--csv"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains(&format!(
            "{ACME},'+cmd,\"'=HYPERLINK(\"\"http://example.invalid\"\",\"\"x\"\")\","
        )),
        "{text}"
    );
    assert!(text.contains(&format!("{BETA},beta,'-2+3,")), "{text}");
    assert!(
        !text.contains(",+cmd,") && !text.contains(",=HYPERLINK"),
        "{text}"
    );
}

#[test]
fn slug_resolution_is_case_insensitive_and_never_guesses() {
    let env = Env::new();
    // Mixed-case input finds the slug.
    let mut server = mockito::Server::new();
    mock_portfolio(&mut server, &two_clients());
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let output = env
        .api(&server)
        .args(["--tenant", "AcMe", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    acme.assert();

    // Two slugs that differ only in case are ambiguous.
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant_named(ACME, "Acme", "One"),
            tenant_named(BETA, "acme", "Two"),
        ],
    );
    let data = never_read(&mut server);
    let output = env
        .api(&server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("More than one client tenant"));
    assert!(output.stdout.is_empty());
    data.assert();

    // A slug with a Cyrillic "а" is not matched by the ASCII word.
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[tenant_named(ACME, "\u{430}cme", "Look-alike")],
    );
    let data = never_read(&mut server);
    let output = env
        .api(&server)
        .args(["--tenant", "acme", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    data.assert();

    // A slug shaped like a UUID that is also another tenant's id is ambiguous.
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant_named(ACME, BETA, "Slug is an id"),
            tenant_named(BETA, "beta", "Has that id"),
        ],
    );
    let data = never_read(&mut server);
    let output = env
        .api(&server)
        .args(["--tenant", BETA, "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("More than one client tenant"));
    assert!(output.stdout.is_empty());
    data.assert();
}

#[test]
fn an_id_that_is_not_a_uuid_fails_before_any_data_request() {
    let env = Env::new();
    for args in [
        &["--all-tenants", "vendors", "list"][..],
        &["--tenant", "weird", "vendors", "list"][..],
    ] {
        let mut server = mockito::Server::new();
        mock_portfolio(
            &mut server,
            &[
                tenant(ACME, "acme", true, "in_force"),
                tenant("not-a-uuid", "weird", true, "in_force"),
            ],
        );
        let data = never_read(&mut server);
        let output = env.api(&server).args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        data.assert();
    }
}

#[test]
fn a_portfolio_key_without_a_selection_sends_no_tenant_header() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let required = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_status(400)
        .with_body(r#"{"error":{"code":"invalid_request","message":"X-HS-Tenant is required","request_id":"r4","details":{"code":"TENANT_REQUIRED"}}}"#)
        .expect(1)
        .create();
    let output = portfolio_cmd(&env, &server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("--all-tenants"));
    required.assert();
}

#[test]
fn look_alike_slugs_are_told_apart_by_id_in_the_table_only() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    mock_portfolio(
        &mut server,
        &[
            tenant_named(ACME, "acme", "Real"),
            tenant_named(BETA, "\u{430}cme", "Look-alike"),
        ],
    );
    mock_vendors(&mut server, ACME, &["Real Hosting"]);
    mock_vendors(&mut server, BETA, &["Fake Hosting"]);
    let table = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&table.stdout);
    assert!(
        stdout.lines().any(|l| l.starts_with("acme ")) && stdout.contains("\u{430}cme [22222222]"),
        "{stdout}"
    );
    let json = env
        .api(&server)
        .args(["--json", "--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    let items: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    assert_eq!(items[1]["tenant_slug"], "\u{430}cme");
}

#[test]
fn a_tenant_listed_on_two_pages_is_read_once_and_a_changing_total_is_reported() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    for (n, items, total) in [
        (
            1_i64,
            vec![
                tenant(ACME, "acme", true, "in_force"),
                tenant(BETA, "beta", true, "grace"),
            ],
            120,
        ),
        (2, vec![tenant(BETA, "beta", true, "grace")], 121),
    ] {
        server
            .mock("GET", "/v1/portfolio/tenants")
            .match_query(mockito::Matcher::UrlEncoded("page".into(), n.to_string()))
            .with_body(page(&items, n, total, 2))
            .create();
    }
    let acme = mock_vendors(&mut server, ACME, &["Acme Hosting"]);
    let beta = server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .match_header("x-hs-tenant", BETA)
        .with_header("x-hs-tenant", BETA)
        .with_body(page(&[vendor("vb", "Beta Hosting")], 1, 1, 1))
        .expect(1)
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed while they were listed (120, then 121)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("2 vendors across 2 client tenants."),
        "{stderr}"
    );
    acme.assert();
    beta.assert();
}

#[test]
fn a_404_with_a_portfolio_code_on_the_listing_is_not_taken_for_a_missing_feature() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"No such tenant","request_id":"r","details":{"code":"TENANT_NOT_FOUND"}}}"#)
        .create();
    let output = env
        .api(&server)
        .args(["--all-tenants", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("does not offer portfolio access"),
        "{stderr}"
    );
}

#[test]
fn the_client_wording_of_a_tenant_rate_limit_needs_a_selected_client() {
    let env = Env::new();
    let limit = |scope: &str| {
        format!(
            r#"{{"error":{{"code":"rate_limited","message":"x","request_id":"r","details":{{"scope":"{scope}","retry_after_seconds":600}}}}}}"#
        )
    };
    let wording = "own limit is used up";
    // A single-tenant key, no selection: the previous message, with no client advice.
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(429)
        .with_header("retry-after", "600")
        .with_body(limit("tenant"))
        .create();
    let output = env
        .api(&server)
        .args(["vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("(limit: tenant)") && !stderr.contains(wording),
        "{stderr}"
    );

    // With a client selected, or for the portfolio's per-client limit, the advice is given.
    for (scope, args) in [
        ("tenant", &["--tenant", "acme", "vendors", "list"][..]),
        (
            "portfolio_tenant",
            &["--tenant", "acme", "vendors", "list"][..],
        ),
        ("portfolio_tenant", &["vendors", "list"][..]),
    ] {
        let mut server = mockito::Server::new();
        mock_portfolio(&mut server, &two_clients());
        server
            .mock("GET", "/v1/vendors")
            .match_query(mockito::Matcher::Any)
            .with_status(429)
            .with_header("retry-after", "600")
            .with_body(limit(scope))
            .create();
        let output = env.api(&server).args(args).output().expect("run");
        assert_eq!(
            output.status.code(),
            Some(6),
            "{scope} {args:?}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(wording),
            "{scope} {args:?}: {output:?}"
        );
    }
}

const REPORT_ID: &str = "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e";

fn report(id: &str, title: &str, status: &str) -> String {
    format!(
        r#"{{"id":"{id}","report_type":"monthly","title":"{title}","period_start":"2026-09-01","period_end":"2026-09-30","status":"{status}","created_at":"2026-10-01T06:00:00.000Z"}}"#
    )
}

/// A mock of the download of [`REPORT_ID`] that serves `body` under `disposition`.
fn mock_download(server: &mut mockito::Server, disposition: &str, body: &[u8]) -> mockito::Mock {
    server
        .mock("GET", format!("/v1/reports/{REPORT_ID}/download").as_str())
        .match_query(mockito::Matcher::Any)
        .with_header("content-type", "application/pdf")
        .with_header("content-disposition", disposition)
        .with_body(body)
        .create()
}

/// The names of the entries of `dir`, sorted.
fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn reports_list_prints_a_table_and_the_json_body() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("report_type".into(), "monthly".into()),
            mockito::Matcher::UrlEncoded("status".into(), "completed".into()),
            mockito::Matcher::UrlEncoded("sort".into(), "period_end".into()),
        ]))
        .with_body(page(
            &[report(REPORT_ID, "September summary", "completed")],
            1,
            1,
            1,
        ))
        .expect(2)
        .create();
    let args = [
        "reports",
        "list",
        "--type",
        "monthly",
        "--status",
        "completed",
        "--sort",
        "period_end",
    ];
    let output = env.api(&server).args(args).output().expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let header: Vec<&str> = stdout
        .lines()
        .next()
        .expect("header")
        .split_whitespace()
        .collect();
    assert_eq!(
        header,
        ["ID", "TYPE", "TITLE", "PERIOD", "STATUS", "CREATED"]
    );
    assert!(
        stdout.contains("September summary")
            && stdout.contains("2026-09-01 to 2026-09-30")
            && stdout.contains("2026-10-01 06:00Z"),
        "{stdout}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");

    let output = env
        .api(&server)
        .arg("--json")
        .args(args)
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(body["data"][0]["title"], "September summary");
}

#[test]
fn listed_report_filters_warn_and_are_sent_as_typed() {
    for (args, param, value, expected) in [
        (
            vec!["reports", "list", "--type", "Monthly"],
            "report_type",
            "Monthly",
            Some(
                "for --report-type (monthly, vendor_risk, nis2_compliance, ens, cyberbrief, compliance, security_posture, board_report); did you mean `monthly`? Sending it anyway.",
            ),
        ),
        (
            vec!["reports", "list", "--report-type", "ens"],
            "report_type",
            "ens",
            None,
        ),
        (
            vec!["reports", "list", "--status", "ready"],
            "status",
            "ready",
            Some(
                "warning: `ready` is not one of the values the API lists for --status (generating, completed, failed); sending it anyway.",
            ),
        ),
    ] {
        let env = Env::new();
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/v1/reports")
            .match_query(mockito::Matcher::UrlEncoded(param.into(), value.into()))
            .with_body(page(&[], 1, 0, 1))
            .expect(1)
            .create();
        let output = env.api(&server).args(&args).output().expect("run");
        assert!(output.status.success(), "{args:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected {
            Some(warning) => assert!(stderr.contains(warning), "{args:?}: {stderr}"),
            None => assert!(!stderr.contains("warning:"), "{args:?}: {stderr}"),
        }
        mock.assert();
    }
}

#[test]
fn reports_get_shows_the_download_formats() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let detail = report(REPORT_ID, "September summary", "completed")
        .replace('}', r#","download_formats":["pdf","xlsx"]}"#);
    server
        .mock("GET", format!("/v1/reports/{REPORT_ID}").as_str())
        .with_body(format!(r#"{{"data":{detail}}}"#))
        .expect(2)
        .create();
    let output = env
        .api(&server)
        .args(["reports", "get", REPORT_ID])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("download_formats  pdf, xlsx"), "{stdout}");
    let output = env
        .api(&server)
        .args(["--json", "reports", "get", REPORT_ID])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(body["data"]["download_formats"][1], "xlsx");
}

#[test]
fn a_download_is_saved_in_the_current_directory_under_the_suggested_name() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    let bytes = b"%PDF-1.7\n\x00\x01binary\xff";
    let mock = server
        .mock("GET", format!("/v1/reports/{REPORT_ID}/download").as_str())
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("format".into(), "xlsx".into()),
            mockito::Matcher::UrlEncoded("locale".into(), "es".into()),
        ]))
        .with_header(
            "content-type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        .with_header(
            "content-disposition",
            r#"attachment; filename="monthly-2026-09.xlsx""#,
        )
        .with_body(bytes)
        .expect(1)
        .create();
    let output = env
        .api(&server)
        .current_dir(cwd.path())
        .args([
            "reports", "download", REPORT_ID, "--format", "xlsx", "--locale", "es",
        ])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    mock.assert();
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!("Saved monthly-2026-09.xlsx ({} bytes).\n", bytes.len())
    );
    assert_eq!(entries(cwd.path()), ["monthly-2026-09.xlsx"]);
    assert_eq!(
        std::fs::read(cwd.path().join("monthly-2026-09.xlsx")).expect("read"),
        bytes
    );
}

#[test]
fn a_download_goes_to_the_output_path_or_into_the_output_directory() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(cwd.path().join("out")).expect("mkdir");
    let mut server = mockito::Server::new();
    mock_download(&mut server, r#"attachment; filename="r.pdf""#, b"%PDF-");
    let target = cwd.path().join("chosen.pdf");
    env.api(&server)
        .current_dir(cwd.path())
        .args(["reports", "download", REPORT_ID, "-o"])
        .arg(&target)
        .assert()
        .success();
    assert_eq!(std::fs::read(&target).expect("read"), b"%PDF-");
    env.api(&server)
        .current_dir(cwd.path())
        .args(["reports", "download", REPORT_ID, "--output", "out"])
        .assert()
        .success()
        .stderr(predicate::str::contains("r.pdf (5 bytes)"));
    assert_eq!(entries(&cwd.path().join("out")), ["r.pdf"]);
    assert_eq!(entries(cwd.path()), ["chosen.pdf", "out"]);
}

#[test]
fn an_existing_file_is_not_replaced_without_force() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    let target = cwd.path().join("keep.pdf");
    std::fs::write(&target, b"mine").expect("write");
    std::fs::write(cwd.path().join("r.pdf"), b"also mine").expect("write");
    let mut server = mockito::Server::new();
    let mock = mock_download(&mut server, r#"attachment; filename="r.pdf""#, b"theirs");

    // A path given with -o is checked before anything is downloaded.
    let output = env
        .api(&server)
        .current_dir(cwd.path())
        .args(["reports", "download", REPORT_ID, "-o", "keep.pdf"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keep.pdf already exists") && stderr.contains("--force"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&target).expect("read"), b"mine");

    // The suggested name is only known after the download; it is not replaced either.
    let output = env
        .api(&server)
        .current_dir(cwd.path())
        .args(["reports", "download", REPORT_ID])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("downloaded but not saved")
            && stderr.contains("r.pdf already exists")
            && stderr.contains("--force")
            && stderr.contains("--output"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read(cwd.path().join("r.pdf")).expect("read"),
        b"also mine"
    );
    assert_eq!(entries(cwd.path()), ["keep.pdf", "r.pdf"]);
    mock.expect(1).assert();

    // --force replaces both.
    for args in [&["-o", "keep.pdf", "--force"][..], &["--force"][..]] {
        env.api(&server)
            .current_dir(cwd.path())
            .args(["reports", "download", REPORT_ID])
            .args(args)
            .assert()
            .success();
    }
    assert_eq!(std::fs::read(&target).expect("read"), b"theirs");
    assert_eq!(
        std::fs::read(cwd.path().join("r.pdf")).expect("read"),
        b"theirs"
    );
    assert_eq!(entries(cwd.path()), ["keep.pdf", "r.pdf"]);
}

#[test]
fn a_hostile_suggested_name_is_saved_as_a_plain_stem_with_the_extension_of_the_format() {
    let fallback = format!("report-{REPORT_ID}.pdf");
    for (disposition, expected) in [
        (r#"attachment; filename="../../etc/passwd""#, "passwd.pdf"),
        (r#"attachment; filename="conftest.py""#, "conftest.pdf"),
        (r#"attachment; filename="x.library-ms""#, "x.pdf"),
        (r#"attachment; filename="a.pdf.exe""#, "a.pdf"),
        (r#"attachment; filename="a.b.pdf""#, "a.pdf"),
        (r#"attachment; filename="a/b\\c.pdf""#, "c.pdf"),
        (r#"attachment; filename="..""#, fallback.as_str()),
        (r#"attachment; filename=".hidden rc""#, "hidden_rc.pdf"),
        (r#"attachment; filename="-rf *.pdf""#, "rf__.pdf"),
        (
            "attachment; filename=\"\u{202e}fdp.exe\"",
            fallback.as_str(),
        ),
        ("attachment", fallback.as_str()),
    ] {
        let env = Env::new();
        let root = tempfile::tempdir().expect("tempdir");
        let cwd = root.path().join("work");
        std::fs::create_dir(&cwd).expect("mkdir");
        let mut server = mockito::Server::new();
        mock_download(&mut server, disposition, b"%PDF-");
        let output = env
            .api(&server)
            .current_dir(&cwd)
            .args(["reports", "download", REPORT_ID])
            .output()
            .expect("run");
        assert!(output.status.success(), "{disposition}: {output:?}");
        assert_eq!(entries(&cwd), [expected], "{disposition}");
        assert_eq!(entries(root.path()), ["work"], "{disposition}");
        assert!(!output.stderr.contains(&0x1b), "{disposition}");
    }
}

#[test]
fn the_extension_follows_the_content_type_when_no_format_is_given() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    server
        .mock("GET", format!("/v1/reports/{REPORT_ID}/download").as_str())
        .match_query(mockito::Matcher::Any)
        .with_header(
            "content-type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        .with_header("content-disposition", r#"attachment; filename="board.dll""#)
        .with_body(b"PK")
        .create();
    env.api(&server)
        .current_dir(cwd.path())
        .args(["reports", "download", REPORT_ID])
        .assert()
        .success();
    assert_eq!(entries(cwd.path()), ["board.xlsx"]);
}

#[test]
fn output_dash_writes_the_file_to_standard_output() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    let bytes = b"%PDF-\x00\x1b\xff";
    mock_download(&mut server, r#"attachment; filename="r.pdf""#, bytes);
    for json in [false, true] {
        let mut cmd = env.api(&server);
        if json {
            cmd.arg("--json");
        }
        let output = cmd
            .current_dir(cwd.path())
            .args(["reports", "download", REPORT_ID, "-o", "-"])
            .output()
            .expect("run");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, bytes, "nothing but the file on stdout");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if json {
            assert!(stderr.is_empty(), "{stderr}");
        } else {
            assert_eq!(stderr, "Wrote 8 bytes to standard output.\n");
        }
    }
    assert!(entries(cwd.path()).is_empty());
}

#[test]
fn a_report_that_cannot_be_served_yet_explains_why() {
    for (details, message, hint) in [
        (
            r#"{"code":"REPORT_NOT_READY","status":"generating"}"#,
            "The report is still being generated, so it has no file yet.",
            "Try again later",
        ),
        (
            r#"{"code":"REPORT_NOT_READY","status":"failed"}"#,
            "The report failed to generate, so it has no file.",
            "Generate it again",
        ),
        (
            r#"{"code":"FORMAT_UNSUPPORTED","formats":["pdf"]}"#,
            "The report cannot be downloaded in that format.",
            "Choose one of its formats with --format: pdf.",
        ),
        (
            r#"{"code":"FORMAT_UNSUPPORTED","formats":[]}"#,
            "The report cannot be downloaded in that format.",
            "reports get <id>` lists the formats",
        ),
        (
            r#"{"code":"FILE_TOO_LARGE","limit_bytes":20971520}"#,
            "larger than the API serves (20971520 bytes)",
            "",
        ),
    ] {
        let env = Env::new();
        let cwd = tempfile::tempdir().expect("tempdir");
        let mut server = mockito::Server::new();
        server
            .mock("GET", format!("/v1/reports/{REPORT_ID}/download").as_str())
            .match_query(mockito::Matcher::Any)
            .with_status(409)
            .with_body(format!(
                r#"{{"error":{{"code":"conflict","message":"no","request_id":"req_409","details":{details}}}}}"#
            ))
            .create();
        let output = env
            .api(&server)
            .current_dir(cwd.path())
            .args(["reports", "download", REPORT_ID])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{details}: {output:?}");
        assert!(output.stdout.is_empty(), "{details}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(message) && stderr.contains(hint),
            "{details}: {stderr}"
        );
        assert!(stderr.contains("request id: req_409"), "{stderr}");
        assert!(entries(cwd.path()).is_empty(), "{details}");
    }
}

#[test]
fn server_text_about_a_download_cannot_drive_the_terminal() {
    let env = Env::new();
    let cwd = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    server
        .mock("GET", format!("/v1/reports/{REPORT_ID}/download").as_str())
        .match_query(mockito::Matcher::Any)
        .with_status(409)
        .with_body(r#"{"error":{"code":"conflict","message":"busy \u001b]0;pwned\u0007 \u009b31m","request_id":"r\u001b[5m","details":{"code":"FORMAT_UNSUPPORTED","formats":["pdf\u001b[2J","xlsx"]}}}"#)
        .create();
    server
        .mock("GET", "/v1/reports/other/download")
        .match_query(mockito::Matcher::Any)
        .with_status(409)
        .with_body(r#"{"error":{"code":"conflict","message":"busy \u001b]0;pwned\u0007 \u009b31m","request_id":"r","details":{"code":"SOMETHING_NEW"}}}"#)
        .create();
    for id in [REPORT_ID, "other"] {
        let output = env
            .api(&server)
            .current_dir(cwd.path())
            .args(["reports", "download", id])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let all = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
        assert!(!all.contains(&0x1b) && !all.contains(&0x07), "{output:?}");
        let text = String::from_utf8_lossy(&all);
        assert!(!text.contains('\u{9b}'), "{text}");
        if id == "other" {
            assert!(text.contains("The API refused the request: busy"), "{text}");
        } else {
            assert!(text.contains("--format: xlsx."), "{text}");
        }
    }
}
