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
        ] {
            cmd.env_remove(var);
        }
        cmd.env("HODEISHIELD_CONFIG", &self.config)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/hodeishield-test",
            )
            .env("NO_COLOR", "1");
        cmd
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
        .expect(6)
        .create();
    for args in [
        vec!["vendors", "list"],
        vec!["alerts", "list"],
        vec!["risks", "list"],
        vec!["evidence", "list"],
        vec!["endpoints", "list"],
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

/// The vendored document lists no values for these filters yet, so they are sent exactly as typed,
/// without a warning, and the command succeeds. (The warning itself is covered by the unit tests
/// of `filters`, with operations that carry lists.)
#[test]
fn free_form_filters_are_sent_as_typed_without_a_warning() {
    for (args, path, param, value) in [
        (
            &["alerts", "list", "--severity", "High"][..],
            "/v1/alerts",
            "severity",
            "High",
        ),
        (
            &["vendors", "list", "--category", "Cloud Host"],
            "/v1/vendors",
            "category",
            "Cloud Host",
        ),
        (
            &["risks", "list", "--domain", "Cyber"],
            "/v1/risks",
            "domain",
            "Cyber",
        ),
        (
            &["risks", "list", "--status", "OPEN"],
            "/v1/risks",
            "status",
            "OPEN",
        ),
        (
            &[
                "compliance",
                "controls",
                "--framework",
                "nis2",
                "--status",
                "Covered",
            ],
            "/v1/compliance/controls",
            "status",
            "Covered",
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
        let output = env.api(&server).args(args).output().expect("run");
        assert!(output.status.success(), "{args:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("warning:"), "{args:?}: {stderr}");
        mock.assert();
    }
}
