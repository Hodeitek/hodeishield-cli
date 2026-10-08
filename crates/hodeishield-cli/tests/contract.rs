// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The scripting surface, pinned.
//!
//! The README ("Stability") promises scripts four things: the exit codes 0 to 8, the shape of
//! `--json` and `--csv` output, and which stream carries what. The tests here fail when any of
//! them changes, so a breaking change is always a deliberate edit of an expectation below, together
//! with a "Changed (scripting surface)" entry in the changelog.
//!
//! Everything runs the real binary against a mock `/v1`, offline, with a throw-away configuration
//! file and without access to the keychain.

use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Output;

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

    fn api(&self, url: &str, args: &[&str]) -> Output {
        self.cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .env("HODEISHIELD_API_URL", url)
            .args(args)
            .output()
            .expect("run")
    }
}

fn out(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// ---------------------------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------------------------

/// Every exit code the README documents, with a command that ends in it.
#[test]
fn exit_code_contract() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let url = server.url();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_body(r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":1}}"#)
        .create();
    for (path, status, headers, body) in [
        (
            "/v1/alerts",
            403,
            vec![],
            r#"{"error":{"code":"forbidden","message":"no","request_id":"r"}}"#,
        ),
        (
            "/v1/risks",
            404,
            vec![],
            r#"{"error":{"code":"not_found","message":"gone","request_id":"r"}}"#,
        ),
        (
            "/v1/evidence",
            429,
            // Longer than the CLI is willing to wait, so it gives up at once.
            vec![("retry-after", "3600")],
            r#"{"error":{"code":"rate_limited","message":"slow down","request_id":"r"}}"#,
        ),
        (
            "/v1/endpoints",
            403,
            vec![],
            r#"{"error":{"code":"forbidden","message":"no","request_id":"r","details":{"code":"LICENCE_INACTIVE","licence":"none"}}}"#,
        ),
        (
            "/v1/compliance/controls",
            401,
            vec![],
            r#"{"error":{"code":"unauthorized","message":"bad","request_id":"r"}}"#,
        ),
    ] {
        let mut mock = server
            .mock("GET", path)
            .match_query(mockito::Matcher::Any)
            .with_status(status);
        for (name, value) in headers {
            mock = mock.with_header(name, value);
        }
        mock.with_body(body).create();
    }

    // Nothing listens on port 9 of the loopback interface.
    let unreachable = "http://127.0.0.1:9";

    struct Case {
        code: i32,
        meaning: &'static str,
        run: Output,
    }
    let cases = [
        Case {
            code: 0,
            meaning: "success",
            run: env.api(&url, &["vendors", "list"]),
        },
        Case {
            code: 1,
            meaning: "error: invalid input",
            run: env.api(&url, &["risks", "get", ".."]),
        },
        Case {
            code: 2,
            meaning: "invalid command line",
            run: env.api(&url, &["vendors", "list", "--no-such-flag"]),
        },
        Case {
            code: 3,
            meaning: "not authenticated: the API rejected the key",
            run: env.api(&url, &["compliance", "controls", "--framework", "nis2"]),
        },
        Case {
            code: 4,
            meaning: "missing scope",
            run: env.api(&url, &["alerts", "list"]),
        },
        Case {
            code: 5,
            meaning: "not found",
            run: env.api(&url, &["risks", "list"]),
        },
        Case {
            code: 6,
            meaning: "rate limited",
            run: env.api(&url, &["evidence", "list"]),
        },
        Case {
            code: 7,
            meaning: "API unreachable",
            run: env.api(unreachable, &["vendors", "list"]),
        },
        Case {
            code: 8,
            meaning: "licence not in force",
            run: env.api(&url, &["endpoints", "list"]),
        },
    ];
    for case in cases {
        assert_eq!(
            case.run.status.code(),
            Some(case.code),
            "exit code {} ({}): {:?}",
            case.code,
            case.meaning,
            case.run
        );
        if case.code != 0 {
            assert!(
                case.run.stdout.is_empty(),
                "exit code {} must leave stdout empty: {:?}",
                case.code,
                out(&case.run)
            );
        }
    }
}

/// 3 also means "no credential at all", which needs no network.
#[test]
fn no_credential_exits_3() {
    let env = Env::new();
    let output = env
        .cmd()
        .args(["--api-url", "http://127.0.0.1:9", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty());
}

/// A server error (5xx) is exit code 7 as well, and says nothing on stdout.
#[test]
fn a_failing_api_exits_7() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_status(500)
        .with_header("retry-after", "0")
        .with_body(r#"{"error":{"code":"internal","message":"boom","request_id":"r"}}"#)
        .expect_at_least(1)
        .create();
    let output = env.api(&server.url(), &["vendors", "list"]);
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    assert!(output.stdout.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Fixtures: one item per resource, with every field the API describes and one it does not.
// ---------------------------------------------------------------------------------------------

struct Resource {
    /// The command words before `list`.
    command: &'static [&'static str],
    /// Extra arguments the list needs.
    list_args: &'static [&'static str],
    path: &'static str,
    /// An item as the API sends it, plus the unknown field `added_later`.
    item: &'static str,
    /// The CSV header: the item's fields, in the order the API sends them.
    csv_header: &'static str,
}

const RESOURCES: [Resource; 5] = [
    Resource {
        command: &["vendors"],
        list_args: &[],
        path: "/v1/vendors",
        item: r#"{"id":"v1","name":"Example Hosting","legal_name":null,"domain":"example.com","category":null,"vendor_type":null,"access_level":null,"business_criticality":"high","data_sensitivity":null,"economic_impact":null,"active":true,"monitoring_status":null,"last_scan_at":"2026-03-04T05:06:07.000Z","lei":null,"hq_country":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","added_later":{"k":[1,2]}}"#,
        csv_header: "id,name,legal_name,domain,category,vendor_type,access_level,business_criticality,data_sensitivity,economic_impact,active,monitoring_status,last_scan_at,lei,hq_country,created_at,updated_at,added_later",
    },
    Resource {
        command: &["alerts"],
        list_args: &[],
        path: "/v1/alerts",
        item: r#"{"id":"a1","vendor_id":"v1","type":"cve","severity":"high","title":"Example alert","description":null,"source_url":null,"economic_impact":null,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z","added_later":"x"}"#,
        csv_header: "id,vendor_id,type,severity,title,description,source_url,economic_impact,status,acknowledged_at,resolved_at,resolution_reason,created_at,added_later",
    },
    Resource {
        command: &["risks"],
        list_args: &[],
        path: "/v1/risks",
        item: r#"{"id":"r1","title":"Example risk","description":null,"domain":"operations","status":"identified","treatment":null,"treatment_notes":null,"threat_source":null,"vulnerability":null,"likelihood_inherent":3,"impact_inherent":4,"inherent_score":12,"likelihood_residual":null,"impact_residual":null,"residual_score":null,"source":"manual","owner_user_id":null,"vendor_id":null,"control_codes":["1.1","1.2"],"review_date":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","added_later":true}"#,
        csv_header: "id,title,description,domain,status,treatment,treatment_notes,threat_source,vulnerability,likelihood_inherent,impact_inherent,inherent_score,likelihood_residual,impact_residual,residual_score,source,owner_user_id,vendor_id,control_codes,review_date,created_at,updated_at,added_later",
    },
    Resource {
        command: &["evidence"],
        list_args: &[],
        path: "/v1/evidence",
        item: r#"{"id":"e1","evidence_type":"policy","source_type":"manual","source_id":"s1","title":"Example evidence","description":null,"vendor_id":null,"asset_id":null,"auto_generated":false,"valid_until":null,"created_at":"2026-01-01T00:00:00Z","added_later":7}"#,
        csv_header: "id,evidence_type,source_type,source_id,title,description,vendor_id,asset_id,auto_generated,valid_until,created_at,added_later",
    },
    Resource {
        command: &["endpoints"],
        list_args: &[],
        path: "/v1/endpoints",
        item: r#"{"id":"n1","producer":"agent","producer_kind":"edr","status":"active","signature_alg":"ed25519","agent_version":"1.2.3","hostname":"host.example.test","enrolled_at":"2026-01-01T00:00:00Z","last_seen_at":null,"revoked_at":null,"added_later":null}"#,
        csv_header: "id,producer,producer_kind,status,signature_alg,agent_version,hostname,enrolled_at,last_seen_at,revoked_at,added_later",
    },
];

const CONTROLS: Resource = Resource {
    command: &["compliance"],
    list_args: &["--framework", "nis2"],
    path: "/v1/compliance/controls",
    item: r#"{"framework":"nis2","control_code":"1.1","status":"covered","evidence_count":5,"last_evaluated_at":null,"added_later":[]}"#,
    csv_header: "framework,control_code,status,evidence_count,last_evaluated_at,added_later",
};

fn list_body(resource: &Resource) -> String {
    format!(
        r#"{{"data":[{}],"pagination":{{"page":1,"per_page":50,"total":1,"total_pages":1,"added_later":"p"}},"added_later_top":1}}"#,
        resource.item
    )
}

fn list_args(resource: &Resource, extra: &[&'static str]) -> Vec<&'static str> {
    let mut args: Vec<&'static str> = Vec::new();
    args.extend_from_slice(resource.command);
    args.push(if resource.command == ["compliance"] {
        "controls"
    } else {
        "list"
    });
    args.extend_from_slice(resource.list_args);
    args.extend_from_slice(extra);
    args
}

fn all_resources() -> impl Iterator<Item = &'static Resource> {
    RESOURCES.iter().chain(std::iter::once(&CONTROLS))
}

// ---------------------------------------------------------------------------------------------
// --json
// ---------------------------------------------------------------------------------------------

/// A list prints the API's body as it came: `data` and `pagination` at the top, in that order, and
/// every field the CLI does not know passes through, at every level.
#[test]
fn json_list_is_the_api_body_with_unknown_fields_passed_through() {
    let env = Env::new();
    for resource in all_resources() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", resource.path)
            .match_query(mockito::Matcher::Any)
            .with_body(list_body(resource))
            .create();
        let output = env.api(&server.url(), &list_args(resource, &["--json"]));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}: {output:?}",
            resource.path
        );
        let text = out(&output);
        let printed: Value = serde_json::from_str(&text).expect("json");
        let sent: Value = serde_json::from_str(&list_body(resource)).expect("fixture");
        assert_eq!(
            printed, sent,
            "{}: the body is passed through",
            resource.path
        );
        let top: Vec<&String> = printed.as_object().expect("object").keys().collect();
        assert_eq!(
            top,
            ["data", "pagination", "added_later_top"],
            "{}: top-level keys and their order",
            resource.path
        );
        assert!(text.starts_with("{\n  \"data\": [\n    {\n"), "{text}");
        assert!(text.ends_with("}\n"), "one trailing newline: {text:?}");
        assert!(
            err(&output).is_empty(),
            "{}: {}",
            resource.path,
            err(&output)
        );
    }
}

/// `--all --json` prints one array of every item (not a page), unchanged.
#[test]
fn json_all_is_an_array_of_the_items() {
    let env = Env::new();
    for resource in all_resources() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", resource.path)
            .match_query(mockito::Matcher::Any)
            .with_body(list_body(resource))
            .create();
        let output = env.api(&server.url(), &list_args(resource, &["--json", "--all"]));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}: {output:?}",
            resource.path
        );
        let printed: Value = serde_json::from_str(&out(&output)).expect("json");
        let sent: Value = serde_json::from_str(resource.item).expect("fixture");
        assert_eq!(printed, Value::Array(vec![sent]), "{}", resource.path);
    }
}

/// `get` prints the API's body, `{"data": {...}}`, with unknown fields.
#[test]
fn json_get_is_the_api_body_with_unknown_fields_passed_through() {
    let env = Env::new();
    for resource in &RESOURCES[..4] {
        let name = resource.command[0];
        let id = "x1";
        let path = format!("{}/{id}", resource.path);
        let body = format!(r#"{{"data":{},"added_later_top":1}}"#, resource.item);
        let mut server = mockito::Server::new();
        server.mock("GET", path.as_str()).with_body(&body).create();
        let output = env.api(&server.url(), &["--json", name, "get", id]);
        assert_eq!(output.status.code(), Some(0), "{name}: {output:?}");
        let printed: Value = serde_json::from_str(&out(&output)).expect("json");
        assert_eq!(
            printed,
            serde_json::from_str::<Value>(&body).expect("fixture"),
            "{name}"
        );
        let top: Vec<&String> = printed.as_object().expect("object").keys().collect();
        assert_eq!(top, ["data", "added_later_top"], "{name}");
    }
}

/// `compliance posture` prints the API's body, `{"data": {...}}`.
#[test]
fn json_posture_is_the_api_body_with_unknown_fields_passed_through() {
    let env = Env::new();
    let body = r#"{"data":{"framework":"nis2","controls_total":3,"by_status":{"covered":2,"missing":1},"evidence_total":9,"last_evaluated_at":null,"added_later":1}}"#;
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/frameworks/nis2")
        .with_body(body)
        .create();
    let output = env.api(&server.url(), &["--json", "compliance", "posture", "nis2"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        printed,
        serde_json::from_str::<Value>(body).expect("fixture")
    );
}

/// `whoami --json` is an object with these fields, in this order (an API key has no more).
#[test]
fn json_whoami_fields() {
    let env = Env::new();
    let server = mockito::Server::new();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    let keys: Vec<&String> = printed.as_object().expect("object").keys().collect();
    assert_eq!(keys, ["profile", "api_url", "app_url", "credential"]);
    assert_eq!(printed["credential"], json!("api_key"));
    assert_eq!(printed["api_url"], json!(format!("{}/", server.url())));
}

// ---------------------------------------------------------------------------------------------
// --csv
// ---------------------------------------------------------------------------------------------

/// The header is the item's top-level fields in the order the API sends them, including a field
/// the CLI does not know; the record follows, and both end in CRLF.
#[test]
fn csv_header_of_every_list_command() {
    let env = Env::new();
    for resource in all_resources() {
        let mut server = mockito::Server::new();
        server
            .mock("GET", resource.path)
            .match_query(mockito::Matcher::Any)
            .with_body(list_body(resource))
            .create();
        let output = env.api(&server.url(), &list_args(resource, &["--csv"]));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}: {output:?}",
            resource.path
        );
        let text = out(&output);
        let (header, rest) = text.split_once("\r\n").expect("a CRLF-terminated header");
        assert_eq!(header, resource.csv_header, "{}", resource.path);
        assert!(rest.ends_with("\r\n"), "{}: {rest:?}", resource.path);
        assert_eq!(rest.matches("\r\n").count(), 1, "one record: {rest:?}");
        assert!(
            !text.contains("\n\n") && !text.starts_with('\u{feff}'),
            "{text:?}"
        );
        // Every line break is CRLF: removing those leaves no bare LF.
        assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
    }
}

/// A full CSV document, character for character: the header, a record with every kind of value,
/// the quoting of RFC 4180 and the guard that keeps a spreadsheet from running a cell as a formula.
#[test]
fn csv_document_snapshot() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/alerts")
        .match_query(mockito::Matcher::Any)
        .with_body(
            r#"{"data":[
{"id":"a1","vendor_id":"v","type":"cve","severity":"+high","title":"=1+1","description":"-x","source_url":"@SUM(A1)","economic_impact":-5,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z"},
{"id":"a2","vendor_id":"v","type":"cve","severity":"say \"hi\"","title":"plain, with comma","description":"two\nlines","source_url":" padded ","economic_impact":2.5,"status":"a=b","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z"}
],"pagination":{"page":1,"per_page":50,"total":2,"total_pages":1}}"#,
        )
        .create();
    let output = env.api(&server.url(), &["alerts", "list", "--csv"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        out(&output),
        "id,vendor_id,type,severity,title,description,source_url,economic_impact,status,\
         acknowledged_at,resolved_at,resolution_reason,created_at\r\n\
         a1,v,cve,'+high,'=1+1,'-x,'@SUM(A1),-5,open,,,,2026-01-01T00:00:00Z\r\n\
         a2,v,cve,\"say \"\"hi\"\"\",\"plain, with comma\",\"two\nlines\",\" padded \",2.5,a=b,,,,2026-01-01T00:00:00Z\r\n"
    );
}

/// No items: nothing on stdout (not even a header), a note on stderr.
#[test]
fn csv_without_items_prints_nothing() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/risks")
        .match_query(mockito::Matcher::Any)
        .with_body(r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":1}}"#)
        .create();
    let output = env.api(&server.url(), &["risks", "list", "--csv"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{:?}", out(&output));
    assert_eq!(err(&output), "No risks found.\n");
}

// ---------------------------------------------------------------------------------------------
// Standard output and standard error
// ---------------------------------------------------------------------------------------------

/// Notes about paging go to stderr in every output format; stdout holds only the data.
#[test]
fn notes_go_to_stderr_and_data_to_stdout() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let body = format!(
        r#"{{"data":[{}],"pagination":{{"page":1,"per_page":1,"total":2,"total_pages":2}}}}"#,
        RESOURCES[1].item
    );
    server
        .mock("GET", "/v1/alerts")
        .match_query(mockito::Matcher::Any)
        .with_body(&body)
        .create();

    let table = env.api(&server.url(), &["alerts", "list"]);
    assert_eq!(table.status.code(), Some(0), "{table:?}");
    assert!(out(&table).starts_with("ID"), "{}", out(&table));
    assert!(!out(&table).contains("Page 1 of 2"));
    assert_eq!(
        err(&table),
        "Page 1 of 2 (2 alerts). Next: --page 2, or --all.\n"
    );

    for flag in ["--json", "--csv"] {
        let output = env.api(&server.url(), &["alerts", "list", flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}: {output:?}");
        assert!(!out(&output).contains("Page 1 of 2"), "{flag}");
        if flag == "--json" {
            serde_json::from_str::<Value>(&out(&output)).expect("stdout is only JSON");
            assert!(
                err(&output).is_empty(),
                "no note beside JSON: {}",
                err(&output)
            );
        } else {
            assert_eq!(
                err(&output),
                "Page 1 of 2 (2 alerts). Next: --page 2, or --all.\n"
            );
        }
    }
}

/// `--verbose` logs the requests to stderr and leaves stdout parseable.
#[test]
fn verbose_logging_never_reaches_stdout() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors/v1")
        .with_body(format!(r#"{{"data":{}}}"#, RESOURCES[0].item))
        .create();
    let output = env.api(
        &server.url(),
        &["--verbose", "--json", "vendors", "get", "v1"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_str::<Value>(&out(&output)).expect("stdout is only JSON");
    assert!(
        err(&output).contains("GET http://127.0.0.1:"),
        "{}",
        err(&output)
    );
}

/// An error writes nothing to stdout in any output format, and starts its stderr with `error: `.
#[test]
fn errors_write_to_stderr_only() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .match_query(mockito::Matcher::Any)
        .with_status(404)
        .with_body(
            r#"{"error":{"code":"not_found","message":"Nothing here.","request_id":"req_1"}}"#,
        )
        .create();
    for flag in ["--json", "--csv", ""] {
        let mut args = vec!["vendors", "list"];
        if !flag.is_empty() {
            args.push(flag);
        }
        let output = env.api(&server.url(), &args);
        assert_eq!(output.status.code(), Some(5), "{flag}: {output:?}");
        assert!(output.stdout.is_empty(), "{flag}: {:?}", out(&output));
        assert_eq!(
            err(&output),
            "error: Nothing here.\nrequest id: req_1\n",
            "{flag}"
        );
    }
}

/// A usage error also leaves stdout empty.
#[test]
fn usage_errors_write_to_stderr_only() {
    let env = Env::new();
    let output = env
        .cmd()
        .args(["vendors", "frobnicate"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{:?}", out(&output));
    assert!(!err(&output).is_empty());
}
