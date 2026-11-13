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
            "HODEISHIELD_TOKEN_STORE",
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
    /// The item's fields with their JSON types, as `name:type`, in the order the API sends them.
    types: &'static str,
}

const RESOURCES: [Resource; 7] = [
    Resource {
        command: &["vendors"],
        list_args: &[],
        path: "/v1/vendors",
        item: r#"{"id":"v1","name":"Example Hosting","legal_name":null,"domain":"example.com","category":null,"vendor_type":null,"access_level":null,"business_criticality":"high","data_sensitivity":null,"economic_impact":null,"active":true,"monitoring_status":null,"last_scan_at":"2026-03-04T05:06:07.000Z","lei":null,"hq_country":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","added_later":{"k":[1,2]}}"#,
        csv_header: "id,name,legal_name,domain,category,vendor_type,access_level,business_criticality,data_sensitivity,economic_impact,active,monitoring_status,last_scan_at,lei,hq_country,created_at,updated_at,added_later",
        types: "id:string,name:string,legal_name:null,domain:string,category:null,vendor_type:null,access_level:null,business_criticality:string,data_sensitivity:null,economic_impact:null,active:boolean,monitoring_status:null,last_scan_at:string,lei:null,hq_country:null,created_at:string,updated_at:string,added_later:object",
    },
    Resource {
        command: &["alerts"],
        list_args: &[],
        path: "/v1/alerts",
        item: r#"{"id":"a1","vendor_id":"v1","type":"cve","severity":"high","title":"Example alert","description":null,"source_url":null,"economic_impact":null,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","added_later":"x"}"#,
        csv_header: "id,vendor_id,type,severity,title,description,source_url,economic_impact,status,acknowledged_at,resolved_at,resolution_reason,created_at,updated_at,added_later",
        types: "id:string,vendor_id:string,type:string,severity:string,title:string,description:null,source_url:null,economic_impact:null,status:string,acknowledged_at:null,resolved_at:null,resolution_reason:null,created_at:string,updated_at:string,added_later:string",
    },
    Resource {
        command: &["risks"],
        list_args: &[],
        path: "/v1/risks",
        item: r#"{"id":"r1","title":"Example risk","description":null,"domain":"operations","status":"identified","treatment":null,"treatment_notes":null,"threat_source":null,"vulnerability":null,"likelihood_inherent":3,"impact_inherent":4,"inherent_score":12,"likelihood_residual":null,"impact_residual":null,"residual_score":null,"source":"manual","owner_user_id":null,"vendor_id":null,"control_codes":["1.1","1.2"],"review_date":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","added_later":true}"#,
        csv_header: "id,title,description,domain,status,treatment,treatment_notes,threat_source,vulnerability,likelihood_inherent,impact_inherent,inherent_score,likelihood_residual,impact_residual,residual_score,source,owner_user_id,vendor_id,control_codes,review_date,created_at,updated_at,added_later",
        types: "id:string,title:string,description:null,domain:string,status:string,treatment:null,treatment_notes:null,threat_source:null,vulnerability:null,likelihood_inherent:number,impact_inherent:number,inherent_score:number,likelihood_residual:null,impact_residual:null,residual_score:null,source:string,owner_user_id:null,vendor_id:null,control_codes:array,review_date:null,created_at:string,updated_at:string,added_later:boolean",
    },
    Resource {
        command: &["evidence"],
        list_args: &[],
        path: "/v1/evidence",
        item: r#"{"id":"e1","evidence_type":"policy","source_type":"manual","source_id":"s1","title":"Example evidence","description":null,"vendor_id":null,"asset_id":null,"auto_generated":false,"valid_until":null,"created_at":"2026-01-01T00:00:00Z","added_later":7}"#,
        csv_header: "id,evidence_type,source_type,source_id,title,description,vendor_id,asset_id,auto_generated,valid_until,created_at,added_later",
        types: "id:string,evidence_type:string,source_type:string,source_id:string,title:string,description:null,vendor_id:null,asset_id:null,auto_generated:boolean,valid_until:null,created_at:string,added_later:number",
    },
    Resource {
        command: &["reports"],
        list_args: &[],
        path: "/v1/reports",
        item: r#"{"id":"0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e","report_type":"monthly","title":"Example report","period_start":"2026-09-01","period_end":"2026-09-30","status":"completed","created_at":"2026-10-01T00:00:00Z","added_later":{"k":"v"}}"#,
        csv_header: "id,report_type,title,period_start,period_end,status,created_at,added_later",
        types: "id:string,report_type:string,title:string,period_start:string,period_end:string,status:string,created_at:string,added_later:object",
    },
    Resource {
        command: &["endpoints"],
        list_args: &[],
        path: "/v1/endpoints",
        item: r#"{"id":"n1","producer":"agent","producer_kind":"edr","status":"active","signature_alg":"ed25519","agent_version":"1.2.3","hostname":"host.example.test","enrolled_at":"2026-01-01T00:00:00Z","last_seen_at":null,"revoked_at":null,"added_later":null}"#,
        csv_header: "id,producer,producer_kind,status,signature_alg,agent_version,hostname,enrolled_at,last_seen_at,revoked_at,added_later",
        types: "id:string,producer:string,producer_kind:string,status:string,signature_alg:string,agent_version:string,hostname:string,enrolled_at:string,last_seen_at:null,revoked_at:null,added_later:null",
    },
    Resource {
        command: &["changes"],
        list_args: &[],
        path: "/v1/changes",
        item: r#"{"id":"c1","ref":"CHG-2026-0007","title":"Rotate the database credentials","status":"scheduled","change_type":"normal","category":"access","risk_level":"medium","planned_start_at":"2026-11-10T08:00:00Z","planned_end_at":"2026-11-10T09:00:00Z","implemented_at":null,"closed_at":null,"outcome":null,"approved_without_second_person":false,"external_ref":null,"approvals":{"approved":2,"rejected":0},"created_at":"2026-11-01T00:00:00Z","added_later":[1]}"#,
        csv_header: "id,ref,title,status,change_type,category,risk_level,planned_start_at,planned_end_at,implemented_at,closed_at,outcome,approved_without_second_person,external_ref,approvals,created_at,added_later",
        types: "id:string,ref:string,title:string,status:string,change_type:string,category:string,risk_level:string,planned_start_at:string,planned_end_at:string,implemented_at:null,closed_at:null,outcome:null,approved_without_second_person:boolean,external_ref:null,approvals:object,created_at:string,added_later:array",
    },
];

const CONTROLS: Resource = Resource {
    command: &["compliance"],
    list_args: &["--framework", "nis2"],
    path: "/v1/compliance/controls",
    item: r#"{"framework":"nis2","control_code":"1.1","status":"covered","evidence_count":5,"last_evaluated_at":null,"added_later":[]}"#,
    csv_header: "framework,control_code,status,evidence_count,last_evaluated_at,added_later",
    types: "framework:string,control_code:string,status:string,evidence_count:number,last_evaluated_at:null,added_later:array",
};

const TENANTS: Resource = Resource {
    command: &["tenants"],
    list_args: &[],
    path: "/v1/portfolio/tenants",
    item: r#"{"id":"6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme S.L.","slug":"acme","organization":{"id":"o-acme","name":"Acme Group"},"internal":false,"active":true,"licence_status":"in_force","added_later":7}"#,
    csv_header: "id,name,slug,organization,internal,active,licence_status,added_later",
    types: "id:string,name:string,slug:string,organization:object,internal:boolean,active:boolean,licence_status:string,added_later:number",
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
    RESOURCES.iter().chain([&CONTROLS, &TENANTS])
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
    for resource in &RESOURCES[..5] {
        let name = resource.command[0];
        let id = "x1";
        let path = format!("{}/{id}", resource.path);
        // A single report also says which formats it can be downloaded in.
        let item = if name == "reports" {
            resource
                .item
                .replacen('{', r#"{"download_formats":["pdf"],"#, 1)
        } else {
            resource.item.to_owned()
        };
        let body = format!(r#"{{"data":{item},"added_later_top":1}}"#);
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

/// `reports download --json` prints where the file went, its size and its type, and nothing else.
#[test]
fn json_report_download_fields() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r1/download")
        .with_header("content-type", "application/pdf")
        .with_header(
            "content-disposition",
            r#"attachment; filename="report.pdf""#,
        )
        .with_body("%PDF-")
        .create();
    let output = env
        .cmd()
        .env("HODEISHIELD_API_KEY", KEY)
        .env("HODEISHIELD_API_URL", server.url())
        .current_dir(dir.path())
        .args(["--json", "reports", "download", "r1"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        printed,
        json!({"path": "report.pdf", "bytes": 5, "content_type": "application/pdf"})
    );
    let keys: Vec<&String> = printed.as_object().expect("object").keys().collect();
    assert_eq!(keys, ["path", "bytes", "content_type"]);
    assert!(err(&output).is_empty(), "{}", err(&output));
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

/// Both compliance commands take the framework as a positional or as `--framework`/`-f`; the same
/// value twice is fine, two different values and no value are usage errors (exit code 2).
#[test]
fn compliance_framework_is_a_positional_or_a_flag_on_both_commands() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/frameworks/nis2")
        .with_body(r#"{"data":{"framework":"nis2","controls_total":0,"by_status":{},"evidence_total":0,"last_evaluated_at":null}}"#)
        .create();
    server
        .mock("GET", "/v1/compliance/controls")
        .match_query(mockito::Matcher::UrlEncoded(
            "framework".into(),
            "nis2".into(),
        ))
        .with_body(r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":1}}"#)
        .create();
    let url = server.url();
    for command in ["posture", "controls"] {
        for forms in [
            vec!["nis2"],
            vec!["--framework", "nis2"],
            vec!["-f", "nis2"],
            vec!["nis2", "--framework", "nis2"],
            vec!["-f", "nis2", "nis2"],
        ] {
            let mut args = vec!["--json", "compliance", command];
            args.extend(forms.iter().copied());
            let output = env.api(&url, &args);
            assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        }
        let output = env.api(
            &url,
            &["compliance", command, "nis2", "--framework", "dora"],
        );
        assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
        assert!(
            err(&output).contains("different values"),
            "{}",
            err(&output)
        );
        let output = env.api(&url, &["compliance", command]);
        assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
        assert!(err(&output).contains("FRAMEWORK"), "{}", err(&output));
    }
}

/// `whoami --json` is an object with these fields, in this order (an API key has no more). The last
/// four come from `GET /v1/me` as the API sends them.
#[test]
fn json_whoami_fields() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    let me = server
        .mock("GET", "/v1/me")
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_body(
            r#"{"data":{"credential":{"type":"tenant","prefix":null,"scopes":["supply_risk:read"]},
                "tenant":{"id":"6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme S.L.","type":"direct"},
                "organization":{"id":"7a1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme Group","type":"direct"},
                "portfolio":null}}"#,
        )
        .expect(1)
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    let keys: Vec<&String> = printed.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        [
            "profile",
            "api_url",
            "app_url",
            "credential",
            "tenant",
            "organization",
            "portfolio",
            "credential_scopes"
        ]
    );
    assert_eq!(printed["credential"], json!("api_key"));
    assert_eq!(printed["api_url"], json!(format!("{}/", server.url())));
    assert_eq!(
        printed["tenant"],
        json!({"id": "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f", "name": "Acme S.L.", "type": "direct"})
    );
    assert_eq!(printed["organization"]["name"], json!("Acme Group"));
    assert_eq!(printed["portfolio"], Value::Null);
    assert_eq!(printed["credential_scopes"], json!(["supply_risk:read"]));
    me.assert();
}

/// A key has no user: whatever `user` the API sends in `GET /v1/me`, neither the table nor `--json`
/// shows one, and the fields stay as they were.
#[test]
fn whoami_with_a_key_ignores_a_user_in_the_answer() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/me")
        .with_body(
            r#"{"data":{"credential":{"type":"tenant","prefix":null,"scopes":["supply_risk:read"]},
                "tenant":{"id":"6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme S.L.","type":"direct"},
                "organization":{"id":"7a1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme Group","type":"direct"},
                "portfolio":null,
                "user":{"id":"u-1","name":"Ana Ruiz","email":"ana@acme.example"}}}"#,
        )
        .expect(2)
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert!(printed.get("user").is_none(), "{printed}");
    assert!(!out(&output).contains("Ana Ruiz"));
    let output = env.api(&server.url(), &["whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!out(&output).contains("User") && !out(&output).contains("Ana"));
}

/// A credential the API does not accept is "not signed in": `whoami` still prints the local details
/// and the warning, leaves the API fields null, and exits 3 with the sign-in hint, as every other
/// command does.
#[test]
fn whoami_with_a_rejected_credential_exits_3() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/me")
        .with_status(401)
        .with_body(r#"{"error":{"code":"unauthorized","message":"bad","request_id":"req-1"}}"#)
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(printed["credential"], "api_key");
    for key in ["tenant", "organization", "portfolio", "credential_scopes"] {
        assert_eq!(printed[key], Value::Null, "{key}");
    }
    let stderr = err(&output);
    assert!(
        stderr.contains("warning: could not read from the API who this credential is:"),
        "{stderr}"
    );
    assert!(stderr.contains("HODEISHIELD_API_KEY"), "{stderr}");

    let output = env.api(&server.url(), &["whoami"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(out(&output).contains("Credential"), "{}", out(&output));
}

/// An API that fails on its side, or cannot be reached, says nothing about the credential:
/// `whoami` still exits 0.
#[test]
fn whoami_with_a_failing_api_still_exits_0() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/me")
        .with_status(503)
        .with_body(r#"{"error":{"code":"unavailable","message":"later","request_id":"req-2"}}"#)
        .expect_at_least(1)
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = env.api("http://127.0.0.1:9", &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// When `GET /v1/me` fails, `whoami` still succeeds with the local fields; the API's are null and
/// standard error says why.
#[test]
fn json_whoami_without_the_api() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/me")
        .with_status(404)
        .with_body(
            r#"{"error":{"code":"NOT_FOUND","message":"Gone\u001b]0;pwned\u0007 away.","request_id":"req-1"}}"#,
        )
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    for key in ["tenant", "organization", "portfolio", "credential_scopes"] {
        assert_eq!(printed[key], Value::Null, "{key}");
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: could not read from the API who this credential is:"),
        "{stderr}"
    );
    // The API's message is untrusted: no escape sequence reaches the terminal.
    assert!(
        !stderr.contains('\u{1b}') && !stderr.contains('\u{7}'),
        "{stderr:?}"
    );
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
{"id":"a1","vendor_id":"v","type":"cve","severity":"+high","title":"=1+1","description":"-x","source_url":"@SUM(A1)","economic_impact":-5,"status":"open","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"},
{"id":"a2","vendor_id":"v","type":"cve","severity":"say \"hi\"","title":"plain, with comma","description":"two\nlines","source_url":" padded ","economic_impact":2.5,"status":"a=b","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}
],"pagination":{"page":1,"per_page":50,"total":2,"total_pages":1}}"#,
        )
        .create();
    let output = env.api(&server.url(), &["alerts", "list", "--csv"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        out(&output),
        "id,vendor_id,type,severity,title,description,source_url,economic_impact,status,\
         acknowledged_at,resolved_at,resolution_reason,created_at,updated_at\r\n\
         a1,v,cve,'+high,'=1+1,'-x,'@SUM(A1),-5,open,,,,2026-01-01T00:00:00Z,2026-01-02T00:00:00Z\r\n\
         a2,v,cve,\"say \"\"hi\"\"\",\"plain, with comma\",\"two\nlines\",\" padded \",2.5,a=b,,,,2026-01-01T00:00:00Z,2026-01-02T00:00:00Z\r\n"
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

// ---------------------------------------------------------------------------------------------
// Field names and JSON types
// ---------------------------------------------------------------------------------------------

/// The JSON type of a value, by the names JSON uses.
fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The fields of an object with their types, as `name:type,name:type`, in the order printed.
fn describe(value: &Value) -> String {
    value
        .as_object()
        .expect("an object")
        .iter()
        .map(|(name, value)| format!("{name}:{}", json_type(value)))
        .collect::<Vec<_>>()
        .join(",")
}

/// For every list command, `--json` shows each item with these field names and these JSON types.
/// Renaming a field or changing its type fails here, whatever the API sends.
#[test]
fn json_list_item_field_names_and_types() {
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
        let printed: Value = serde_json::from_str(&out(&output)).expect("json");
        assert_eq!(
            describe(&printed["data"][0]),
            resource.types,
            "{}",
            resource.path
        );
        assert_eq!(
            describe(&printed["pagination"]),
            "page:number,per_page:number,total:number,total_pages:number,added_later:string",
            "{}",
            resource.path
        );
        assert_eq!(json_type(&printed["data"]), "array", "{}", resource.path);
    }
}

/// (`reports get` is below, with the fields only a single report has.)
/// `get` shows the item under `data` with the same field names and types as the list does.
#[test]
fn json_get_item_field_names_and_types() {
    let env = Env::new();
    for resource in &RESOURCES[..4] {
        let name = resource.command[0];
        let path = format!("{}/x1", resource.path);
        let mut server = mockito::Server::new();
        server
            .mock("GET", path.as_str())
            .with_body(format!(r#"{{"data":{}}}"#, resource.item))
            .create();
        let output = env.api(&server.url(), &["--json", name, "get", "x1"]);
        assert_eq!(output.status.code(), Some(0), "{name}: {output:?}");
        let printed: Value = serde_json::from_str(&out(&output)).expect("json");
        assert_eq!(describe(&printed["data"]), resource.types, "{name}");
    }
}

/// `compliance posture --json` and `reports get --json` have fields no list has.
#[test]
fn json_posture_and_report_detail_field_names_and_types() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/frameworks/nis2")
        .with_body(r#"{"data":{"framework":"nis2","controls_total":3,"by_status":{"covered":2,"missing":1},"evidence_total":9,"last_evaluated_at":null}}"#)
        .create();
    server
        .mock("GET", "/v1/reports/r1")
        .with_body(format!(
            r#"{{"data":{}}}"#,
            RESOURCES[4]
                .item
                .replacen('{', r#"{"download_formats":["pdf","xlsx"],"#, 1)
        ))
        .create();
    let output = env.api(&server.url(), &["--json", "compliance", "posture", "nis2"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed["data"]),
        "framework:string,controls_total:number,by_status:object,evidence_total:number,last_evaluated_at:null"
    );
    assert_eq!(
        json_type(&printed["data"]["by_status"]["covered"]),
        "number"
    );

    let output = env.api(&server.url(), &["--json", "reports", "get", "r1"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed["data"]),
        format!("download_formats:array,{}", RESOURCES[4].types)
    );
}

/// `tenants list --json` is the API's body; `--all` is an array of the tenants.
#[test]
fn json_tenants_list_is_the_api_body() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", TENANTS.path)
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("sort".into(), "name".into()),
            mockito::Matcher::UrlEncoded("order".into(), "asc".into()),
        ]))
        .with_body(list_body(&TENANTS))
        .create();
    let output = env.api(&server.url(), &["tenants", "list", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(describe(&printed["data"][0]), TENANTS.types);
    assert_eq!(
        describe(&printed["data"][0]["organization"]),
        "id:string,name:string"
    );
}

/// `config show --json` is built by the CLI: these fields, in this order, with these types.
#[test]
fn json_config_show_fields() {
    let env = Env::new();
    let output = env
        .cmd()
        .args(["config", "show", "--json"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed),
        "config_file:string,profile:string,api_url:string,app_url:string,oauth_client_id:string,\
         oauth_scopes:null,update_check:boolean,token_store:string"
    );
    assert_eq!(printed["profile"], "default");
    assert_eq!(printed["api_url"], "https://api.hodeishield.com/");
    assert_eq!(printed["update_check"], true);
    assert_eq!(printed["token_store"], "keychain");
    assert_eq!(
        printed["config_file"],
        env.config.display().to_string().as_str()
    );
    assert!(err(&output).is_empty(), "{}", err(&output));

    // Scopes that were set are a list of strings; the settings that were changed show as changed.
    for args in [
        &[
            "config",
            "set",
            "oauth_scopes",
            "supply_risk:read compliance:read",
        ][..],
        &["config", "set", "api_url", "https://api.example.test"][..],
        &["config", "set", "update_check", "false"][..],
        &["config", "set", "token_store", "plaintext-file"][..],
    ] {
        let output = env.cmd().args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
    }
    let output = env
        .cmd()
        .args(["config", "show", "--json"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed),
        "config_file:string,profile:string,api_url:string,app_url:string,oauth_client_id:string,\
         oauth_scopes:array,update_check:boolean,token_store:string"
    );
    assert_eq!(
        printed["oauth_scopes"],
        json!(["supply_risk:read", "compliance:read"])
    );
    assert_eq!(printed["api_url"], "https://api.example.test/");
    assert_eq!(printed["update_check"], false);
    assert_eq!(printed["token_store"], "plaintext-file");
}

/// `whoami --json` has these types (an API key has no more fields).
#[test]
fn json_whoami_field_types() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/me")
        .with_body(
            r#"{"data":{"credential":{"type":"tenant","prefix":null,"scopes":["supply_risk:read"]},
                "tenant":{"id":"6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme S.L.","type":"direct"},
                "organization":{"id":"7a1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f","name":"Acme Group","type":"direct"},
                "portfolio":null}}"#,
        )
        .create();
    let output = env.api(&server.url(), &["--json", "whoami"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed),
        "profile:string,api_url:string,app_url:string,credential:string,tenant:object,\
         organization:object,portfolio:null,credential_scopes:array"
    );
    assert_eq!(
        describe(&printed["tenant"]),
        "id:string,name:string,type:string"
    );
}

/// `reports download --json` has these types.
#[test]
fn json_report_download_field_types() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r1/download")
        .with_header("content-type", "application/pdf")
        .with_header("content-disposition", r#"attachment; filename="a.pdf""#)
        .with_body("%PDF-")
        .create();
    let output = env
        .cmd()
        .env("HODEISHIELD_API_KEY", KEY)
        .env("HODEISHIELD_API_URL", server.url())
        .current_dir(dir.path())
        .args(["--json", "reports", "download", "r1"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let printed: Value = serde_json::from_str(&out(&output)).expect("json");
    assert_eq!(
        describe(&printed),
        "path:string,bytes:number,content_type:string"
    );
}

// ---------------------------------------------------------------------------------------------
// Exit codes, command by command
// ---------------------------------------------------------------------------------------------

/// What the API answers, to see how a command ends.
struct Answer {
    status: usize,
    retry_after: Option<&'static str>,
    body: &'static str,
}

const UNAUTHORIZED: Answer = Answer {
    status: 401,
    retry_after: None,
    body: r#"{"error":{"code":"unauthorized","message":"bad","request_id":"r"}}"#,
};
const FORBIDDEN: Answer = Answer {
    status: 403,
    retry_after: None,
    body: r#"{"error":{"code":"forbidden","message":"no","request_id":"r"}}"#,
};
const NOT_FOUND: Answer = Answer {
    status: 404,
    retry_after: None,
    body: r#"{"error":{"code":"not_found","message":"gone","request_id":"r"}}"#,
};
const RATE_LIMITED: Answer = Answer {
    status: 429,
    // Longer than the CLI is willing to wait, so it gives up at once.
    retry_after: Some("3600"),
    body: r#"{"error":{"code":"rate_limited","message":"slow down","request_id":"r"}}"#,
};
const FAILING: Answer = Answer {
    status: 500,
    retry_after: Some("0"),
    body: r#"{"error":{"code":"internal","message":"boom","request_id":"r"}}"#,
};
const LICENCE_INACTIVE: Answer = Answer {
    status: 403,
    retry_after: None,
    body: r#"{"error":{"code":"forbidden","message":"no","request_id":"r","details":{"code":"LICENCE_INACTIVE","licence":"none"}}}"#,
};

/// Every command that reads from the API: its words and the path it requests.
const READS: [(&[&str], &str); 17] = [
    (&["vendors", "list"], "/v1/vendors"),
    (&["vendors", "get", "x1"], "/v1/vendors/x1"),
    (&["alerts", "list"], "/v1/alerts"),
    (&["alerts", "get", "x1"], "/v1/alerts/x1"),
    (&["risks", "list"], "/v1/risks"),
    (&["risks", "get", "x1"], "/v1/risks/x1"),
    (&["changes", "list"], "/v1/changes"),
    (
        &["compliance", "controls", "nis2"],
        "/v1/compliance/controls",
    ),
    (
        &["compliance", "posture", "nis2"],
        "/v1/compliance/frameworks/nis2",
    ),
    (&["evidence", "list"], "/v1/evidence"),
    (&["evidence", "get", "x1"], "/v1/evidence/x1"),
    (&["endpoints", "list"], "/v1/endpoints"),
    (&["reports", "list"], "/v1/reports"),
    (&["reports", "get", "x1"], "/v1/reports/x1"),
    (&["reports", "download", "x1"], "/v1/reports/x1/download"),
    (&["tenants", "list"], "/v1/portfolio/tenants"),
    (&["--json", "tenants", "list"], "/v1/portfolio/tenants"),
];

/// Every command that reads from the API ends in the documented exit code for each way the API can
/// answer, and says nothing on standard output when it fails. Downloads run in an empty directory.
#[test]
fn every_read_command_maps_the_api_answers_to_the_documented_exit_codes() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    for (words, path) in READS {
        for (answer, code) in [
            (&UNAUTHORIZED, 3),
            (&FORBIDDEN, 4),
            (&NOT_FOUND, 5),
            (&RATE_LIMITED, 6),
            (&FAILING, 7),
            (&LICENCE_INACTIVE, 8),
        ] {
            let mut server = mockito::Server::new();
            let mut mock = server
                .mock("GET", path)
                .match_query(mockito::Matcher::Any)
                .with_status(answer.status);
            if let Some(wait) = answer.retry_after {
                mock = mock.with_header("retry-after", wait);
            }
            mock.with_body(answer.body).expect_at_least(1).create();
            // An API with no portfolio route is one that does not offer portfolio access: 7.
            let code = if path == TENANTS.path && code == 5 {
                7
            } else {
                code
            };
            let output = env
                .cmd()
                .env("HODEISHIELD_API_KEY", KEY)
                .env("HODEISHIELD_API_URL", server.url())
                .current_dir(dir.path())
                .args(words)
                .output()
                .expect("run");
            assert_eq!(
                output.status.code(),
                Some(code),
                "{words:?} after a {}: {output:?}",
                answer.status
            );
            assert!(
                output.stdout.is_empty(),
                "{words:?} must leave stdout empty: {:?}",
                out(&output)
            );
            assert!(
                err(&output).starts_with("error: "),
                "{words:?}: {}",
                err(&output)
            );
        }
    }
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("dir").count(),
        0,
        "a failed download leaves no file"
    );
}

/// Every command that reads from the API exits 3 with no credential at all, before any request.
#[test]
fn every_read_command_exits_3_without_a_credential() {
    let env = Env::new();
    for (words, _) in READS {
        let output = env
            .cmd()
            .args(["--api-url", "http://127.0.0.1:9"])
            .args(words)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(3), "{words:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{words:?}: {:?}", out(&output));
    }
}

/// Every command that reads from the API exits 7 when the API cannot be reached.
#[test]
fn every_read_command_exits_7_when_the_api_is_unreachable() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    for (words, _) in READS {
        let output = env
            .cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .env("HODEISHIELD_API_URL", "http://127.0.0.1:9")
            .current_dir(dir.path())
            .args(words)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(7), "{words:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{words:?}: {:?}", out(&output));
    }
}

/// An answer the CLI cannot read is exit code 1 (an unexpected answer), never a success and never
/// a partial print.
#[test]
fn an_unexpected_answer_exits_1() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    for (words, path) in READS {
        if words[..] == ["reports", "download", "x1"] {
            continue;
        }
        for (what, status, body) in [
            ("a 200 that is not JSON", 200, "<html>maintenance</html>"),
            ("a 200 with an empty body", 200, ""),
            (
                "a 200 that is not the described shape",
                200,
                r#"{"unexpected":true}"#,
            ),
            (
                "a status the API does not use",
                418,
                r#"{"error":{"code":"teapot","message":"short","request_id":"r"}}"#,
            ),
        ] {
            let mut server = mockito::Server::new();
            server
                .mock("GET", path)
                .match_query(mockito::Matcher::Any)
                .with_status(status)
                .with_body(body)
                .create();
            let output = env
                .cmd()
                .env("HODEISHIELD_API_KEY", KEY)
                .env("HODEISHIELD_API_URL", server.url())
                .current_dir(dir.path())
                .args(words)
                .output()
                .expect("run");
            assert_eq!(
                output.status.code(),
                Some(1),
                "{words:?} after {what}: {output:?}"
            );
            assert!(
                output.stdout.is_empty(),
                "{words:?} after {what}: {:?}",
                out(&output)
            );
        }
    }
}

/// A conflict on a download (a report with no file yet) is exit code 1.
#[test]
fn a_report_without_a_file_exits_1() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    for details in [
        r#"{"code":"REPORT_NOT_READY","status":"generating"}"#,
        r#"{"code":"REPORT_NOT_READY","status":"failed"}"#,
        r#"{"code":"FORMAT_UNSUPPORTED","formats":["pdf"]}"#,
        r#"{"code":"FILE_TOO_LARGE","limit_bytes":10}"#,
    ] {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/reports/r1/download")
            .match_query(mockito::Matcher::Any)
            .with_status(409)
            .with_body(format!(
                r#"{{"error":{{"code":"conflict","message":"no file","request_id":"r","details":{details}}}}}"#
            ))
            .create();
        let output = env
            .cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .env("HODEISHIELD_API_URL", server.url())
            .current_dir(dir.path())
            .args(["reports", "download", "r1"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{details}: {output:?}");
        assert!(output.stdout.is_empty(), "{details}: {:?}", out(&output));
    }
}

/// A bad request (400) is exit code 1.
#[test]
fn a_rejected_request_exits_1() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/changes")
        .match_query(mockito::Matcher::Any)
        .with_status(400)
        .with_body(r#"{"error":{"code":"bad_request","message":"Bad value.","request_id":"r"}}"#)
        .create();
    let output = env.api(&server.url(), &["changes", "list"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{:?}", out(&output));
}

/// `reports download` never replaces a file without `--force` (exit code 1, the file untouched),
/// and cannot write where there is no directory (exit code 1).
#[test]
fn report_download_refusals_exit_1_and_leave_files_alone() {
    let env = Env::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r1/download")
        .with_header("content-type", "application/pdf")
        .with_header(
            "content-disposition",
            r#"attachment; filename="report.pdf""#,
        )
        .with_body("%PDF-new")
        .expect_at_least(0)
        .create();
    let run = |args: &[&str]| {
        env.cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .env("HODEISHIELD_API_URL", server.url())
            .current_dir(dir.path())
            .args(args)
            .output()
            .expect("run")
    };

    std::fs::write(dir.path().join("mine.pdf"), "old").expect("write");
    std::fs::write(dir.path().join("report.pdf"), "old").expect("write");
    for args in [
        &["reports", "download", "r1", "--output", "mine.pdf"][..],
        &["reports", "download", "r1"][..],
        &["--json", "reports", "download", "r1"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
        assert!(
            err(&output).contains("already exists"),
            "{args:?}: {}",
            err(&output)
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.path().join("mine.pdf")).expect("read"),
        "old"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("report.pdf")).expect("read"),
        "old"
    );

    // A directory that is not there cannot be written to.
    let output = run(&[
        "reports",
        "download",
        "r1",
        "--output",
        "missing/dir/out.pdf",
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{:?}", out(&output));
    assert!(!dir.path().join("missing").exists());

    // The same, but replacing is allowed with --force: success, and the new bytes.
    let output = run(&[
        "reports", "download", "r1", "--output", "mine.pdf", "--force",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("mine.pdf")).expect("read"),
        "%PDF-new"
    );
}

/// A download to standard output puts the file, and nothing else, on stdout.
#[test]
fn report_download_to_stdout_prints_only_the_file() {
    let env = Env::new();
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r1/download")
        .with_header("content-type", "application/pdf")
        .with_body("%PDF-bytes")
        .create();
    let output = env.api(
        &server.url(),
        &["reports", "download", "r1", "--output", "-"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"%PDF-bytes");
    assert!(err(&output).starts_with("Wrote "), "{}", err(&output));
}

/// Usage errors (exit code 2) of the commands that have arguments of their own.
#[test]
fn usage_errors_exit_2_command_by_command() {
    let env = Env::new();
    for args in [
        &["vendors", "get"][..],
        &["alerts", "get"][..],
        &["risks", "get"][..],
        &["evidence", "get"][..],
        &["reports", "get"][..],
        &["reports", "download"][..],
        &["reports", "download", "r1", "--format", "docx"][..],
        &["reports", "download", "r1", "--locale", "xx"][..],
        &["reports", "list", "--sort", "bogus"][..],
        &["changes", "list", "--status", "bogus"][..],
        &["changes", "list", "--page", "0"][..],
        &["changes", "list", "--per-page", "201"][..],
        &["changes", "list", "--json", "--csv"][..],
        &["--json", "changes", "list", "--csv"][..],
        &["compliance", "posture"][..],
        &["tenants", "list", "--page", "1", "--all"][..],
        &["tenants", "frobnicate"][..],
        &["--tenant", "a", "--all-tenants", "vendors", "list"][..],
        &["--tenant", "a", "tenants", "list"][..],
        &["--all-tenants", "vendors", "get", "x1"][..],
        &["config"][..],
        &["config", "set"][..],
        &["config", "set", "api_url"][..],
        &["config", "set", "no_such_key", "x"][..],
        &["config", "unset", "no_such_key"][..],
        &["config", "unset"][..],
        &["config", "use"][..],
        &["config", "frobnicate"][..],
        &["completions"][..],
        &["completions", "no-such-shell"][..],
        &["login", "--device", "--no-browser"][..],
        &["login", "--no-such-flag"][..],
        &["logout", "now"][..],
        &["frobnicate"][..],
        &[][..],
    ] {
        let output = env
            .cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .args(args)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
        assert!(!err(&output).is_empty(), "{args:?}");
    }
}

/// `--help` and `--version` are successes, and print on stdout.
#[test]
fn help_and_version_exit_0() {
    let env = Env::new();
    for args in [
        &["--help"][..],
        &["--version"][..],
        &["reports", "download", "--help"][..],
    ] {
        let output = env.cmd().args(args).output().expect("run");
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert!(!output.stdout.is_empty(), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}: {}", err(&output));
    }
}

/// `completions` prints the script for each shell it knows, on stdout only.
#[test]
fn completions_exit_0_for_every_shell() {
    let env = Env::new();
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let output = env
            .cmd()
            .args(["completions", shell])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(0), "{shell}: {output:?}");
        assert!(out(&output).contains("hodeishield"), "{shell}");
        assert!(output.stderr.is_empty(), "{shell}: {}", err(&output));
    }
}

/// `config` commands: what ends in 0, what in 1 (a value or a profile that is not valid) and what
/// in 2 (a key that does not exist). Nothing is written when the value is refused.
#[test]
fn config_commands_exit_codes() {
    let env = Env::new();
    let run = |args: &[&str]| env.cmd().args(args).output().expect("run");

    let output = run(&["config", "path"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(out(&output), format!("{}\n", env.config.display()));
    let output = run(&["config", "show"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(out(&output).starts_with("config_file "), "{}", out(&output));

    for args in [
        &["config", "set", "api_url", "not a url"][..],
        &["config", "set", "app_url", "not a url"][..],
        &["config", "set", "update_check", "maybe"][..],
        &["config", "set", "token_store", "file"][..],
        &["config", "use", "no-such-profile"][..],
        &[
            "--profile",
            "",
            "config",
            "set",
            "api_url",
            "https://api.example.test",
        ][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
        assert!(
            err(&output).starts_with("error: "),
            "{args:?}: {}",
            err(&output)
        );
    }
    assert!(!env.config.exists(), "a refused change writes nothing");

    for args in [
        &["config", "set", "api_url", "https://api.example.test"][..],
        &[
            "--profile",
            "staging",
            "config",
            "set",
            "api_url",
            "https://staging.example.test",
        ][..],
        &["config", "use", "staging"][..],
        &["config", "use", "default"][..],
        &["config", "unset", "api_url"][..],
        &["config", "set", "update_check", "false"][..],
        &["config", "unset", "update_check"][..],
        &["config", "set", "token_store", "plaintext-file"][..],
        &["config", "unset", "token_store"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "{args:?}: notes go to stderr: {:?}",
            out(&output)
        );
        assert!(!err(&output).is_empty(), "{args:?}");
    }
}

/// A configuration file that cannot be read is an error (exit code 1), for the commands that read
/// the configuration, and nothing reaches stdout.
#[test]
fn a_broken_configuration_file_exits_1() {
    let env = Env::new();
    std::fs::write(&env.config, "this is = not [valid toml").expect("write");
    for args in [
        &["config", "show"][..],
        &["config", "set", "api_url", "https://api.example.test"][..],
        &["config", "use", "default"][..],
        &["whoami"][..],
        &["vendors", "list"][..],
    ] {
        let output = env
            .cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .args(args)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
    }
    // `config path` only says where the file is.
    let output = env.cmd().args(["config", "path"]).output().expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// A setting that is not valid is exit code 1: the API URL from the environment or the flag, and
/// the token store.
#[test]
fn an_invalid_setting_exits_1() {
    let env = Env::new();
    for (var, value) in [
        ("HODEISHIELD_API_URL", "not a url"),
        ("HODEISHIELD_APP_URL", "not a url"),
        ("HODEISHIELD_TOKEN_STORE", "file"),
    ] {
        let output = env
            .cmd()
            .env("HODEISHIELD_API_KEY", KEY)
            .env(var, value)
            .args(["vendors", "list"])
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{var}: {output:?}");
        assert!(output.stdout.is_empty(), "{var}: {:?}", out(&output));
    }
    let output = env
        .cmd()
        .env("HODEISHIELD_API_KEY", KEY)
        .args(["--api-url", "not a url", "vendors", "list"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

/// Without a reachable Secret Service (as in every test here) signing in and out are refused with
/// exit code 1, as the README says. Only on Linux: elsewhere the real keychain would be consulted.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn login_and_logout_exit_1_without_a_keychain() {
    let env = Env::new();
    for args in [
        &["login"][..],
        &["login", "--device"][..],
        &["login", "--no-browser"][..],
        &["logout"][..],
    ] {
        let output = env
            .cmd()
            .env("HODEISHIELD_API_URL", "http://127.0.0.1:9")
            .env("HODEISHIELD_APP_URL", "http://127.0.0.1:9")
            .args(args)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
        assert!(
            err(&output).starts_with("error: "),
            "{args:?}: {}",
            err(&output)
        );
    }
}

/// With the opt-in token file, in a home of the test's own: `logout` with nothing stored is a
/// success that says so, and `login` against an app that cannot be reached is exit code 7.
#[cfg(unix)]
#[test]
fn logout_with_nothing_stored_exits_0_and_login_without_an_app_exits_7() {
    let env = Env::new();
    let home = tempfile::tempdir().expect("tempdir");
    let file_store = || {
        let mut cmd = env.cmd();
        cmd.env("HODEISHIELD_TOKEN_STORE", "plaintext-file")
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", home.path().join("state"));
        cmd
    };
    let output = file_store().arg("logout").output().expect("run");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{:?}", out(&output));
    assert!(
        err(&output).starts_with("Not signed in"),
        "{}",
        err(&output)
    );

    for args in [
        &["login"][..],
        &["login", "--device"][..],
        &["login", "--no-browser"][..],
    ] {
        let output = file_store()
            .env("HODEISHIELD_API_URL", "http://127.0.0.1:9")
            .env("HODEISHIELD_APP_URL", "http://127.0.0.1:9")
            .args(args)
            .output()
            .expect("run");
        assert_eq!(output.status.code(), Some(7), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", out(&output));
    }
}
