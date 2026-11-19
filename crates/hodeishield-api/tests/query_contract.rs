// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Every query parameter the client can send is declared in the vendored OpenAPI document.
//!
//! The API answers `400 invalid_request` (`UNKNOWN_QUERY_PARAMETER`) to a query parameter name the
//! operation does not declare, so a name the client sends and the document lacks is a request that
//! can never succeed. Each parameter set below is filled in completely, with no defaults, so adding
//! a field to one of them fails to compile here until the test covers it.

use hodeishield_api::v1::{
    AlertSort, AlertStatus, BusinessCriticality, ChangeCategory, ChangeSort, ChangeStatus,
    ChangeType, ComplianceControlSort, DownloadReportParams, EndpointSort, EndpointStatus,
    EvidenceSort, Format, ListAlertsParams, ListChangesParams, ListComplianceControlsParams,
    ListEndpointsParams, ListEvidenceParams, ListPortfolioTenantsParams, ListReportsParams,
    ListRisksParams, ListVendorsParams, Locale, Order, PortfolioTenantSort, ReportSort, RiskSort,
    VendorSort,
};
use serde_json::Value;
use std::collections::BTreeSet;

const DOCUMENT: &str = include_str!("../../../openapi/v1.json");

/// The query parameters the document declares for `operation_id`.
fn declared(operation_id: &str) -> BTreeSet<String> {
    let document: Value = serde_json::from_str(DOCUMENT).expect("the OpenAPI document is JSON");
    for item in document["paths"].as_object().expect("paths").values() {
        for operation in item.as_object().expect("path item").values() {
            if operation["operationId"] == operation_id {
                return operation["parameters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|p| p["in"] == "query")
                    .map(|p| p["name"].as_str().expect("parameter name").to_owned())
                    .collect();
            }
        }
    }
    panic!("{operation_id} is not in the OpenAPI document");
}

/// The names sent by `pairs` are exactly the ones the document declares for the operation.
fn check(operation_id: &str, pairs: Vec<(&'static str, String)>) {
    let sent: Vec<&str> = pairs.iter().map(|(name, _)| *name).collect();
    let unique: BTreeSet<String> = sent.iter().map(|n| (*n).to_owned()).collect();
    assert_eq!(unique.len(), sent.len(), "{operation_id} repeats a name");
    assert_eq!(
        unique,
        declared(operation_id),
        "{operation_id}: the query parameters the client sends differ from the document's"
    );
}

fn s(text: &str) -> Option<String> {
    Some(text.to_owned())
}

#[test]
fn every_query_parameter_the_client_sends_is_declared_for_its_operation() {
    check(
        "listVendors",
        ListVendorsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(VendorSort::CreatedAt),
            order: Some(Order::Asc),
            q: s("q"),
            category: s("category"),
            active: s("true"),
            business_criticality: Some(BusinessCriticality::Low),
        }
        .query_pairs(),
    );
    check(
        "listAlerts",
        ListAlertsParams {
            page: Some(1),
            per_page: Some(1),
            cursor: s("c"),
            sort: Some(AlertSort::CreatedAt),
            order: Some(Order::Asc),
            status: Some(AlertStatus::Open),
            severity: s("high"),
            vendor_id: s("v"),
            since: s("2026-01-01T00:00:00Z"),
            updated_since: s("2026-01-01T00:00:00Z"),
        }
        .query_pairs(),
    );
    check(
        "listPendingActProposals",
        hodeishield_api::v1::ListPendingActProposalsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(hodeishield_api::v1::PendingActProposalSort::ExpiresAt),
            order: Some(Order::Asc),
            class: Some(hodeishield_api::v1::Class::CreateTask),
            module: s("supply_risk"),
            expires_before: s("2026-01-01T00:00:00Z"),
        }
        .query_pairs(),
    );
    check(
        "listIncidents",
        hodeishield_api::v1::ListIncidentsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(hodeishield_api::v1::IncidentSort::DetectedAt),
            order: Some(Order::Asc),
            status: s("open"),
            severity: s("high"),
            r#type: s("cybersecurity"),
        }
        .query_pairs(),
    );
    check(
        "listAiSystems",
        hodeishield_api::v1::ListAiSystemsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(hodeishield_api::v1::AiSystemSort::Name),
            order: Some(Order::Asc),
            risk_class: s("high_risk"),
            lifecycle_status: s("in_use"),
            vendor_id: s("v"),
        }
        .query_pairs(),
    );
    check(
        "listRisks",
        ListRisksParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(RiskSort::CreatedAt),
            order: Some(Order::Asc),
            status: s("open"),
            domain: s("domain"),
            vendor_id: s("v"),
            min_inherent_score: Some(1),
        }
        .query_pairs(),
    );
    check(
        "listComplianceControls",
        ListComplianceControlsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(ComplianceControlSort::ControlCode),
            order: Some(Order::Asc),
            framework: "nis2".to_owned(),
            status: s("compliant"),
        }
        .query_pairs(),
    );
    check(
        "listEvidence",
        ListEvidenceParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(EvidenceSort::CreatedAt),
            order: Some(Order::Asc),
            evidence_type: s("policy"),
            source_type: s("manual"),
            vendor_id: s("v"),
            expiring_before: s("2026-01-01T00:00:00Z"),
        }
        .query_pairs(),
    );
    check(
        "listEndpoints",
        ListEndpointsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(EndpointSort::EnrolledAt),
            order: Some(Order::Asc),
            status: Some(EndpointStatus::Active),
            silent_since: s("2026-01-01T00:00:00Z"),
        }
        .query_pairs(),
    );
    check(
        "listPortfolioTenants",
        ListPortfolioTenantsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(PortfolioTenantSort::Name),
            order: Some(Order::Asc),
        }
        .query_pairs(),
    );
    check(
        "listReports",
        ListReportsParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(ReportSort::CreatedAt),
            order: Some(Order::Asc),
            report_type: s("executive"),
            status: s("ready"),
            since: s("2026-01-01T00:00:00Z"),
        }
        .query_pairs(),
    );
    check(
        "downloadReport",
        DownloadReportParams {
            format: Some(Format::Pdf),
            locale: Some(Locale::Es),
        }
        .query_pairs(),
    );
    check(
        "listChanges",
        ListChangesParams {
            page: Some(1),
            per_page: Some(1),
            sort: Some(ChangeSort::CreatedAt),
            order: Some(Order::Asc),
            status: Some(ChangeStatus::Draft),
            change_type: Some(ChangeType::Normal),
            category: Some(ChangeCategory::Infrastructure),
            created_from: s("2026-01-01T00:00:00Z"),
            created_to: s("2026-01-02T00:00:00Z"),
        }
        .query_pairs(),
    );
}

/// The tenant listing has its own hand-written parameters; they are checked through the request the
/// client sends.
#[test]
fn the_tenant_listing_sends_only_declared_query_parameters() {
    use hodeishield_api::Client;
    use hodeishield_api::portfolio::{ListTenantsParams, TenantSort};
    use secrecy::SecretString;

    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::Any)
        .match_request(|request| {
            let query = request
                .path_and_query()
                .split_once('?')
                .map_or("", |(_, q)| q);
            let sent: BTreeSet<String> = query
                .split('&')
                .filter_map(|pair| pair.split('=').next())
                .map(str::to_owned)
                .collect();
            sent == declared("listPortfolioTenants")
        })
        .with_status(200)
        .with_body(r#"{"data":[],"pagination":{"page":1,"per_page":1,"total":0,"total_pages":0}}"#)
        .create();
    let client = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsp_example"),
    )
    .build()
    .expect("client");
    let _ = client.list_tenants(&ListTenantsParams {
        page: Some(1),
        per_page: Some(1),
        sort: Some(TenantSort::Name),
        order: Some(Order::Asc),
    });
    mock.assert();
}

/// The members of the JSON body the document declares for `operation_id`, with whether each is
/// required.
fn declared_body(operation_id: &str) -> Vec<(String, bool)> {
    let document: Value = serde_json::from_str(DOCUMENT).expect("the OpenAPI document is JSON");
    for item in document["paths"].as_object().expect("paths").values() {
        for operation in item.as_object().expect("path item").values() {
            if operation["operationId"] == operation_id {
                let schema = &operation["requestBody"]["content"]["application/json"]["schema"];
                assert_eq!(schema["additionalProperties"], false, "{operation_id}");
                let required: Vec<&str> = schema["required"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                return schema["properties"]
                    .as_object()
                    .expect("properties")
                    .keys()
                    .map(|name| (name.clone(), required.contains(&name.as_str())))
                    .collect();
            }
        }
    }
    panic!("{operation_id} is not in the OpenAPI document");
}

/// The alert writes send exactly the body members the document declares (an unknown key is a 400),
/// no query parameter, and the method and scope the document gives.
#[test]
fn the_alert_writes_send_what_the_document_declares() {
    use hodeishield_api::Client;
    use hodeishield_api::v1::operations;
    use mockito::Matcher;
    use secrecy::SecretString;
    for (id, method, scope) in [
        ("acknowledgeAlert", "post", "alerts:write"),
        ("resolveAlert", "post", "alerts:write"),
    ] {
        assert!(declared(id).is_empty(), "{id} declares a query parameter");
        let document: Value = serde_json::from_str(DOCUMENT).expect("JSON");
        let operation = document["paths"]
            .as_object()
            .expect("paths")
            .values()
            .find_map(|item| item.get(method).filter(|op| op["operationId"] == id))
            .unwrap_or_else(|| panic!("{id} is not a {method} in the document"));
        assert_eq!(operation["x-hs-scope"]["scopes"][0], scope);
    }
    assert_eq!(
        declared_body("acknowledgeAlert"),
        [("reason".to_owned(), false)]
    );
    assert_eq!(declared_body("resolveAlert"), [("reason".to_owned(), true)]);

    let mut server = mockito::Server::new();
    let only_reason = |request: &mockito::Request| {
        let body = request.body().expect("a body");
        let value: Value = serde_json::from_slice(body).expect("a JSON body");
        value
            .as_object()
            .expect("an object")
            .keys()
            .all(|k| k == "reason")
    };
    let ack = server
        .mock("POST", "/v1/alerts/a1/acknowledge")
        .match_query(Matcher::Missing)
        .match_request(only_reason)
        .with_body(r#"{"data":{"id":"a1","status":"acknowledged","acknowledged_at":null,"resolved_at":null,"resolution_reason":null,"updated_at":"2026-11-14T10:00:00Z"},"changed":true}"#)
        .expect(2)
        .create();
    let resolve = server
        .mock("POST", "/v1/alerts/a1/resolve")
        .match_query(Matcher::Missing)
        .match_request(only_reason)
        .with_body(r#"{"data":{"id":"a1","status":"resolved","acknowledged_at":null,"resolved_at":null,"resolution_reason":"done","updated_at":"2026-11-14T10:00:00Z"},"changed":true}"#)
        .expect(1)
        .create();
    let client = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .build()
    .expect("client");
    client.acknowledge_alert("a1", None).expect("ok");
    client.acknowledge_alert("a1", Some("why")).expect("ok");
    client.resolve_alert("a1", "done").expect("ok");
    ack.assert();
    resolve.assert();
    assert_eq!(operations::ACKNOWLEDGE_ALERT.method, "POST");
}

/// The risk move and the two decisions send exactly the body members the document declares.
#[test]
fn the_risk_and_decision_writes_send_what_the_document_declares() {
    use hodeishield_api::Client;
    use mockito::Matcher;
    use secrecy::SecretString;
    assert_eq!(
        declared_body("transitionRisk"),
        [("to_status".to_owned(), true), ("note".to_owned(), false)]
    );
    assert_eq!(
        declared_body("approveActProposal"),
        [("reason".to_owned(), true)]
    );
    assert_eq!(
        declared_body("rejectActProposal"),
        [("reason".to_owned(), true)]
    );
    for id in ["transitionRisk", "approveActProposal", "rejectActProposal"] {
        assert!(declared(id).is_empty(), "{id} declares a query parameter");
    }

    let mut server = mockito::Server::new();
    let keys = |allowed: &'static [&'static str]| {
        move |request: &mockito::Request| {
            let value: Value =
                serde_json::from_slice(request.body().expect("a body")).expect("a JSON body");
            value
                .as_object()
                .expect("an object")
                .keys()
                .all(|k| allowed.contains(&k.as_str()))
        }
    };
    let risk = server
        .mock("POST", "/v1/risks/r1/transition")
        .match_query(Matcher::Missing)
        .match_request(keys(&["to_status", "note"]))
        .with_body(r#"{"data":{"id":"r1","status":"assessed","updated_at":"2026-11-18T10:00:00Z"},"changed":true}"#)
        .expect(1)
        .create();
    let decision = server
        .mock("POST", Matcher::Regex("^/v1/act/proposals/p1/(approve|reject)$".into()))
        .match_query(Matcher::Missing)
        .match_request(keys(&["reason"]))
        .with_body(r#"{"data":{"id":"p1","status":"approved","approval_expires_at":null,"ledger_entry_id":"l1"}}"#)
        .expect(2)
        .create();
    let client = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .build()
    .expect("client");
    client
        .transition_risk("r1", "assessed", Some("why"))
        .expect("ok");
    client.approve_act_proposal("p1", "why").expect("ok");
    client.reject_act_proposal("p1", "why").expect("ok");
    risk.assert();
    decision.assert();
}
