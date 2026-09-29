//! The generated client against a mock `/v1`.

use hodeishield_api::v1::{ListComplianceControlsParams, ListVendorsParams, Order, VendorSort};
use hodeishield_api::{Client, Error};
use secrecy::SecretString;
use std::time::Duration;

const VENDOR: &str = r#"{
  "id": "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e",
  "name": "Example Hosting",
  "legal_name": null,
  "domain": "example.com",
  "category": null,
  "vendor_type": null,
  "access_level": null,
  "business_criticality": "high",
  "data_sensitivity": null,
  "economic_impact": null,
  "active": true,
  "monitoring_status": null,
  "last_scan_at": null,
  "lei": null,
  "hq_country": "ES",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-02T00:00:00Z",
  "field_added_later": {"nested": true}
}"#;

fn client(server: &mockito::Server) -> Client {
    Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .rate_limit_retries(1, Duration::from_secs(5))
    .build()
    .expect("client")
}

#[test]
fn list_sends_the_bearer_and_the_query_and_keeps_unknown_fields_in_raw() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/vendors")
        .match_header("authorization", "Bearer hsk_example")
        .match_header("accept", "application/json")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("sort".into(), "name".into()),
            mockito::Matcher::UrlEncoded("order".into(), "asc".into()),
            mockito::Matcher::UrlEncoded("q".into(), "exa mple".into()),
        ]))
        .with_status(200)
        .with_header("x-request-id", "req_1")
        .with_header("ratelimit-limit", "100")
        .with_header("ratelimit-remaining", "99")
        .with_header("ratelimit-reset", "30")
        .with_header("ratelimit-policy", "100;w=60")
        .with_body(format!(
            r#"{{"data":[{VENDOR}],"pagination":{{"page":1,"per_page":50,"total":1,"total_pages":1}}}}"#
        ))
        .create();

    let params = ListVendorsParams {
        sort: Some(VendorSort::Name),
        order: Some(Order::Asc),
        q: Some("exa mple".to_owned()),
        ..ListVendorsParams::default()
    };
    let page = client(&server).list_vendors(&params).expect("list");
    mock.assert();
    assert_eq!(page.data.data.len(), 1);
    assert_eq!(page.data.data[0].name, "Example Hosting");
    assert_eq!(page.data.pagination.total, 1);
    assert_eq!(page.meta.request_id.as_deref(), Some("req_1"));
    let limit = page.meta.rate_limit.expect("rate limit");
    assert_eq!(
        (limit.limit, limit.remaining, limit.reset_seconds),
        (100, 99, 30)
    );
    assert_eq!(page.raw["data"][0]["field_added_later"]["nested"], true);
}

#[test]
fn path_arguments_are_encoded() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/compliance/frameworks/iso%2027001")
        .with_status(200)
        .with_body(r#"{"data":{"framework":"iso 27001","controls_total":2,"by_status":{"passing":1,"failing":1},"evidence_total":3,"last_evaluated_at":null}}"#)
        .create();
    let posture = client(&server)
        .get_framework_posture("iso 27001")
        .expect("posture");
    mock.assert();
    assert_eq!(posture.data.data.by_status.get("failing"), Some(&1));

    let err = client(&server).get_vendor("..").expect_err("dot segment");
    assert!(matches!(err, Error::InvalidPathArgument(_)));
}

#[test]
fn an_error_envelope_is_decoded_with_the_required_scope() {
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/compliance/controls")
        .match_query(mockito::Matcher::UrlEncoded(
            "framework".into(),
            "nis2".into(),
        ))
        .with_status(403)
        .with_header("x-request-id", "req_403")
        .with_body(
            r#"{"error":{"code":"forbidden","message":"missing scope","request_id":"req_403"}}"#,
        )
        .create();
    let err = client(&server)
        .list_compliance_controls(&ListComplianceControlsParams::new("nis2"))
        .expect_err("forbidden");
    let api = err.api().expect("api error");
    assert_eq!(api.status, 403);
    assert_eq!(api.code(), Some("forbidden"));
    assert_eq!(api.request_id(), Some("req_403"));
    assert_eq!(api.required_scopes, &["compliance.<framework>:read"]);
}

#[test]
fn a_non_envelope_error_body_still_gives_the_status() {
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/endpoints")
        .with_status(502)
        .with_body("<html>bad gateway</html>")
        .create();
    let err = client(&server)
        .list_endpoints(&hodeishield_api::v1::ListEndpointsParams::default())
        .expect_err("502");
    let api = err.api().expect("api error");
    assert_eq!(api.status, 502);
    assert!(api.body.is_none());
}

#[test]
fn a_429_is_retried_after_retry_after() {
    let mut server = mockito::Server::new();
    let limited = server
        .mock("GET", "/v1/alerts")
        .with_status(429)
        .with_header("retry-after", "1")
        .with_body(r#"{"error":{"code":"rate_limited","message":"slow down","request_id":"r","details":{"scope":"key"}}}"#)
        .expect(2)
        .create();
    let first = client(&server).list_alerts(&hodeishield_api::v1::ListAlertsParams::default());
    // The retry got another 429, and one retry is all this client allows.
    let err = first.expect_err("still limited");
    assert_eq!(err.api().map(|a| a.status), Some(429));
    limited.assert();
}

#[test]
fn redirects_are_not_followed() {
    let mut server = mockito::Server::new();
    let mut elsewhere = mockito::Server::new();
    let never = elsewhere
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create();
    server
        .mock("GET", "/v1/risks")
        .with_status(302)
        .with_header("location", &format!("{}/steal", elsewhere.url()))
        .create();
    let err = client(&server)
        .list_risks(&hodeishield_api::v1::ListRisksParams::default())
        .expect_err("redirect");
    assert_eq!(err.api().map(|a| a.status), Some(302));
    never.assert();
}

#[test]
fn a_body_that_breaks_the_contract_is_a_decode_error() {
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/evidence/abc")
        .with_status(200)
        .with_body(r#"{"data":{"id":"abc"}}"#)
        .create();
    let err = client(&server).get_evidence("abc").expect_err("decode");
    assert!(matches!(
        err,
        Error::Decode {
            operation: "getEvidence",
            ..
        }
    ));
}

fn page_of_nothing() -> &'static str {
    r#"{"data":[],"pagination":{"page":1,"per_page":25,"total":0,"total_pages":0}}"#
}

#[test]
fn a_401_renews_the_credential_once_and_resends_the_request() {
    let mut server = mockito::Server::new();
    let refused = server
        .mock("GET", "/v1/vendors")
        .match_header("authorization", "Bearer hs_at_old")
        .with_status(401)
        .with_body(
            r#"{"error":{"code":"unauthorized","message":"NOT_AUTHENTICATED","request_id":"r1"}}"#,
        )
        .expect(1)
        .create();
    let accepted = server
        .mock("GET", "/v1/vendors")
        .match_header("authorization", "Bearer hs_at_new")
        .with_body(page_of_nothing())
        .expect(2)
        .create();
    let renewals = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&renewals);
    let client = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hs_at_old"),
    )
    .renew_credential(move || {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(SecretString::from("hs_at_new"))
    })
    .build()
    .expect("client");
    client
        .list_vendors(&ListVendorsParams::default())
        .expect("renewed");
    // The renewed credential stays: the next request does not start with the refused one.
    client
        .list_vendors(&ListVendorsParams::default())
        .expect("still renewed");
    refused.assert();
    accepted.assert();
    assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn a_401_after_renewing_is_returned_and_not_renewed_again() {
    let mut server = mockito::Server::new();
    let refused = server
        .mock("GET", "/v1/vendors")
        .with_status(401)
        .with_body(
            r#"{"error":{"code":"unauthorized","message":"NOT_AUTHENTICATED","request_id":"r1"}}"#,
        )
        .expect(2)
        .create();
    let renewals = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&renewals);
    let client = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hs_at_old"),
    )
    .renew_credential(move || {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(SecretString::from("hs_at_new"))
    })
    .build()
    .expect("client");
    let err = client
        .list_vendors(&ListVendorsParams::default())
        .expect_err("refused");
    assert_eq!(err.api().map(|a| a.status), Some(401));
    refused.assert();
    assert_eq!(renewals.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn without_a_renewal_a_401_is_returned_as_is() {
    let mut server = mockito::Server::new();
    let refused = server
        .mock("GET", "/v1/vendors")
        .with_status(401)
        .expect(1)
        .create();
    let err = client(&server)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("refused");
    assert_eq!(err.api().map(|a| a.status), Some(401));
    refused.assert();
}
