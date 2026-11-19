// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The generated client against a mock `/v1`.

use hodeishield_api::v1::{ListComplianceControlsParams, ListVendorsParams, Order, VendorSort};
use hodeishield_api::{Client, Error};
use secrecy::SecretString;
use std::time::{Duration, Instant};

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

const TENANT: &str = "3f2b8c1a-0d4e-4f6a-9b7c-5e1d2a3b4c5d";

fn tenant_meta(status: usize, headers: &[&str]) -> hodeishield_api::ResponseMeta {
    let mut server = mockito::Server::new();
    let mut mock = server.mock("GET", "/v1/vendors").with_status(status);
    for value in headers {
        mock = mock.with_header("x-hs-tenant", value);
    }
    let body = if status == 200 {
        r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":0}}"#
    } else {
        r#"{"error":{"code":"forbidden","message":"no","request_id":"r"}}"#
    };
    let _mock = mock.with_body(body).create();
    match client(&server).list_vendors(&ListVendorsParams::default()) {
        Ok(page) => page.meta,
        Err(e) => e.api().expect("api error").meta.clone(),
    }
}

#[test]
fn the_tenant_header_of_a_2xx_answer_is_kept_lowercase() {
    assert_eq!(
        tenant_meta(200, &[TENANT]).tenant_id.as_deref(),
        Some(TENANT)
    );
    let upper = TENANT.to_ascii_uppercase();
    assert_eq!(
        tenant_meta(200, &[upper.as_str()]).tenant_id.as_deref(),
        Some(TENANT)
    );
}

#[test]
fn a_missing_malformed_or_duplicated_tenant_header_gives_none() {
    assert_eq!(tenant_meta(200, &[]).tenant_id, None);
    for bad in [
        "",
        "not-a-uuid",
        "3f2b8c1a0d4e4f6a9b7c5e1d2a3b4c5d",
        "3f2b8c1a-0d4e-4f6a-9b7c-5e1d2a3b4c5",
        "3f2b8c1a-0d4e-4f6a-9b7c-5e1d2a3b4c5g",
        "{3f2b8c1a-0d4e-4f6a-9b7c-5e1d2a3b4c5d}",
    ] {
        assert_eq!(tenant_meta(200, &[bad]).tenant_id, None, "{bad:?}");
    }
    let other = "11111111-2222-4333-8444-555555555555";
    assert_eq!(tenant_meta(200, &[TENANT, other]).tenant_id, None);
    assert_eq!(tenant_meta(200, &[TENANT, TENANT]).tenant_id, None);
}

#[test]
fn a_tenant_header_on_an_error_answer_is_ignored() {
    assert_eq!(tenant_meta(403, &[TENANT]).tenant_id, None);
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

/// Helper to build a client with fast transient retries.
fn client_with_transient_retries(server: &mockito::Server, max_retries: u32) -> Client {
    Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .transient_retries(max_retries, Duration::from_millis(1))
    .build()
    .expect("client")
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

#[test]
fn an_answer_larger_than_the_size_limit_is_not_read_in_full() {
    let mut server = mockito::Server::new();
    let padding = "x".repeat(9 * 1024 * 1024);
    let mock = server
        .mock("GET", "/v1/vendors")
        .with_status(200)
        .with_body(format!(
            r#"{{"data":[],"pagination":{{"page":1,"per_page":50,"total":0,"total_pages":0}},"padding":"{padding}"}}"#
        ))
        .create();
    let err = client(&server)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("over the limit");
    mock.assert();
    assert!(err.to_string().contains("larger than"), "{err}");
}

/// Serves one chunked answer (no `Content-Length`) of unbounded length until the peer hangs up, and
/// returns how many body bytes it managed to send.
fn serve_chunked_until_closed(listener: std::net::TcpListener) -> u64 {
    use std::io::{Read, Write};
    const CHUNK: usize = 16 * 1024;
    const GIVE_UP_AFTER: u64 = 1024 * 1024 * 1024;
    let (mut stream, _) = listener.accept().expect("accept");
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).expect("read request");
        assert!(n > 0, "the client closed before sending a request");
        request.extend_from_slice(&buf[..n]);
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
        .expect("write head");
    let mut frame = format!("{CHUNK:x}\r\n").into_bytes();
    frame.extend(std::iter::repeat_n(b'x', CHUNK));
    frame.extend_from_slice(b"\r\n");
    let mut sent = 0_u64;
    while sent < GIVE_UP_AFTER {
        if stream.write_all(&frame).is_err() {
            break;
        }
        sent += CHUNK as u64;
    }
    sent
}

#[test]
fn a_chunked_answer_without_a_content_length_is_still_cut_off_at_the_size_limit() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = std::thread::spawn(move || serve_chunked_until_closed(listener));

    let response = reqwest::blocking::get(format!("http://127.0.0.1:{port}/")).expect("response");
    assert!(
        response.content_length().is_none(),
        "the answer must not declare its length"
    );
    let err = hodeishield_api::read_body(response, 1024).expect_err("over the limit");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("larger than 1024"), "{err}");

    let sent = server.join().expect("server thread");
    assert!(
        sent < 64 * 1024 * 1024,
        "the reader kept consuming a body it had already rejected ({sent} bytes sent)"
    );
}

#[test]
fn a_503_then_200_is_retried_and_succeeds() {
    let mut server = mockito::Server::new();
    let unavailable = server
        .mock("GET", "/v1/vendors")
        .with_status(503)
        .expect(1)
        .create();
    let success = server
        .mock("GET", "/v1/vendors")
        .with_status(200)
        .with_body(page_of_nothing())
        .expect(1)
        .create();
    let result =
        client_with_transient_retries(&server, 2).list_vendors(&ListVendorsParams::default());
    assert!(result.is_ok(), "should succeed after retry");
    unavailable.assert();
    success.assert();
}

#[test]
fn a_502_and_504_then_200_is_retried_and_succeeds() {
    let mut server = mockito::Server::new();
    let bad_gateway = server
        .mock("GET", "/v1/vendors")
        .with_status(502)
        .expect(1)
        .create();
    let gateway_timeout = server
        .mock("GET", "/v1/vendors")
        .with_status(504)
        .expect(1)
        .create();
    let success = server
        .mock("GET", "/v1/vendors")
        .with_status(200)
        .with_body(page_of_nothing())
        .expect(1)
        .create();
    let result =
        client_with_transient_retries(&server, 2).list_vendors(&ListVendorsParams::default());
    assert!(result.is_ok(), "should succeed after retries");
    bad_gateway.assert();
    gateway_timeout.assert();
    success.assert();
}

#[test]
fn three_503s_exhausts_retries_and_fails_on_the_third() {
    let mut server = mockito::Server::new();
    let unavailable = server
        .mock("GET", "/v1/vendors")
        .with_status(503)
        .expect(3)
        .create();
    let result =
        client_with_transient_retries(&server, 2).list_vendors(&ListVendorsParams::default());
    assert!(result.is_err(), "should fail after exhausting retries");
    let err = result.expect_err("unwrap error");
    assert_eq!(err.api().map(|a| a.status), Some(503));
    unavailable.assert();
}

#[test]
fn a_500_is_not_retried() {
    let mut server = mockito::Server::new();
    let error = server
        .mock("GET", "/v1/vendors")
        .with_status(500)
        .expect(1)
        .create();
    let result =
        client_with_transient_retries(&server, 2).list_vendors(&ListVendorsParams::default());
    assert!(result.is_err(), "500 should not be retried");
    error.assert();
}

#[test]
fn a_404_is_not_retried() {
    let mut server = mockito::Server::new();
    let not_found = server
        .mock("GET", "/v1/vendors")
        .with_status(404)
        .expect(1)
        .create();
    let result =
        client_with_transient_retries(&server, 2).list_vendors(&ListVendorsParams::default());
    assert!(result.is_err(), "404 should not be retried");
    not_found.assert();
}

#[test]
fn a_503_with_retry_after_1s_within_max_wait_is_honored() {
    let mut server = mockito::Server::new();
    let unavailable = server
        .mock("GET", "/v1/vendors")
        .with_status(503)
        .with_header("retry-after", "1")
        .expect(1)
        .create();
    let success = server
        .mock("GET", "/v1/vendors")
        .with_status(200)
        .with_body(page_of_nothing())
        .expect(1)
        .create();

    let started = Instant::now();
    let result = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .transient_retries(2, Duration::from_millis(1))
    .build()
    .expect("client")
    .list_vendors(&ListVendorsParams::default());
    let elapsed = started.elapsed();

    assert!(
        result.is_ok(),
        "should succeed after respecting Retry-After"
    );
    assert!(
        elapsed >= Duration::from_secs(1),
        "should have waited at least 1 second, waited {:?}",
        elapsed
    );
    unavailable.assert();
    success.assert();
}

#[test]
fn a_503_with_retry_after_longer_than_max_wait_does_not_retry() {
    let mut server = mockito::Server::new();
    let unavailable = server
        .mock("GET", "/v1/vendors")
        .with_status(503)
        .with_header("retry-after", "120")
        .expect(1)
        .create();

    let result = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .transient_retries(2, Duration::from_millis(1))
    .build()
    .expect("client")
    .list_vendors(&ListVendorsParams::default());

    assert!(
        result.is_err(),
        "should not retry when Retry-After exceeds max_wait"
    );
    unavailable.assert();
}

#[test]
fn a_connection_error_is_retried() {
    // Keep the listener bound for the whole test so no other test can take the port. It never
    // accepts, so every attempt connects (the kernel completes the handshake) and then gets no
    // answer: a timeout, which is retried like a refused connection.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let url = format!("http://127.0.0.1:{port}");
    let retry_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&retry_count);

    let result = Client::builder(url.parse().expect("url"), SecretString::from("hsk_example"))
        .timeout(Duration::from_millis(200))
        .transient_retries(2, Duration::from_millis(1))
        .retry_observer(move |_event| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .build()
        .expect("client")
        .list_vendors(&ListVendorsParams::default());

    assert!(result.is_err(), "should fail with a connection error");
    assert!(matches!(result.expect_err("error"), Error::Transport(_)));
    let retries = retry_count.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(retries, 2, "should have retried exactly 2 times");
    drop(listener);
}

#[test]
fn a_refused_connection_is_retried() {
    // Bind to get a free port, then close it: nothing listens there, so every attempt is refused.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let retries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&retries);
    let result = Client::builder(
        format!("http://127.0.0.1:{port}").parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .transient_retries(2, Duration::from_millis(1))
    .retry_observer(move |_event| {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })
    .build()
    .expect("client")
    .list_vendors(&ListVendorsParams::default());

    assert!(matches!(result, Err(Error::Transport(_))));
    assert_eq!(retries.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn retry_observer_receives_expected_events() {
    let mut server = mockito::Server::new();
    let unavailable = server
        .mock("GET", "/v1/vendors")
        .with_status(503)
        .expect(2)
        .create();
    let success = server
        .mock("GET", "/v1/vendors")
        .with_status(200)
        .with_body(page_of_nothing())
        .expect(1)
        .create();

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = std::sync::Arc::clone(&events);

    let result = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from("hsk_example"),
    )
    .transient_retries(2, Duration::from_millis(1))
    .retry_observer(move |event| {
        if let Ok(mut e) = collected.lock() {
            e.push((event.attempt, event.reason.to_owned()));
        }
    })
    .build()
    .expect("client")
    .list_vendors(&ListVendorsParams::default());

    assert!(result.is_ok());
    let collected_events = events.lock().expect("lock");
    assert_eq!(
        collected_events.len(),
        2,
        "should have exactly 2 retry events"
    );
    assert_eq!(collected_events[0].0, 1, "first retry should be attempt 1");
    assert!(
        collected_events[0].1.contains("503"),
        "first retry reason should mention 503"
    );
    assert_eq!(collected_events[1].0, 2, "second retry should be attempt 2");
    assert!(
        collected_events[1].1.contains("503"),
        "second retry reason should mention 503"
    );
    unavailable.assert();
    success.assert();
}

// The portfolio contract (version 2026-10-16): the listing, the tenant selection and its echo.

/// The shape of a portfolio key: `hsp_`, 12 hex, `_`, 64 hex.
const PORTFOLIO_KEY: &str =
    "hsp_3f2a9c0d1b4e_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";
const TENANT_B: &str = "22222222-2222-4222-8222-222222222222";
const EMPTY_PAGE: &str =
    r#"{"data":[],"pagination":{"page":1,"per_page":50,"total":0,"total_pages":0}}"#;

fn tenant_client(server: &mockito::Server, tenant: &str) -> Client {
    Client::builder(
        server.url().parse().expect("url"),
        SecretString::from(PORTFOLIO_KEY),
    )
    .tenant(tenant)
    .expect("a UUID")
    .build()
    .expect("client")
}

#[test]
fn list_tenants_decodes_the_listing_and_never_sends_a_tenant() {
    use hodeishield_api::portfolio::ListTenantsParams;
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/portfolio/tenants")
        .match_header("authorization", format!("Bearer {PORTFOLIO_KEY}").as_str())
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_body(format!(
            r#"{{"data":[{{"id":"{TENANT_A}","name":"Acme","slug":"acme","organization":{{"id":"o1","name":"Acme Group"}},"internal":false,"active":true,"licence_status":"in_force","later":1}},{{"id":"{TENANT_B}","name":"Beta","slug":"beta","organization":{{"id":"o2","name":"Beta Group"}},"internal":true,"active":false,"licence_status":"something_new"}}],"pagination":{{"page":1,"per_page":50,"total":2,"total_pages":1}}}}"#
        ))
        .create();
    // Even a client built for one tenant lists the whole portfolio.
    let response = tenant_client(&server, TENANT_B)
        .list_tenants(&ListTenantsParams::default())
        .expect("listing");
    mock.assert();
    assert_eq!(response.data.data[0].slug, "acme");
    assert_eq!(response.data.data[0].licence_status, "in_force");
    assert_eq!(response.raw["data"][0]["later"], 1);
    // An unknown licence status decodes, and is not readable.
    let beta = &response.data.data[1];
    assert_eq!(beta.licence_status, "something_new");
    assert!(!beta.readable() && beta.internal);
    assert!(response.data.data[0].readable());
}

#[test]
fn a_selected_tenant_travels_on_data_calls_and_must_be_confirmed() {
    let mut server = mockito::Server::new();
    let ok = server
        .mock("GET", "/v1/vendors")
        .match_header("x-hs-tenant", TENANT_A)
        // Header names are case-insensitive; the value is the lowercase UUID.
        .with_header("X-HS-Tenant", TENANT_A)
        .with_header("Vary", "X-HS-Tenant")
        .with_body(EMPTY_PAGE)
        .create();
    tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect("confirmed answer");
    ok.assert();
}

#[test]
fn an_answer_for_another_tenant_or_for_none_is_refused() {
    let mut server = mockito::Server::new();
    let other = server
        .mock("GET", "/v1/vendors")
        .with_header("x-hs-tenant", TENANT_B)
        .with_body(EMPTY_PAGE)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("another tenant");
    assert!(
        matches!(&err, Error::TenantMismatch { answered: Some(a), .. } if a == TENANT_B),
        "{err:?}"
    );
    other.remove();
    server
        .mock("GET", "/v1/vendors")
        .with_body(EMPTY_PAGE)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("no confirmation");
    assert!(
        matches!(err, Error::TenantMismatch { answered: None, .. }),
        "{err:?}"
    );
}

#[test]
fn a_client_without_a_tenant_sends_no_selection_and_checks_nothing() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/vendors")
        .match_header("x-hs-tenant", mockito::Matcher::Missing)
        .with_body(EMPTY_PAGE)
        .create();
    client(&server)
        .list_vendors(&ListVendorsParams::default())
        .expect("plain call");
    mock.assert();
}

#[test]
fn a_tenant_that_is_not_a_uuid_is_refused_before_any_request() {
    for bad in [
        "acme",
        "",
        "11111111-1111-4111-8111-111111111111, 22222222-2222-4222-8222-222222222222",
    ] {
        let err = Client::builder(
            "https://api.example.test".parse().expect("url"),
            SecretString::from("k"),
        )
        .tenant(bad)
        .expect_err("not a UUID");
        assert!(matches!(err, Error::InvalidTenant(_)), "{bad:?}");
    }
}

#[test]
fn the_tenant_is_sent_in_lowercase_and_the_echo_must_be_exactly_that() {
    let lower = "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e";
    let upper = lower.to_ascii_uppercase();
    let mut server = mockito::Server::new();
    // The request carries the lowercase form even when the caller gave capitals.
    let sent = server
        .mock("GET", "/v1/vendors")
        .match_header("x-hs-tenant", lower)
        .with_header("x-hs-tenant", lower)
        .with_body(EMPTY_PAGE)
        .create();
    tenant_client(&server, &upper)
        .list_vendors(&ListVendorsParams::default())
        .expect("lowercase echo");
    sent.assert();
    // An echo in capitals is not what the contract promises: refused.
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_header("x-hs-tenant", &upper)
        .with_body(EMPTY_PAGE)
        .create();
    let err = tenant_client(&server, lower)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("not the contract's form");
    assert!(matches!(err, Error::TenantMismatch { .. }), "{err:?}");
}

#[test]
fn an_echo_that_names_two_tenants_is_refused() {
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_header("x-hs-tenant", TENANT_A)
        .with_header("x-hs-tenant", TENANT_B)
        .with_body(EMPTY_PAGE)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("two values");
    assert!(matches!(err, Error::TenantMismatch { .. }), "{err:?}");
}

#[test]
fn every_data_operation_sends_the_selection_and_checks_the_echo() {
    use hodeishield_api::v1::{
        ListAlertsParams, ListComplianceControlsParams, ListEndpointsParams, ListEvidenceParams,
        ListRisksParams,
    };
    let mut server = mockito::Server::new();
    let any = server
        .mock("GET", mockito::Matcher::Any)
        .match_header("x-hs-tenant", TENANT_A)
        .with_header("x-hs-tenant", TENANT_B)
        .with_body(EMPTY_PAGE)
        .expect(7)
        .create();
    let c = tenant_client(&server, TENANT_A);
    fn refused<T>(r: Result<T, Error>) -> bool {
        matches!(r, Err(Error::TenantMismatch { .. }))
    }
    assert!(refused(c.list_alerts(&ListAlertsParams::default())));
    assert!(refused(c.list_risks(&ListRisksParams::default())));
    assert!(refused(c.list_incidents(
        &hodeishield_api::v1::ListIncidentsParams::default()
    )));
    assert!(refused(c.list_ai_systems(
        &hodeishield_api::v1::ListAiSystemsParams::default()
    )));
    assert!(refused(c.list_evidence(&ListEvidenceParams::default())));
    assert!(refused(c.list_endpoints(&ListEndpointsParams::default())));
    assert!(refused(c.list_compliance_controls(
        &ListComplianceControlsParams {
            page: None,
            per_page: None,
            sort: None,
            order: None,
            framework: "nis2".to_owned(),
            status: None,
        }
    )));
    any.assert();
}

#[test]
fn an_error_answer_is_reported_as_the_api_error_whatever_the_header_says() {
    // The contract has no echo on errors; a client must not mistake one for a mismatch, nor hide
    // the real refusal behind it.
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"No such tenant in this credential's portfolio.","request_id":"r","details":{"code":"TENANT_NOT_FOUND"}}}"#)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("not in the portfolio");
    let api = err.api().expect("the API's own error");
    assert_eq!(api.status, 404);
    let details = api
        .body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .expect("details");
    assert_eq!(details["code"], "TENANT_NOT_FOUND");
}

#[test]
fn the_listing_asks_for_the_order_it_is_given() {
    use hodeishield_api::portfolio::ListTenantsParams;
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/portfolio/tenants")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("page".into(), "2".into()),
            mockito::Matcher::UrlEncoded("per_page".into(), "200".into()),
            mockito::Matcher::UrlEncoded("sort".into(), "name".into()),
            mockito::Matcher::UrlEncoded("order".into(), "asc".into()),
        ]))
        .with_body(EMPTY_PAGE)
        .create();
    client(&server)
        .list_tenants(&ListTenantsParams::alphabetical(Some(2), Some(200)))
        .expect("listing");
    mock.assert();
}

#[test]
fn a_listing_that_breaks_the_contract_is_a_decode_error() {
    use hodeishield_api::portfolio::ListTenantsParams;
    let mut server = mockito::Server::new();
    // `organization` is never null.
    server
        .mock("GET", "/v1/portfolio/tenants")
        .with_body(format!(
            r#"{{"data":[{{"id":"{TENANT_A}","name":"A","slug":"a","organization":null,"internal":false,"active":true,"licence_status":"in_force"}}],"pagination":{{"page":1,"per_page":50,"total":1,"total_pages":1}}}}"#
        ))
        .create();
    let err = client(&server)
        .list_tenants(&ListTenantsParams::default())
        .expect_err("null organization");
    assert!(matches!(err, Error::Decode { .. }), "{err:?}");
}

#[test]
fn an_api_without_the_listing_route_is_told_apart_from_other_errors() {
    use hodeishield_api::portfolio::ListTenantsParams;
    for status in [404_usize, 405] {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/portfolio/tenants")
            .with_status(status)
            .with_body(r#"{"error":{"code":"not_found","message":"Not found","request_id":"r"}}"#)
            .create();
        let err = client(&server)
            .list_tenants(&ListTenantsParams::default())
            .expect_err("no route");
        assert!(
            matches!(&err, Error::PortfolioNotOffered { status: s } if usize::from(*s) == status),
            "{status}: {err:?}"
        );
    }
    // Other statuses stay what the API said, and a 404 on a data operation is not this.
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/portfolio/tenants")
        .with_status(403)
        .with_body(r#"{"error":{"code":"forbidden","message":"x","request_id":"r","details":{"code":"INSUFFICIENT_SCOPE","missing":["portfolio:read"]}}}"#)
        .create();
    server
        .mock("GET", "/v1/vendors/v1")
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"x","request_id":"r"}}"#)
        .create();
    let c = client(&server);
    let err = c
        .list_tenants(&ListTenantsParams::default())
        .expect_err("403");
    assert_eq!(err.api().map(|a| a.status), Some(403));
    let err = c.get_vendor("v1").expect_err("404");
    assert_eq!(err.api().map(|a| a.status), Some(404));
}

#[test]
fn a_portfolio_429_is_retried_after_a_short_retry_after_and_reports_its_scope_otherwise() {
    use hodeishield_api::portfolio::ListTenantsParams;
    let body = r#"{"error":{"code":"rate_limited","message":"x","request_id":"r","details":{"scope":"portfolio_key","limit":100,"window_seconds":60,"retry_after_seconds":1}}}"#;
    // Within the wait the client accepts: waited out, then served.
    let mut server = mockito::Server::new();
    let limited = server
        .mock("GET", "/v1/portfolio/tenants")
        .with_status(429)
        .with_header("retry-after", "1")
        .with_body(body)
        .expect(1)
        .create();
    let served = server
        .mock("GET", "/v1/portfolio/tenants")
        .with_body(EMPTY_PAGE)
        .expect(1)
        .create();
    client(&server)
        .list_tenants(&ListTenantsParams::default())
        .expect("served after the wait");
    limited.assert();
    served.assert();
    // Longer than the client accepts: one request, and the scope is in the error.
    let mut server = mockito::Server::new();
    let once = server
        .mock("GET", "/v1/portfolio/tenants")
        .with_status(429)
        .with_header("retry-after", "600")
        .with_body(body)
        .expect(1)
        .create();
    let err = client(&server)
        .list_tenants(&ListTenantsParams::default())
        .expect_err("too long to wait");
    once.assert();
    let api = err.api().expect("API error");
    assert_eq!(api.status, 429);
    assert_eq!(api.meta.retry_after, Some(600));
    let details = api
        .body
        .as_ref()
        .and_then(|b| b.details.as_ref())
        .expect("details");
    assert_eq!(details["scope"], "portfolio_key");
}

#[test]
fn a_portfolio_key_is_sent_whole_and_never_shown() {
    let server = mockito::Server::new();
    let c = tenant_client(&server, TENANT_A);
    let shown = format!("{c:?}");
    let secret = PORTFOLIO_KEY.rsplit('_').next().expect("secret part");
    assert!(
        !shown.contains(secret) && !shown.contains(PORTFOLIO_KEY),
        "{shown}"
    );
    let builder = Client::builder(
        server.url().parse().expect("url"),
        SecretString::from(PORTFOLIO_KEY),
    );
    let shown = format!("{builder:?}");
    assert!(!shown.contains(secret), "{shown}");
}

// Review follow-ups: the echo is checked on every operation, on every attempt, and only on success.

fn tenant_client_retrying(server: &mockito::Server, tenant: &str) -> Client {
    Client::builder(
        server.url().parse().expect("url"),
        SecretString::from(PORTFOLIO_KEY),
    )
    .tenant(tenant)
    .expect("a UUID")
    .transient_retries(2, Duration::from_millis(1))
    .rate_limit_retries(1, Duration::from_secs(5))
    .build()
    .expect("client")
}

#[test]
fn every_single_item_operation_checks_the_echo() {
    let mut server = mockito::Server::new();
    let any = server
        .mock("GET", mockito::Matcher::Any)
        .match_header("x-hs-tenant", TENANT_A)
        .with_header("x-hs-tenant", TENANT_B)
        .with_body("{}")
        .expect(7)
        .create();
    let c = tenant_client(&server, TENANT_A);
    fn refused<T>(r: Result<T, Error>) -> bool {
        matches!(r, Err(Error::TenantMismatch { .. }))
    }
    assert!(refused(c.get_vendor("v1")));
    assert!(refused(c.get_alert("a1")));
    assert!(refused(c.get_risk("r1")));
    assert!(refused(c.get_incident("i1")));
    assert!(refused(c.get_ai_system("s1")));
    assert!(refused(c.get_evidence("e1")));
    assert!(refused(c.get_framework_posture("nis2")));
    any.assert();
}

#[test]
fn an_answer_after_a_retry_is_checked_too() {
    // A 503 and then a 200 that confirms nothing, or another tenant: refused in both cases.
    for echo in [None, Some(TENANT_B)] {
        let mut server = mockito::Server::new();
        let unavailable = server
            .mock("GET", "/v1/vendors")
            .with_status(503)
            .expect(1)
            .create();
        let mut served = server.mock("GET", "/v1/vendors").with_body(EMPTY_PAGE);
        if let Some(echo) = echo {
            served = served.with_header("x-hs-tenant", echo);
        }
        let served = served.expect(1).create();
        let err = tenant_client_retrying(&server, TENANT_A)
            .list_vendors(&ListVendorsParams::default())
            .expect_err("unconfirmed answer after a retry");
        assert!(
            matches!(err, Error::TenantMismatch { .. }),
            "{echo:?}: {err:?}"
        );
        unavailable.assert();
        served.assert();
    }
    // The same after a 429 that is waited out.
    for echo in [None, Some(TENANT_B)] {
        let mut server = mockito::Server::new();
        let limited = server
            .mock("GET", "/v1/vendors")
            .with_status(429)
            .with_header("retry-after", "1")
            .expect(1)
            .create();
        let mut served = server.mock("GET", "/v1/vendors").with_body(EMPTY_PAGE);
        if let Some(echo) = echo {
            served = served.with_header("x-hs-tenant", echo);
        }
        let served = served.expect(1).create();
        let err = tenant_client_retrying(&server, TENANT_A)
            .list_vendors(&ListVendorsParams::default())
            .expect_err("unconfirmed answer after a wait");
        assert!(
            matches!(err, Error::TenantMismatch { .. }),
            "{echo:?}: {err:?}"
        );
        limited.assert();
        served.assert();
    }
    // A confirmed answer after a retry is served.
    let mut server = mockito::Server::new();
    server.mock("GET", "/v1/vendors").with_status(503).create();
    server
        .mock("GET", "/v1/vendors")
        .with_header("x-hs-tenant", TENANT_A)
        .with_body(EMPTY_PAGE)
        .create();
    tenant_client_retrying(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect("confirmed after a retry");
}

#[test]
fn a_redirect_on_a_scoped_client_is_an_error_and_the_target_gets_nothing() {
    let mut server = mockito::Server::new();
    let mut elsewhere = mockito::Server::new();
    let never = elsewhere
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create();
    server
        .mock("GET", "/v1/vendors")
        .match_header("x-hs-tenant", TENANT_A)
        .with_status(302)
        .with_header("location", &format!("{}/steal", elsewhere.url()))
        .with_header("x-hs-tenant", TENANT_A)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("redirect");
    assert_eq!(err.api().map(|a| a.status), Some(302), "{err:?}");
    never.assert();
}

#[test]
fn only_a_decodable_success_is_one_even_with_the_right_echo() {
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_status(204)
        .with_header("x-hs-tenant", TENANT_A)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("no body");
    assert!(matches!(err, Error::Decode { .. }), "{err:?}");

    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/vendors")
        .with_status(304)
        .with_header("x-hs-tenant", TENANT_A)
        .create();
    let err = tenant_client(&server, TENANT_A)
        .list_vendors(&ListVendorsParams::default())
        .expect_err("not modified is not data");
    assert_eq!(err.api().map(|a| a.status), Some(304), "{err:?}");
}

#[test]
fn the_listing_is_unscoped_by_its_operation_and_the_data_operations_are_scoped() {
    use hodeishield_api::v1::operations;
    let listing = operations::LIST_PORTFOLIO_TENANTS;
    assert_eq!(listing.method, "GET");
    assert_eq!(listing.path, "/v1/portfolio/tenants");
    assert_eq!(listing.scopes, ["portfolio:read"]);
    assert!(!listing.tenant_scoped);
    // `GET /v1/me` describes the credential itself: it needs no scope and refuses `X-HS-Tenant`.
    let me = operations::WHO_AM_I;
    assert_eq!(me.path, "/v1/me");
    assert!(me.scopes.is_empty());
    assert!(!me.tenant_scoped);
    let data: Vec<_> = operations::ALL
        .iter()
        .filter(|op| op.id != listing.id && op.id != me.id)
        .collect();
    assert!(data.len() >= 11);
    assert!(data.iter().all(|op| op.tenant_scoped));
}

#[test]
fn a_404_or_405_with_a_portfolio_code_is_the_apis_own_error() {
    use hodeishield_api::portfolio::ListTenantsParams;
    for (status, code) in [
        (404_usize, "TENANT_NOT_FOUND"),
        (405, "TENANT_SELECTOR_NOT_SUPPORTED"),
        (404, "TENANT_SOMETHING_NEW"),
    ] {
        let mut server = mockito::Server::new();
        server
            .mock("GET", "/v1/portfolio/tenants")
            .with_status(status)
            .with_body(format!(
                r#"{{"error":{{"code":"not_found","message":"x","request_id":"r","details":{{"code":"{code}"}}}}}}"#
            ))
            .create();
        let err = client(&server)
            .list_tenants(&ListTenantsParams::default())
            .expect_err("API error");
        assert_eq!(
            err.api().map(|a| a.status),
            Some(u16::try_from(status).expect("status")),
            "{status} {code}: {err:?}"
        );
    }
    // An unrelated code, or none, still means the route is not there.
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/portfolio/tenants")
        .with_status(404)
        .with_body(r#"{"error":{"code":"not_found","message":"x","request_id":"r","details":{"code":"SOMETHING_ELSE"}}}"#)
        .create();
    let err = client(&server)
        .list_tenants(&ListTenantsParams::default())
        .expect_err("no route");
    assert!(
        matches!(err, Error::PortfolioNotOffered { status: 404 }),
        "{err:?}"
    );
}

#[test]
fn a_report_download_returns_the_file_its_type_and_its_name() {
    use hodeishield_api::v1::{DownloadReportParams, Format};
    let mut server = mockito::Server::new();
    let file = b"%PDF-1.7\n\x00\xff binary".to_vec();
    let mock = server
        .mock("GET", "/v1/reports/r-1/download")
        .match_query(mockito::Matcher::UrlEncoded("format".into(), "pdf".into()))
        .match_header(
            "accept",
            "application/pdf, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, \
             application/json",
        )
        .with_header("content-type", "application/pdf")
        .with_header(
            "content-disposition",
            r#"attachment; filename="board-2026-09.pdf""#,
        )
        .with_body(file.clone())
        .expect(1)
        .create();
    let params = DownloadReportParams {
        format: Some(Format::Pdf),
        ..DownloadReportParams::default()
    };
    let download = client(&server)
        .download_report("r-1", &params)
        .expect("download");
    assert_eq!(download.bytes, file);
    assert_eq!(download.content_type.as_deref(), Some("application/pdf"));
    assert_eq!(download.file_name.as_deref(), Some("board-2026-09.pdf"));
    assert_eq!(download.meta.status, 200);
    mock.assert();
}

#[test]
fn a_report_that_is_not_ready_is_an_api_error_with_its_code() {
    use hodeishield_api::v1::DownloadReportParams;
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r-2/download")
        .with_status(409)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"error":{"code":"REPORT_NOT_READY","message":"The report is still being generated.","request_id":"req-1"}}"#,
        )
        .create();
    let err = client(&server)
        .download_report("r-2", &DownloadReportParams::default())
        .expect_err("not ready");
    let api = err.api().expect("api error");
    assert_eq!(api.status, 409);
    assert_eq!(api.code(), Some("REPORT_NOT_READY"));
    assert_eq!(api.operation, "downloadReport");
}

#[test]
fn the_body_of_an_error_is_read_with_the_normal_limit_not_the_download_one() {
    use hodeishield_api::v1::DownloadReportParams;
    let mut server = mockito::Server::new();
    server
        .mock("GET", "/v1/reports/r-3/download")
        .with_status(500)
        .with_body(vec![b'x'; 9 * 1024 * 1024])
        .create();
    let err = client(&server)
        .download_report("r-3", &DownloadReportParams::default())
        .expect_err("too large");
    assert!(matches!(err, hodeishield_api::Error::Body(_)), "{err:?}");
}

// The alert writes (`POST`), against a mock of the published contract.

const WRITE_ANSWER: &str = r#"{"data":{"id":"a1","status":"resolved","acknowledged_at":"2026-11-14T10:00:00Z","resolved_at":"2026-11-14T11:00:00Z","resolution_reason":"patched","updated_at":"2026-11-14T11:00:00Z"},"changed":true}"#;

#[test]
fn the_write_operations_are_posts_under_the_write_scope() {
    use hodeishield_api::v1::operations;
    for (operation, path) in [
        (operations::ACKNOWLEDGE_ALERT, "/v1/alerts/{id}/acknowledge"),
        (operations::RESOLVE_ALERT, "/v1/alerts/{id}/resolve"),
    ] {
        assert_eq!(operation.method, "POST");
        assert_eq!(operation.path, path);
        assert_eq!(operation.scopes, ["alerts:write"]);
        assert!(operation.tenant_scoped);
    }
    // Every other operation the client has reads.
    let writes: Vec<_> = operations::ALL
        .iter()
        .filter(|op| op.method != "GET")
        .map(|op| op.id)
        .collect();
    assert_eq!(
        writes,
        [
            "acknowledgeAlert",
            "resolveAlert",
            "transitionRisk",
            "approveActProposal",
            "rejectActProposal"
        ]
    );
}

#[test]
fn acknowledge_posts_an_empty_object_or_the_reason_and_decodes_the_answer() {
    let mut server = mockito::Server::new();
    let bare = server
        .mock("POST", "/v1/alerts/a1/acknowledge")
        .match_header("authorization", "Bearer hsk_example")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::JsonString("{}".into()))
        .with_body(WRITE_ANSWER)
        .expect(1)
        .create();
    let response = client(&server).acknowledge_alert("a1", None).expect("ok");
    assert!(response.data.changed);
    assert_eq!(response.data.data.id, "a1");
    assert_eq!(response.raw["changed"], true);
    assert_eq!(response.meta.status, 200);
    bare.assert();

    let with_reason = server
        .mock("POST", "/v1/alerts/a2/acknowledge")
        .match_body(mockito::Matcher::JsonString(r#"{"reason":"on it"}"#.into()))
        .with_body(WRITE_ANSWER)
        .expect(1)
        .create();
    client(&server)
        .acknowledge_alert("a2", Some("on it"))
        .expect("ok");
    with_reason.assert();
}

#[test]
fn resolve_posts_the_reason_and_encodes_the_id() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("POST", "/v1/alerts/a%2F1/resolve")
        .match_body(mockito::Matcher::JsonString(
            r#"{"reason":"patched \"now\""}"#.into(),
        ))
        .with_body(WRITE_ANSWER)
        .expect(1)
        .create();
    let response = client(&server)
        .resolve_alert("a/1", "patched \"now\"")
        .expect("ok");
    assert_eq!(response.data.data.status, "resolved");
    mock.assert();
    assert!(matches!(
        client(&server).resolve_alert("..", "x"),
        Err(Error::InvalidPathArgument(_))
    ));
}

#[test]
fn a_write_sends_the_tenant_selection_and_checks_the_echo() {
    let mut server = mockito::Server::new();
    let ok = server
        .mock("POST", "/v1/alerts/a1/acknowledge")
        .match_header("x-hs-tenant", TENANT_A)
        .with_header("x-hs-tenant", TENANT_A)
        .with_body(WRITE_ANSWER)
        .expect(1)
        .create();
    tenant_client(&server, TENANT_A)
        .acknowledge_alert("a1", None)
        .expect("ok");
    ok.assert();

    let mut other = mockito::Server::new();
    other
        .mock("POST", "/v1/alerts/a1/acknowledge")
        .with_header("x-hs-tenant", TENANT_B)
        .with_body(WRITE_ANSWER)
        .create();
    assert!(matches!(
        tenant_client(&other, TENANT_A).acknowledge_alert("a1", None),
        Err(Error::TenantMismatch { .. })
    ));
}

#[test]
fn a_write_is_not_sent_again_after_a_gateway_error_or_a_timeout() {
    let mut server = mockito::Server::new();
    let gateway = server
        .mock("POST", "/v1/alerts/a1/resolve")
        .with_status(503)
        .with_body("busy")
        .expect(1)
        .create();
    let err = client_with_transient_retries(&server, 2)
        .resolve_alert("a1", "done")
        .expect_err("503");
    assert_eq!(err.api().map(|a| a.status), Some(503));
    gateway.assert();

    // The same answer to a read is retried.
    let read = server
        .mock("GET", "/v1/alerts/a1")
        .with_status(503)
        .with_body("busy")
        .expect(3)
        .create();
    let _ = client_with_transient_retries(&server, 2).get_alert("a1");
    read.assert();

    let slow = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", slow.local_addr().expect("addr"));
    let accepted = std::thread::spawn(move || {
        let mut held = Vec::new();
        // Hold every connection open without answering; count them.
        let deadline = Instant::now() + Duration::from_secs(2);
        slow.set_nonblocking(true).expect("nonblocking");
        while Instant::now() < deadline {
            if let Ok((stream, _)) = slow.accept() {
                held.push(stream);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        held.len()
    });
    let patient = Client::builder(url.parse().expect("url"), SecretString::from("hsk_example"))
        .timeout(Duration::from_millis(300))
        .transient_retries(2, Duration::from_millis(1))
        .build()
        .expect("client");
    let err = patient.resolve_alert("a1", "done").expect_err("timeout");
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    assert_eq!(accepted.join().expect("thread"), 1, "sent once, not again");
}

#[test]
fn a_write_refused_for_the_rate_limit_is_sent_again_after_retry_after() {
    let mut server = mockito::Server::new();
    let limited = server
        .mock("POST", "/v1/alerts/a1/acknowledge")
        .with_status(429)
        .with_header("retry-after", "1")
        .with_body(r#"{"error":{"code":"rate_limited","message":"slow","request_id":"r","details":{"scope":"write_key"}}}"#)
        .expect(2)
        .create();
    let err = client(&server)
        .acknowledge_alert("a1", None)
        .expect_err("still limited");
    let api = err.api().expect("api error");
    assert_eq!(api.status, 429);
    assert_eq!(
        api.body
            .as_ref()
            .and_then(|b| b.details.as_ref())
            .and_then(|d| d.get("scope"))
            .and_then(|v| v.as_str()),
        Some("write_key")
    );
    limited.assert();
}

#[test]
fn the_write_refusals_the_contract_lists_arrive_as_api_errors() {
    for (status, code) in [
        (403_usize, "ROLE_NOT_PERMITTED"),
        (403, "WRITE_ACTOR_UNRESOLVED"),
        (403, "LICENCE_INACTIVE"),
        (409, "ALERT_RESOLVED"),
        (409, "ALERT_STATE_CHANGED"),
    ] {
        let mut server = mockito::Server::new();
        server
            .mock("POST", "/v1/alerts/a1/resolve")
            .with_status(status)
            .with_body(format!(
                r#"{{"error":{{"code":"x","message":"m","request_id":"r","details":{{"code":"{code}"}}}}}}"#
            ))
            .create();
        let err = client(&server)
            .resolve_alert("a1", "done")
            .expect_err("refused");
        let api = err.api().expect("api error");
        assert_eq!(api.operation, "resolveAlert");
        assert_eq!(api.required_scopes, ["alerts:write"]);
        assert_eq!(
            api.body
                .as_ref()
                .and_then(|b| b.details.as_ref())
                .and_then(|d| d.get("code"))
                .and_then(|v| v.as_str()),
            Some(code)
        );
    }
}

// Moving a risk and deciding proposals, against a mock of the published contract.

const RISK_ANSWER: &str = r#"{"data":{"id":"r1","status":"assessed","updated_at":"2026-11-18T10:00:00Z"},"changed":true}"#;
const DECISION_ANSWER: &str = r#"{"data":{"id":"p1","status":"approved","approval_expires_at":"2026-11-18T10:15:00Z","ledger_entry_id":"l1"}}"#;
const INBOX_ANSWER: &str = r#"{"data":[{"id":"p1","class":"create_task","module":null,"payload_kind":"task","payload":{"title":"Rotate keys","extra":{"deep":[1,2]}},"rationale":"Because.","confidence":0.5,"proposed_via":"agent","proposed_by_you":true,"created_at":"2026-11-18T09:00:00Z","expires_at":"2026-11-25T09:00:00Z","added_later":1}],"pagination":{"page":1,"per_page":50,"total":1,"total_pages":1}}"#;

#[test]
fn the_risk_and_decision_operations_have_the_scopes_the_document_gives() {
    use hodeishield_api::v1::operations;
    for (operation, method, path, scope) in [
        (
            operations::TRANSITION_RISK,
            "POST",
            "/v1/risks/{id}/transition",
            "risks:write",
        ),
        (
            operations::LIST_PENDING_ACT_PROPOSALS,
            "GET",
            "/v1/act/inbox",
            "act:decide",
        ),
        (
            operations::APPROVE_ACT_PROPOSAL,
            "POST",
            "/v1/act/proposals/{id}/approve",
            "act:decide",
        ),
        (
            operations::REJECT_ACT_PROPOSAL,
            "POST",
            "/v1/act/proposals/{id}/reject",
            "act:decide",
        ),
    ] {
        assert_eq!(operation.method, method, "{}", operation.id);
        assert_eq!(operation.path, path);
        assert_eq!(operation.scopes, [scope]);
    }
    // The proposal-creating write of the document is not in this client.
    assert!(
        operations::ALL
            .iter()
            .all(|op| op.id != "createActProposal")
    );
}

#[test]
fn transition_risk_posts_the_status_and_the_optional_note() {
    let mut server = mockito::Server::new();
    let bare = server
        .mock("POST", "/v1/risks/r1/transition")
        .match_header("authorization", "Bearer hsk_example")
        .match_header("content-type", "application/json")
        .match_body(mockito::Matcher::JsonString(
            r#"{"to_status":"assessed"}"#.into(),
        ))
        .with_body(RISK_ANSWER)
        .expect(1)
        .create();
    let response = client(&server)
        .transition_risk("r1", "assessed", None)
        .expect("ok");
    assert!(response.data.changed);
    assert_eq!(response.data.data.status, "assessed");
    bare.assert();

    let noted = server
        .mock("POST", "/v1/risks/r2/transition")
        .match_body(mockito::Matcher::JsonString(
            r#"{"to_status":"closed","note":"mitigated"}"#.into(),
        ))
        .with_body(RISK_ANSWER)
        .expect(1)
        .create();
    client(&server)
        .transition_risk("r2", "closed", Some("mitigated"))
        .expect("ok");
    noted.assert();
}

#[test]
fn the_inbox_is_a_get_with_the_declared_query_and_decodes_every_field() {
    let mut server = mockito::Server::new();
    let mock = server
        .mock("GET", "/v1/act/inbox")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("class".into(), "create_task".into()),
            mockito::Matcher::UrlEncoded("sort".into(), "created_at".into()),
            mockito::Matcher::UrlEncoded("per_page".into(), "10".into()),
        ]))
        .with_body(INBOX_ANSWER)
        .expect(1)
        .create();
    let params = hodeishield_api::v1::ListPendingActProposalsParams {
        per_page: Some(10),
        class: Some(hodeishield_api::v1::Class::CreateTask),
        sort: Some(hodeishield_api::v1::PendingActProposalSort::CreatedAt),
        ..Default::default()
    };
    let response = client(&server)
        .list_pending_act_proposals(&params)
        .expect("ok");
    let proposal = &response.data.data[0];
    assert_eq!(proposal.id, "p1");
    assert!(proposal.proposed_by_you);
    assert_eq!(proposal.module, None);
    assert_eq!(proposal.payload["extra"]["deep"][1], 2);
    assert_eq!(response.data.pagination.total, 1);
    mock.assert();
}

#[test]
fn approve_and_reject_post_the_reason_and_decode_the_answer() {
    let mut server = mockito::Server::new();
    let approve = server
        .mock("POST", "/v1/act/proposals/p1/approve")
        .match_body(mockito::Matcher::JsonString(
            r#"{"reason":"checked the payload"}"#.into(),
        ))
        .with_body(DECISION_ANSWER)
        .expect(1)
        .create();
    let response = client(&server)
        .approve_act_proposal("p1", "checked the payload")
        .expect("ok");
    assert_eq!(response.data.data.status, "approved");
    assert_eq!(
        response.data.data.approval_expires_at.as_deref(),
        Some("2026-11-18T10:15:00Z")
    );
    approve.assert();

    let reject = server
        .mock("POST", "/v1/act/proposals/p2/reject")
        .match_body(mockito::Matcher::JsonString(
            r#"{"reason":"not needed"}"#.into(),
        ))
        .with_body(
            r#"{"data":{"id":"p2","status":"rejected","approval_expires_at":null,"ledger_entry_id":"l2"}}"#,
        )
        .expect(1)
        .create();
    let response = client(&server)
        .reject_act_proposal("p2", "not needed")
        .expect("ok");
    assert_eq!(response.data.data.approval_expires_at, None);
    reject.assert();
    assert!(matches!(
        client(&server).approve_act_proposal("..", "x"),
        Err(Error::InvalidPathArgument(_))
    ));
}

#[test]
fn a_decision_and_a_risk_move_are_not_sent_again_after_a_gateway_error() {
    let mut server = mockito::Server::new();
    let approve = server
        .mock("POST", "/v1/act/proposals/p1/approve")
        .with_status(503)
        .with_body("busy")
        .expect(1)
        .create();
    let err = client_with_transient_retries(&server, 2)
        .approve_act_proposal("p1", "ok")
        .expect_err("503");
    assert_eq!(err.api().map(|a| a.status), Some(503));
    approve.assert();

    let transition = server
        .mock("POST", "/v1/risks/r1/transition")
        .with_status(502)
        .with_body("bad gateway")
        .expect(1)
        .create();
    let err = client_with_transient_retries(&server, 2)
        .transition_risk("r1", "assessed", None)
        .expect_err("502");
    assert_eq!(err.api().map(|a| a.status), Some(502));
    transition.assert();
}

#[test]
fn the_refusals_of_the_new_operations_arrive_as_api_errors_with_their_code() {
    for (status, code, call) in [
        (403_usize, "STEP_UP_REQUIRED", "approve"),
        (403, "CREDENTIAL_NOT_ALLOWED", "approve"),
        (403, "OWN_PROPOSAL", "approve"),
        (403, "ROLE_NOT_PERMITTED", "reject"),
        (409, "PROPOSAL_EXPIRED", "approve"),
        (409, "ALREADY_DECIDED", "reject"),
        (409, "ACTIONS_PAUSED", "approve"),
        (409, "NOT_DECIDABLE", "approve"),
        (409, "TRANSITION_NOT_ALLOWED", "risk"),
        (403, "WRITE_ACTOR_UNRESOLVED", "risk"),
    ] {
        let mut server = mockito::Server::new();
        let path = match call {
            "approve" => "/v1/act/proposals/p1/approve",
            "reject" => "/v1/act/proposals/p1/reject",
            _ => "/v1/risks/p1/transition",
        };
        server
            .mock("POST", path)
            .with_status(status)
            .with_body(format!(
                r#"{{"error":{{"code":"x","message":"m","request_id":"r","details":{{"code":"{code}"}}}}}}"#
            ))
            .create();
        let c = client(&server);
        let err = match call {
            "approve" => c.approve_act_proposal("p1", "why").expect_err("refused"),
            "reject" => c.reject_act_proposal("p1", "why").expect_err("refused"),
            _ => c
                .transition_risk("p1", "closed", None)
                .expect_err("refused"),
        };
        let api = err.api().expect("api error");
        assert_eq!(api.status as usize, status);
        assert_eq!(
            api.body
                .as_ref()
                .and_then(|b| b.details.as_ref())
                .and_then(|d| d.get("code"))
                .and_then(|v| v.as_str()),
            Some(code)
        );
    }
}
