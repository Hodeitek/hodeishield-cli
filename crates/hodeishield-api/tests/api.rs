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
    // Bind to port 0 to get an ephemeral port, then drop the listener to free it.
    // The next connection attempt to that port will be refused.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let url = format!("http://127.0.0.1:{port}");
    let retry_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&retry_count);

    let result = Client::builder(url.parse().expect("url"), SecretString::from("hsk_example"))
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
