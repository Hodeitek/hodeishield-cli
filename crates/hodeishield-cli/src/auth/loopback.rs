// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! The one-shot loopback listener that receives the browser's redirect (RFC 8252 §7.3).
//!
//! It listens on `127.0.0.1` on a port the operating system picks, answers exactly one valid
//! callback, and stops. Requests for any other path get a 404 and are otherwise ignored, so a stray
//! `favicon.ico` does not end the sign-in.

use crate::failure::{Failure, Kind, Result};
use secrecy::SecretString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const CALLBACK_PATH: &str = "/callback";

/// The most a single read may wait for the next bytes of a request.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// The most a single connection may take to deliver its whole request head. The listener serves one
/// connection at a time, so this bounds how long a stalled or trickling client can hold it.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);

/// How long the listener waits on one connection. Injectable so tests need not sleep for seconds.
#[derive(Debug, Clone, Copy)]
struct Limits {
    read: Duration,
    connection: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            read: READ_TIMEOUT,
            connection: CONNECTION_DEADLINE,
        }
    }
}

#[derive(Debug)]
pub struct Loopback {
    listener: TcpListener,
    redirect_uri: String,
    limits: Limits,
}

/// What the browser brought back.
#[derive(Debug)]
pub struct Callback {
    pub code: SecretString,
}

impl Loopback {
    pub fn bind() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
            Failure::general(format!(
                "Cannot listen on 127.0.0.1 for the sign-in redirect: {e}."
            ))
            .hint("Use `hodeishield login --device` instead.")
        })?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            redirect_uri: format!("http://127.0.0.1:{port}{CALLBACK_PATH}"),
            limits: Limits::default(),
        })
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Waits for the redirect. `state` must come back unchanged; `issuer`, when the server sends
    /// `iss` (RFC 9207), must be the one we started with, and `iss` is mandatory when the server's
    /// metadata says it sends it.
    pub fn wait(
        &self,
        state: &str,
        issuer: &str,
        require_iss: bool,
        timeout: Duration,
    ) -> Result<Callback> {
        let deadline = Instant::now() + timeout;
        loop {
            // Checked before every accept, not only when idle: a client that keeps connecting keeps
            // the queue full, and must not be able to postpone the timeout.
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(timed_out());
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let request = Request {
                        state,
                        issuer,
                        require_iss,
                        limits: self.limits,
                        deadline,
                    };
                    if let Some(result) = handle(stream, &request) {
                        return result;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100).min(left));
                }
                // A client that reset before we accepted it (reported on macOS, the BSDs and
                // Windows) is not the end of the sign-in.
                Err(e) if is_aborted_connection(e.kind()) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

fn timed_out() -> Failure {
    Failure::new(
        Kind::NotAuthenticated,
        "Timed out waiting for the browser to finish signing in.",
    )
    .hint("Run `hodeishield login` again, or `hodeishield login --device`.")
}

fn is_aborted_connection(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
    )
}

/// What `handle` checks a connection against.
struct Request<'a> {
    state: &'a str,
    issuer: &'a str,
    require_iss: bool,
    limits: Limits,
    /// When the whole sign-in gives up; no connection may outlive it.
    deadline: Instant,
}

/// `None`: not the callback, keep waiting. `Some`: the sign-in ended, one way or another.
fn handle(mut stream: TcpStream, request: &Request<'_>) -> Option<Result<Callback>> {
    let Request {
        state,
        issuer,
        require_iss,
        ..
    } = *request;
    let _ = stream.set_nonblocking(false);
    // A client that never reads the answer must not hold the listener either.
    let _ = stream.set_write_timeout(Some(request.limits.read));
    let connection_deadline = Instant::now() + request.limits.connection;
    let target = read_request_target(
        &mut stream,
        request.limits.read,
        connection_deadline.min(request.deadline),
    )?;
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    if path != CALLBACK_PATH {
        respond(&mut stream, "404 Not Found", "Not found.");
        return None;
    }
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if get("state") != Some(state) {
        // Not our sign-in: an old tab, another page probing local ports, or a forged request.
        // Refuse it and keep waiting, so that it cannot cancel the real one either.
        respond(
            &mut stream,
            "400 Bad Request",
            "This sign-in response does not match the one the CLI started. You can close this tab and return to the terminal.",
        );
        return None;
    }
    if require_iss && get("iss").is_none() {
        respond(
            &mut stream,
            "400 Bad Request",
            "Missing issuer. You can close this tab and return to the terminal.",
        );
        return Some(Err(Failure::new(
            Kind::NotAuthenticated,
            "The sign-in response did not say which server issued it, and the app promises it does.",
        )));
    }
    if let Some(iss) = get("iss")
        && iss.trim_end_matches('/') != issuer.trim_end_matches('/')
    {
        respond(
            &mut stream,
            "400 Bad Request",
            "Unexpected issuer. You can close this tab and return to the terminal.",
        );
        return Some(Err(Failure::new(
            Kind::NotAuthenticated,
            format!("The sign-in response came from issuer {iss}, not {issuer}."),
        )));
    }
    if let Some(error) = get("error") {
        let detail = get("error_description").map_or_else(String::new, |d| format!(" ({d})"));
        respond(
            &mut stream,
            "200 OK",
            "Sign-in did not complete. You can close this tab and return to the terminal.",
        );
        return Some(Err(Failure::new(
            Kind::NotAuthenticated,
            if error == "access_denied" {
                "Sign-in was denied in the browser.".to_owned()
            } else {
                format!("Sign-in failed: {error}{detail}.")
            },
        )));
    }
    let Some(code) = get("code").filter(|c| !c.is_empty()) else {
        respond(
            &mut stream,
            "400 Bad Request",
            "No authorization code. You can close this tab and return to the terminal.",
        );
        return Some(Err(Failure::new(
            Kind::NotAuthenticated,
            "The sign-in response carried no authorization code.",
        )));
    };
    respond(
        &mut stream,
        "200 OK",
        "Signed in to HodeiShield. You can close this tab and return to the terminal.",
    );
    Some(Ok(Callback {
        code: SecretString::from(code.to_owned()),
    }))
}

/// The request target of a `GET` request line, or `None` for anything else.
///
/// Every read waits for at most `read_timeout` and never past `deadline`, so a client that sends a
/// byte now and then cannot hold the connection beyond it.
fn read_request_target(
    stream: &mut TcpStream,
    read_timeout: Duration,
    deadline: Instant,
) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") && buffer.len() < 16 * 1024 {
        let left = deadline.saturating_duration_since(Instant::now());
        let wait = read_timeout.min(left);
        // A zero timeout is an error for the socket; out of time means stop reading.
        if wait.is_zero() || stream.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) => Some(target.to_owned()),
        _ => None,
    }
}

fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>HodeiShield CLI</title>\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>\
         <body style=\"font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:#1a1a1a\">\
         <h1 style=\"font-size:1.1rem;margin:0 0 0.5rem\">HodeiShield CLI</h1>\
         <p style=\"margin:0\">{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn hit(uri: &str, path_and_query: &str) -> String {
        let addr = uri
            .trim_start_matches("http://")
            .split('/')
            .next()
            .expect("host")
            .to_owned();
        let mut stream = TcpStream::connect(addr).expect("connect");
        write!(stream, "GET {path_and_query} HTTP/1.1\r\nHost: x\r\n\r\n").expect("write");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
    }

    fn run(requests: Vec<String>) -> (Result<Callback>, Vec<String>) {
        run_with(requests, false)
    }

    fn run_with(requests: Vec<String>, require_iss: bool) -> (Result<Callback>, Vec<String>) {
        let loopback = Loopback::bind().expect("bind");
        let uri = loopback.redirect_uri().to_owned();
        assert!(uri.starts_with("http://127.0.0.1:") && uri.ends_with("/callback"));
        let client =
            std::thread::spawn(move || requests.iter().map(|r| hit(&uri, r)).collect::<Vec<_>>());
        let result = loopback.wait(
            "expected-state",
            "https://app.example.test",
            require_iss,
            Duration::from_secs(10),
        );
        (result, client.join().expect("client"))
    }

    #[test]
    fn accepts_the_callback_after_ignoring_other_paths() {
        let (result, answers) = run(vec![
            "/favicon.ico".to_owned(),
            "/callback?code=abc&state=expected-state&iss=https%3A%2F%2Fapp.example.test".to_owned(),
        ]);
        assert!(answers[0].starts_with("HTTP/1.1 404"));
        assert!(answers[1].starts_with("HTTP/1.1 200"));
        assert_eq!(result.expect("code").code.expose_secret(), "abc");
    }

    #[test]
    fn a_foreign_state_is_refused_without_ending_the_sign_in() {
        let (result, answers) = run(vec![
            "/callback?code=forged&state=other".to_owned(),
            "/callback?code=abc&state=expected-state".to_owned(),
        ]);
        assert!(answers[0].starts_with("HTTP/1.1 400"));
        assert!(answers[1].starts_with("HTTP/1.1 200"));
        assert_eq!(result.expect("real callback").code.expose_secret(), "abc");
    }

    #[test]
    fn refuses_another_issuer() {
        let (result, _) = run(vec![
            "/callback?code=abc&state=expected-state&iss=https%3A%2F%2Fevil.example.test"
                .to_owned(),
        ]);
        assert!(
            result
                .expect_err("iss")
                .message
                .contains("evil.example.test")
        );
    }

    #[test]
    fn requires_iss_when_the_app_promises_it() {
        let (result, _) = run_with(
            vec!["/callback?code=abc&state=expected-state".to_owned()],
            true,
        );
        assert!(result.expect_err("no iss").message.contains("did not say"));
    }

    #[test]
    fn reports_a_denial() {
        let (result, _) = run(vec![
            "/callback?error=access_denied&state=expected-state".to_owned(),
        ]);
        assert!(result.expect_err("denied").message.contains("denied"));
    }

    /// Connects and sends one byte every `pause`, `count` times, stopping when the server hangs up.
    fn trickle(uri: &str, pause: Duration, count: u32) -> std::thread::JoinHandle<()> {
        let addr = uri
            .trim_start_matches("http://")
            .split('/')
            .next()
            .expect("host")
            .to_owned();
        let mut stream = TcpStream::connect(addr).expect("connect");
        std::thread::spawn(move || {
            for _ in 0..count {
                if stream.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(pause);
            }
        })
    }

    #[test]
    fn an_aborted_connection_does_not_end_the_sign_in() {
        use std::io::ErrorKind::*;
        assert!(is_aborted_connection(ConnectionAborted));
        assert!(is_aborted_connection(ConnectionReset));
        assert!(!is_aborted_connection(WouldBlock));
        assert!(!is_aborted_connection(PermissionDenied));
    }

    #[test]
    fn the_overall_timeout_holds_while_clients_keep_connecting() {
        let loopback = Loopback::bind().expect("bind");
        let uri = loopback.redirect_uri().to_owned();
        let addr = uri
            .trim_start_matches("http://")
            .split('/')
            .next()
            .expect("host")
            .to_owned();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let churn = std::thread::spawn(move || {
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                // Connect and close at once, so there is always something waiting to be accepted.
                drop(TcpStream::connect(&addr));
            }
        });
        let started = Instant::now();
        let result = loopback.wait(
            "expected-state",
            "https://app.example.test",
            false,
            Duration::from_millis(400),
        );
        let elapsed = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        churn.join().expect("churn");
        assert!(
            result.expect_err("timeout").message.contains("Timed out"),
            "timed out"
        );
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }

    fn quick(read_ms: u64, connection_ms: u64) -> Limits {
        Limits {
            read: Duration::from_millis(read_ms),
            connection: Duration::from_millis(connection_ms),
        }
    }

    #[test]
    fn a_trickling_client_is_cut_off_and_the_real_callback_still_gets_in() {
        let mut loopback = Loopback::bind().expect("bind");
        // Each byte arrives well inside the read timeout, so only the connection deadline stops it.
        loopback.limits = quick(1_000, 300);
        let uri = loopback.redirect_uri().to_owned();
        let slow = trickle(&uri, Duration::from_millis(50), 100);
        let started = Instant::now();
        let real = {
            let uri = uri.clone();
            std::thread::spawn(move || hit(&uri, "/callback?code=abc&state=expected-state"))
        };
        let result = loopback.wait(
            "expected-state",
            "https://app.example.test",
            false,
            Duration::from_secs(10),
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.expect("real callback").code.expose_secret(), "abc");
        assert!(real.join().expect("client").starts_with("HTTP/1.1 200"));
        slow.join().expect("trickler");
    }

    #[test]
    fn the_overall_timeout_holds_while_a_trickling_client_is_connected() {
        let mut loopback = Loopback::bind().expect("bind");
        loopback.limits = quick(1_000, 5_000);
        let uri = loopback.redirect_uri().to_owned();
        let slow = trickle(&uri, Duration::from_millis(50), 100);
        let started = Instant::now();
        let result = loopback.wait(
            "expected-state",
            "https://app.example.test",
            false,
            Duration::from_millis(400),
        );
        let elapsed = started.elapsed();
        assert!(
            result.expect_err("timeout").message.contains("Timed out"),
            "timed out"
        );
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        slow.join().expect("trickler");
    }
}
