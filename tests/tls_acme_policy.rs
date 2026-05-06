use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use stellar_gateway::acme::{
    Http01ChallengeStore, Http01Decision, Http01Request, Http01RequestPolicy, http01_body_for_path,
};
use stellar_gateway::routing::{
    IssuanceAuthorization, RequestAuthorization, RouteAuthorizationPolicy, RouteMatch,
};
use stellar_gateway::tls::{AskClient, AskDecision, AskDenyReason};

fn start_ask_server(response: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ask server");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(response.as_bytes());
    });
    port
}

fn start_ask_status_server(status_line: &'static str) -> u16 {
    let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    start_ask_server(Box::leak(resp.into_boxed_str()))
}

fn unused_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    listener.local_addr().expect("local addr").port()
}

fn start_stalling_ask_server(stall_for: Duration) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalling ask server");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept");
        thread::sleep(stall_for);
    });
    (port, handle)
}

#[test]
fn ask_client_should_allow_on_200() {
    let port = start_ask_status_server("HTTP/1.1 200 OK");
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{port}/ask").parse().unwrap(),
        Duration::from_millis(200),
    )
    .expect("http ask URL should be supported");
    let decision = client.authorize("demo.page.hdd.ink");
    assert!(decision.is_allow());
}

#[test]
fn ask_client_should_deny_non_2xx_with_denied_reason() {
    let port = start_ask_status_server("HTTP/1.1 403 Forbidden");
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{port}/ask").parse().unwrap(),
        Duration::from_millis(200),
    )
    .expect("http ask URL should be supported");
    let decision = client.authorize("demo.page.hdd.ink");
    assert_eq!(decision, AskDecision::Deny(AskDenyReason::Denied));
}

#[test]
fn ask_client_should_deny_malformed_response_with_malformed_response_reason() {
    let port = start_ask_server("not an http response\r\n\r\n");
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{port}/ask").parse().unwrap(),
        Duration::from_millis(200),
    )
    .expect("http ask URL should be supported");
    let decision = client.authorize("demo.page.hdd.ink");
    assert_eq!(
        decision,
        AskDecision::Deny(AskDenyReason::MalformedResponse)
    );
}

#[test]
fn ask_client_should_deny_network_failure_with_network_failure_reason() {
    let port = unused_local_port();
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{port}/ask").parse().unwrap(),
        Duration::from_millis(50),
    )
    .expect("http ask URL should be supported");
    let decision = client.authorize("demo.page.hdd.ink");
    assert_eq!(decision, AskDecision::Deny(AskDenyReason::NetworkFailure));
}

#[test]
fn ask_client_should_deny_stalled_response_with_timeout_reason() {
    let (port, handle) = start_stalling_ask_server(Duration::from_millis(150));
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{port}/ask").parse().unwrap(),
        Duration::from_millis(20),
    )
    .expect("http ask URL should be supported");
    let decision = client.authorize("demo.page.hdd.ink");
    handle
        .join()
        .expect("stalling ask server thread should finish");
    assert_eq!(decision, AskDecision::Deny(AskDenyReason::Timeout));
}

#[test]
fn ask_deny_reason_should_expose_stable_log_reason_class_string() {
    assert_eq!(AskDenyReason::Timeout.as_str(), "timeout");
}

#[test]
fn request_authorization_should_require_route_match_even_when_ask_allows() {
    let policy = RouteAuthorizationPolicy::new("page.hdd.ink");
    let decision = policy.authorize_request(
        "unrouted.example.com",
        IssuanceAuthorization::AllowedByAsk,
        RouteMatch::NoMatch,
    );
    assert_eq!(decision, RequestAuthorization::DenyNotRouted);
}

#[test]
fn request_authorization_should_allow_gatewayfile_route_match_even_when_ask_denies() {
    let policy = RouteAuthorizationPolicy::new("page.hdd.ink");
    let decision = policy.authorize_request(
        "demo.page.hdd.ink",
        IssuanceAuthorization::DeniedByAsk,
        RouteMatch::Matched,
    );
    assert_eq!(decision, RequestAuthorization::AllowRouted);
}

#[test]
fn http01_should_return_expected_body_when_token_active() {
    let store = Http01ChallengeStore::default();
    store.set_for_host("demo.page.hdd.ink", "unit-token", "keyauth");
    let body = http01_body_for_path("/.well-known/acme-challenge/unit-token", &store);
    assert_eq!(body.as_deref(), Some("keyauth"));
}

#[test]
fn http01_inactive_token_should_continue_to_route_handling() {
    let policy = Http01RequestPolicy::new(Http01ChallengeStore::default());
    let decision = policy.authorize(
        Http01Request::new("/.well-known/acme-challenge/inactive", "demo.page.hdd.ink"),
        RouteMatch::Matched,
    );
    assert_eq!(decision, Http01Decision::RouteNormally);
}

#[test]
fn http01_active_token_should_respond_with_body() {
    let store = Http01ChallengeStore::default();
    store.set_for_host("demo.page.hdd.ink", "active", "body");
    let policy = Http01RequestPolicy::new(store);
    let decision = policy.authorize(
        Http01Request::new("/.well-known/acme-challenge/active", "demo.page.hdd.ink"),
        RouteMatch::NoMatch,
    );
    assert_eq!(decision, Http01Decision::RespondWithBody("body".to_owned()));
}

#[test]
fn http01_any_host_challenge_should_not_authorize_arbitrary_host() {
    let store = Http01ChallengeStore::default();
    store.set("shared-token", "keyauth");
    let policy = Http01RequestPolicy::new(store);
    let decision = policy.authorize(
        Http01Request::new(
            "/.well-known/acme-challenge/shared-token",
            "attacker.example.com",
        ),
        RouteMatch::NoMatch,
    );
    assert_eq!(decision, Http01Decision::RouteNormally);
}
