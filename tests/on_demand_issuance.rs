use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use stellar_gateway::acme::Http01ChallengeStore;
use stellar_gateway::acme_issuer::AcmeIssuer;
use stellar_gateway::cert_cache::{CertificateCacheEntry, CertificateMaterial};
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::reload::GatewayRuntimeState;

fn gatewayfile(cache_dir: &std::path::Path, ask_port: u16) -> String {
    format!(
        r#"
listeners:
  http:
    bind: "127.0.0.1:8080"
  https:
    bind: "127.0.0.1:8443"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

tls:
  ask_url: "http://127.0.0.1:{ask_port}/ask"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: true

cert_cache:
  dir: "{}"

reload:
  enabled: true

logging:
  level: "info"
"#,
        cache_dir.display()
    )
}

fn caddyfile_gatewayfile(cache_dir: &std::path::Path, ask_port: u16) -> String {
    format!(
        r#"listeners:
  http:
    bind: "127.0.0.1:8080"
  https:
    bind: "127.0.0.1:8443"

routes:
  apex:
    host: "hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false
  wildcard:
    suffix: "hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

tls:
  ask_url: "http://127.0.0.1:{ask_port}/ask"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: true

cert_cache:
  dir: "{}"

reload:
  enabled: true

logging:
  level: "info"
"#,
        cache_dir.display()
    )
}

fn start_ask_server(status_line: &'static str, max_requests: usize) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ask server");
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_thread = Arc::clone(&calls);
    std::thread::spawn(move || {
        for _ in 0..max_requests {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            calls_thread.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, calls)
}

#[derive(Debug)]
struct FakeIssuer {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl AcmeIssuer for FakeIssuer {
    async fn issue_certificate(
        &self,
        _config: &GatewayConfig,
        hostname: &str,
        _store: &Http01ChallengeStore,
    ) -> stellar_gateway::error::Result<CertificateCacheEntry> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let certificate = rcgen::generate_simple_self_signed(vec![hostname.to_owned()]).unwrap();
        Ok(CertificateCacheEntry::new(
            hostname,
            CertificateMaterial::new(
                certificate.cert.pem(),
                certificate.signing_key.serialize_pem(),
            ),
            SystemTime::now() + Duration::from_secs(3600),
        ))
    }
}

#[tokio::test]
async fn runtime_should_issue_and_cache_certificate_when_ask_allows() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 200 OK", 2);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state
        .certificate_for_sni("demo.page.hdd.ink")
        .await
        .expect("issued certificate material");

    assert!(
        material.certificate_pem().contains("BEGIN CERTIFICATE")
            && issuer_calls.load(Ordering::SeqCst) == 1
            && ask_calls.load(Ordering::SeqCst) == 1
            && state.certificate_for("demo.page.hdd.ink").is_some()
    );
}

#[tokio::test]
async fn runtime_should_issue_apex_certificate_when_exact_route_allows() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 200 OK", 2);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        caddyfile_gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state
        .certificate_for_sni("hdd.ink")
        .await
        .expect("issued apex certificate material");

    assert!(
        material.certificate_pem().contains("BEGIN CERTIFICATE")
            && issuer_calls.load(Ordering::SeqCst) == 1
            && ask_calls.load(Ordering::SeqCst) == 1
            && state.certificate_for("hdd.ink").is_some()
    );
}

#[tokio::test]
async fn runtime_should_not_call_ask_or_issuer_for_legacy_wildcard_apex_sni() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 200 OK", 1);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state.certificate_for_sni("page.hdd.ink").await;

    assert!(
        material.is_none()
            && issuer_calls.load(Ordering::SeqCst) == 0
            && ask_calls.load(Ordering::SeqCst) == 0
    );
}

#[tokio::test]
async fn runtime_should_issue_wildcard_certificate_when_caddyfile_route_allows() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 200 OK", 2);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        caddyfile_gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state
        .certificate_for_sni("zhirang.hdd.ink")
        .await
        .expect("issued wildcard certificate material");

    assert!(
        material.certificate_pem().contains("BEGIN CERTIFICATE")
            && issuer_calls.load(Ordering::SeqCst) == 1
            && ask_calls.load(Ordering::SeqCst) == 1
            && state.certificate_for("zhirang.hdd.ink").is_some()
    );
}

#[tokio::test]
async fn runtime_should_not_call_ask_or_issuer_for_non_wildcard_sni() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 200 OK", 1);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state.certificate_for_sni("attacker.example.com").await;

    assert!(
        material.is_none()
            && issuer_calls.load(Ordering::SeqCst) == 0
            && ask_calls.load(Ordering::SeqCst) == 0
    );
}

#[tokio::test]
async fn runtime_should_not_call_issuer_when_ask_denies() {
    let dir = tempfile::tempdir().unwrap();
    let (ask_port, ask_calls) = start_ask_server("HTTP/1.1 403 Forbidden", 1);
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::write(
        &gatewayfile_path,
        gatewayfile(&dir.path().join("cert-cache"), ask_port),
    )
    .unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile_path).unwrap();
    let issuer_calls = Arc::new(AtomicUsize::new(0));
    let state = GatewayRuntimeState::new_with_issuer(
        config,
        &gatewayfile_path,
        SystemTime::now(),
        Arc::new(FakeIssuer {
            calls: Arc::clone(&issuer_calls),
        }),
    )
    .unwrap();

    let material = state.certificate_for_sni("denied.page.hdd.ink").await;

    assert!(
        material.is_none()
            && issuer_calls.load(Ordering::SeqCst) == 0
            && ask_calls.load(Ordering::SeqCst) == 1
    );
}
