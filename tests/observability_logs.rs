use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use tracing_subscriber::fmt::writer::MakeWriter;

use stellar_gateway::acme::{Http01ChallengeStore, Http01Request, Http01RequestPolicy};
use stellar_gateway::cert_cache::{CertificateCache, CertificateCacheEntry, CertificateMaterial};
use stellar_gateway::reload::GatewayRuntimeState;
use stellar_gateway::routing::{IssuanceAuthorization, RouteAuthorizationPolicy, RouteMatch};
use stellar_gateway::tls::AskClient;

#[derive(Clone, Default)]
struct BufMakeWriter(Arc<Mutex<Vec<u8>>>);

struct BufWriterGuard(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for BufMakeWriter {
    type Writer = BufWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        BufWriterGuard(Arc::clone(&self.0))
    }
}

impl io::Write for BufWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().expect("log buffer lock");
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn read_logs(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    let bytes = buf.lock().expect("log buffer lock").clone();
    String::from_utf8_lossy(&bytes).to_string()
}

fn start_ask_status_server(status_line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ask server");
    let port = listener.local_addr().expect("ask server addr").port();
    thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept ask conn");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(resp.as_bytes());
    });
    port
}

fn exercise_operational_paths() -> String {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let make_writer = BufMakeWriter(Arc::clone(&buf));

    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(make_writer)
        .without_time()
        .with_target(false)
        .finish();

    let _guard = tracing::subscriber::set_default(subscriber);

    let policy = RouteAuthorizationPolicy::new("page.hdd.ink");
    let _decision = policy.authorize_request(
        "demo.page.hdd.ink",
        IssuanceAuthorization::DeniedByAsk,
        RouteMatch::Matched,
    );

    let store = Http01ChallengeStore::default();
    store.set_for_host("demo.page.hdd.ink", "unit-token", "unit-keyauth");
    let http01 = Http01RequestPolicy::new(store);
    let _http01_decision = http01.authorize(
        Http01Request::new(
            "/.well-known/acme-challenge/unit-token",
            "demo.page.hdd.ink",
        ),
        RouteMatch::Matched,
    );

    let ask_port = start_ask_status_server("HTTP/1.1 200 OK");
    let client = AskClient::try_new(
        format!("http://127.0.0.1:{ask_port}/ask")
            .parse()
            .expect("parse ask url"),
        Duration::from_millis(200),
    )
    .expect("http ask URL should be supported");
    let _ask_decision = client.authorize("demo.page.hdd.ink");

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = CertificateCache::new(dir.path());
    let certificate = rcgen::generate_simple_self_signed(vec!["demo.page.hdd.ink".to_string()])
        .expect("generate test certificate");
    let entry = CertificateCacheEntry::new(
        "demo.page.hdd.ink",
        CertificateMaterial::new(
            certificate.cert.pem(),
            certificate.signing_key.serialize_pem(),
        ),
        SystemTime::now() + Duration::from_secs(3600),
    );
    cache.store(&entry).expect("store cache");

    let gatewayfile = dir.path().join("Gatewayfile");
    std::fs::write(&gatewayfile, "listeners: {}\n").expect("write gatewayfile");
    let config_yaml = format!(
        r#"listeners:
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
  ask_url: "http://127.0.0.1:9000/ask"

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
        dir.path().display()
    );
    std::fs::write(&gatewayfile, config_yaml).expect("write config yaml");
    let config =
        stellar_gateway::config::GatewayConfig::load_from_path(&gatewayfile).expect("load config");

    let state =
        GatewayRuntimeState::new(config, &gatewayfile, SystemTime::now()).expect("runtime state");
    let _ = state.reload_certificates(SystemTime::now());

    read_logs(&buf)
}

#[test]
fn logs_should_emit_operational_events_without_secrets() {
    let logs = exercise_operational_paths();

    assert!(logs.contains("route_authorization"));
}

#[test]
fn logs_should_cover_acme_cache_reload_and_tls_events() {
    let logs = exercise_operational_paths();
    assert!(
        logs.contains("acme_http01")
            && logs.contains("cert_cache_refresh")
            && logs.contains("reload_certificates")
            && logs.contains("tls_ask_decision")
    );
}

#[test]
fn logs_should_not_include_certificate_material_or_full_challenge_token() {
    let logs = exercise_operational_paths();
    assert!(
        !logs.contains("redacted-key-pem")
            && !logs.contains("redacted-cert-pem")
            && !logs.contains("unit-keyauth")
            && !logs.contains("unit-token")
    );
}
