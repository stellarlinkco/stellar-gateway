use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509VerifyResult;
use stellar_gateway::acme::{
    Http01ChallengeStore, Http01Decision, Http01Request, Http01RequestPolicy,
};
use stellar_gateway::cert_cache::{CertificateCache, CertificateCacheEntry, CertificateMaterial};
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::proxy::GatewayProxy;
use stellar_gateway::reload::GatewayRuntimeState;
use stellar_gateway::routing::RouteMatch;
use stellar_gateway::tls::AskClient;
use tempfile::TempDir;
use url::Url;

fn gatewayfile_yaml(
    cache_dir: &Path,
    http_port: u16,
    https_port: u16,
    upstream: SocketAddr,
    upstream_tls: bool,
    ask_url: &str,
    logging_level: &str,
) -> String {
    format!(
        r#"listeners:
  http:
    bind: "127.0.0.1:{http_port}"
  https:
    bind: "127.0.0.1:{https_port}"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "{upstream}"
      tls: {upstream_tls}

tls:
  ask_url: "{ask_url}"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: true

cert_cache:
  dir: "{}"

reload:
  enabled: true

logging:
  level: "{logging_level}"
"#,
        cache_dir.display()
    )
}

fn write_gatewayfile_with_ask_url(
    dir: &TempDir,
    http_port: u16,
    https_port: u16,
    upstream: SocketAddr,
    ask_url: &str,
) -> PathBuf {
    let cache_dir = dir.path().join("cert-cache");
    std::fs::create_dir_all(&cache_dir).expect("create cert cache");
    let path = dir.path().join("Gatewayfile");
    std::fs::write(
        &path,
        gatewayfile_yaml(
            &cache_dir, http_port, https_port, upstream, false, ask_url, "info",
        ),
    )
    .expect("write Gatewayfile");
    path
}

fn write_gatewayfile(
    dir: &TempDir,
    http_port: u16,
    https_port: u16,
    upstream: SocketAddr,
) -> PathBuf {
    write_gatewayfile_with_ask_url(
        dir,
        http_port,
        https_port,
        upstream,
        "http://127.0.0.1:9000/ask",
    )
}

fn pick_unused_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn gateway_bin_path() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_stellar_gateway")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_stellar-gateway"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("debug")
                .join(if cfg!(windows) {
                    "stellar-gateway.exe"
                } else {
                    "stellar-gateway"
                })
        })
}

fn spawn_gateway(gatewayfile: &Path) -> ChildGuard {
    ChildGuard(
        Command::new(gateway_bin_path())
            .arg("--gatewayfile")
            .arg(gatewayfile)
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stellar-gateway"),
    )
}

fn wait_for_connect(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn https_get_peer_certificate_names(
    port: u16,
    server_name: &str,
) -> std::io::Result<(Vec<String>, Vec<String>)> {
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut builder = SslConnector::builder(SslMethod::tls()).expect("TLS connector builder");
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let stream = connector
        .connect(server_name, stream)
        .map_err(std::io::Error::other)?;
    let certificate = stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| std::io::Error::other("missing peer certificate"))?;
    let mut dns_names = Vec::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        dns_names.extend(
            subject_alt_names
                .iter()
                .filter_map(|name| name.dnsname().map(ToOwned::to_owned)),
        );
    }
    let common_names = certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .filter_map(|entry| entry.data().as_utf8().ok().map(|name| name.to_string()))
        .collect();
    Ok((dns_names, common_names))
}

fn https_verified_handshake_result(
    port: u16,
    server_name: &str,
) -> Result<X509VerifyResult, String> {
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|err| err.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| err.to_string())?;

    let connector = SslConnector::builder(SslMethod::tls())
        .map_err(|err| err.to_string())?
        .build();
    let stream = connector
        .connect(server_name, stream)
        .map_err(|err| err.to_string())?;
    Ok(stream.ssl().verify_result())
}

struct BodyUpstream {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl BodyUpstream {
    fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream");
        listener.set_nonblocking(true).expect("set nonblocking");
        let addr = listener.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for BodyUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_ask_status_server(status_line: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ask server");
    let port = listener.local_addr().expect("ask addr").port();
    thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut stream, _peer)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    port
}

fn start_recording_ask_status_server(status_line: &'static str) -> (u16, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ask server");
    let port = listener.local_addr().expect("ask addr").port();
    let called = Arc::new(AtomicBool::new(false));
    let called_thread = Arc::clone(&called);
    thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut stream, _peer)) = listener.accept() else {
                return;
            };
            called_thread.store(true, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, called)
}

fn cache_certificate_for_host(cache_dir: &Path, hostname: &str, common_name: &str) {
    let certificate = rcgen::generate_simple_self_signed(vec![common_name.to_owned()])
        .expect("generate cache certificate");
    let entry = CertificateCacheEntry::new(
        hostname,
        CertificateMaterial::new(
            certificate.cert.pem(),
            certificate.signing_key.serialize_pem(),
        ),
        SystemTime::now() + Duration::from_secs(3600),
    );
    CertificateCache::new(cache_dir)
        .store(&entry)
        .expect("store cache certificate");
}

#[test]
fn review_gateway_runtime_should_reject_non_wildcard_sni_without_calling_ask() {
    let temp = TempDir::new().expect("tempdir");
    let http_port = pick_unused_port();
    let https_port = pick_unused_port();
    let upstream = BodyUpstream::start("upstream-ok");
    let (ask_port, ask_called) = start_recording_ask_status_server("HTTP/1.1 200 OK");
    let gatewayfile = write_gatewayfile_with_ask_url(
        &temp,
        http_port,
        https_port,
        upstream.addr,
        &format!("http://127.0.0.1:{ask_port}/ask"),
    );
    let _gateway = spawn_gateway(&gatewayfile);
    let server_name = "attacker.example.com";
    assert!(wait_for_connect(http_port, Duration::from_secs(3)));

    let result = https_verified_handshake_result(https_port, server_name);

    assert!(
        result.is_err() && !ask_called.load(Ordering::SeqCst),
        "expected non-wildcard SNI to fail before ask; result={result:?}"
    );
}

#[test]
fn review_gateway_runtime_should_select_cached_certificate_by_sni() {
    let temp = TempDir::new().expect("tempdir");
    let http_port = pick_unused_port();
    let https_port = pick_unused_port();
    let upstream = BodyUpstream::start("upstream-ok");
    let gatewayfile = write_gatewayfile(&temp, http_port, https_port, upstream.addr);
    let cache_dir = temp.path().join("cert-cache");
    cache_certificate_for_host(&cache_dir, "cached.page.hdd.ink", "cached.page.hdd.ink");
    let _gateway = spawn_gateway(&gatewayfile);
    assert!(wait_for_connect(http_port, Duration::from_secs(3)));

    let (dns_names, common_names) =
        https_get_peer_certificate_names(https_port, "cached.page.hdd.ink")
            .expect("HTTPS certificate should be available");

    assert!(
        dns_names.contains(&"cached.page.hdd.ink".to_owned())
            || common_names.contains(&"cached.page.hdd.ink".to_owned()),
        "expected SNI-selected cached certificate; dns_names={dns_names:?}; common_names={common_names:?}"
    );
}

#[test]
fn review_gateway_runtime_should_reject_uncached_sni_when_ask_denies() {
    let temp = TempDir::new().expect("tempdir");
    let http_port = pick_unused_port();
    let https_port = pick_unused_port();
    let upstream = BodyUpstream::start("upstream-ok");
    let (ask_port, ask_called) = start_recording_ask_status_server("HTTP/1.1 403 Forbidden");
    let gatewayfile = write_gatewayfile_with_ask_url(
        &temp,
        http_port,
        https_port,
        upstream.addr,
        &format!("http://127.0.0.1:{ask_port}/ask"),
    );
    let _gateway = spawn_gateway(&gatewayfile);
    assert!(wait_for_connect(http_port, Duration::from_secs(3)));

    let result = https_verified_handshake_result(https_port, "denied.page.hdd.ink");

    let denied = match &result {
        Ok(verify) => *verify != X509VerifyResult::OK,
        Err(_) => true,
    };

    assert!(
        denied && ask_called.load(Ordering::SeqCst),
        "expected ask-denied uncached SNI to consult ask endpoint and fail certificate verification, got {result:?}"
    );
}

#[test]
fn review_gateway_runtime_state_proxy_reload_should_update_active_upstream() {
    let temp = TempDir::new().expect("tempdir");
    let first = BodyUpstream::start("upstream-one");
    let second = BodyUpstream::start("upstream-two");
    let gatewayfile = write_gatewayfile(&temp, 18080, 18443, first.addr);
    let config = GatewayConfig::load_from_path(&gatewayfile).expect("initial config");
    let state =
        Arc::new(GatewayRuntimeState::new(config, &gatewayfile, SystemTime::now()).unwrap());
    let proxy = GatewayProxy::from_runtime_state(Arc::clone(&state));
    std::fs::write(
        &gatewayfile,
        gatewayfile_yaml(
            &temp.path().join("cert-cache"),
            18080,
            18443,
            second.addr,
            false,
            "http://127.0.0.1:9000/ask",
            "info",
        ),
    )
    .expect("rewrite Gatewayfile");

    state.reload_config().expect("reload config");

    assert_eq!(
        proxy.active_upstream_for_host("demo.page.hdd.ink").unwrap(),
        second.addr.to_string()
    );
}

#[test]
fn review_http01_challenge_should_require_host_match_not_token_only() {
    let store = Http01ChallengeStore::default();
    store.set_for_host("demo.page.hdd.ink", "shared-token", "keyauth");
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

#[test]
fn review_ask_client_should_reject_unsupported_url_scheme() {
    let err = AskClient::try_new(
        Url::parse("ftp://127.0.0.1/ask").unwrap(),
        Duration::from_millis(100),
    )
    .unwrap_err();

    assert!(err.to_string().contains("unsupported URL scheme"));
}

#[test]
fn review_ask_client_should_build_authorization_request_for_dns_host() {
    let port = start_ask_status_server("HTTP/1.1 200 OK");
    let client = AskClient::try_new(
        Url::parse(&format!("http://localhost:{port}/ask")).unwrap(),
        Duration::from_millis(500),
    )
    .expect("DNS host ask URL should be supported");

    assert!(client.authorize("demo.page.hdd.ink").is_allow());
}

#[test]
fn review_gatewayfile_should_reject_https_upstream_without_server_name() {
    let temp = TempDir::new().expect("tempdir");
    let config = gatewayfile_yaml(
        &temp.path().join("cert-cache"),
        8080,
        8443,
        "127.0.0.1:3000".parse().unwrap(),
        true,
        "http://127.0.0.1:9000/ask",
        "info",
    );

    assert!(GatewayConfig::load_from_str(&config).is_err());
}

#[test]
fn review_logging_level_should_build_runtime_filter() {
    let temp = TempDir::new().expect("tempdir");
    let config = GatewayConfig::load_from_str(&gatewayfile_yaml(
        &temp.path().join("cert-cache"),
        8080,
        8443,
        "127.0.0.1:3000".parse().unwrap(),
        false,
        "http://127.0.0.1:9000/ask",
        "debug",
    ))
    .expect("Gatewayfile with debug logging level");

    assert_eq!(config.logging.to_env_filter().to_string(), "debug");
}

#[test]
fn review_certificate_cache_should_reject_malformed_pem_with_valid_yaml_metadata() {
    let temp = TempDir::new().expect("tempdir");
    std::fs::write(
        temp.path().join("bad.page.hdd.ink.yaml"),
        r#"hostname: bad.page.hdd.ink
expires_at_unix: 4102444800
certificate_pem: "not a pem certificate"
private_key_pem: "not a pem private key"
"#,
    )
    .expect("write malformed cache entry");

    let cache = CertificateCache::load(temp.path(), SystemTime::now()).unwrap();

    assert!(cache.lookup("bad.page.hdd.ink").is_none());
}
