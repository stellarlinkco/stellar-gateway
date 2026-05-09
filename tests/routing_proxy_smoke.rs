use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use pingora::prelude::{Opt, Server, http_proxy_service};
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::proxy::GatewayProxy;
use tempfile::TempDir;

type UpstreamHandle = (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<Mutex<String>>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

fn pick_unused_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn start_upstream() -> UpstreamHandle {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream");
    listener.set_nonblocking(true).expect("set_nonblocking");

    let addr = listener.local_addr().expect("local addr");
    let request_count = Arc::new(AtomicUsize::new(0));
    let last_request = Arc::new(Mutex::new(String::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let request_count_thread = Arc::clone(&request_count);
    let last_request_thread = Arc::clone(&last_request);
    let stop_thread = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    request_count_thread.fetch_add(1, Ordering::SeqCst);

                    let mut buf = [0u8; 4096];
                    let mut seen = Vec::new();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                seen.extend_from_slice(&buf[..n]);
                                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => break,
                        }
                    }

                    if let Ok(request) = String::from_utf8(seen.clone()) {
                        *last_request_thread.lock().expect("lock last request") = request;
                    }

                    let body = b"upstream-ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(body);
                    let _ = stream.flush();
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (addr, request_count, last_request, stop, handle)
}

fn gateway_bin_path() -> PathBuf {
    let bin_path = option_env!("CARGO_BIN_EXE_stellar-gateway")
        .map(PathBuf::from)
        .or_else(|| {
            let current_exe = std::env::current_exe().ok()?;
            let debug_dir = current_exe.parent()?.parent()?;
            Some(debug_dir.join("stellar-gateway"))
        })
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("debug")
                .join("stellar-gateway")
        });
    assert!(
        bin_path.exists(),
        "expected gateway binary at {} (run with `cargo test --all-targets`)",
        bin_path.display()
    );
    bin_path
}

fn write_gatewayfile(dir: &TempDir, http_port: u16, upstream: SocketAddr) -> std::path::PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"listeners:
  http:
    bind: "127.0.0.1:{http_port}"
  https:
    bind: "127.0.0.1:0"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "{upstream}"
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
  enabled: false

logging:
  level: "error"
"#,
            dir.path().join("cert-cache").display()
        ),
    )
}

fn write_caddyfile_gatewayfile(
    dir: &TempDir,
    http_port: u16,
    upstream: SocketAddr,
) -> std::path::PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"{{
	http_port {http_port}
	https_port 0
}}

hdd.ink, *.hdd.ink {{
	reverse_proxy {upstream}
}}
"#
        ),
    )
}

fn write_caddyfile_gatewayfile_with_host_override(
    dir: &TempDir,
    http_port: u16,
    upstream: SocketAddr,
) -> std::path::PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"{{
	http_port {http_port}
	https_port 0
}}

geo.stellarlink.co, *.geo.stellarlink.co {{
	reverse_proxy {upstream} {{
		header_up Host 127.0.0.1
	}}
}}
"#
        ),
    )
}

fn write_gatewayfile_contents(dir: &TempDir, contents: String) -> std::path::PathBuf {
    let gatewayfile_path = dir.path().join("Gatewayfile");
    std::fs::create_dir_all(dir.path().join("cert-cache")).expect("create cert-cache dir");
    std::fs::write(&gatewayfile_path, contents).expect("write Gatewayfile");
    gatewayfile_path
}

fn spawn_gateway(gatewayfile: &std::path::Path) -> Child {
    Command::new(gateway_bin_path())
        .arg("--gatewayfile")
        .arg(gatewayfile)
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stellar-gateway")
}

fn spawn_in_process_gateway_with_http01_challenge(
    gatewayfile: &std::path::Path,
    host: &str,
    token: &str,
    body: &str,
) {
    let config = GatewayConfig::load_from_path(gatewayfile).expect("load Gatewayfile");
    let http_bind = config.listeners.http.bind.to_string();
    let proxy = GatewayProxy::new(config);
    proxy.http01_store().set_for_host(host, token, body);

    let mut server = Server::new(Some(Opt::default())).expect("create pingora server");
    server.bootstrap();
    let mut service = http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&http_bind);
    server.add_service(service);

    thread::spawn(move || server.run_forever());
}

fn wait_for_listen(port: u16) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(30));
    }
    panic!("gateway did not start listening on port {port}");
}

fn http_get(port: u16, host_header: &str) -> (u16, Vec<u8>) {
    http_get_path(port, host_header, "/")
}

fn http_get_path(port: u16, host_header: &str, path: &str) -> (u16, Vec<u8>) {
    http_get_path_with_extra_headers(port, host_header, path, &[])
}

fn http_get_path_with_extra_headers(
    port: u16,
    host_header: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect gateway");
    let extra_headers = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\n{extra_headers}Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write request");

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read response");

    let status = resp
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| {
            let line = line.strip_suffix(b"\r")?;
            let mut parts = line.split(|b| *b == b' ');
            let _http = parts.next()?;
            let code = parts.next()?;
            std::str::from_utf8(code).ok()?.parse::<u16>().ok()
        })
        .expect("parse status code");

    (status, resp)
}

struct TestEnv {
    _temp: TempDir,
    gateway_port: u16,
    upstream_count: Arc<AtomicUsize>,
    last_upstream_request: Arc<Mutex<String>>,
    upstream_stop: Arc<AtomicBool>,
    upstream_handle: Option<thread::JoinHandle<()>>,
    gateway_child: Child,
}

impl TestEnv {
    fn new() -> Self {
        Self::new_with_gatewayfile(write_gatewayfile)
    }

    fn new_with_caddyfile() -> Self {
        Self::new_with_gatewayfile(write_caddyfile_gatewayfile)
    }

    fn new_with_gatewayfile(writer: fn(&TempDir, u16, SocketAddr) -> std::path::PathBuf) -> Self {
        let temp = TempDir::new().expect("tempdir");

        let (upstream_addr, upstream_count, last_upstream_request, upstream_stop, upstream_handle) =
            start_upstream();
        let gateway_port = pick_unused_port();
        let gatewayfile = writer(&temp, gateway_port, upstream_addr);

        let gateway_child = spawn_gateway(&gatewayfile);
        wait_for_listen(gateway_port);

        Self {
            _temp: temp,
            gateway_port,
            upstream_count,
            last_upstream_request,
            upstream_stop,
            upstream_handle: Some(upstream_handle),
            gateway_child,
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = self.gateway_child.kill();
        let _ = self.gateway_child.wait();

        self.upstream_stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.upstream_handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn gateway_should_proxy_to_upstream_when_host_matches_wildcard() {
    let env = TestEnv::new();
    let (status, _resp) = http_get(env.gateway_port, "foo.page.hdd.ink");
    let upstream_count = env.upstream_count.load(Ordering::SeqCst);

    assert_eq!((status, upstream_count), (200, 1));
}

#[test]
fn gateway_should_answer_active_http01_challenge_before_upstream_routing() {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_count, _last_request, upstream_stop, upstream_handle) =
        start_upstream();
    let gateway_port = pick_unused_port();
    let gatewayfile = write_gatewayfile(&temp, gateway_port, upstream_addr);

    spawn_in_process_gateway_with_http01_challenge(
        &gatewayfile,
        "demo.page.hdd.ink",
        "unit-token",
        "unit-keyauth",
    );
    wait_for_listen(gateway_port);

    let (status, resp) = http_get_path(
        gateway_port,
        "demo.page.hdd.ink",
        "/.well-known/acme-challenge/unit-token",
    );
    upstream_stop.store(true, Ordering::SeqCst);
    let _ = upstream_handle.join();

    assert!(
        status == 200
            && resp.ends_with(b"unit-keyauth")
            && upstream_count.load(Ordering::SeqCst) == 0,
        "status={status}; upstream_count={}; resp={}",
        upstream_count.load(Ordering::SeqCst),
        String::from_utf8_lossy(&resp)
    );
}

#[test]
fn gateway_should_proxy_caddyfile_apex_and_wildcard_hosts() {
    let env = TestEnv::new_with_caddyfile();

    let (apex_status, _apex_resp) = http_get(env.gateway_port, "hdd.ink");
    let (tenant_status, _tenant_resp) = http_get(env.gateway_port, "zhirang.hdd.ink");
    let (second_tenant_status, _second_tenant_resp) = http_get(env.gateway_port, "aichao.hdd.ink");
    let upstream_count = env.upstream_count.load(Ordering::SeqCst);

    assert_eq!(
        (
            apex_status,
            tenant_status,
            second_tenant_status,
            upstream_count
        ),
        (200, 200, 200, 3)
    );
}

#[test]
fn gateway_should_preserve_host_and_overwrite_forwarded_host() {
    let env = TestEnv::new_with_caddyfile();

    let (status, _resp) = http_get_path_with_extra_headers(
        env.gateway_port,
        "zhirang.hdd.ink",
        "/",
        &[("X-Forwarded-Host", "attacker.example")],
    );
    let upstream_request = env
        .last_upstream_request
        .lock()
        .expect("lock last request")
        .clone();
    let normalized_request = upstream_request.to_ascii_lowercase();

    assert!(
        status == 200
            && normalized_request.contains("\r\nhost: zhirang.hdd.ink\r\n")
            && normalized_request.contains("\r\nx-forwarded-host: zhirang.hdd.ink\r\n")
            && !normalized_request.contains("attacker.example"),
        "status={status}; upstream_request={upstream_request}"
    );
}

#[test]
fn gateway_should_apply_configured_upstream_host_override() {
    let env = TestEnv::new_with_gatewayfile(write_caddyfile_gatewayfile_with_host_override);

    let (status, _resp) = http_get_path_with_extra_headers(
        env.gateway_port,
        "geo.stellarlink.co",
        "/",
        &[("X-Forwarded-Host", "attacker.example")],
    );
    let upstream_request = env
        .last_upstream_request
        .lock()
        .expect("lock last request")
        .clone();
    let normalized_request = upstream_request.to_ascii_lowercase();

    assert!(
        status == 200
            && normalized_request.contains("\r\nhost: 127.0.0.1\r\n")
            && normalized_request.contains("\r\nx-forwarded-host: geo.stellarlink.co\r\n")
            && !normalized_request.contains("attacker.example"),
        "status={status}; upstream_request={upstream_request}"
    );
}

#[test]
fn gateway_should_reject_and_not_call_upstream_when_host_does_not_match() {
    let env = TestEnv::new();
    let (status, _resp) = http_get(env.gateway_port, "example.com");
    let upstream_count = env.upstream_count.load(Ordering::SeqCst);

    assert_eq!((status, upstream_count), (404, 0));
}

#[test]
fn gateway_should_serve_health_without_wildcard_host_match() {
    let env = TestEnv::new();
    let (status, resp) = http_get_path(env.gateway_port, "example.com", "/health");
    let upstream_count = env.upstream_count.load(Ordering::SeqCst);

    assert!(
        status == 200 && resp.ends_with(b"ok\n") && upstream_count == 0,
        "status={status}; upstream_count={upstream_count}; resp={}",
        String::from_utf8_lossy(&resp)
    );
}

#[test]
fn gateway_should_serve_prometheus_metrics_without_wildcard_host_match() {
    let env = TestEnv::new();
    let _ = http_get(env.gateway_port, "foo.page.hdd.ink");
    let (status, resp) = http_get_path(env.gateway_port, "example.com", "/metrics");
    let upstream_count = env.upstream_count.load(Ordering::SeqCst);
    let body = String::from_utf8_lossy(&resp);

    assert!(
        status == 200
            && body.contains("# TYPE stellar_gateway_requests_total counter")
            && body.contains("stellar_gateway_route_matches_total 1")
            && upstream_count == 1,
        "status={status}; upstream_count={upstream_count}; body={body}"
    );
}
