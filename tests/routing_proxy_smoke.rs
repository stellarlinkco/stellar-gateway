use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::HeaderMap;
use pingora::prelude::{Opt, Server, http_proxy_service};
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::proxy::GatewayProxy;
use tempfile::TempDir;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};

type UpstreamHandle = (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<Mutex<String>>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

static GRPC_SMOKE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn grpc_smoke_lock() -> &'static tokio::sync::Mutex<()> {
    GRPC_SMOKE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn pick_unused_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn start_upstream() -> UpstreamHandle {
    start_upstream_with_body("upstream-ok")
}

fn start_upstream_with_body(body: &'static str) -> UpstreamHandle {
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

                    let seen = read_http_request_headers(&mut stream);

                    if let Ok(request) = String::from_utf8(seen.clone()) {
                        *last_request_thread.lock().expect("lock last request") = request;
                    }

                    let body = body.as_bytes();
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

fn read_http_request_headers(stream: &mut TcpStream) -> Vec<u8> {
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
    seen
}

fn start_websocket_upgrade_upstream() -> UpstreamHandle {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind websocket upstream");
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
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let seen = read_http_request_headers(&mut stream);
                    if let Ok(request) = String::from_utf8(seen.clone()) {
                        *last_request_thread.lock().expect("lock last request") = request;
                    }

                    let response = concat!(
                        "HTTP/1.1 101 Switching Protocols\r\n",
                        "Upgrade: websocket\r\n",
                        "Connection: Upgrade\r\n",
                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                        "\r\n"
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        continue;
                    }
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

fn start_websocket_echo_upstream() -> UpstreamHandle {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind websocket echo upstream");
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
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                    let seen = read_http_request_headers(&mut stream);
                    let mut request = String::from_utf8_lossy(&seen).to_string();

                    let response = concat!(
                        "HTTP/1.1 101 Switching Protocols\r\n",
                        "Upgrade: websocket\r\n",
                        "Connection: Upgrade\r\n",
                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                        "\r\n"
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        continue;
                    }
                    let _ = stream.flush();

                    match read_websocket_text_frame(&mut stream) {
                        Ok(text) => {
                            request.push_str("\nwebsocket-text: ");
                            request.push_str(&text);
                            *last_request_thread.lock().expect("lock last request") = request;
                            let _ = write_websocket_text_frame(&mut stream, "echo: hello");
                        }
                        Err(err) => {
                            request.push_str("\nwebsocket-read-error: ");
                            request.push_str(&err.to_string());
                            *last_request_thread.lock().expect("lock last request") = request;
                        }
                    }
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

fn start_oversized_websocket_header_upstream() -> UpstreamHandle {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("bind websocket large header upstream");
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
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let seen = read_http_request_headers(&mut stream);
                    if let Ok(request) = String::from_utf8(seen.clone()) {
                        *last_request_thread.lock().expect("lock last request") = request;
                    }

                    let mut response = b"HTTP/1.1 101 Switching Protocols\r\nX-Pad: ".to_vec();
                    response.extend(vec![b'a'; 70 * 1024]);
                    if stream.write_all(&response).is_err() {
                        continue;
                    }
                    let _ = stream.flush();

                    let mut byte = [0u8; 1];
                    while !stop_thread.load(Ordering::Relaxed) {
                        match stream.read(&mut byte) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) => {}
                            Err(_) => break,
                        }
                    }
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

fn read_websocket_text_frame(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    assert_eq!(header[0] & 0x0f, 0x1, "expected text frame opcode");
    assert_ne!(header[1] & 0x80, 0, "client WebSocket frame must be masked");
    let payload_len = (header[1] & 0x7f) as usize;
    assert!(payload_len <= 125, "test helper only supports small frames");

    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    String::from_utf8(payload)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn write_websocket_text_frame(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    let payload = text.as_bytes();
    assert!(
        payload.len() <= 125,
        "test helper only supports small frames"
    );
    stream.write_all(&[0x81, payload.len() as u8])?;
    stream.write_all(payload)?;
    stream.flush()
}

fn start_sse_upstream() -> UpstreamHandle {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind sse upstream");
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
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let seen = read_http_request_headers(&mut stream);
                    if let Ok(request) = String::from_utf8(seen.clone()) {
                        *last_request_thread.lock().expect("lock last request") = request;
                    }

                    let response = concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Content-Type: text/event-stream\r\n",
                        "Cache-Control: no-cache\r\n",
                        "Transfer-Encoding: chunked\r\n",
                        "Connection: close\r\n",
                        "\r\n"
                    );
                    if stream.write_all(response.as_bytes()).is_err() {
                        continue;
                    }
                    write_chunk(&mut stream, b"id: 1\ndata: first\n\n");
                    thread::sleep(Duration::from_millis(300));
                    write_chunk(&mut stream, b"id: 2\ndata: second\n\n");
                    thread::sleep(Duration::from_millis(300));
                    let _ = stream.write_all(b"0\r\n\r\n");
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

fn write_chunk(stream: &mut TcpStream, body: &[u8]) {
    let header = format!("{:x}\r\n", body.len());
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.write_all(b"\r\n");
    let _ = stream.flush();
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

fn write_warning_only_caddyfile_gatewayfile(
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
	encode gzip
	reverse_proxy {upstream}
}}
"#
        ),
    )
}

fn write_degraded_caddyfile_gatewayfile(
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

secure.example {{
	basicauth /admin/* {{
		user JDJhJDE0JHVuaXQ=
	}}
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

fn write_h2c_grpc_caddyfile(
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

hdd.ink {{
	reverse_proxy h2c://{upstream}
}}
"#
        ),
    )
}

fn write_grpcs_grpc_caddyfile(dir: &TempDir, http_port: u16, upstream_port: u16) -> PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"{{
	http_port {http_port}
	https_port 0
}}

hdd.ink {{
	reverse_proxy grpcs://127.0.0.1:{upstream_port} {{
		header_up Host localhost
	}}
}}
"#
        ),
    )
}

fn write_static_caddyfile(
    dir: &TempDir,
    http_port: u16,
    static_root: &std::path::Path,
) -> std::path::PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"{{
	http_port {http_port}
	https_port 0
}}

static.example.test {{
	root * {}
	file_server
}}
"#,
            static_root.display()
        ),
    )
}

fn write_multisite_path_caddyfile(
    dir: &TempDir,
    http_port: u16,
    site_upstream: SocketAddr,
    api_upstream: SocketAddr,
    fallback_upstream: SocketAddr,
) -> std::path::PathBuf {
    write_gatewayfile_contents(
        dir,
        format!(
            r#"{{
	http_port {http_port}
	https_port 0
}}

one.example.test {{
	reverse_proxy {site_upstream}
}}

api.example.test {{
	reverse_proxy /v1/* {api_upstream}
	reverse_proxy {fallback_upstream}
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
    spawn_gateway_with_env(gatewayfile, &[])
}

fn start_gateway_with_port(
    dir: &TempDir,
    writer: fn(&TempDir, u16, SocketAddr) -> std::path::PathBuf,
    upstream: SocketAddr,
) -> (u16, PathBuf, Child) {
    let gateway_port = pick_unused_port();
    let gatewayfile = writer(dir, gateway_port, upstream);
    let gateway_child = spawn_gateway(&gatewayfile);
    wait_for_listen(gateway_port);
    (gateway_port, gatewayfile, gateway_child)
}

fn start_gateway_from_caddyfile_with_env(
    dir: &TempDir,
    write_gatewayfile: impl FnOnce(&TempDir, u16) -> PathBuf,
    envs: &[(&str, &OsStr)],
) -> (u16, PathBuf, Child) {
    let gateway_port = pick_unused_port();
    let gatewayfile = write_gatewayfile(dir, gateway_port);
    let gateway_child = spawn_gateway_with_env(&gatewayfile, envs);
    wait_for_listen(gateway_port);
    (gateway_port, gatewayfile, gateway_child)
}

fn spawn_gateway_with_env(gatewayfile: &std::path::Path, envs: &[(&str, &OsStr)]) -> Child {
    let mut command = Command::new(gateway_bin_path());
    command
        .arg("--gatewayfile")
        .arg(gatewayfile)
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in envs {
        command.env(name, value);
    }
    command.spawn().expect("spawn stellar-gateway")
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

fn wait_for_gateway_health(port: u16) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
            let request = b"GET /health HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
            if stream.write_all(request).is_ok() {
                let mut response = Vec::new();
                if stream.read_to_end(&mut response).is_ok()
                    && response.starts_with(b"HTTP/1.1 200")
                {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_millis(30));
    }
    panic!("gateway health endpoint did not become ready on port {port}");
}

fn http_get(port: u16, host_header: &str) -> (u16, Vec<u8>) {
    http_get_path(port, host_header, "/")
}

fn http_get_path(port: u16, host_header: &str, path: &str) -> (u16, Vec<u8>) {
    http_get_path_with_extra_headers(port, host_header, path, &[])
}

fn websocket_upgrade_stream(port: u16, host_header: &str) -> (TcpStream, u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set write timeout");
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write upgrade");

    let headers = read_http_response_headers(&mut stream);
    let status = parse_http_status(&headers);
    (stream, status, headers)
}

fn websocket_upgrade_handshake(port: u16, host_header: &str) -> (u16, Vec<u8>) {
    let (_stream, status, headers) = websocket_upgrade_stream(port, host_header);
    (status, headers)
}

fn websocket_upgrade_first_read(port: u16, host_header: &str) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;

    let mut response = vec![0u8; 4096];
    let read = stream.read(&mut response)?;
    response.truncate(read);
    Ok(response)
}

fn websocket_text_roundtrip(
    port: u16,
    host_header: &str,
    text: &str,
) -> (u16, Vec<u8>, Result<String, String>) {
    let (mut stream, status, headers) = websocket_upgrade_stream(port, host_header);
    if status != 101 {
        return (
            status,
            headers.clone(),
            Err(format!(
                "websocket upgrade failed: {}",
                String::from_utf8_lossy(&headers)
            )),
        );
    }
    if let Err(err) = write_masked_websocket_text_frame(&mut stream, text) {
        return (status, headers, Err(format!("write websocket text: {err}")));
    }
    let response_text = read_unmasked_websocket_text_frame(&mut stream)
        .map_err(|err| format!("read websocket text: {err}"));
    (status, headers, response_text)
}

fn write_masked_websocket_text_frame(stream: &mut TcpStream, text: &str) -> std::io::Result<()> {
    let payload = text.as_bytes();
    assert!(
        payload.len() <= 125,
        "test helper only supports small frames"
    );
    let mask = [0x12, 0x34, 0x56, 0x78];
    stream.write_all(&[0x81, 0x80 | payload.len() as u8])?;
    stream.write_all(&mask)?;
    for (index, byte) in payload.iter().enumerate() {
        stream.write_all(&[*byte ^ mask[index % 4]])?;
    }
    stream.flush()
}

fn read_unmasked_websocket_text_frame(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    assert_eq!(header[0] & 0x0f, 0x1, "expected text frame opcode");
    assert_eq!(
        header[1] & 0x80,
        0,
        "server WebSocket frame must not be masked"
    );
    let payload_len = (header[1] & 0x7f) as usize;
    assert!(payload_len <= 125, "test helper only supports small frames");
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    String::from_utf8(payload)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn read_http_response_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.windows(4).any(|w| w == b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response header");
        headers.push(byte[0]);
    }
    headers
}

fn parse_http_status(headers: &[u8]) -> u16 {
    headers
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| {
            let line = line.strip_suffix(b"\r")?;
            let mut parts = line.split(|b| *b == b' ');
            let _http = parts.next()?;
            let code = parts.next()?;
            std::str::from_utf8(code).ok()?.parse::<u16>().ok()
        })
        .expect("parse status code")
}

fn sse_events_until_second(port: u16, host_header: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    let req = format!(
        "GET /events HTTP/1.1\r\nHost: {host_header}\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write sse request");

    let headers = read_http_response_headers(&mut stream);
    let status = parse_http_status(&headers);
    let first_deadline = Instant::now() + Duration::from_millis(250);
    let mut body = Vec::new();
    let mut byte = [0u8; 1];
    while !body
        .windows(b"data: first".len())
        .any(|w| w == b"data: first")
    {
        assert!(
            Instant::now() < first_deadline,
            "first SSE event was buffered or delayed: {}",
            String::from_utf8_lossy(&body)
        );
        stream.read_exact(&mut byte).expect("read first sse event");
        body.push(byte[0]);
        assert!(
            !body
                .windows(b"data: second".len())
                .any(|w| w == b"data: second"),
            "second SSE event arrived before the first event was observed independently: {}",
            String::from_utf8_lossy(&body)
        );
    }
    while !body
        .windows(b"data: second".len())
        .any(|w| w == b"data: second")
    {
        stream.read_exact(&mut byte).expect("read second sse event");
        body.push(byte[0]);
    }
    (status, body)
}

fn stop_upstream(stop: Arc<AtomicBool>, handle: thread::JoinHandle<()>) {
    stop.store(true, Ordering::SeqCst);
    let _ = handle.join();
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
        let (gateway_port, _gatewayfile, gateway_child) =
            start_gateway_with_port(&temp, writer, upstream_addr);

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

#[derive(Debug)]
struct GrpcFixtureObserved {
    path: String,
    client_metadata: Option<String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct GrpcClientResult {
    status: u16,
    headers: HeaderMap,
    chunks: Vec<Vec<u8>>,
    trailers: HeaderMap,
}

async fn start_h2c_grpc_upstream() -> (SocketAddr, tokio::task::JoinHandle<GrpcFixtureObserved>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind h2c grpc upstream");
    let addr = listener.local_addr().expect("h2c grpc upstream local addr");
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _peer) = listener.accept().await.expect("accept h2c grpc upstream");
            match handle_grpc_h2_connection(stream).await {
                Ok(observed) => break observed,
                Err(GrpcFixtureAcceptError::ProbeConnection) => continue,
            }
        }
    });
    (addr, handle)
}

async fn start_grpcs_grpc_upstream(
    ca_cert_path: &Path,
) -> (SocketAddr, tokio::task::JoinHandle<GrpcFixtureObserved>) {
    let (server_config, ca_pem) = grpc_tls_server_config();
    std::fs::write(ca_cert_path, ca_pem).expect("write grpcs CA certificate");
    let ipv4_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind grpcs grpc ipv4 upstream");
    let addr = ipv4_listener
        .local_addr()
        .expect("grpcs grpc upstream local addr");
    let ipv6_listener = tokio::net::TcpListener::bind(("::1", addr.port()))
        .await
        .ok();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let handle = tokio::spawn(async move {
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(accept_grpcs_fixture_connections(
            ipv4_listener,
            acceptor.clone(),
            observed_tx.clone(),
        ));
        if let Some(ipv6_listener) = ipv6_listener {
            tokio::spawn(accept_grpcs_fixture_connections(
                ipv6_listener,
                acceptor,
                observed_tx,
            ));
        }
        observed_rx
            .recv()
            .await
            .expect("grpcs fixture should observe a proxied request")
    });
    (addr, handle)
}

async fn accept_grpcs_fixture_connections(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    observed_tx: tokio::sync::mpsc::Sender<GrpcFixtureObserved>,
) {
    loop {
        let (stream, _peer) = listener.accept().await.expect("accept grpcs grpc upstream");
        let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
        else {
            continue;
        };
        assert_eq!(
            stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice()),
            "grpcs upstream must negotiate HTTP/2 with gateway"
        );
        match handle_grpc_h2_connection(stream).await {
            Ok(observed) => {
                let _ = observed_tx.send(observed).await;
                break;
            }
            Err(GrpcFixtureAcceptError::ProbeConnection) => continue,
        }
    }
}

fn grpc_tls_server_config() -> (rustls::ServerConfig, String) {
    let mut cert_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("gRPC fixture subject alternative names are valid");
    cert_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    cert_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    cert_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    cert_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let cert_key = rcgen::KeyPair::generate().expect("generate grpcs certificate key");
    let cert = cert_params
        .self_signed(&cert_key)
        .expect("sign grpcs certificate");
    let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert_key.serialize_der()),
    );
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private_key)
        .expect("build grpcs rustls server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    (config, cert.pem())
}

#[derive(Debug)]
enum GrpcFixtureAcceptError {
    ProbeConnection,
}

async fn handle_grpc_h2_connection<T>(
    stream: T,
) -> Result<GrpcFixtureObserved, GrpcFixtureAcceptError>
where
    T: TokioAsyncRead + TokioAsyncWrite + Unpin,
{
    let mut connection = h2::server::handshake(stream)
        .await
        .map_err(|_| GrpcFixtureAcceptError::ProbeConnection)?;
    let Some(request) = connection.accept().await else {
        return Err(GrpcFixtureAcceptError::ProbeConnection);
    };
    let (request, mut respond) = request.map_err(|_| GrpcFixtureAcceptError::ProbeConnection)?;
    let path = request.uri().path().to_owned();
    let client_metadata = request
        .headers()
        .get("x-client-metadata")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body_stream = request.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        body.extend_from_slice(&chunk.expect("grpc upstream body chunk"));
    }

    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("x-upstream-metadata", "server-md")
        .body(())
        .expect("build grpc upstream response");
    let mut send = respond
        .send_response(response, false)
        .expect("send grpc upstream response headers");
    send.send_data(Bytes::from_static(b"\0\0\0\0\x07payload"), false)
        .expect("send grpc upstream response body");
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().expect("grpc status header"));
    trailers.insert("grpc-message", "ok".parse().expect("grpc message header"));
    trailers.insert(
        "x-upstream-trailer",
        "server-trailer".parse().expect("grpc custom trailer"),
    );
    send.send_trailers(trailers)
        .expect("send grpc upstream trailers");
    let _ = tokio::time::timeout(Duration::from_millis(100), connection.accept()).await;

    Ok(GrpcFixtureObserved {
        path,
        client_metadata,
        body,
    })
}

async fn grpc_h2c_unary_via_gateway(port: u16) -> Result<GrpcClientResult, String> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| format!("connect gateway h2c: {err}"))?;
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .map_err(|err| format!("h2c client handshake with gateway: {err}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://hdd.ink:{port}/stellar.NativeGrpc/Echo"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("x-client-metadata", "client-md")
        .body(())
        .map_err(|err| format!("build grpc request: {err}"))?;
    let (response, mut send_stream) = client
        .send_request(request, false)
        .map_err(|err| format!("send grpc request headers: {err}"))?;
    send_stream
        .send_data(Bytes::from_static(b"\0\0\0\0\x05hello"), true)
        .map_err(|err| format!("send grpc request body: {err}"))?;

    let response = response
        .await
        .map_err(|err| format!("read grpc response headers: {err}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body_stream = response.into_body();
    let mut chunks = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        chunks.push(
            chunk
                .map_err(|err| format!("read grpc response body: {err}"))?
                .to_vec(),
        );
    }
    let trailers = body_stream
        .trailers()
        .await
        .map_err(|err| format!("read grpc response trailers: {err}"))?
        .unwrap_or_default();

    Ok(GrpcClientResult {
        status,
        headers,
        chunks,
        trailers,
    })
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
    let gateway_port = {
        let gateway_port = pick_unused_port();
        let gatewayfile = write_gatewayfile(&temp, gateway_port, upstream_addr);
        spawn_in_process_gateway_with_http01_challenge(
            &gatewayfile,
            "demo.page.hdd.ink",
            "unit-token",
            "unit-keyauth",
        );
        wait_for_listen(gateway_port);
        gateway_port
    };

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

#[tokio::test]
async fn gateway_should_proxy_native_grpc_h2c_with_metadata_and_trailers() {
    let _grpc_guard = grpc_smoke_lock().lock().await;
    let mut last_error = String::new();
    let mut result = None;
    for _attempt in 0..3 {
        match run_h2c_grpc_smoke_once().await {
            Ok(value) => {
                result = Some(value);
                break;
            }
            Err(err) => {
                last_error = err;
                if !last_error.contains("timed out") {
                    break;
                }
            }
        }
    }
    let (observed, client) =
        result.unwrap_or_else(|| panic!("h2c grpc smoke failed: {last_error}"));

    assert_eq!(observed.path, "/stellar.NativeGrpc/Echo");
    assert_eq!(observed.client_metadata.as_deref(), Some("client-md"));
    assert_eq!(observed.body, b"\0\0\0\0\x05hello");
    assert_eq!(client.status, 200);
    assert_eq!(
        client
            .headers
            .get("x-upstream-metadata")
            .and_then(|value| value.to_str().ok()),
        Some("server-md")
    );
    assert_eq!(client.chunks, vec![b"\0\0\0\0\x07payload".to_vec()]);
    assert_eq!(
        client
            .trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        client
            .trailers
            .get("x-upstream-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("server-trailer")
    );
}

async fn run_h2c_grpc_smoke_once() -> Result<(GrpcFixtureObserved, GrpcClientResult), String> {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_task) = start_h2c_grpc_upstream().await;
    let (gateway_port, _gatewayfile, mut gateway_child) = start_gateway_from_caddyfile_with_env(
        &temp,
        |dir, gateway_port| write_h2c_grpc_caddyfile(dir, gateway_port, upstream_addr),
        &[],
    );
    wait_for_gateway_health(gateway_port);

    let client_result = tokio::time::timeout(
        Duration::from_secs(30),
        grpc_h2c_unary_via_gateway(gateway_port),
    )
    .await;

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();

    let client = match client_result {
        Ok(Ok(client)) => client,
        Ok(Err(err)) => {
            upstream_task.abort();
            return Err(err);
        }
        Err(_) => {
            upstream_task.abort();
            return Err("timed out waiting for h2c grpc client response".to_owned());
        }
    };
    let observed = match tokio::time::timeout(Duration::from_secs(1), upstream_task).await {
        Ok(Ok(observed)) => observed,
        Ok(Err(err)) => return Err(format!("h2c grpc upstream task failed: {err}")),
        Err(_) => {
            return Err(format!(
                "timed out waiting for h2c grpc upstream after client response {client:?}"
            ));
        }
    };

    Ok((observed, client))
}

#[tokio::test]
async fn gateway_should_proxy_native_grpc_grpcs_with_metadata_and_trailers() {
    let _grpc_guard = grpc_smoke_lock().lock().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut last_error = String::new();
    let mut result = None;
    for _attempt in 0..3 {
        match run_grpcs_grpc_smoke_once().await {
            Ok(value) => {
                result = Some(value);
                break;
            }
            Err(err) => {
                last_error = err;
                if !last_error.contains("timed out") {
                    break;
                }
            }
        }
    }
    let (observed, client) =
        result.unwrap_or_else(|| panic!("grpcs grpc smoke failed: {last_error}"));

    assert_eq!(observed.path, "/stellar.NativeGrpc/Echo");
    assert_eq!(observed.client_metadata.as_deref(), Some("client-md"));
    assert_eq!(observed.body, b"\0\0\0\0\x05hello");
    assert_eq!(client.status, 200);
    assert_eq!(
        client
            .headers
            .get("x-upstream-metadata")
            .and_then(|value| value.to_str().ok()),
        Some("server-md")
    );
    assert_eq!(client.chunks, vec![b"\0\0\0\0\x07payload".to_vec()]);
    assert_eq!(
        client
            .trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        client
            .trailers
            .get("x-upstream-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("server-trailer")
    );
}

async fn run_grpcs_grpc_smoke_once() -> Result<(GrpcFixtureObserved, GrpcClientResult), String> {
    let temp = TempDir::new().expect("tempdir");
    let ca_cert_path = temp.path().join("grpcs-ca.pem");
    let (upstream_addr, upstream_task) = start_grpcs_grpc_upstream(&ca_cert_path).await;
    let (gateway_port, _gatewayfile, mut gateway_child) = start_gateway_from_caddyfile_with_env(
        &temp,
        |dir, gateway_port| write_grpcs_grpc_caddyfile(dir, gateway_port, upstream_addr.port()),
        &[("SSL_CERT_FILE", ca_cert_path.as_os_str())],
    );
    wait_for_gateway_health(gateway_port);

    let client_result = tokio::time::timeout(
        Duration::from_secs(30),
        grpc_h2c_unary_via_gateway(gateway_port),
    )
    .await;

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();

    let client = match client_result {
        Ok(Ok(client)) => client,
        Ok(Err(err)) => {
            upstream_task.abort();
            return Err(err);
        }
        Err(_) => {
            upstream_task.abort();
            return Err("timed out waiting for grpcs grpc client response".to_owned());
        }
    };
    let observed = match tokio::time::timeout(Duration::from_secs(1), upstream_task).await {
        Ok(Ok(observed)) => observed,
        Ok(Err(err)) => return Err(format!("grpcs grpc upstream task failed: {err}")),
        Err(_) => {
            return Err(format!(
                "timed out waiting for grpcs grpc upstream after client response {client:?}"
            ));
        }
    };

    Ok((observed, client))
}

#[test]
fn gateway_should_proxy_multisite_caddyfile_hosts_and_path_specific_routes() {
    let temp = TempDir::new().expect("tempdir");
    let (site_addr, site_count, _site_request, site_stop, site_handle) =
        start_upstream_with_body("site-one");
    let (api_addr, api_count, _api_request, api_stop, api_handle) =
        start_upstream_with_body("api-v1");
    let (fallback_addr, fallback_count, _fallback_request, fallback_stop, fallback_handle) =
        start_upstream_with_body("api-fallback");
    let (gateway_port, _gatewayfile, mut gateway_child) = start_gateway_from_caddyfile_with_env(
        &temp,
        |dir, gateway_port| {
            write_multisite_path_caddyfile(dir, gateway_port, site_addr, api_addr, fallback_addr)
        },
        &[],
    );

    let (site_status, _site_resp) = http_get_path(gateway_port, "one.example.test", "/");
    let (api_status, _api_resp) = http_get_path(gateway_port, "api.example.test", "/v1/users");
    let (fallback_status, _fallback_resp) =
        http_get_path(gateway_port, "api.example.test", "/other");
    let (rejected_status, _rejected_resp) =
        http_get_path(gateway_port, "missing.example.test", "/");

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();
    stop_upstream(site_stop, site_handle);
    stop_upstream(api_stop, api_handle);
    stop_upstream(fallback_stop, fallback_handle);

    assert_eq!(
        (
            site_status,
            api_status,
            fallback_status,
            rejected_status,
            site_count.load(Ordering::SeqCst),
            api_count.load(Ordering::SeqCst),
            fallback_count.load(Ordering::SeqCst),
        ),
        (200, 200, 200, 404, 1, 1, 1)
    );
}

#[test]
fn gateway_should_forward_websocket_upgrade_handshake() {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_count, last_request, upstream_stop, upstream_handle) =
        start_websocket_upgrade_upstream();
    let (gateway_port, _gatewayfile, mut gateway_child) =
        start_gateway_with_port(&temp, write_caddyfile_gatewayfile, upstream_addr);

    let (status, response_headers) = websocket_upgrade_handshake(gateway_port, "hdd.ink");
    let upstream_request = last_request.lock().expect("lock last request").clone();

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();
    stop_upstream(upstream_stop, upstream_handle);

    assert!(
        status == 101
            && response_headers
                .windows(b"Upgrade: websocket".len())
                .any(|window| window.eq_ignore_ascii_case(b"Upgrade: websocket"))
            && upstream_count.load(Ordering::SeqCst) == 1
            && upstream_request
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
        "status={status}; response_headers={}; upstream_request={upstream_request}",
        String::from_utf8_lossy(&response_headers)
    );
}

#[test]
fn gateway_should_proxy_websocket_upgrade_and_one_text_message() {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_count, last_request, upstream_stop, upstream_handle) =
        start_websocket_echo_upstream();
    let (gateway_port, _gatewayfile, mut gateway_child) =
        start_gateway_with_port(&temp, write_caddyfile_gatewayfile, upstream_addr);

    let (status, response_headers, response_text_result) =
        websocket_text_roundtrip(gateway_port, "hdd.ink", "hello");
    let upstream_request = last_request.lock().expect("lock last request").clone();

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();
    stop_upstream(upstream_stop, upstream_handle);

    assert!(
        status == 101
            && response_headers
                .windows(b"Upgrade: websocket".len())
                .any(|window| window.eq_ignore_ascii_case(b"Upgrade: websocket"))
            && response_text_result.as_deref() == Ok("echo: hello")
            && upstream_count.load(Ordering::SeqCst) == 1
            && upstream_request
                .to_ascii_lowercase()
                .contains("upgrade: websocket")
            && upstream_request.contains("websocket-text: hello"),
        "status={status}; response_headers={}; response_text_result={response_text_result:?}; upstream_request={upstream_request}",
        String::from_utf8_lossy(&response_headers)
    );
}

#[test]
fn gateway_should_stop_websocket_upgrade_when_upstream_headers_are_too_large() {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_count, last_request, upstream_stop, upstream_handle) =
        start_oversized_websocket_header_upstream();
    let (gateway_port, _gatewayfile, mut gateway_child) =
        start_gateway_with_port(&temp, write_caddyfile_gatewayfile, upstream_addr);

    let response_result = websocket_upgrade_first_read(gateway_port, "hdd.ink");
    let upstream_request = last_request.lock().expect("lock last request").clone();

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();
    stop_upstream(upstream_stop, upstream_handle);

    match response_result {
        Ok(response) => assert!(
            !response.starts_with(b"HTTP/1.1 101"),
            "gateway accepted oversized upstream websocket headers: {}",
            String::from_utf8_lossy(&response)
        ),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            panic!("gateway did not reject oversized upstream websocket headers promptly")
        }
        Err(_) => {}
    }
    assert!(
        upstream_count.load(Ordering::SeqCst) == 1
            && upstream_request
                .to_ascii_lowercase()
                .contains("upgrade: websocket"),
        "upstream_count={}; upstream_request={upstream_request}",
        upstream_count.load(Ordering::SeqCst)
    );
}

#[test]
fn gateway_should_stream_sse_events_without_waiting_for_close() {
    let temp = TempDir::new().expect("tempdir");
    let (upstream_addr, upstream_count, last_request, upstream_stop, upstream_handle) =
        start_sse_upstream();
    let (gateway_port, _gatewayfile, mut gateway_child) =
        start_gateway_with_port(&temp, write_caddyfile_gatewayfile, upstream_addr);

    let (status, body) = sse_events_until_second(gateway_port, "hdd.ink");
    let upstream_request = last_request.lock().expect("lock last request").clone();

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();
    stop_upstream(upstream_stop, upstream_handle);

    let first = body
        .windows(b"data: first".len())
        .position(|window| window == b"data: first");
    let second = body
        .windows(b"data: second".len())
        .position(|window| window == b"data: second");

    assert!(
        status == 200
            && first.is_some()
            && second.is_some()
            && first < second
            && upstream_count.load(Ordering::SeqCst) == 1
            && upstream_request.contains("Accept: text/event-stream"),
        "status={status}; body={}; upstream_request={upstream_request}",
        String::from_utf8_lossy(&body)
    );
}

#[test]
fn gateway_should_serve_static_files_from_caddyfile_root() {
    let temp = TempDir::new().expect("tempdir");
    let static_root = temp.path().join("site");
    std::fs::create_dir_all(&static_root).expect("create static root");
    std::fs::write(static_root.join("index.html"), "<h1>home</h1>").expect("write index");
    std::fs::write(static_root.join("hello.txt"), "hello static").expect("write file");
    let (gateway_port, _gatewayfile, mut gateway_child) = start_gateway_from_caddyfile_with_env(
        &temp,
        |dir, gateway_port| write_static_caddyfile(dir, gateway_port, &static_root),
        &[],
    );

    let (index_status, index_resp) = http_get_path(gateway_port, "static.example.test", "/");
    let (file_status, file_resp) = http_get_path(gateway_port, "static.example.test", "/hello.txt");

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();

    assert!(
        index_status == 200
            && index_resp.ends_with(b"<h1>home</h1>")
            && file_status == 200
            && file_resp.ends_with(b"hello static"),
        "index_status={index_status}; index_resp={}; file_status={file_status}; file_resp={}",
        String::from_utf8_lossy(&index_resp),
        String::from_utf8_lossy(&file_resp)
    );
}

#[test]
fn gateway_should_return_static_file_errors_without_escaping_root() {
    let temp = TempDir::new().expect("tempdir");
    let static_root = temp.path().join("site");
    std::fs::create_dir_all(&static_root).expect("create static root");
    std::fs::write(static_root.join("index.html"), "inside root").expect("write index");
    std::fs::write(temp.path().join("outside.txt"), "outside root").expect("write outside file");
    let (gateway_port, _gatewayfile, mut gateway_child) = start_gateway_from_caddyfile_with_env(
        &temp,
        |dir, gateway_port| write_static_caddyfile(dir, gateway_port, &static_root),
        &[],
    );

    let (missing_status, missing_resp) =
        http_get_path(gateway_port, "static.example.test", "/missing.txt");
    let (traversal_status, traversal_resp) =
        http_get_path(gateway_port, "static.example.test", "/%2e%2e/outside.txt");

    let _ = gateway_child.kill();
    let _ = gateway_child.wait();

    assert!(
        missing_status == 404
            && missing_resp.ends_with(b"not found\n")
            && traversal_status == 403
            && !traversal_resp.ends_with(b"outside root"),
        "missing_status={missing_status}; missing_resp={}; traversal_status={traversal_status}; traversal_resp={}",
        String::from_utf8_lossy(&missing_resp),
        String::from_utf8_lossy(&traversal_resp)
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
fn gateway_should_report_ready_for_healthy_and_warning_only_config() {
    let healthy = TestEnv::new_with_caddyfile();
    let (healthy_status, healthy_resp) =
        http_get_path(healthy.gateway_port, "example.com", "/ready");

    let warning_only = TestEnv::new_with_gatewayfile(write_warning_only_caddyfile_gatewayfile);
    let (warning_status, warning_resp) =
        http_get_path(warning_only.gateway_port, "example.com", "/ready");

    assert!(
        healthy_status == 200
            && healthy_resp.ends_with(b"ready\n")
            && warning_status == 200
            && String::from_utf8_lossy(&warning_resp).contains("encode")
            && String::from_utf8_lossy(&warning_resp).contains("warning"),
        "healthy_status={healthy_status}; healthy_resp={}; warning_status={warning_status}; warning_resp={}",
        String::from_utf8_lossy(&healthy_resp),
        String::from_utf8_lossy(&warning_resp)
    );
}

#[test]
fn gateway_should_keep_health_live_but_ready_degraded_for_security_sensitive_config() {
    let env = TestEnv::new_with_gatewayfile(write_degraded_caddyfile_gatewayfile);
    let (health_status, health_resp) = http_get_path(env.gateway_port, "example.com", "/health");
    let (ready_status, ready_resp) = http_get_path(env.gateway_port, "example.com", "/ready");
    let ready_body = String::from_utf8_lossy(&ready_resp);

    assert!(
        health_status == 200
            && health_resp.ends_with(b"ok\n")
            && ready_status == 503
            && ready_body.contains("not ready")
            && ready_body.contains("site=secure.example")
            && ready_body.contains("directive=basicauth")
            && ready_body.contains("line=7")
            && ready_body.contains("impact=degrades_readiness"),
        "health_status={health_status}; health_resp={}; ready_status={ready_status}; ready_resp={ready_body}",
        String::from_utf8_lossy(&health_resp)
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
