use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::{env, path::PathBuf};

fn read_http_response(mut stream: TcpStream) -> String {
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

fn send_http_request(addr: &str, host: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to gateway");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");
    read_http_response(stream)
}

fn wait_for_listen(addr: &str, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway did not start listening on {addr} within {timeout:?}");
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let mut req_buf = [0u8; 4096];
            let _ = stream.read(&mut req_buf);

            let body = b"upstream-ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    port
}

fn allocate_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind for port allocation")
        .local_addr()
        .unwrap()
        .port()
}

fn write_gatewayfile(
    temp_dir: &tempfile::TempDir,
    gw_port: u16,
    upstream_port: u16,
) -> std::path::PathBuf {
    let gatewayfile_path = temp_dir.path().join("Gatewayfile");
    let contents = format!(
        r#"
listeners:
  http:
    bind: "127.0.0.1:{gw_port}"
  https:
    bind: "127.0.0.1:0"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:{upstream_port}"
      tls: false

tls:
  ask_url: "http://127.0.0.1:9000/ask"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: true

cert_cache:
  dir: "./cert-cache"

reload:
  enabled: true

logging:
  level: "info"
"#
    );
    std::fs::write(&gatewayfile_path, contents).expect("write Gatewayfile");
    gatewayfile_path
}

fn start_gateway(gatewayfile_path: &std::path::Path) -> (ChildGuard, mpsc::Receiver<String>) {
    let bin = env::var_os("CARGO_BIN_EXE_stellar_gateway")
        .or_else(|| env::var_os("CARGO_BIN_EXE_stellar-gateway"))
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
        });

    let mut child = Command::new(bin)
        .arg("--gatewayfile")
        .arg(gatewayfile_path)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway");

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let (tx, rx) = mpsc::channel();
    let stdout_tx = tx.clone();
    thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut buf = [0u8; 1024];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = stdout_tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
        }
    });
    let stderr_tx = tx.clone();
    thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut buf = [0u8; 1024];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = stderr_tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
        }
    });
    drop(tx);

    (ChildGuard { child }, rx)
}

#[test]
fn logs_should_redact_http01_challenge_token() {
    let temp_dir = tempfile::tempdir().unwrap();
    let upstream_port = start_upstream();
    let gw_port = allocate_free_port();

    let gatewayfile_path = write_gatewayfile(&temp_dir, gw_port, upstream_port);
    let (gateway, logs_rx) = start_gateway(&gatewayfile_path);
    let gw_addr = format!("127.0.0.1:{gw_port}");
    wait_for_listen(&gw_addr, Duration::from_secs(2));

    let token = "VERY_SECRET_TOKEN_123";
    let _ = send_http_request(
        &gw_addr,
        "demo.page.hdd.ink",
        &format!("/.well-known/acme-challenge/{token}"),
    );

    let start = Instant::now();
    let mut logs = String::new();
    while start.elapsed() < Duration::from_secs(2) && !logs.contains("acme_http01") {
        match logs_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(chunk) => logs.push_str(&chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(gateway);
    for chunk in logs_rx.try_iter() {
        logs.push_str(&chunk);
    }

    assert!(
        logs.contains("acme_http01") && !logs.contains(token),
        "captured logs:\n{logs}"
    );
}
