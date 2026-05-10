use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use openssl::x509::X509;
use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::prelude::{HttpPeer, ProxyHttp, Session};
use pingora::protocols::http::server::Session as DownstreamSession;
use pingora::protocols::raw_connect::ProxyDigest;
use pingora::protocols::tls::CaType;
use pingora::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, Stream,
    TimingDigest, UniqueID, UniqueIDType,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::acme::{Http01ChallengeStore, Http01Decision, Http01Request, Http01RequestPolicy};
use crate::config::{GatewayConfig, RouteKind, UpstreamConfig};
use crate::gateway_plan::{
    ActiveGatewayPlan, GatewayPlan, HandlerPlan, SharedGatewayPlan, UpstreamTransport,
};
use crate::metrics::METRICS;
use crate::reload::GatewayRuntimeState;
use crate::routing::{RouteMatch, normalize_host};

const MAX_WEBSOCKET_UPSTREAM_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

pub struct GatewayProxy {
    config: GatewayProxyConfig,
    http01_store: Http01ChallengeStore,
}

#[derive(Clone)]
enum GatewayProxyConfig {
    Static {
        config: Arc<GatewayConfig>,
        active_plan: Arc<ActiveGatewayPlan>,
    },
    Runtime(Arc<GatewayRuntimeState>),
}

impl GatewayProxyConfig {
    fn current(&self) -> GatewayConfig {
        match self {
            Self::Static { config, .. } => config.as_ref().clone(),
            Self::Runtime(runtime_state) => runtime_state.config(),
        }
    }

    fn current_plan(&self) -> SharedGatewayPlan {
        match self {
            Self::Static { active_plan, .. } => active_plan.snapshot(),
            Self::Runtime(runtime_state) => runtime_state.plan_snapshot(),
        }
    }
}

#[derive(Debug)]
pub struct RequestCtx {
    started_at: Instant,
    host: Option<String>,
    original_host: Option<String>,
    path: String,
    request_id: Option<String>,
    route_match: RouteMatch,
    route_kind: Option<RouteKind>,
    upstream: Option<String>,
    upstream_transport: Option<UpstreamTransport>,
    selected_upstream: Option<UpstreamConfig>,
    static_root: Option<PathBuf>,
    acme_http01: bool,
    http01_responded: bool,
}

impl RequestCtx {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            host: None,
            original_host: None,
            path: String::new(),
            request_id: None,
            route_match: RouteMatch::NoMatch,
            route_kind: None,
            upstream: None,
            upstream_transport: None,
            selected_upstream: None,
            static_root: None,
            acme_http01: false,
            http01_responded: false,
        }
    }

    fn path_for_log(path: &str) -> String {
        const PREFIX: &str = "/.well-known/acme-challenge/";
        if path.starts_with(PREFIX) {
            format!("{PREFIX}<redacted>")
        } else {
            path.to_owned()
        }
    }
}

impl GatewayProxy {
    pub fn new(config: GatewayConfig) -> Self {
        let plan = GatewayPlan::from_config(&config)
            .expect("validated config must compile to Gateway Plan");
        Self {
            config: GatewayProxyConfig::Static {
                config: Arc::new(config),
                active_plan: Arc::new(ActiveGatewayPlan::new(plan)),
            },
            http01_store: Http01ChallengeStore::default(),
        }
    }

    pub fn from_runtime_state(runtime_state: Arc<GatewayRuntimeState>) -> Self {
        let http01_store = runtime_state.http01_store();
        Self {
            config: GatewayProxyConfig::Runtime(runtime_state),
            http01_store,
        }
    }

    pub fn http01_store(&self) -> Http01ChallengeStore {
        self.http01_store.clone()
    }

    pub fn active_upstream_for_host(&self, host: &str) -> Option<String> {
        let plan = self.config.current_plan();
        plan.select_route(host, "/")
            .and_then(|selection| match selection.handler {
                HandlerPlan::ReverseProxy { upstream } => Some(upstream.address),
                HandlerPlan::StaticFiles { .. } => None,
            })
    }

    fn readiness_response(plan: &GatewayPlan) -> (StatusCode, String) {
        let health = plan.config_health();
        let mut body = if health.ready {
            "ready\n".to_owned()
        } else {
            "not ready\n".to_owned()
        };

        for diagnostic in plan.compatibility_diagnostics() {
            let site = diagnostic.site.as_deref().unwrap_or("<global>");
            body.push_str(&format!(
                "site={site} directive={} line={} impact={} message={}\n",
                diagnostic.directive,
                diagnostic.line,
                diagnostic.impact.as_str(),
                diagnostic.message
            ));
        }

        let status = if health.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (status, body)
    }

    async fn respond_text(
        session: &mut Session,
        status: StatusCode,
        content_type: &str,
        body: impl Into<Bytes>,
    ) -> pingora::Result<()> {
        let bytes = body.into();
        let mut resp = ResponseHeader::build(status, Some(bytes.len()))?;
        resp.insert_header(header::CONTENT_TYPE, content_type)?;
        resp.insert_header(header::CACHE_CONTROL, "no-store")?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(bytes), true).await
    }

    async fn respond_bytes(
        session: &mut Session,
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
    ) -> pingora::Result<()> {
        let bytes = Bytes::from(body);
        let mut resp = ResponseHeader::build(status, Some(bytes.len()))?;
        resp.insert_header(header::CONTENT_TYPE, content_type)?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(bytes), true).await
    }

    async fn serve_static_file(
        session: &mut Session,
        root: &Path,
        request_path: &str,
    ) -> pingora::Result<()> {
        let Some(file_path) = safe_static_file_path(root, request_path) else {
            return Self::respond_text(session, StatusCode::FORBIDDEN, "text/plain", "forbidden\n")
                .await;
        };

        match std::fs::read(&file_path) {
            Ok(body) => {
                let content_type = static_content_type(&file_path);
                Self::respond_bytes(session, StatusCode::OK, content_type, body).await
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Self::respond_text(session, StatusCode::NOT_FOUND, "text/plain", "not found\n")
                    .await
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                Self::respond_text(session, StatusCode::FORBIDDEN, "text/plain", "forbidden\n")
                    .await
            }
            Err(_) => {
                Self::respond_text(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain",
                    "static file error\n",
                )
                .await
            }
        }
    }

    async fn proxy_websocket_upgrade(
        session: &mut Session,
        upstream: &UpstreamConfig,
        original_host: &str,
    ) -> pingora::Result<()> {
        let mut upstream_stream = tokio::net::TcpStream::connect(upstream.addr.as_str())
            .await
            .map_err(|err| {
                pingora::Error::because(pingora::ConnectError, "connecting websocket upstream", err)
            })?;

        let request_bytes = websocket_upstream_request(session, upstream, original_host)?;
        upstream_stream
            .write_all(&request_bytes)
            .await
            .map_err(|err| {
                pingora::Error::because(
                    pingora::WriteError,
                    "writing websocket upstream request",
                    err,
                )
            })?;
        upstream_stream.flush().await.map_err(|err| {
            pingora::Error::because(
                pingora::WriteError,
                "flushing websocket upstream request",
                err,
            )
        })?;

        let response_header = read_websocket_upstream_response(&mut upstream_stream).await?;
        if response_header.status != StatusCode::SWITCHING_PROTOCOLS {
            session
                .write_response_header(Box::new(response_header), true)
                .await?;
            return Ok(());
        }
        session
            .write_response_header(Box::new(response_header), false)
            .await?;
        let downstream_stream = take_downstream_stream(session)?;

        tunnel_websocket(downstream_stream, upstream_stream).await
    }
}

fn ssl_cert_file_ca() -> pingora::Result<Option<Arc<CaType>>> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else {
        return Ok(None);
    };
    let pem = std::fs::read(&path).map_err(|err| {
        pingora::Error::because(
            pingora::ReadError,
            "reading SSL_CERT_FILE for grpcs upstream CA",
            err,
        )
    })?;
    let certs = X509::stack_from_pem(&pem).map_err(|err| {
        pingora::Error::because(
            pingora::InternalError,
            "parsing SSL_CERT_FILE for grpcs upstream CA",
            err,
        )
    })?;
    Ok(Some(Arc::new(certs.into_boxed_slice())))
}

fn is_websocket_upgrade_request(request: &RequestHeader) -> bool {
    request.headers.get(header::UPGRADE).is_some()
        || request.headers.get("sec-websocket-key").is_some()
}

fn websocket_upstream_request(
    session: &Session,
    upstream: &UpstreamConfig,
    original_host: &str,
) -> pingora::Result<Vec<u8>> {
    let mut upstream_request = session.req_header().clone();
    upstream_request.set_version(http::Version::HTTP_11);
    let upstream_host = upstream.host_header.as_deref().unwrap_or(original_host);
    upstream_request.insert_header(header::HOST, upstream_host)?;
    upstream_request.insert_header("X-Forwarded-Host", original_host)?;

    let mut request = Vec::new();
    request.extend_from_slice(upstream_request.method.as_str().as_bytes());
    request.push(b' ');
    request.extend_from_slice(upstream_request.raw_path());
    request.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in &upstream_request.headers {
        request.extend_from_slice(name.as_str().as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

async fn read_websocket_upstream_response(
    upstream_stream: &mut tokio::net::TcpStream,
) -> pingora::Result<ResponseHeader> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw.len() >= MAX_WEBSOCKET_UPSTREAM_RESPONSE_HEADER_BYTES {
            return pingora::Error::e_explain(
                pingora::InvalidHTTPHeader,
                "websocket upstream response headers exceeded limit",
            );
        }

        let read = upstream_stream.read(&mut byte).await.map_err(|err| {
            pingora::Error::because(
                pingora::ReadError,
                "reading websocket upstream response",
                err,
            )
        })?;
        if read == 0 {
            return pingora::Error::e_explain(
                pingora::ConnectionClosed,
                "websocket upstream closed before response headers",
            );
        }
        raw.push(byte[0]);
    }

    let raw = std::str::from_utf8(&raw).map_err(|err| {
        pingora::Error::because(
            pingora::InvalidHTTPHeader,
            "websocket upstream response was not utf-8",
            err,
        )
    })?;
    let mut lines = raw.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        pingora::Error::explain(
            pingora::InvalidHTTPHeader,
            "websocket upstream response missing status line",
        )
    })?;
    let mut status_parts = status_line.split_whitespace();
    let version = match status_parts.next() {
        Some("HTTP/1.1") => http::Version::HTTP_11,
        Some("HTTP/1.0") => http::Version::HTTP_10,
        _ => {
            return pingora::Error::e_explain(
                pingora::InvalidHTTPHeader,
                "websocket upstream response had unsupported HTTP version",
            );
        }
    };
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            pingora::Error::explain(
                pingora::InvalidHTTPHeader,
                "websocket upstream response had invalid status code",
            )
        })?;
    let status = StatusCode::from_u16(status_code).map_err(|err| {
        pingora::Error::because(
            pingora::InvalidHTTPHeader,
            "websocket upstream response had invalid status code",
            err,
        )
    })?;
    let mut response = ResponseHeader::build(status, None)?;
    response.set_version(version);
    for line in lines.take_while(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once(':') {
            response.append_header(name.trim().to_owned(), value.trim().to_owned())?;
        }
    }
    Ok(response)
}

fn take_downstream_stream(session: &mut Session) -> pingora::Result<Stream> {
    let (dummy, _peer) = tokio::io::duplex(1);
    let dummy_session = DownstreamSession::new_http1(Box::new(DummyIo(dummy)));
    let downstream_session = std::mem::replace(&mut *session.downstream_session, dummy_session);
    match downstream_session {
        DownstreamSession::H1(h1) => Ok(h1.into_inner()),
        _ => pingora::Error::e_explain(
            pingora::InternalError,
            "websocket upgrade tunnel requires an HTTP/1 downstream session",
        ),
    }
}

async fn tunnel_websocket(
    mut downstream_stream: Stream,
    mut upstream_stream: tokio::net::TcpStream,
) -> pingora::Result<()> {
    tokio::io::copy_bidirectional(&mut downstream_stream, &mut upstream_stream)
        .await
        .map_err(|err| {
            pingora::Error::because(
                pingora::ReadError,
                "tunneling websocket upgraded connection",
                err,
            )
        })?;
    Ok(())
}

#[derive(Debug)]
struct DummyIo(tokio::io::DuplexStream);

impl AsyncRead for DummyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DummyIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for DummyIo {
    async fn shutdown(&mut self) {
        let _ = AsyncWriteExt::shutdown(&mut self.0).await;
    }
}

impl UniqueID for DummyIo {
    fn id(&self) -> UniqueIDType {
        0
    }
}

impl Ssl for DummyIo {}

#[async_trait]
impl Peek for DummyIo {}

impl GetTimingDigest for DummyIo {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for DummyIo {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for DummyIo {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}

fn safe_static_file_path(root: &Path, request_path: &str) -> Option<PathBuf> {
    let root = root.canonicalize().ok()?;
    let decoded = percent_decode_path(request_path)?;
    if decoded.contains('\0') {
        return None;
    }

    let mut candidate = root.clone();
    for segment in decoded.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        candidate.push(segment);
    }

    if request_path.ends_with('/') || candidate.is_dir() {
        candidate.push("index.html");
    }

    match candidate.canonicalize() {
        Ok(canonical) if canonical.starts_with(&root) && canonical.is_file() => Some(canonical),
        Ok(_) => None,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some(candidate),
        Err(_) => None,
    }
}

fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex_value(high)? * 16 + hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn static_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[async_trait]
impl ProxyHttp for GatewayProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx::new()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let req = session.req_header();
        let path = req.uri.path().to_owned();
        ctx.path = RequestCtx::path_for_log(&path);
        METRICS.record_request();
        ctx.request_id = req
            .headers
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        match path.as_str() {
            "/health" => {
                Self::respond_text(session, StatusCode::OK, "text/plain", "ok\n").await?;
                return Ok(true);
            }
            "/ready" => {
                let plan = self.config.current_plan();
                let (status, body) = Self::readiness_response(&plan);
                Self::respond_text(session, status, "text/plain", body).await?;
                return Ok(true);
            }
            "/metrics" => {
                Self::respond_text(
                    session,
                    StatusCode::OK,
                    "text/plain; version=0.0.4; charset=utf-8",
                    METRICS.render_prometheus(),
                )
                .await?;
                return Ok(true);
            }
            _ => {}
        }

        let host = req
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri.authority().map(|a| a.as_str()));

        let Some(host) = host else {
            tracing::warn!(
                event = "routing",
                path = %ctx.path,
                request_id = ctx.request_id.as_deref(),
                "missing Host header"
            );
            session.respond_error(400).await?;
            return Ok(true);
        };

        ctx.host = normalize_host(host);
        ctx.original_host = Some(host.to_owned());
        let log_host = ctx.host.as_deref().unwrap_or("<unparseable>");

        let config = self.config.current();
        let plan = self.config.current_plan();
        let route_selection = plan.select_route(host, &path);
        let route_match = if route_selection.is_some() {
            RouteMatch::Matched
        } else {
            RouteMatch::NoMatch
        };
        if let Some(selection) = route_selection {
            ctx.route_kind = selection.route_kind;
            match selection.handler {
                HandlerPlan::ReverseProxy { upstream } => {
                    ctx.upstream = Some(upstream.address.clone());
                    ctx.upstream_transport = Some(upstream.transport);
                    ctx.selected_upstream = Some(upstream.to_upstream_config());
                }
                HandlerPlan::StaticFiles { root } => {
                    ctx.static_root = Some(root);
                }
            }
        }
        ctx.route_match = route_match;

        if path.starts_with("/.well-known/acme-challenge/") {
            ctx.acme_http01 = true;
            tracing::info!(
                event = "acme_http01",
                host = %log_host,
                path = %ctx.path,
                request_id = ctx.request_id.as_deref(),
                "received http-01 request"
            );
        }

        if config.acme.http_01 {
            let policy = Http01RequestPolicy::new(self.http01_store.clone());
            match policy.authorize(Http01Request::new(&path, host), route_match) {
                Http01Decision::RespondWithBody(body) => {
                    ctx.http01_responded = true;
                    METRICS.record_http01_response();
                    Self::respond_text(session, StatusCode::OK, "text/plain", body).await?;
                    tracing::info!(
                        event = "acme_http01",
                        host = %log_host,
                        path = %ctx.path,
                        request_id = ctx.request_id.as_deref(),
                        "responded to http-01 request"
                    );
                    return Ok(true);
                }
                Http01Decision::RouteNormally => {}
            }
        }

        match route_match {
            RouteMatch::Matched => {
                METRICS.record_route_match();
                tracing::info!(
                    event = "routing",
                    host = %log_host,
                    path = %ctx.path,
                    request_id = ctx.request_id.as_deref(),
                    route_kind = ?ctx.route_kind,
                    upstream = ctx.upstream.as_deref(),
                    "matched route"
                );
                if let Some(root) = ctx.static_root.clone() {
                    Self::serve_static_file(session, &root, &path).await?;
                    return Ok(true);
                }
                if is_websocket_upgrade_request(session.req_header())
                    && let Some(upstream) = ctx.selected_upstream.clone()
                    && !upstream.tls
                {
                    let original_host = ctx.original_host.clone().unwrap_or_default();
                    Self::proxy_websocket_upgrade(session, &upstream, &original_host).await?;
                    return Ok(true);
                }
                Ok(false)
            }
            RouteMatch::NoMatch => {
                METRICS.record_route_rejection();
                tracing::info!(
                    event = "routing",
                    host = %log_host,
                    path = %ctx.path,
                    request_id = ctx.request_id.as_deref(),
                    status = 404u16,
                    "rejected non-matching host"
                );
                session.respond_error(404).await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let upstream = ctx
            .selected_upstream
            .clone()
            .expect("matched routes must select an upstream");
        ctx.upstream = Some(upstream.addr.clone());
        tracing::info!(
            event = "proxy_upstream",
            host = ctx.host.as_deref(),
            path = %ctx.path,
            request_id = ctx.request_id.as_deref(),
            route_kind = ?ctx.route_kind,
            upstream = %upstream.addr,
            upstream_tls = upstream.tls,
            "selected upstream peer"
        );
        let server_name = upstream.server_name.clone().unwrap_or_default();
        let mut peer = HttpPeer::new(upstream.addr.as_str(), upstream.tls, server_name);
        if matches!(
            ctx.upstream_transport,
            Some(UpstreamTransport::H2c | UpstreamTransport::Grpcs)
        ) {
            peer.options.set_http_version(2, 2);
            peer.options.max_h2_streams = 128;
        }
        if matches!(ctx.upstream_transport, Some(UpstreamTransport::Grpcs)) {
            peer.options.ca = ssl_cert_file_ca()?;
        }
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if is_websocket_upgrade_request(session.req_header()) {
            upstream_request.set_version(http::Version::HTTP_11);
        }
        if let Some(host) = ctx.original_host.as_deref() {
            let upstream_host = ctx
                .selected_upstream
                .as_ref()
                .and_then(|upstream| upstream.host_header.as_deref())
                .unwrap_or(host);
            upstream_request.insert_header("Host", upstream_host)?;
            upstream_request.insert_header("X-Forwarded-Host", host)?;
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&pingora::Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        let status = session
            .response_written()
            .map(|h| h.status.as_u16())
            .unwrap_or(0);
        if e.is_some() {
            METRICS.record_upstream_error();
        }
        let latency_ms = ctx.started_at.elapsed().as_millis();
        let host = ctx.host.as_deref().unwrap_or("<unknown>");

        tracing::info!(
            event = "access",
            host = %host,
            path = %ctx.path,
            request_id = ctx.request_id.as_deref(),
            route_match = ?ctx.route_match,
            route_kind = ?ctx.route_kind,
            upstream = ctx.upstream.as_deref(),
            status,
            latency_ms,
            acme_http01 = ctx.acme_http01,
            http01_responded = ctx.http01_responded,
            error = e.map(|err| err.to_string()).as_deref(),
            "request complete"
        );
    }
}
