use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use pingora::http::{RequestHeader, ResponseHeader, StatusCode};
use pingora::prelude::{HttpPeer, ProxyHttp, Session};

use crate::acme::{Http01ChallengeStore, Http01Decision, Http01Request, Http01RequestPolicy};
use crate::config::{GatewayConfig, RouteKind, UpstreamConfig};
use crate::metrics::METRICS;
use crate::reload::GatewayRuntimeState;
use crate::routing::{RouteMatch, normalize_host};

pub struct GatewayProxy {
    config: GatewayProxyConfig,
    http01_store: Http01ChallengeStore,
}

#[derive(Clone)]
enum GatewayProxyConfig {
    Static(Arc<GatewayConfig>),
    Runtime(Arc<GatewayRuntimeState>),
}

impl GatewayProxyConfig {
    fn current(&self) -> GatewayConfig {
        match self {
            Self::Static(config) => config.as_ref().clone(),
            Self::Runtime(runtime_state) => runtime_state.config(),
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
    selected_upstream: Option<UpstreamConfig>,
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
            selected_upstream: None,
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
        Self {
            config: GatewayProxyConfig::Static(Arc::new(config)),
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
        let config = self.config.current();
        config
            .routes
            .select_route(host)
            .map(|selection| selection.upstream.addr)
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
        let path = req.uri.path();
        ctx.path = RequestCtx::path_for_log(path);
        METRICS.record_request();
        ctx.request_id = req
            .headers
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_owned());

        match path {
            "/health" => {
                Self::respond_text(session, StatusCode::OK, "text/plain", "ok\n").await?;
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
        let route_selection = config.routes.select_route(host);
        let route_match = if route_selection.is_some() {
            RouteMatch::Matched
        } else {
            RouteMatch::NoMatch
        };
        if let Some(selection) = route_selection {
            ctx.route_kind = Some(selection.kind);
            ctx.upstream = Some(selection.upstream.addr.clone());
            ctx.selected_upstream = Some(selection.upstream);
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
            match policy.authorize(Http01Request::new(path, host), route_match) {
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
        let peer = HttpPeer::new(upstream.addr.as_str(), upstream.tls, server_name);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(host) = ctx.original_host.as_deref() {
            upstream_request.insert_header("Host", host)?;
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
