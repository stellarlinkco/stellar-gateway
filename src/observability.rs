#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalEvent {
    RoutingDecision,
    TlsAskDecision,
    AcmeHttp01Decision,
    CertificateCacheDecision,
    ProxyUpstreamDecision,
    ReloadAttempt,
}

impl OperationalEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoutingDecision => "route_authorization",
            Self::TlsAskDecision => "tls_ask_decision",
            Self::AcmeHttp01Decision => "acme_http01",
            Self::CertificateCacheDecision => "cert_cache_refresh",
            Self::ProxyUpstreamDecision => "proxy_upstream",
            Self::ReloadAttempt => "reload_certificates",
        }
    }
}

pub const fn required_event_kinds() -> [OperationalEvent; 6] {
    [
        OperationalEvent::RoutingDecision,
        OperationalEvent::TlsAskDecision,
        OperationalEvent::AcmeHttp01Decision,
        OperationalEvent::CertificateCacheDecision,
        OperationalEvent::ProxyUpstreamDecision,
        OperationalEvent::ReloadAttempt,
    ]
}
