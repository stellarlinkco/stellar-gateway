use std::sync::Arc;
use std::time::Duration;
use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
};

use async_trait::async_trait;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::ssl::{AlpnError, NameType, SslRef, select_next_proto};
use thiserror::Error;
use url::Url;

use crate::reload::GatewayRuntimeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskDecision {
    Allow,
    Deny(AskDenyReason),
}

impl AskDecision {
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskDenyReason {
    Denied,
    Timeout,
    MalformedResponse,
    NetworkFailure,
}

impl AskDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Timeout => "timeout",
            Self::MalformedResponse => "malformed_response",
            Self::NetworkFailure => "network_failure",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AskClient {
    ask_url: Url,
    timeout: Duration,
}

#[derive(Debug, Error)]
pub enum AskClientBuildError {
    #[error("unsupported URL scheme")]
    UnsupportedUrlScheme,
}

pub struct GatewayTlsAccept {
    runtime_state: Arc<GatewayRuntimeState>,
}

impl GatewayTlsAccept {
    pub fn new(runtime_state: Arc<GatewayRuntimeState>) -> Self {
        Self { runtime_state }
    }

    fn cached_material_for_sni(&self, sni: &str) -> Option<crate::cert_cache::CertificateMaterial> {
        self.runtime_state.certificate_for(sni)
    }

    fn tls_alpn_challenge_material_for_sni(
        &self,
        sni: &str,
    ) -> Option<crate::cert_cache::CertificateMaterial> {
        self.runtime_state.tls_alpn_challenge_for(sni)
    }
}

#[async_trait]
impl TlsAccept for GatewayTlsAccept {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let Some(sni) = ssl.servername(NameType::HOST_NAME).map(ToOwned::to_owned) else {
            return;
        };
        let selected_alpn = ssl.selected_alpn_protocol();
        let (material, source) = match self.tls_alpn_challenge_material_for_sni(&sni) {
            Some(material) if should_use_tls_alpn_challenge(selected_alpn) => {
                (material, "tls-alpn-01")
            }
            _ => match self.cached_material_for_sni(&sni) {
                Some(material) => (material, "cache"),
                None => match self.runtime_state.certificate_for_sni(&sni).await {
                    Some(material) => (material, "issued"),
                    None => return,
                },
            },
        };
        let certificate = match X509::from_pem(material.certificate_pem().as_bytes()) {
            Ok(certificate) => certificate,
            Err(err) => {
                tracing::warn!(event = "tls_certificate_select", hostname = %sni, error = %err, "tls_certificate_select");
                return;
            }
        };
        let private_key = match PKey::<Private>::private_key_from_pem(
            material.private_key_pem().as_bytes(),
        ) {
            Ok(private_key) => private_key,
            Err(err) => {
                tracing::warn!(event = "tls_certificate_select", hostname = %sni, error = %err, "tls_certificate_select");
                return;
            }
        };
        if let Err(err) = ext::ssl_use_certificate(ssl, &certificate) {
            tracing::warn!(event = "tls_certificate_select", hostname = %sni, error = %err, "tls_certificate_select");
            return;
        }
        if let Err(err) = ext::ssl_use_private_key(ssl, &private_key) {
            tracing::warn!(event = "tls_certificate_select", hostname = %sni, error = %err, "tls_certificate_select");
            return;
        }
        tracing::info!(event = "tls_certificate_select", hostname = %sni, source, "tls_certificate_select");
    }
}

pub fn tls_accept_callbacks(runtime_state: Arc<GatewayRuntimeState>) -> TlsAcceptCallbacks {
    Box::new(GatewayTlsAccept::new(runtime_state))
}

pub fn tls_settings(runtime_state: Arc<GatewayRuntimeState>) -> pingora::Result<TlsSettings> {
    let mut settings = TlsSettings::with_callbacks(tls_accept_callbacks(runtime_state))?;
    settings.set_alpn_select_callback(select_gateway_alpn);
    Ok(settings)
}

fn select_gateway_alpn<'a>(
    _ssl: &mut SslRef,
    client_protocols: &'a [u8],
) -> std::result::Result<&'a [u8], AlpnError> {
    if client_protocols.is_empty() {
        return Err(AlpnError::NOACK);
    }
    select_next_proto(b"\x0aacme-tls/1\x02h2\x08http/1.1", client_protocols).ok_or(AlpnError::NOACK)
}

fn should_use_tls_alpn_challenge(selected_alpn: Option<&[u8]>) -> bool {
    matches!(selected_alpn, Some(protocol) if protocol == b"acme-tls/1")
}

impl AskClient {
    fn new(ask_url: Url, timeout: Duration) -> Self {
        Self { ask_url, timeout }
    }

    pub fn try_new(ask_url: Url, timeout: Duration) -> Result<Self, AskClientBuildError> {
        match ask_url.scheme() {
            "http" => Ok(Self::new(ask_url, timeout)),
            _ => Err(AskClientBuildError::UnsupportedUrlScheme),
        }
    }

    fn deny(hostname: &str, reason: AskDenyReason) -> AskDecision {
        tracing::warn!(
            event = "tls_ask_decision",
            hostname = %hostname,
            decision = "deny",
            reason_class = reason.as_str(),
            "tls_ask_decision"
        );
        AskDecision::Deny(reason)
    }

    pub fn authorize(&self, hostname: &str) -> AskDecision {
        let host = match self.ask_url.host_str() {
            Some(h) => h,
            None => return Self::deny(hostname, AskDenyReason::MalformedResponse),
        };
        let port = self.ask_url.port_or_known_default().unwrap_or(80);
        let addrs = match (host, port).to_socket_addrs() {
            Ok(addrs) => addrs,
            Err(_) => return Self::deny(hostname, AskDenyReason::NetworkFailure),
        };

        let mut last_error_kind = None;
        let mut stream = None;
        for addr in addrs {
            match std::net::TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(err) => last_error_kind = Some(err.kind()),
            }
        }
        let mut stream = match stream {
            Some(stream) => stream,
            None if last_error_kind == Some(std::io::ErrorKind::TimedOut) => {
                return Self::deny(hostname, AskDenyReason::Timeout);
            }
            None => return Self::deny(hostname, AskDenyReason::NetworkFailure),
        };

        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        let path = {
            let mut url = self.ask_url.clone();
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("domain", hostname);
            drop(pairs);

            let path = if url.path().is_empty() {
                "/"
            } else {
                url.path()
            };
            match url.query() {
                Some(q) => format!("{path}?{q}"),
                None => path.to_owned(),
            }
        };

        let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        if stream.write_all(req.as_bytes()).is_err() {
            return Self::deny(hostname, AskDenyReason::NetworkFailure);
        }

        let mut buf = [0u8; 1024];
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Self::deny(hostname, AskDenyReason::Timeout);
            }
            Err(_) => return Self::deny(hostname, AskDenyReason::NetworkFailure),
        };

        let text = String::from_utf8_lossy(&buf[..n]);
        let Some(first_line) = text.lines().next() else {
            return Self::deny(hostname, AskDenyReason::MalformedResponse);
        };
        let mut parts = first_line.split_whitespace();
        let _http_version = parts.next();
        let status = parts.next().and_then(|s| s.parse::<u16>().ok());
        let Some(status) = status else {
            return Self::deny(hostname, AskDenyReason::MalformedResponse);
        };

        if (200..300).contains(&status) {
            tracing::info!(
                event = "tls_ask_decision",
                hostname = %hostname,
                decision = "allow",
                status,
                "tls_ask_decision"
            );
            AskDecision::Allow
        } else {
            Self::deny(hostname, AskDenyReason::Denied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_alpn_challenge_material_requires_negotiated_acme_alpn() {
        assert!(!should_use_tls_alpn_challenge(None));
        assert!(!should_use_tls_alpn_challenge(Some(b"h2")));
        assert!(!should_use_tls_alpn_challenge(Some(b"http/1.1")));
        assert!(should_use_tls_alpn_challenge(Some(b"acme-tls/1")));
    }
}
