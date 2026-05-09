use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::cert_cache::CertificateMaterial;
use crate::routing::RouteMatch;

const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ChallengeKey {
    AnyHost(String),
    HostToken { host: String, token: String },
}

#[derive(Debug, Clone, Default)]
pub struct Http01ChallengeStore {
    inner: Arc<RwLock<HashMap<ChallengeKey, String>>>,
}

#[derive(Debug, Clone, Default)]
pub struct TlsAlpnChallengeStore {
    inner: Arc<RwLock<HashMap<String, CertificateMaterial>>>,
}

impl TlsAlpnChallengeStore {
    pub fn set_for_host(&self, host: &str, material: CertificateMaterial) {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(host.to_owned(), material);
        tracing::info!(
            event = "acme_tls_alpn01",
            host = %host,
            decision = "stored_host_challenge",
            "stored host-scoped tls-alpn-01 challenge"
        );
    }

    pub fn get_for_host(&self, host: &str) -> Option<CertificateMaterial> {
        let guard = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(host).cloned()
    }

    pub fn clear_for_host(&self, host: &str) {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(host);
        tracing::info!(
            event = "acme_tls_alpn01",
            host = %host,
            decision = "cleared_challenge",
            "cleared tls-alpn-01 challenge"
        );
    }
}

impl Http01ChallengeStore {
    pub fn set(&self, token: &str, body: &str) {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(ChallengeKey::AnyHost(token.to_owned()), body.to_owned());
        tracing::info!(
            event = "acme_http01",
            token_length = token.len(),
            body_length = body.len(),
            decision = "stored_challenge",
            "stored http-01 challenge"
        );
    }

    pub fn set_for_host(&self, host: &str, token: &str, body: &str) {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(
            ChallengeKey::HostToken {
                host: host.to_owned(),
                token: token.to_owned(),
            },
            body.to_owned(),
        );
        tracing::info!(
            event = "acme_http01",
            host = %host,
            token_length = token.len(),
            body_length = body.len(),
            decision = "stored_host_challenge",
            "stored host-scoped http-01 challenge"
        );
    }

    pub fn clear(&self, token: &str) {
        let mut guard = match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|key, _| match key {
            ChallengeKey::AnyHost(existing) => existing != token,
            ChallengeKey::HostToken {
                token: existing, ..
            } => existing != token,
        });
        tracing::info!(
            event = "acme_http01",
            token_length = token.len(),
            decision = "cleared_challenge",
            "cleared http-01 challenge"
        );
    }

    pub fn get(&self, token: &str) -> Option<String> {
        let guard = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .get(&ChallengeKey::AnyHost(token.to_owned()))
            .or_else(|| {
                guard.iter().find_map(|(key, body)| match key {
                    ChallengeKey::HostToken {
                        token: existing, ..
                    } if existing == token => Some(body),
                    _ => None,
                })
            })
            .cloned()
    }

    fn get_for_host(&self, host: &str, token: &str) -> Option<String> {
        let guard = match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .get(&ChallengeKey::HostToken {
                host: host.to_owned(),
                token: token.to_owned(),
            })
            .cloned()
    }
}

fn http01_token_for_path(path: &str) -> Option<&str> {
    let token = path.strip_prefix(HTTP01_PREFIX)?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    Some(token)
}

pub fn http01_body_for_path(path: &str, store: &Http01ChallengeStore) -> Option<String> {
    let token = http01_token_for_path(path)?;
    store.get(token)
}

#[derive(Debug, Clone)]
pub struct Http01Request {
    path: String,
    host: String,
}

impl Http01Request {
    pub fn new(path: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http01Decision {
    RespondWithBody(String),
    RouteNormally,
}

#[derive(Debug, Clone)]
pub struct Http01RequestPolicy {
    store: Http01ChallengeStore,
}

impl Http01RequestPolicy {
    pub fn new(store: Http01ChallengeStore) -> Self {
        Self { store }
    }

    pub fn authorize(&self, req: Http01Request, route_match: RouteMatch) -> Http01Decision {
        let decision = match http01_token_for_path(req.path())
            .and_then(|token| self.store.get_for_host(req.host(), token))
        {
            Some(body) => Http01Decision::RespondWithBody(body),
            None => Http01Decision::RouteNormally,
        };
        tracing::info!(
            event = "acme_http01",
            host = %req.host(),
            path = %redacted_http01_path(req.path()),
            route_match = ?route_match,
            decision = http01_decision_label(&decision),
            "acme_http01"
        );
        decision
    }
}

fn redacted_http01_path(path: &str) -> String {
    match path.strip_prefix(HTTP01_PREFIX) {
        Some(_) => format!("{HTTP01_PREFIX}<redacted>"),
        None => path.to_owned(),
    }
}

fn http01_decision_label(decision: &Http01Decision) -> &'static str {
    match decision {
        Http01Decision::RespondWithBody(_) => "respond_with_body",
        Http01Decision::RouteNormally => "route_normally",
    }
}
