use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::acme::{Http01ChallengeStore, TlsAlpnChallengeStore};
use crate::acme_issuer::{AcmeIssuer, InstantAcmeIssuer};
use crate::cert_cache::{CertificateCache, CertificateMaterial};
use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use crate::metrics::METRICS;
use crate::routing::normalize_host;
use crate::tls::{AskClient, AskDecision};

pub struct GatewayRuntimeState {
    gatewayfile_path: PathBuf,
    config: RwLock<GatewayConfig>,
    cert_cache: RwLock<CertificateCache>,
    http01_store: Http01ChallengeStore,
    tls_alpn_store: TlsAlpnChallengeStore,
    issuer: Arc<dyn AcmeIssuer>,
    issuance_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    config_version: AtomicU64,
    cert_cache_version: AtomicU64,
}

impl GatewayRuntimeState {
    pub fn new(
        config: GatewayConfig,
        gatewayfile_path: impl AsRef<Path>,
        now: SystemTime,
    ) -> Result<Self> {
        Self::new_with_issuer(
            config,
            gatewayfile_path,
            now,
            Arc::new(InstantAcmeIssuer::default()),
        )
    }

    pub fn new_with_issuer(
        config: GatewayConfig,
        gatewayfile_path: impl AsRef<Path>,
        now: SystemTime,
        issuer: Arc<dyn AcmeIssuer>,
    ) -> Result<Self> {
        let gatewayfile_path = gatewayfile_path.as_ref().to_path_buf();
        let cert_cache = CertificateCache::load(&config.cert_cache.dir, now)?;
        Ok(Self {
            gatewayfile_path,
            config: RwLock::new(config),
            cert_cache: RwLock::new(cert_cache),
            http01_store: Http01ChallengeStore::default(),
            tls_alpn_store: TlsAlpnChallengeStore::default(),
            issuer,
            issuance_locks: std::sync::Mutex::new(HashMap::new()),
            config_version: AtomicU64::new(1),
            cert_cache_version: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> GatewayConfig {
        match self.config.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn reload_config(&self) -> Result<()> {
        tracing::info!(
            event = "reload_config",
            gatewayfile = %self.gatewayfile_path.display(),
            config_version = self.config_version.load(Ordering::Relaxed),
            "reload_config"
        );
        let loaded = match GatewayConfig::load_from_path(&self.gatewayfile_path) {
            Ok(config) => config,
            Err(err) => {
                tracing::warn!(
                    event = "reload_config",
                    gatewayfile = %self.gatewayfile_path.display(),
                    config_version = self.config_version.load(Ordering::Relaxed),
                    error = %err,
                    "reload_config"
                );
                return Err(err);
            }
        };
        let mut guard = match self.config.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = loaded;
        let version = self.config_version.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!(
            event = "reload_config",
            gatewayfile = %self.gatewayfile_path.display(),
            config_version = version,
            "reload_config"
        );
        Ok(())
    }

    pub fn reload_certificates(&self, now: SystemTime) -> Result<()> {
        let config = self.config();
        tracing::info!(
            event = "reload_certificates",
            cache_dir = %config.cert_cache.dir.display(),
            cert_cache_version = self.cert_cache_version.load(Ordering::Relaxed),
            "reload_certificates"
        );
        let loaded = match CertificateCache::load(&config.cert_cache.dir, now) {
            Ok(cache) => cache,
            Err(err) => {
                tracing::warn!(
                    event = "reload_certificates",
                    cache_dir = %config.cert_cache.dir.display(),
                    cert_cache_version = self.cert_cache_version.load(Ordering::Relaxed),
                    error = %err,
                    "reload_certificates"
                );
                return Err(err);
            }
        };
        let mut guard = match self.cert_cache.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = loaded;
        let version = self.cert_cache_version.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!(
            event = "reload_certificates",
            cache_dir = %config.cert_cache.dir.display(),
            cert_cache_version = version,
            entries = guard.entry_count(),
            rejections = guard.rejection_count(),
            "reload_certificates"
        );
        Ok(())
    }

    pub fn certificate_for(&self, hostname: &str) -> Option<CertificateMaterial> {
        let guard = match self.cert_cache.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.lookup(hostname).map(|e| e.material().clone())
    }

    pub fn http01_store(&self) -> Http01ChallengeStore {
        self.http01_store.clone()
    }

    pub fn tls_alpn_challenge_for(&self, hostname: &str) -> Option<CertificateMaterial> {
        self.tls_alpn_store.get_for_host(hostname)
    }

    pub fn reload_if_enabled(&self, now: SystemTime) -> Result<()> {
        if !self.config().reload.enabled {
            tracing::info!(
                event = "reload",
                decision = "ignored",
                reason = "reload_disabled",
                "reload trigger ignored"
            );
            return Ok(());
        }
        match self
            .reload_config()
            .and_then(|_| self.reload_certificates(now))
        {
            Ok(()) => {
                METRICS.record_reload_success();
                Ok(())
            }
            Err(err) => {
                METRICS.record_reload_failure();
                Err(err)
            }
        }
    }

    pub async fn certificate_for_sni(&self, sni: &str) -> Option<CertificateMaterial> {
        if let Some(material) = self.certificate_for(sni) {
            tracing::info!(
                event = "tls_certificate_select",
                hostname = %sni,
                source = "cache",
                "tls_certificate_select"
            );
            return Some(material);
        }

        let hostname = match normalize_host(sni) {
            Some(hostname) => hostname,
            None => {
                tracing::warn!(
                    event = "tls_issuance_policy",
                    hostname = %sni,
                    decision = "deny",
                    reason_class = "invalid_hostname",
                    "tls_issuance_policy"
                );
                return None;
            }
        };

        let lock = {
            let mut guard = match self.issuance_locks.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard
                .entry(hostname.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().await;

        if let Some(material) = self.certificate_for(&hostname) {
            return Some(material);
        }

        let config = self.config();
        if !config.routes.is_routable_host(&hostname) {
            tracing::warn!(
                event = "tls_issuance_policy",
                hostname = %hostname,
                decision = "deny",
                reason_class = "route_mismatch",
                "tls_issuance_policy"
            );
            return None;
        }

        let client = match AskClient::try_new(
            config.tls.ask_url.clone(),
            std::time::Duration::from_secs(2),
        ) {
            Ok(client) => client,
            Err(err) => {
                tracing::warn!(
                    event = "tls_issuance_policy",
                    hostname = %hostname,
                    decision = "deny",
                    reason_class = "ask_client_error",
                    error = %err,
                    "tls_issuance_policy"
                );
                return None;
            }
        };
        if !matches!(client.authorize(&hostname), AskDecision::Allow) {
            return None;
        }

        METRICS.record_cert_issuance_attempt();
        let entry = match self
            .issuer
            .issue_certificate(&config, &hostname, &self.http01_store, &self.tls_alpn_store)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                METRICS.record_cert_issuance_failure();
                tracing::warn!(
                    event = "tls_acme_issuance",
                    hostname = %hostname,
                    decision = "error",
                    error = %err,
                    "tls_acme_issuance"
                );
                return None;
            }
        };

        if let Err(err) = self.store_certificate(entry.clone()) {
            METRICS.record_cert_issuance_failure();
            tracing::warn!(
                event = "tls_acme_issuance",
                hostname = %hostname,
                decision = "cache_store_error",
                error = %err,
                "tls_acme_issuance"
            );
            return None;
        }

        tracing::info!(
            event = "tls_acme_issuance",
            hostname = %hostname,
            decision = "issued",
            "tls_acme_issuance"
        );
        METRICS.record_cert_issuance_success();
        Some(entry.material().clone())
    }

    fn store_certificate(&self, entry: crate::cert_cache::CertificateCacheEntry) -> Result<()> {
        let config = self.config();
        CertificateCache::new(&config.cert_cache.dir).store(&entry)?;
        let loaded = CertificateCache::load(&config.cert_cache.dir, SystemTime::now())?;
        {
            let mut guard = match self.cert_cache.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            *guard = loaded;
        }
        let _ = self.cert_cache_version.fetch_add(1, Ordering::Relaxed);
        if self.certificate_for(entry.hostname()).is_none() {
            return Err(GatewayError::CertificateCache(format!(
                "stored certificate for `{}` did not validate after reload",
                entry.hostname()
            )));
        }
        Ok(())
    }
}
