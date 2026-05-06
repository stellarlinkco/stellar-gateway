use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::cert_cache::{CertificateCache, CertificateMaterial};
use crate::config::GatewayConfig;
use crate::error::Result;

#[derive(Debug)]
pub struct GatewayRuntimeState {
    gatewayfile_path: PathBuf,
    config: RwLock<GatewayConfig>,
    cert_cache: RwLock<CertificateCache>,
    config_version: AtomicU64,
    cert_cache_version: AtomicU64,
}

impl GatewayRuntimeState {
    pub fn new(
        config: GatewayConfig,
        gatewayfile_path: impl AsRef<Path>,
        now: SystemTime,
    ) -> Result<Self> {
        let gatewayfile_path = gatewayfile_path.as_ref().to_path_buf();
        let cert_cache = CertificateCache::load(&config.cert_cache.dir, now)?;
        Ok(Self {
            gatewayfile_path,
            config: RwLock::new(config),
            cert_cache: RwLock::new(cert_cache),
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
}
