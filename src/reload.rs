use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::acme::{Http01ChallengeStore, TlsAlpnChallengeStore};
use crate::acme_issuer::{AcmeIssuer, InstantAcmeIssuer};
use crate::cert_cache::{CertificateCache, CertificateMaterial};
use crate::config::{
    AcmeConfig, ApexRouteConfig, CertCacheConfig, GatewayConfig, HttpListenerConfig,
    HttpsListenerConfig, ListenersConfig, LoggingConfig, ReloadConfig, RoutesConfig, TlsConfig,
    UpstreamConfig, WildcardRouteConfig,
};
use crate::error::{GatewayError, Result};
use crate::gateway_plan::{
    ActiveGatewayPlan, GatewayPlan, HandlerPlan, HostMatcher, SharedGatewayPlan,
};
use crate::metrics::METRICS;
use crate::routing::normalize_host;
use crate::tls::{AskClient, AskDecision};
use url::Url;

pub struct LoadedGatewayRuntime {
    pub config: GatewayConfig,
    pub plan: GatewayPlan,
}

impl LoadedGatewayRuntime {
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(|err| {
            GatewayError::Gatewayfile(format!(
                "failed to read Gatewayfile `{}`: {err}",
                path.display()
            ))
        })?;
        Self::load_from_str(&contents)
    }

    pub fn load_from_str(contents: &str) -> Result<Self> {
        match GatewayConfig::load_from_str(contents) {
            Ok(config) => {
                let plan = GatewayPlan::from_config(&config)?;
                Ok(Self { config, plan })
            }
            Err(err) if looks_like_caddyfile(contents) => {
                let plan = GatewayPlan::compile_caddyfile(contents)?;
                let config = runtime_config_from_caddyfile(contents, &plan)?;
                Ok(Self { config, plan })
            }
            Err(err) => Err(err),
        }
    }
}

pub struct GatewayRuntimeState {
    gatewayfile_path: PathBuf,
    config: RwLock<GatewayConfig>,
    active_plan: ActiveGatewayPlan,
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
        let plan = GatewayPlan::from_config(&config)?;
        Self::new_with_issuer_and_plan(config, plan, gatewayfile_path, now, issuer)
    }

    pub fn new_loaded(
        loaded: LoadedGatewayRuntime,
        gatewayfile_path: impl AsRef<Path>,
        now: SystemTime,
    ) -> Result<Self> {
        Self::new_with_issuer_and_plan(
            loaded.config,
            loaded.plan,
            gatewayfile_path,
            now,
            Arc::new(InstantAcmeIssuer::default()),
        )
    }

    fn new_with_issuer_and_plan(
        config: GatewayConfig,
        plan: GatewayPlan,
        gatewayfile_path: impl AsRef<Path>,
        now: SystemTime,
        issuer: Arc<dyn AcmeIssuer>,
    ) -> Result<Self> {
        let gatewayfile_path = gatewayfile_path.as_ref().to_path_buf();
        let cert_cache = CertificateCache::load(&config.cert_cache.dir, now)?;
        Ok(Self {
            gatewayfile_path,
            config: RwLock::new(config),
            active_plan: ActiveGatewayPlan::new(plan),
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

    pub fn plan_snapshot(&self) -> SharedGatewayPlan {
        self.active_plan.snapshot()
    }

    pub fn reload_config(&self) -> Result<()> {
        tracing::info!(
            event = "reload_config",
            gatewayfile = %self.gatewayfile_path.display(),
            config_version = self.config_version.load(Ordering::Relaxed),
            "reload_config"
        );
        let loaded = match LoadedGatewayRuntime::load_from_path(&self.gatewayfile_path) {
            Ok(loaded) => loaded,
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
        *guard = loaded.config;
        self.active_plan.replace(loaded.plan);
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
        if !self.plan_snapshot().is_routable_host(&hostname) {
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

fn looks_like_caddyfile(contents: &str) -> bool {
    contents.contains('{') || contents.contains("reverse_proxy")
}

fn runtime_config_from_caddyfile(contents: &str, plan: &GatewayPlan) -> Result<GatewayConfig> {
    let (http_bind, https_bind) = caddyfile_listener_binds(contents)?;
    let upstream = first_reverse_proxy_upstream(plan).unwrap_or_else(default_static_upstream);
    let apex_host = first_exact_host(plan);
    let wildcard_suffix = first_wildcard_suffix(plan)
        .or_else(|| apex_host.clone())
        .ok_or_else(|| {
            GatewayError::Gatewayfile("runtime Caddyfile must include a site host".to_owned())
        })?;

    Ok(GatewayConfig {
        listeners: ListenersConfig {
            http: HttpListenerConfig { bind: http_bind },
            https: HttpsListenerConfig { bind: https_bind },
        },
        routes: RoutesConfig {
            apex: apex_host.map(|host| ApexRouteConfig {
                host,
                upstream: upstream.clone(),
            }),
            wildcard: WildcardRouteConfig {
                suffix: wildcard_suffix,
                upstream,
            },
        },
        tls: TlsConfig {
            ask_url: Url::parse(&plan.tls_policy().ask_url).expect("Gateway Plan ask URL is valid"),
        },
        acme: AcmeConfig {
            directory_url: Url::parse("https://acme-staging-v02.api.letsencrypt.org/directory")
                .expect("valid default acme url"),
            email: "admin@example.com".to_owned(),
            http_01: true,
            tls_alpn_01: true,
            ca_cert_path: None,
        },
        cert_cache: CertCacheConfig {
            dir: PathBuf::from("./cert-cache"),
        },
        reload: ReloadConfig { enabled: true },
        logging: LoggingConfig {
            level: "info".to_owned(),
        },
    })
}

fn caddyfile_listener_binds(contents: &str) -> Result<(SocketAddr, SocketAddr)> {
    let mut http_bind = "0.0.0.0:8080".parse().expect("valid default http bind");
    let mut https_bind = "0.0.0.0:8443".parse().expect("valid default https bind");
    let mut in_global_options = false;

    for raw_line in contents.lines() {
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(left, _)| left)
            .trim();
        if line.is_empty() {
            continue;
        }
        if !in_global_options {
            if line == "{" {
                in_global_options = true;
            }
            continue;
        }
        if line == "}" {
            break;
        }

        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some("http_port"), Some(port), None) => {
                http_bind = parse_caddyfile_port_bind("http_port", port)?;
            }
            (Some("https_port"), Some(port), None) => {
                https_bind = parse_caddyfile_port_bind("https_port", port)?;
            }
            _ => {}
        }
    }

    Ok((http_bind, https_bind))
}

fn parse_caddyfile_port_bind(option: &str, port: &str) -> Result<SocketAddr> {
    format!("0.0.0.0:{port}")
        .parse()
        .map_err(|err| GatewayError::Gatewayfile(format!("invalid Caddyfile {option}: {err}")))
}

fn first_reverse_proxy_upstream(plan: &GatewayPlan) -> Option<UpstreamConfig> {
    plan.sites()
        .iter()
        .flat_map(|site| site.routes.iter())
        .find_map(|route| match &route.handler {
            HandlerPlan::ReverseProxy { upstream } => Some(upstream.to_upstream_config()),
            HandlerPlan::StaticFiles { .. } => None,
        })
}

fn default_static_upstream() -> UpstreamConfig {
    UpstreamConfig {
        addr: "127.0.0.1:0".to_owned(),
        tls: false,
        server_name: None,
        host_header: None,
    }
}

fn first_exact_host(plan: &GatewayPlan) -> Option<String> {
    plan.sites()
        .iter()
        .flat_map(|site| site.hosts.iter())
        .find_map(|host| match host {
            HostMatcher::Exact(host) => Some(host.clone()),
            HostMatcher::WildcardSuffix(_) => None,
        })
}

fn first_wildcard_suffix(plan: &GatewayPlan) -> Option<String> {
    plan.sites()
        .iter()
        .flat_map(|site| site.hosts.iter())
        .find_map(|host| match host {
            HostMatcher::Exact(_) => None,
            HostMatcher::WildcardSuffix(suffix) => Some(suffix.clone()),
        })
}
