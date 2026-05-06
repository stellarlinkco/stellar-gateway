use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::error::{GatewayError, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub listeners: ListenersConfig,
    pub routes: RoutesConfig,
    pub tls: TlsConfig,
    pub acme: AcmeConfig,
    pub cert_cache: CertCacheConfig,
    pub reload: ReloadConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenersConfig {
    pub http: HttpListenerConfig,
    pub https: HttpsListenerConfig,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpListenerConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsListenerConfig {
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesConfig {
    pub wildcard: WildcardRouteConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WildcardRouteConfig {
    pub suffix: String,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub addr: String,
    pub tls: bool,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ask_url: Url,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    pub directory_url: Url,
    pub email: String,
    pub http_01: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertCacheConfig {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReloadConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: String,
}

impl LoggingConfig {
    pub fn to_env_filter(&self) -> EnvFilter {
        EnvFilter::new(self.level.clone())
    }
}

impl GatewayConfig {
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
        let deserializer = serde_yaml::Deserializer::from_str(contents);
        let config: Self = serde_path_to_error::deserialize(deserializer).map_err(|err| {
            let path = err.path().to_string();
            let inner = err.into_inner();
            if path.is_empty() {
                GatewayError::Gatewayfile(format!("{inner}"))
            } else {
                GatewayError::Gatewayfile(format!("{path}: {inner}"))
            }
        })?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.routes.wildcard.suffix.trim().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "routes.wildcard.suffix must not be empty".to_owned(),
            ));
        }

        if self.routes.wildcard.upstream.addr.trim().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "routes.wildcard.upstream.addr must not be empty".to_owned(),
            ));
        }

        if self.routes.wildcard.upstream.tls
            && self
                .routes
                .wildcard
                .upstream
                .server_name
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
        {
            return Err(GatewayError::Gatewayfile(
                "routes.wildcard.upstream.server_name must be set when upstream.tls is true"
                    .to_owned(),
            ));
        }

        if self.cert_cache.dir.as_os_str().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "cert_cache.dir must not be empty".to_owned(),
            ));
        }

        if !self.acme.http_01 {
            return Err(GatewayError::Gatewayfile(
                "acme.http_01 must be true for MVP".to_owned(),
            ));
        }

        if self.acme.email.trim().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "acme.email must not be empty".to_owned(),
            ));
        }

        if self.logging.level.trim().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "logging.level must not be empty".to_owned(),
            ));
        }

        Ok(())
    }
}
