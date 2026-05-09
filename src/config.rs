use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing_subscriber::EnvFilter;
use url::Url;

use crate::error::{GatewayError, Result};
use crate::routing::{is_exact_host_match, is_wildcard_host_match, normalize_host};

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
    #[serde(default)]
    pub apex: Option<ApexRouteConfig>,
    pub wildcard: WildcardRouteConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApexRouteConfig {
    pub host: String,
    pub upstream: UpstreamConfig,
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
    #[serde(default)]
    pub host_header: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Apex,
    Wildcard,
}

#[derive(Debug, Clone)]
pub struct RouteSelection {
    pub kind: RouteKind,
    pub upstream: UpstreamConfig,
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
    #[serde(default = "default_true")]
    pub tls_alpn_01: bool,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
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

impl RoutesConfig {
    pub fn select_route(&self, host: &str) -> Option<RouteSelection> {
        if let Some(apex) = &self.apex
            && is_exact_host_match(host, &apex.host)
        {
            return Some(RouteSelection {
                kind: RouteKind::Apex,
                upstream: apex.upstream.clone(),
            });
        }

        if is_wildcard_host_match(host, &self.wildcard.suffix) {
            return Some(RouteSelection {
                kind: RouteKind::Wildcard,
                upstream: self.wildcard.upstream.clone(),
            });
        }

        None
    }

    pub fn is_routable_host(&self, host: &str) -> bool {
        self.select_route(host).is_some()
    }
}

fn default_true() -> bool {
    true
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
        if looks_like_yaml_gatewayfile(contents) {
            return Self::load_from_yaml_str(contents);
        }

        match Self::load_from_yaml_str(contents) {
            Ok(config) => Ok(config),
            Err(yaml_error) => {
                if contents.contains('{') || contents.contains("reverse_proxy") {
                    parse_caddyfile_subset(contents)
                } else {
                    Err(yaml_error)
                }
            }
        }
    }

    fn load_from_yaml_str(contents: &str) -> Result<Self> {
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
        if let Some(apex) = &self.routes.apex {
            if normalize_host(&apex.host).is_none() {
                return Err(GatewayError::Gatewayfile(
                    "routes.apex.host must be a valid host".to_owned(),
                ));
            }
            validate_upstream("routes.apex.upstream", &apex.upstream)?;
        }

        if normalize_host(&self.routes.wildcard.suffix).is_none() {
            return Err(GatewayError::Gatewayfile(
                "routes.wildcard.suffix must be a valid host suffix".to_owned(),
            ));
        }

        validate_upstream("routes.wildcard.upstream", &self.routes.wildcard.upstream)?;

        if self.cert_cache.dir.as_os_str().is_empty() {
            return Err(GatewayError::Gatewayfile(
                "cert_cache.dir must not be empty".to_owned(),
            ));
        }

        if !self.acme.http_01 && !self.acme.tls_alpn_01 {
            return Err(GatewayError::Gatewayfile(
                "at least one ACME challenge must be enabled".to_owned(),
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

fn validate_upstream(path: &str, upstream: &UpstreamConfig) -> Result<()> {
    if upstream.addr.trim().is_empty() {
        return Err(GatewayError::Gatewayfile(format!(
            "{path}.addr must not be empty"
        )));
    }

    if upstream.tls
        && upstream
            .server_name
            .as_deref()
            .is_none_or(|name| name.trim().is_empty())
    {
        return Err(GatewayError::Gatewayfile(format!(
            "{path}.server_name must be set when upstream.tls is true"
        )));
    }

    if let Some(host_header) = &upstream.host_header
        && (host_header.trim().is_empty()
            || host_header.contains('\r')
            || host_header.contains('\n'))
    {
        return Err(GatewayError::Gatewayfile(format!(
            "{path}.host_header must be a valid header value"
        )));
    }

    Ok(())
}

fn looks_like_yaml_gatewayfile(contents: &str) -> bool {
    let trimmed = contents.trim_start();
    trimmed.starts_with("listeners:")
        || trimmed.starts_with("routes:")
        || trimmed.starts_with("tls:")
        || trimmed.starts_with("acme:")
        || trimmed.starts_with("cert_cache:")
        || trimmed.starts_with("reload:")
        || trimmed.starts_with("logging:")
}

fn parse_caddyfile_subset(contents: &str) -> Result<GatewayConfig> {
    let without_comments = contents
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(left, _)| left).trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");

    let mut caddyfile = without_comments.trim();
    let mut http_bind = "0.0.0.0:8080".to_owned();
    let mut https_bind = "0.0.0.0:8443".to_owned();

    if caddyfile.starts_with('{') {
        let (global_options, rest) = split_leading_caddy_block(caddyfile)?;
        for line in global_options
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("http_port"), Some(port), None) => http_bind = format!("0.0.0.0:{port}"),
                (Some("https_port"), Some(port), None) => https_bind = format!("0.0.0.0:{port}"),
                (Some(option), _, _) => {
                    return Err(GatewayError::Gatewayfile(format!(
                        "unsupported Caddyfile global option `{option}`"
                    )));
                }
                (None, _, _) => {}
            }
        }
        caddyfile = rest.trim();
    }

    let (addresses, body_with_suffix) = caddyfile.split_once('{').ok_or_else(|| {
        GatewayError::Gatewayfile("Caddyfile route block must contain `{`".to_owned())
    })?;
    let (body, trailing) = body_with_suffix.rsplit_once('}').ok_or_else(|| {
        GatewayError::Gatewayfile("Caddyfile route block must contain `}`".to_owned())
    })?;

    if !trailing.trim().is_empty() {
        return Err(GatewayError::Gatewayfile(
            "Caddyfile subset supports a single route block".to_owned(),
        ));
    }

    let mut apex_host = None;
    let mut wildcard_suffix = None;
    for raw_address in addresses.split(',') {
        let address = raw_address.trim();
        if address.is_empty() {
            continue;
        }

        if let Some(suffix) = address.strip_prefix("*.") {
            let normalized = normalize_host(suffix).ok_or_else(|| {
                GatewayError::Gatewayfile(format!("invalid Caddyfile wildcard address `{address}`"))
            })?;
            wildcard_suffix = Some(normalized);
        } else {
            let normalized = normalize_host(address).ok_or_else(|| {
                GatewayError::Gatewayfile(format!("invalid Caddyfile site address `{address}`"))
            })?;
            apex_host = Some(normalized);
        }
    }

    let Some(wildcard_suffix) = wildcard_suffix else {
        return Err(GatewayError::Gatewayfile(
            "Caddyfile route block must include a wildcard address like `*.hdd.ink`".to_owned(),
        ));
    };

    let mut upstream = None;
    let body_lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut index = 0;
    while index < body_lines.len() {
        let line = body_lines[index];
        let mut parts = line.split_whitespace();
        let directive = parts.next().unwrap_or_default();
        match directive {
            "reverse_proxy" => {
                if upstream.is_some() {
                    return Err(GatewayError::Gatewayfile(
                        "Caddyfile subset supports one reverse_proxy directive".to_owned(),
                    ));
                }
                let target = parts.next().ok_or_else(|| {
                    GatewayError::Gatewayfile("reverse_proxy requires an upstream".to_owned())
                })?;
                let mut parsed_upstream = parse_reverse_proxy_upstream(target)?;
                match (parts.next(), parts.next()) {
                    (None, None) => {}
                    (Some("{"), None) => {
                        index += 1;
                        let mut closed = false;
                        while index < body_lines.len() {
                            let option_line = body_lines[index];
                            if option_line == "}" {
                                closed = true;
                                break;
                            }
                            apply_reverse_proxy_option(&mut parsed_upstream, option_line)?;
                            index += 1;
                        }
                        if !closed {
                            return Err(GatewayError::Gatewayfile(
                                "reverse_proxy block must contain `}`".to_owned(),
                            ));
                        }
                    }
                    _ => {
                        return Err(GatewayError::Gatewayfile(
                            "reverse_proxy supports exactly one upstream in this subset".to_owned(),
                        ));
                    }
                }
                upstream = Some(parsed_upstream);
            }
            "}" => {
                return Err(GatewayError::Gatewayfile(
                    "unexpected Caddyfile block terminator".to_owned(),
                ));
            }
            other => {
                return Err(GatewayError::Gatewayfile(format!(
                    "unsupported Caddyfile directive `{other}`"
                )));
            }
        }
        index += 1;
    }

    let upstream = upstream.ok_or_else(|| {
        GatewayError::Gatewayfile("Caddyfile route block must include reverse_proxy".to_owned())
    })?;

    let apex = apex_host.map(|host| ApexRouteConfig {
        host,
        upstream: upstream.clone(),
    });
    let config = GatewayConfig {
        listeners: ListenersConfig {
            http: HttpListenerConfig {
                bind: http_bind.parse().map_err(|err| {
                    GatewayError::Gatewayfile(format!("invalid Caddyfile http_port: {err}"))
                })?,
            },
            https: HttpsListenerConfig {
                bind: https_bind.parse().map_err(|err| {
                    GatewayError::Gatewayfile(format!("invalid Caddyfile https_port: {err}"))
                })?,
            },
        },
        routes: RoutesConfig {
            apex,
            wildcard: WildcardRouteConfig {
                suffix: wildcard_suffix,
                upstream,
            },
        },
        tls: TlsConfig {
            ask_url: Url::parse("http://127.0.0.1:9000/ask").expect("valid default ask url"),
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
    };

    config.validate()?;
    Ok(config)
}

fn split_leading_caddy_block(contents: &str) -> Result<(&str, &str)> {
    let mut depth = 0usize;
    for (index, ch) in contents.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok((&contents[1..index], &contents[index + 1..]));
                }
            }
            _ => {}
        }
    }

    Err(GatewayError::Gatewayfile(
        "Caddyfile global options block must contain `}`".to_owned(),
    ))
}

fn apply_reverse_proxy_option(upstream: &mut UpstreamConfig, line: &str) -> Result<()> {
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("header_up"), Some("Host"), Some(value), None) => {
            upstream.host_header = Some(value.to_owned());
            Ok(())
        }
        (Some(option), _, _, _) => Err(GatewayError::Gatewayfile(format!(
            "unsupported reverse_proxy option `{option}`"
        ))),
        (None, _, _, _) => Ok(()),
    }
}

fn parse_reverse_proxy_upstream(target: &str) -> Result<UpstreamConfig> {
    if target.trim().is_empty() {
        return Err(GatewayError::Gatewayfile(
            "reverse_proxy upstream must not be empty".to_owned(),
        ));
    }

    if let Some(addr) = target.strip_prefix("http://") {
        return Ok(UpstreamConfig {
            addr: addr.to_owned(),
            tls: false,
            server_name: None,
            host_header: None,
        });
    }

    if let Some(addr) = target.strip_prefix("https://") {
        let server_name = addr.split(':').next().filter(|name| !name.is_empty());
        return Ok(UpstreamConfig {
            addr: addr.to_owned(),
            tls: true,
            server_name: server_name.map(str::to_owned),
            host_header: None,
        });
    }

    Ok(UpstreamConfig {
        addr: target.to_owned(),
        tls: false,
        server_name: None,
        host_header: None,
    })
}
