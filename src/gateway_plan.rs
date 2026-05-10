use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::config::{GatewayConfig, RouteKind, UpstreamConfig};
use crate::error::{GatewayError, Result};
use crate::routing::{is_exact_host_match, is_wildcard_host_match, normalize_host};

pub type SharedGatewayPlan = Arc<GatewayPlan>;

#[derive(Debug, Clone)]
pub struct GatewayPlan {
    sites: Vec<SitePlan>,
    tls_policy: TlsPolicyPlan,
    config_health: ConfigHealth,
    diagnostics: Vec<CompatibilityDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePlan {
    pub hosts: Vec<HostMatcher>,
    pub routes: Vec<RoutePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMatcher {
    Exact(String),
    WildcardSuffix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub matcher: MatcherPlan,
    pub handler: HandlerPlan,
    pub route_kind: Option<RouteKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatcherPlan {
    PathExact(String),
    PathPrefix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerPlan {
    ReverseProxy { upstream: UpstreamPlan },
    StaticFiles { root: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamPlan {
    pub address: String,
    pub transport: UpstreamTransport,
    pub server_name: Option<String>,
    pub host_header: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTransport {
    Http,
    Https,
    H2c,
    Grpcs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsPolicyPlan {
    pub ask_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigHealth {
    pub status: ConfigHealthStatus,
    pub ready: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigHealthStatus {
    Ready,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityDiagnostic {
    pub site: Option<String>,
    pub directive: String,
    pub line: usize,
    pub impact: CompatibilityImpact,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityImpact {
    Warning,
    DegradesReadiness,
}

#[derive(Debug, Clone)]
pub struct PlannedRoute {
    pub handler: HandlerPlan,
    pub route_kind: Option<RouteKind>,
}

pub struct ActiveGatewayPlan {
    plan: RwLock<SharedGatewayPlan>,
}

impl ActiveGatewayPlan {
    pub fn new(plan: GatewayPlan) -> Self {
        Self {
            plan: RwLock::new(Arc::new(plan)),
        }
    }

    pub fn snapshot(&self) -> SharedGatewayPlan {
        match self.plan.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    pub fn replace(&self, plan: GatewayPlan) {
        let mut guard = match self.plan.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Arc::new(plan);
    }
}

impl GatewayPlan {
    pub fn from_config(config: &GatewayConfig) -> Result<Self> {
        let mut sites = Vec::new();

        if let Some(apex) = &config.routes.apex {
            sites.push(SitePlan {
                hosts: vec![HostMatcher::Exact(normalize_host(&apex.host).ok_or_else(
                    || {
                        GatewayError::Gatewayfile(
                            "routes.apex.host must be a valid host".to_owned(),
                        )
                    },
                )?)],
                routes: vec![RoutePlan::reverse_proxy(
                    MatcherPlan::PathPrefix("/".to_owned()),
                    UpstreamPlan::from_config(&apex.upstream),
                    Some(RouteKind::Apex),
                )],
            });
        }

        sites.push(SitePlan {
            hosts: vec![HostMatcher::WildcardSuffix(
                normalize_host(&config.routes.wildcard.suffix).ok_or_else(|| {
                    GatewayError::Gatewayfile(
                        "routes.wildcard.suffix must be a valid host suffix".to_owned(),
                    )
                })?,
            )],
            routes: vec![RoutePlan::reverse_proxy(
                MatcherPlan::PathPrefix("/".to_owned()),
                UpstreamPlan::from_config(&config.routes.wildcard.upstream),
                Some(RouteKind::Wildcard),
            )],
        });

        Ok(Self::new(
            sites,
            TlsPolicyPlan {
                ask_url: config.tls.ask_url.to_string(),
            },
            Vec::new(),
        ))
    }

    pub fn compile_caddyfile(contents: &str) -> Result<Self> {
        let mut sites = Vec::new();
        let mut diagnostics = Vec::new();
        let parsed = parse_caddyfile(contents)?;

        for (line, option) in parsed.global_options {
            let directive = option.split_whitespace().next().unwrap_or_default();
            if directive.is_empty()
                || directive == "}"
                || is_supported_runtime_global_option(directive)
            {
                continue;
            }
            let impact = unsupported_directive_impact(directive);
            diagnostics.push(CompatibilityDiagnostic {
                site: None,
                directive: directive.to_owned(),
                line,
                impact,
                message: format!(
                    "unsupported Caddyfile global option `{directive}` was ignored during Gateway Plan compilation"
                ),
            });
        }

        for block in parsed.site_blocks {
            let hosts = parse_site_hosts(&block.addresses)?;
            let site_name = block.addresses.trim().to_owned();
            let mut routes = Vec::new();
            let mut static_root = None;
            let mut index = 0;
            while index < block.lines.len() {
                let (line_number, line) = &block.lines[index];
                let mut parts = line.split_whitespace();
                let directive = parts.next().unwrap_or_default();
                match directive {
                    "reverse_proxy" => {
                        routes.push(parse_reverse_proxy_route(
                            line,
                            MatcherPlan::PathPrefix("/".to_owned()),
                            &block.lines,
                            &mut index,
                        )?);
                    }
                    "root" => {
                        static_root = Some(parse_root_directive(line)?);
                    }
                    "file_server" => {
                        routes.push(parse_file_server_route(
                            line,
                            MatcherPlan::PathPrefix("/".to_owned()),
                            static_root.as_ref(),
                        )?);
                    }
                    "handle" => {
                        let handle_matcher = parse_handle_matcher(&mut parts)?;
                        index += 1;
                        while index < block.lines.len() {
                            let (nested_line_number, nested_line) = &block.lines[index];
                            if nested_line == "}" {
                                break;
                            }

                            let mut nested_parts = nested_line.split_whitespace();
                            let nested_directive = nested_parts.next().unwrap_or_default();
                            match nested_directive {
                                "reverse_proxy" => routes.push(parse_reverse_proxy_route(
                                    nested_line,
                                    handle_matcher.clone(),
                                    &block.lines,
                                    &mut index,
                                )?),
                                "root" => {
                                    static_root = Some(parse_root_directive(nested_line)?);
                                }
                                "file_server" => routes.push(parse_file_server_route(
                                    nested_line,
                                    handle_matcher.clone(),
                                    static_root.as_ref(),
                                )?),
                                "" => {}
                                other => {
                                    let impact = unsupported_directive_impact(other);
                                    diagnostics.push(CompatibilityDiagnostic {
                                        site: Some(site_name.clone()),
                                        directive: other.to_owned(),
                                        line: *nested_line_number,
                                        impact,
                                        message: format!(
                                            "unsupported Caddyfile directive `{other}` was ignored during Gateway Plan compilation"
                                        ),
                                    });
                                    if nested_line.ends_with('{') {
                                        skip_nested_block(&block.lines, &mut index);
                                    }
                                }
                            }
                            index += 1;
                        }
                    }
                    "}" => {}
                    "" => {}
                    other => {
                        let impact = unsupported_directive_impact(other);
                        diagnostics.push(CompatibilityDiagnostic {
                            site: Some(site_name.clone()),
                            directive: other.to_owned(),
                            line: *line_number,
                            impact,
                            message: format!(
                                "unsupported Caddyfile directive `{other}` was ignored during Gateway Plan compilation"
                            ),
                        });
                        if line.ends_with('{') {
                            skip_nested_block(&block.lines, &mut index);
                        }
                    }
                }
                index += 1;
            }

            sites.push(SitePlan {
                hosts,
                routes: sort_routes_caddy(routes),
            });
        }

        Ok(Self::new(
            sites,
            TlsPolicyPlan {
                ask_url: "http://127.0.0.1:9000/ask".to_owned(),
            },
            diagnostics,
        ))
    }

    pub fn sites(&self) -> &[SitePlan] {
        &self.sites
    }

    pub fn tls_policy(&self) -> &TlsPolicyPlan {
        &self.tls_policy
    }

    pub fn config_health(&self) -> &ConfigHealth {
        &self.config_health
    }

    pub fn compatibility_diagnostics(&self) -> &[CompatibilityDiagnostic] {
        &self.diagnostics
    }

    pub fn startup_compatibility_summary(&self) -> Option<String> {
        if self.diagnostics.is_empty() {
            return None;
        }

        let mut summary = format!(
            "unsupported Caddyfile directives: config_health={:?}",
            self.config_health.status
        );
        for diagnostic in &self.diagnostics {
            let site = diagnostic.site.as_deref().unwrap_or("<global>");
            summary.push_str(&format!(
                "; site={site} directive={} line={} impact={} message={}",
                diagnostic.directive,
                diagnostic.line,
                diagnostic.impact.as_str(),
                diagnostic.message
            ));
        }
        Some(summary)
    }

    pub fn select_route(&self, host: &str, path: &str) -> Option<PlannedRoute> {
        self.sites.iter().find_map(|site| {
            if !site.hosts.iter().any(|matcher| matcher.matches(host)) {
                return None;
            }
            site.routes.iter().find_map(|route| {
                if route.matches(path) {
                    Some(PlannedRoute {
                        handler: route.handler.clone(),
                        route_kind: route.route_kind,
                    })
                } else {
                    None
                }
            })
        })
    }

    pub fn is_routable_host(&self, host: &str) -> bool {
        self.sites
            .iter()
            .any(|site| site.hosts.iter().any(|matcher| matcher.matches(host)))
    }

    fn new(
        sites: Vec<SitePlan>,
        tls_policy: TlsPolicyPlan,
        diagnostics: Vec<CompatibilityDiagnostic>,
    ) -> Self {
        let degraded = diagnostics
            .iter()
            .any(|diagnostic| diagnostic.impact == CompatibilityImpact::DegradesReadiness);
        Self {
            sites,
            tls_policy,
            config_health: ConfigHealth {
                status: if degraded {
                    ConfigHealthStatus::Degraded
                } else {
                    ConfigHealthStatus::Ready
                },
                ready: !degraded,
            },
            diagnostics,
        }
    }
}

impl HostMatcher {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(configured_host) => is_exact_host_match(host, configured_host),
            Self::WildcardSuffix(suffix) => is_wildcard_host_match(host, suffix),
        }
    }
}

impl RoutePlan {
    fn reverse_proxy(
        matcher: MatcherPlan,
        upstream: UpstreamPlan,
        route_kind: Option<RouteKind>,
    ) -> Self {
        Self {
            matcher,
            handler: HandlerPlan::ReverseProxy { upstream },
            route_kind,
        }
    }

    fn static_files(matcher: MatcherPlan, root: PathBuf) -> Self {
        Self {
            matcher,
            handler: HandlerPlan::StaticFiles { root },
            route_kind: None,
        }
    }

    fn matches(&self, path: &str) -> bool {
        match &self.matcher {
            MatcherPlan::PathExact(exact) => path == exact,
            MatcherPlan::PathPrefix(prefix) => path.starts_with(prefix),
        }
    }
}

impl CompatibilityImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::DegradesReadiness => "degrades_readiness",
        }
    }
}

impl UpstreamPlan {
    fn from_config(upstream: &UpstreamConfig) -> Self {
        Self {
            address: upstream.addr.clone(),
            transport: if upstream.tls {
                UpstreamTransport::Https
            } else {
                UpstreamTransport::Http
            },
            server_name: upstream.server_name.clone(),
            host_header: upstream.host_header.clone(),
        }
    }

    pub fn to_upstream_config(&self) -> UpstreamConfig {
        UpstreamConfig {
            addr: self.address.clone(),
            tls: matches!(
                self.transport,
                UpstreamTransport::Https | UpstreamTransport::Grpcs
            ),
            server_name: self.server_name.clone(),
            host_header: self.host_header.clone(),
        }
    }
}

#[derive(Debug)]
struct ParsedCaddyfile {
    global_options: Vec<(usize, String)>,
    site_blocks: Vec<SiteBlock>,
}

#[derive(Debug)]
struct SiteBlock {
    addresses: String,
    lines: Vec<(usize, String)>,
}

fn parse_caddyfile(contents: &str) -> Result<ParsedCaddyfile> {
    let mut global_options = Vec::new();
    let mut blocks = Vec::new();
    let mut current: Option<SiteBlock> = None;
    let mut nested_depth = 0usize;
    let mut global_depth = 0usize;

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line
            .split_once('#')
            .map_or(raw_line, |(left, _)| left)
            .trim();
        if line.is_empty() {
            continue;
        }

        if global_depth > 0 {
            if line == "}" && global_depth == 1 {
                global_depth = 0;
                continue;
            }
            if line.ends_with('{') {
                global_depth += 1;
            } else if line == "}" {
                global_depth = global_depth.saturating_sub(1);
            }
            global_options.push((line_number, line.to_owned()));
            continue;
        }

        if let Some(block) = current.as_mut() {
            if line == "}" && nested_depth == 0 {
                blocks.push(current.take().expect("current block exists"));
                continue;
            }
            if line.ends_with('{') {
                nested_depth += 1;
            } else if line == "}" {
                nested_depth = nested_depth.saturating_sub(1);
            }
            block.lines.push((line_number, line.to_owned()));
            continue;
        }

        if line == "{" {
            global_depth = 1;
            continue;
        }

        let Some((addresses, rest)) = line.split_once('{') else {
            return Err(GatewayError::Gatewayfile(format!(
                "Caddyfile site block on line {line_number} must contain `{{`"
            )));
        };
        if !rest.trim().is_empty() {
            return Err(GatewayError::Gatewayfile(format!(
                "Caddyfile site block on line {line_number} must end after `{{`"
            )));
        }
        current = Some(SiteBlock {
            addresses: addresses.trim().to_owned(),
            lines: Vec::new(),
        });
    }

    if current.is_some() {
        return Err(GatewayError::Gatewayfile(
            "Caddyfile site block must contain `}`".to_owned(),
        ));
    }
    if global_depth > 0 {
        return Err(GatewayError::Gatewayfile(
            "Caddyfile global options block must contain `}`".to_owned(),
        ));
    }

    Ok(ParsedCaddyfile {
        global_options,
        site_blocks: blocks,
    })
}

fn parse_site_hosts(addresses: &str) -> Result<Vec<HostMatcher>> {
    let mut hosts = Vec::new();
    for raw_address in addresses.split(',') {
        let address = raw_address.trim();
        if address.is_empty() {
            continue;
        }
        let host_address = caddy_site_host(address);
        if let Some(suffix) = host_address.strip_prefix("*.") {
            hosts.push(HostMatcher::WildcardSuffix(
                normalize_host(suffix).ok_or_else(|| {
                    GatewayError::Gatewayfile(format!(
                        "invalid Caddyfile wildcard address `{address}`"
                    ))
                })?,
            ));
        } else {
            hosts.push(HostMatcher::Exact(
                normalize_host(host_address).ok_or_else(|| {
                    GatewayError::Gatewayfile(format!("invalid Caddyfile site address `{address}`"))
                })?,
            ));
        }
    }

    if hosts.is_empty() {
        return Err(GatewayError::Gatewayfile(
            "Caddyfile site block must include at least one address".to_owned(),
        ));
    }

    Ok(hosts)
}

fn caddy_site_host(address: &str) -> &str {
    let without_scheme = address.split_once("://").map_or(address, |(_, rest)| rest);
    without_scheme
        .split_once('/')
        .map_or(without_scheme, |(host, _)| host)
}

fn parse_handle_matcher<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<MatcherPlan> {
    match (parts.next(), parts.next()) {
        (Some("{"), None) => Ok(MatcherPlan::PathPrefix("/".to_owned())),
        (Some(path), Some("{")) if is_path_matcher(path) => Ok(caddy_path_matcher(path)),
        (Some(matcher), _) => Err(GatewayError::Gatewayfile(format!(
            "unsupported handle matcher `{matcher}`"
        ))),
        (None, _) => Err(GatewayError::Gatewayfile(
            "handle block must contain `{`".to_owned(),
        )),
    }
}

fn parse_reverse_proxy_route(
    line: &str,
    default_matcher: MatcherPlan,
    block_lines: &[(usize, String)],
    index: &mut usize,
) -> Result<RoutePlan> {
    let mut parts = line.split_whitespace();
    let directive = parts.next();
    debug_assert_eq!(directive, Some("reverse_proxy"));
    let first = parts.next().ok_or_else(|| {
        GatewayError::Gatewayfile("reverse_proxy requires an upstream".to_owned())
    })?;
    let (matcher, target) = if is_path_matcher(first) {
        let target = parts.next().ok_or_else(|| {
            GatewayError::Gatewayfile("reverse_proxy path matcher requires an upstream".to_owned())
        })?;
        (caddy_path_matcher(first), target)
    } else {
        (default_matcher, first)
    };
    let mut upstream = parse_upstream_plan(target)?;
    if matches!(parts.next(), Some("{")) {
        *index += 1;
        while *index < block_lines.len() {
            let (_, option_line) = &block_lines[*index];
            if option_line == "}" {
                break;
            }
            apply_reverse_proxy_option(&mut upstream, option_line);
            *index += 1;
        }
    }
    Ok(RoutePlan::reverse_proxy(matcher, upstream, None))
}

fn parse_root_directive(line: &str) -> Result<PathBuf> {
    let mut parts = line.split_whitespace();
    debug_assert_eq!(parts.next(), Some("root"));
    let first = parts
        .next()
        .ok_or_else(|| GatewayError::Gatewayfile("root requires a filesystem path".to_owned()))?;
    let root = if first == "*" || is_path_matcher(first) {
        parts.next().ok_or_else(|| {
            GatewayError::Gatewayfile("root matcher requires a filesystem path".to_owned())
        })?
    } else {
        first
    };
    if parts.next().is_some() {
        return Err(GatewayError::Gatewayfile(
            "root supports one optional matcher and one filesystem path".to_owned(),
        ));
    }
    Ok(PathBuf::from(root))
}

fn parse_file_server_route(
    line: &str,
    default_matcher: MatcherPlan,
    static_root: Option<&PathBuf>,
) -> Result<RoutePlan> {
    let mut parts = line.split_whitespace();
    debug_assert_eq!(parts.next(), Some("file_server"));
    let matcher = match parts.next() {
        Some(value) if is_path_matcher(value) => caddy_path_matcher(value),
        Some(value) => {
            return Err(GatewayError::Gatewayfile(format!(
                "unsupported file_server argument `{value}`"
            )));
        }
        None => default_matcher,
    };
    if parts.next().is_some() {
        return Err(GatewayError::Gatewayfile(
            "file_server supports at most one path matcher".to_owned(),
        ));
    }
    let root = static_root
        .ok_or_else(|| GatewayError::Gatewayfile("file_server requires root".to_owned()))?
        .clone();
    Ok(RoutePlan::static_files(matcher, root))
}

fn skip_nested_block(block_lines: &[(usize, String)], index: &mut usize) {
    let mut depth = 1usize;
    while depth > 0 && *index + 1 < block_lines.len() {
        *index += 1;
        let nested = &block_lines[*index].1;
        if nested.ends_with('{') {
            depth += 1;
        }
        if nested == "}" {
            depth = depth.saturating_sub(1);
        }
    }
}

fn parse_upstream_plan(target: &str) -> Result<UpstreamPlan> {
    if target.trim().is_empty() {
        return Err(GatewayError::Gatewayfile(
            "reverse_proxy upstream must not be empty".to_owned(),
        ));
    }

    let (transport, address) = if let Some(address) = target.strip_prefix("http://") {
        (UpstreamTransport::Http, address)
    } else if let Some(address) = target.strip_prefix("https://") {
        (UpstreamTransport::Https, address)
    } else if let Some(address) = target.strip_prefix("h2c://") {
        (UpstreamTransport::H2c, address)
    } else if let Some(address) = target.strip_prefix("grpcs://") {
        (UpstreamTransport::Grpcs, address)
    } else {
        (UpstreamTransport::Http, target)
    };

    let server_name = if matches!(
        transport,
        UpstreamTransport::Https | UpstreamTransport::Grpcs
    ) {
        address
            .split(':')
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    } else {
        None
    };

    Ok(UpstreamPlan {
        address: address.to_owned(),
        transport,
        server_name,
        host_header: None,
    })
}

fn is_path_matcher(value: &str) -> bool {
    value.starts_with('/')
}

fn caddy_path_matcher(value: &str) -> MatcherPlan {
    if let Some(prefix) = value.strip_suffix('*') {
        MatcherPlan::PathPrefix(prefix.to_owned())
    } else {
        MatcherPlan::PathExact(value.to_owned())
    }
}

fn sort_routes_caddy(routes: Vec<RoutePlan>) -> Vec<RoutePlan> {
    let mut indexed_routes = routes.into_iter().enumerate().collect::<Vec<_>>();
    indexed_routes.sort_by(|(left_index, left), (right_index, right)| {
        route_precedence(right)
            .cmp(&route_precedence(left))
            .then_with(|| left_index.cmp(right_index))
    });
    indexed_routes.into_iter().map(|(_, route)| route).collect()
}

fn route_precedence(route: &RoutePlan) -> (u8, usize) {
    match &route.matcher {
        MatcherPlan::PathExact(path) => (2, path.len()),
        MatcherPlan::PathPrefix(prefix) => (1, prefix.len()),
    }
}

fn apply_reverse_proxy_option(upstream: &mut UpstreamPlan, line: &str) {
    let mut parts = line.split_whitespace();
    if matches!(parts.next(), Some("header_up"))
        && matches!(parts.next(), Some("Host"))
        && let Some(value) = parts.next()
    {
        upstream.host_header = Some(value.to_owned());
        if matches!(
            upstream.transport,
            UpstreamTransport::Https | UpstreamTransport::Grpcs
        ) {
            upstream.server_name = Some(value.to_owned());
        }
    }
}

fn unsupported_directive_impact(directive: &str) -> CompatibilityImpact {
    match directive {
        "basicauth" | "basic_auth" | "forward_auth" | "oauth2" => {
            CompatibilityImpact::DegradesReadiness
        }
        _ => CompatibilityImpact::Warning,
    }
}

fn is_supported_runtime_global_option(directive: &str) -> bool {
    matches!(directive, "http_port" | "https_port")
}
