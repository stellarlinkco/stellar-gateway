pub fn normalize_host(host_header_value: &str) -> Option<String> {
    let host = host_header_value.trim();
    if host.is_empty() {
        return None;
    }

    if host.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }

    let without_port = if host.starts_with('[') {
        // IPv6 literals are never valid wildcard hosts for the MVP domain.
        host
    } else if let Some((left, right)) = host.rsplit_once(':') {
        if !left.is_empty() && right.bytes().all(|b| b.is_ascii_digit()) {
            left
        } else {
            host
        }
    } else {
        host
    };

    Some(without_port.to_ascii_lowercase())
}

pub fn is_wildcard_host_match(host_header_value: &str, suffix: &str) -> bool {
    let Some(host) = normalize_host(host_header_value) else {
        return false;
    };
    let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
    if suffix.is_empty() {
        return false;
    }
    if host == suffix {
        return false;
    }

    let Some(rest) = host.strip_suffix(&suffix) else {
        return false;
    };

    if !rest.ends_with('.') {
        return false;
    }

    let prefix = &rest[..rest.len().saturating_sub(1)];
    if prefix.is_empty() {
        return false;
    }
    if prefix.starts_with('.') || prefix.ends_with('.') {
        return false;
    }
    if prefix.contains("..") {
        return false;
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatch {
    Matched,
    NoMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceAuthorization {
    AllowedByAsk,
    DeniedByAsk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAuthorization {
    AllowRouted,
    DenyNotRouted,
    DenyUnauthorizedIssuance,
    DenyInvalidHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAuthorizationPolicy {
    suffix: Option<String>,
}

impl RouteAuthorizationPolicy {
    pub fn new(suffix: &str) -> Self {
        Self {
            suffix: normalize_host(suffix),
        }
    }

    pub fn route_match(&self, host_header_value: &str) -> RouteMatch {
        let Some(suffix) = self.suffix.as_deref() else {
            return RouteMatch::NoMatch;
        };
        if is_wildcard_host_match(host_header_value, suffix) {
            RouteMatch::Matched
        } else {
            RouteMatch::NoMatch
        }
    }

    pub fn authorize_request(
        &self,
        host_header_value: &str,
        _issuance: IssuanceAuthorization,
        route_match: RouteMatch,
    ) -> RequestAuthorization {
        let normalized_host = normalize_host(host_header_value);
        let decision = if self.suffix.is_none() || normalized_host.is_none() {
            RequestAuthorization::DenyInvalidHost
        } else {
            match route_match {
                RouteMatch::NoMatch => RequestAuthorization::DenyNotRouted,
                RouteMatch::Matched => RequestAuthorization::AllowRouted,
            }
        };

        tracing::info!(
            event = "route_authorization",
            host = normalized_host.as_deref(),
            route_match = ?route_match,
            decision = ?decision,
            "route_authorization"
        );

        decision
    }
}
