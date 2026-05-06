use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct GatewayMetrics {
    requests_total: AtomicU64,
    route_matches_total: AtomicU64,
    route_rejections_total: AtomicU64,
    http01_responses_total: AtomicU64,
    upstream_errors_total: AtomicU64,
    cert_issuance_attempts_total: AtomicU64,
    cert_issuance_success_total: AtomicU64,
    cert_issuance_failures_total: AtomicU64,
    reload_success_total: AtomicU64,
    reload_failures_total: AtomicU64,
}

impl GatewayMetrics {
    pub const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            route_matches_total: AtomicU64::new(0),
            route_rejections_total: AtomicU64::new(0),
            http01_responses_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            cert_issuance_attempts_total: AtomicU64::new(0),
            cert_issuance_success_total: AtomicU64::new(0),
            cert_issuance_failures_total: AtomicU64::new(0),
            reload_success_total: AtomicU64::new(0),
            reload_failures_total: AtomicU64::new(0),
        }
    }

    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_match(&self) {
        self.route_matches_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_rejection(&self) {
        self.route_rejections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_http01_response(&self) {
        self.http01_responses_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_error(&self) {
        self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cert_issuance_attempt(&self) {
        self.cert_issuance_attempts_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cert_issuance_success(&self) {
        self.cert_issuance_success_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cert_issuance_failure(&self) {
        self.cert_issuance_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload_success(&self) {
        self.reload_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload_failure(&self) {
        self.reload_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        self.write_counter(
            &mut out,
            "stellar_gateway_requests_total",
            "Total HTTP requests observed by the gateway.",
            self.requests_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_route_matches_total",
            "Requests that matched the wildcard route.",
            self.route_matches_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_route_rejections_total",
            "Requests rejected because the host did not match.",
            self.route_rejections_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_http01_responses_total",
            "HTTP-01 challenge responses served by the gateway.",
            self.http01_responses_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_upstream_errors_total",
            "Requests that completed with a proxy upstream error.",
            self.upstream_errors_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_cert_issuance_attempts_total",
            "On-demand certificate issuance attempts.",
            self.cert_issuance_attempts_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_cert_issuance_success_total",
            "Successful on-demand certificate issuances.",
            self.cert_issuance_success_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_cert_issuance_failures_total",
            "Failed on-demand certificate issuances.",
            self.cert_issuance_failures_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_reload_success_total",
            "Successful Gatewayfile and certificate cache reloads.",
            self.reload_success_total.load(Ordering::Relaxed),
        );
        self.write_counter(
            &mut out,
            "stellar_gateway_reload_failures_total",
            "Failed Gatewayfile or certificate cache reloads.",
            self.reload_failures_total.load(Ordering::Relaxed),
        );
        out
    }

    fn write_counter(&self, out: &mut String, name: &str, help: &str, value: u64) {
        out.push_str("# HELP ");
        out.push_str(name);
        out.push(' ');
        out.push_str(help);
        out.push('\n');
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push_str(" counter\n");
        out.push_str(name);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }
}

pub static METRICS: GatewayMetrics = GatewayMetrics::new();

#[cfg(test)]
mod tests {
    use super::GatewayMetrics;

    #[test]
    fn prometheus_output_should_include_gateway_counters() {
        let metrics = GatewayMetrics::new();
        metrics.record_request();
        metrics.record_route_match();

        let body = metrics.render_prometheus();

        assert!(
            body.contains("# TYPE stellar_gateway_requests_total counter")
                && body.contains("stellar_gateway_requests_total 1")
                && body.contains("stellar_gateway_route_matches_total 1")
        );
    }
}
