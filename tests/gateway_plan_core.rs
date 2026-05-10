use std::path::PathBuf;
use std::sync::Arc;

use stellar_gateway::config::GatewayConfig;
use stellar_gateway::gateway_plan::{
    ActiveGatewayPlan, CompatibilityImpact, ConfigHealthStatus, GatewayPlan, HandlerPlan,
    HostMatcher, UpstreamTransport,
};

const VALID_MVP_GATEWAYFILE: &str = r#"
listeners:
  http:
    bind: "0.0.0.0:8080"
  https:
    bind: "0.0.0.0:8443"

routes:
  apex:
    host: "hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false
      host_header: "origin.internal"
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:3001"
      tls: true
      server_name: "origin.example"

tls:
  ask_url: "http://127.0.0.1:9000/ask"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: true

cert_cache:
  dir: "./cert-cache"

reload:
  enabled: true

logging:
  level: "info"
"#;

#[test]
fn gateway_plan_should_compile_existing_yaml_gatewayfile_behavior() {
    let config = GatewayConfig::load_from_str(VALID_MVP_GATEWAYFILE).unwrap();
    let plan = GatewayPlan::from_config(&config).unwrap();

    assert_eq!(plan.config_health().status, ConfigHealthStatus::Ready);
    assert!(plan.compatibility_diagnostics().is_empty());
    assert_eq!(plan.sites().len(), 2);
    assert!(plan.select_route("hdd.ink:443", "/").is_some());
    assert!(plan.select_route("foo.page.hdd.ink", "/").is_some());
    assert!(plan.select_route("page.hdd.ink", "/").is_none());

    let apex_route = plan.select_route("hdd.ink", "/").unwrap();
    assert!(matches!(
        apex_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3000"
            && upstream.transport == UpstreamTransport::Http
            && upstream.host_header.as_deref() == Some("origin.internal")
    ));

    let wildcard_route = plan.select_route("foo.page.hdd.ink", "/").unwrap();
    assert!(matches!(
        wildcard_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3001"
            && upstream.transport == UpstreamTransport::Https
            && upstream.server_name.as_deref() == Some("origin.example")
    ));
}

#[test]
fn gateway_plan_should_compile_caddyfile_sites_hosts_paths_and_supported_reverse_proxy() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"hdd.ink, *.hdd.ink {
    reverse_proxy 127.0.0.1:3000
}

api.example.com {
    reverse_proxy /v1/* h2c://127.0.0.1:50051
}

tls.example.com {
    reverse_proxy grpcs://127.0.0.1:50052 {
        header_up Host localhost
    }
}
"#,
    )
    .unwrap();

    assert_eq!(plan.config_health().status, ConfigHealthStatus::Ready);
    assert_eq!(plan.sites().len(), 3);
    assert!(
        plan.sites()[0]
            .hosts
            .contains(&HostMatcher::Exact("hdd.ink".into()))
    );
    assert!(
        plan.sites()[0]
            .hosts
            .contains(&HostMatcher::WildcardSuffix("hdd.ink".into()))
    );

    let default_route = plan.select_route("tenant.hdd.ink", "/anything").unwrap();
    assert!(matches!(
        default_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3000"
            && upstream.transport == UpstreamTransport::Http
    ));

    assert!(plan.select_route("api.example.com", "/other").is_none());
    let grpc_route = plan.select_route("api.example.com", "/v1/users").unwrap();
    assert!(matches!(
        grpc_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:50051"
            && upstream.transport == UpstreamTransport::H2c
    ));

    let grpcs_route = plan.select_route("tls.example.com", "/").unwrap();
    assert!(matches!(
        grpcs_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:50052"
            && upstream.transport == UpstreamTransport::Grpcs
            && upstream.host_header.as_deref() == Some("localhost")
            && upstream.server_name.as_deref() == Some("localhost")
    ));
}

#[test]
fn gateway_plan_should_compile_caddyfile_root_and_file_server() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"static.example.test {
    root * /srv/static-site
    file_server
}
"#,
    )
    .unwrap();

    let route = plan
        .select_route("static.example.test", "/index.html")
        .unwrap();
    assert!(matches!(
        route.handler,
        HandlerPlan::StaticFiles { ref root } if root == &PathBuf::from("/srv/static-site")
    ));
}

#[test]
fn gateway_plan_should_compile_multisite_caddyfile_with_global_option_diagnostics() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"{
    admin off
}

one.example.com {
    reverse_proxy 127.0.0.1:3000
}

two.example.com {
    reverse_proxy 127.0.0.1:3001
}
"#,
    )
    .unwrap();

    assert!(plan.select_route("one.example.com", "/").is_some());
    assert!(plan.select_route("two.example.com", "/").is_some());
    assert_eq!(plan.compatibility_diagnostics().len(), 1);
    let diagnostic = &plan.compatibility_diagnostics()[0];
    assert_eq!(diagnostic.site, None);
    assert_eq!(diagnostic.directive, "admin");
    assert_eq!(diagnostic.line, 2);
    assert_eq!(diagnostic.impact, CompatibilityImpact::Warning);
}

#[test]
fn gateway_plan_should_normalize_caddy_site_addresses_with_schemes_and_ports() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"https://api.example.com, http://www.example.com:8080 {
    reverse_proxy 127.0.0.1:3000
}
"#,
    )
    .unwrap();

    assert!(plan.select_route("api.example.com", "/").is_some());
    assert!(plan.select_route("www.example.com:8080", "/").is_some());
    assert!(
        plan.select_route("http://www.example.com:8080", "/")
            .is_none()
    );
}

#[test]
fn gateway_plan_should_apply_caddy_path_specificity_and_exact_path_semantics() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"api.example.com {
    reverse_proxy 127.0.0.1:3000
    reverse_proxy /v1/* 127.0.0.1:5001
    reverse_proxy /exact 127.0.0.1:5002
}
"#,
    )
    .unwrap();

    let api_route = plan.select_route("api.example.com", "/v1/users").unwrap();
    assert!(matches!(
        api_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:5001"
    ));

    let exact_route = plan.select_route("api.example.com", "/exact").unwrap();
    assert!(matches!(
        exact_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:5002"
    ));

    let fallback_route = plan
        .select_route("api.example.com", "/exact/child")
        .unwrap();
    assert!(matches!(
        fallback_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3000"
    ));
}

#[test]
fn gateway_plan_should_compile_caddy_handle_blocks_as_mutually_exclusive_routes() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"app.example.com {
    handle {
        reverse_proxy 127.0.0.1:3000
    }
    handle /admin/* {
        reverse_proxy 127.0.0.1:3001
    }
}
"#,
    )
    .unwrap();

    let admin_route = plan
        .select_route("app.example.com", "/admin/users")
        .unwrap();
    assert!(matches!(
        admin_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3001"
    ));

    let fallback_route = plan.select_route("app.example.com", "/public").unwrap();
    assert!(matches!(
        fallback_route.handler,
        HandlerPlan::ReverseProxy { ref upstream } if upstream.address == "127.0.0.1:3000"
    ));
}

#[test]
fn gateway_plan_should_warn_for_unsupported_caddyfile_directives_without_blocking_startup() {
    let plan = GatewayPlan::compile_caddyfile(
        "hdd.ink {\n\tencode gzip\n\treverse_proxy 127.0.0.1:3000\n}\n",
    )
    .unwrap();

    assert_eq!(plan.config_health().status, ConfigHealthStatus::Ready);
    assert!(plan.select_route("hdd.ink", "/").is_some());
    assert_eq!(plan.compatibility_diagnostics().len(), 1);

    let diagnostic = &plan.compatibility_diagnostics()[0];
    assert_eq!(diagnostic.site.as_deref(), Some("hdd.ink"));
    assert_eq!(diagnostic.directive, "encode");
    assert_eq!(diagnostic.line, 2);
    assert_eq!(diagnostic.impact, CompatibilityImpact::Warning);
}

#[test]
fn gateway_plan_should_degrade_config_health_for_security_sensitive_unsupported_directives() {
    let plan = GatewayPlan::compile_caddyfile(
        "secure.example {\n\tbasicauth /admin/* {\n\t\tuser JDJhJDE0JHVuaXQ=\n\t}\n\treverse_proxy 127.0.0.1:3000\n}\n",
    )
    .unwrap();

    assert_eq!(plan.config_health().status, ConfigHealthStatus::Degraded);
    assert!(!plan.config_health().ready);
    assert!(plan.select_route("secure.example", "/").is_some());

    let diagnostic = &plan.compatibility_diagnostics()[0];
    assert_eq!(diagnostic.site.as_deref(), Some("secure.example"));
    assert_eq!(diagnostic.directive, "basicauth");
    assert_eq!(diagnostic.line, 2);
    assert_eq!(diagnostic.impact, CompatibilityImpact::DegradesReadiness);
}

#[test]
fn gateway_plan_should_report_startup_compatibility_summary_with_diagnostic_detail() {
    let plan = GatewayPlan::compile_caddyfile(
        r#"{
    admin off
}

secure.example {
    encode gzip
    basicauth /admin/* {
        user JDJhJDE0JHVuaXQ=
    }
    reverse_proxy 127.0.0.1:3000
}
"#,
    )
    .unwrap();

    let summary = plan
        .startup_compatibility_summary()
        .expect("unsupported directives should produce a startup summary");

    assert!(
        summary.contains("site=<global> directive=admin line=2 impact=warning")
            && summary.contains("site=secure.example directive=encode line=6 impact=warning")
            && summary.contains(
                "site=secure.example directive=basicauth line=7 impact=degrades_readiness"
            ),
        "summary={summary}"
    );
}

#[test]
fn active_gateway_plan_should_publish_shared_immutable_snapshots() {
    let first =
        GatewayPlan::compile_caddyfile("first.example {\n\treverse_proxy 127.0.0.1:3000\n}\n")
            .unwrap();
    let second =
        GatewayPlan::compile_caddyfile("second.example {\n\treverse_proxy 127.0.0.1:4000\n}\n")
            .unwrap();
    let active = ActiveGatewayPlan::new(first);

    let first_snapshot = active.snapshot();
    assert!(first_snapshot.select_route("first.example", "/").is_some());

    active.replace(second);

    let second_snapshot = active.snapshot();
    assert!(
        second_snapshot
            .select_route("second.example", "/")
            .is_some()
    );
    assert!(first_snapshot.select_route("first.example", "/").is_some());
    assert!(first_snapshot.select_route("second.example", "/").is_none());
    assert!(!Arc::ptr_eq(&first_snapshot, &second_snapshot));
}
