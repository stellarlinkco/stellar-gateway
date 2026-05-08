use stellar_gateway::config::GatewayConfig;
use stellar_gateway::routing::{is_exact_host_match, is_wildcard_host_match};

#[test]
fn is_wildcard_host_match_should_match_case_insensitive_and_ignore_port() {
    assert!(is_wildcard_host_match(
        "Foo.PaGe.HdD.InK:443",
        "page.hdd.ink"
    ));
}

#[test]
fn is_wildcard_host_match_should_not_match_apex_suffix() {
    assert!(!is_wildcard_host_match("page.hdd.ink", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_not_match_outside_host() {
    assert!(!is_wildcard_host_match("example.com", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_match_multiple_labels_before_suffix() {
    assert!(is_wildcard_host_match("a.b.page.hdd.ink", "page.hdd.ink"));
}

#[test]
fn is_wildcard_host_match_should_not_match_when_label_is_missing() {
    assert!(!is_wildcard_host_match(".page.hdd.ink", "page.hdd.ink"));
}

#[test]
fn is_exact_host_match_should_match_case_insensitive_and_ignore_port() {
    assert!(is_exact_host_match("HDD.Ink:443", "hdd.ink"));
}

#[test]
fn is_exact_host_match_should_not_match_subdomain() {
    assert!(!is_exact_host_match("zhirang.hdd.ink", "hdd.ink"));
}

#[test]
fn routes_should_match_caddyfile_apex_and_wildcard_hosts() {
    let config = GatewayConfig::load_from_str(
        r#"
hdd.ink, *.hdd.ink {
	reverse_proxy website:3000
}
"#,
    )
    .unwrap();

    assert!(config.routes.select_route("hdd.ink").is_some());
    assert!(config.routes.select_route("zhirang.hdd.ink").is_some());
    assert!(config.routes.select_route("aichao.hdd.ink:443").is_some());
    assert!(config.routes.select_route("example.com").is_none());
}
