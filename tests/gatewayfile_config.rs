use stellar_gateway::config::GatewayConfig;
use url::Url;

const VALID_MVP_GATEWAYFILE: &str = r#"
listeners:
  http:
    bind: "0.0.0.0:8080"
  https:
    bind: "0.0.0.0:8443"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

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

fn load_valid() -> GatewayConfig {
    GatewayConfig::load_from_str(VALID_MVP_GATEWAYFILE).expect("valid fixture must load")
}

#[test]
fn gatewayfile_should_load_valid_mvp_fixture() {
    let result = GatewayConfig::load_from_str(VALID_MVP_GATEWAYFILE);
    assert!(result.is_ok());
}

#[test]
fn gatewayfile_should_load_http_listener_bind() {
    let config = load_valid();
    assert_eq!(config.listeners.http.bind, "0.0.0.0:8080".parse().unwrap());
}

#[test]
fn gatewayfile_should_load_https_listener_bind() {
    let config = load_valid();
    assert_eq!(config.listeners.https.bind, "0.0.0.0:8443".parse().unwrap());
}

#[test]
fn gatewayfile_should_load_wildcard_route_suffix() {
    let config = load_valid();
    assert_eq!(config.routes.wildcard.suffix, "page.hdd.ink");
}

#[test]
fn gatewayfile_should_load_wildcard_upstream_addr() {
    let config = load_valid();
    assert_eq!(config.routes.wildcard.upstream.addr, "127.0.0.1:3000");
}

#[test]
fn gatewayfile_should_load_tls_ask_url() {
    let config = load_valid();
    assert_eq!(
        config.tls.ask_url,
        Url::parse("http://127.0.0.1:9000/ask").unwrap()
    );
}

#[test]
fn gatewayfile_should_load_acme_http01_enabled() {
    let config = load_valid();
    assert!(config.acme.http_01);
}

#[test]
fn gatewayfile_should_load_cert_cache_dir() {
    let config = load_valid();
    assert_eq!(
        config.cert_cache.dir,
        std::path::PathBuf::from("./cert-cache")
    );
}

#[test]
fn gatewayfile_should_load_reload_enabled() {
    let config = load_valid();
    assert!(config.reload.enabled);
}

#[test]
fn gatewayfile_should_load_logging_level() {
    let config = load_valid();
    assert_eq!(config.logging.level, "info");
}

#[test]
fn gatewayfile_should_error_on_missing_required_field() {
    let invalid = r#"
listeners:
  http: {}
  https:
    bind: "0.0.0.0:8443"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

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

    let err = GatewayConfig::load_from_str(invalid).unwrap_err();
    assert!(err.to_string().contains("listeners.http"));
}

#[test]
fn gatewayfile_should_error_on_unsupported_field() {
    let invalid = r#"
listeners:
  http:
    bind: "0.0.0.0:8080"
  https:
    bind: "0.0.0.0:8443"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    unsupported: true
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

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

    let err = GatewayConfig::load_from_str(invalid).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown field") && msg.contains("unsupported"));
}

#[test]
fn gatewayfile_should_error_on_invalid_yaml_syntax() {
    let invalid = r#"
listeners:
  http:
    bind "0.0.0.0:8080"
"#;

    let err = GatewayConfig::load_from_str(invalid).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("line") || msg.contains("column"));
}

#[test]
fn gatewayfile_should_load_from_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("Gatewayfile");
    std::fs::write(&path, VALID_MVP_GATEWAYFILE).unwrap();

    let result = GatewayConfig::load_from_path(&path);
    assert!(result.is_ok());
}

#[test]
fn gatewayfile_should_error_when_acme_http01_disabled() {
    let invalid = r#"
listeners:
  http:
    bind: "0.0.0.0:8080"
  https:
    bind: "0.0.0.0:8443"

routes:
  wildcard:
    suffix: "page.hdd.ink"
    upstream:
      addr: "127.0.0.1:3000"
      tls: false

tls:
  ask_url: "http://127.0.0.1:9000/ask"

acme:
  directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory"
  email: "admin@example.com"
  http_01: false

cert_cache:
  dir: "./cert-cache"

reload:
  enabled: true

logging:
  level: "info"
"#;

    let err = GatewayConfig::load_from_str(invalid).unwrap_err();
    assert!(err.to_string().contains("acme.http_01 must be true"));
}
