use std::time::{Duration, SystemTime};

use stellar_gateway::cert_cache::{
    CacheEntryRejection, CertificateCache, CertificateCacheEntry, CertificateMaterial,
};
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::reload::GatewayRuntimeState;

fn valid_gatewayfile(cache_dir: &std::path::Path, suffix: &str) -> String {
    format!(
        r#"
listeners:
  http:
    bind: "127.0.0.1:8080"
  https:
    bind: "127.0.0.1:8443"

routes:
  wildcard:
    suffix: "{suffix}"
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
  dir: "{}"

reload:
  enabled: true

logging:
  level: "info"
"#,
        cache_dir.display()
    )
}

fn valid_entry_with_expiry(hostname: &str, expires_at: SystemTime) -> CertificateCacheEntry {
    let certificate = rcgen::generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
    CertificateCacheEntry::new(
        hostname,
        CertificateMaterial::new(
            certificate.cert.pem(),
            certificate.signing_key.serialize_pem(),
        ),
        expires_at,
    )
}

fn valid_entry(hostname: &str) -> CertificateCacheEntry {
    valid_entry_with_expiry(hostname, SystemTime::now() + Duration::from_secs(3600))
}

#[test]
fn certificate_cache_should_reject_redacted_material_placeholders_as_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let hostname = "redacted.page.hdd.ink";
    std::fs::write(
        dir.path().join(format!("{hostname}.yaml")),
        format!(
            "hostname: {hostname}\nexpires_at_unix: 4102444800\ncertificate_pem: redacted-cert-pem\nprivate_key_pem: redacted-key-pem\n"
        ),
    )
    .unwrap();

    let loaded = CertificateCache::load(dir.path(), SystemTime::now()).unwrap();

    assert!(
        loaded.lookup(hostname).is_none()
            && loaded
                .rejections()
                .iter()
                .any(|record| record.class == CacheEntryRejection::Malformed)
    );
}

#[test]
fn certificate_cache_should_reject_mismatched_certificate_and_private_key_pair() {
    let dir = tempfile::tempdir().unwrap();
    let hostname = "mismatch.page.hdd.ink";
    let certificate = rcgen::generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
    let other_certificate = rcgen::generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
    let certificate_pem = certificate.cert.pem();
    let private_key_pem = other_certificate.signing_key.serialize_pem();
    let indent_pem = |pem: &str| {
        pem.lines()
            .map(|line| format!("  {line}\n"))
            .collect::<String>()
    };
    std::fs::write(
        dir.path().join(format!("{hostname}.yaml")),
        format!(
            "hostname: {hostname}\nexpires_at_unix: 4102444800\ncertificate_pem: |\n{}private_key_pem: |\n{}",
            indent_pem(&certificate_pem),
            indent_pem(&private_key_pem)
        ),
    )
    .unwrap();

    let loaded = CertificateCache::load(dir.path(), SystemTime::now()).unwrap();

    assert!(
        loaded.lookup(hostname).is_none()
            && loaded
                .rejections()
                .iter()
                .any(|record| record.class == CacheEntryRejection::Malformed)
    );
}

#[test]
fn certificate_cache_should_reuse_valid_entry_after_state_recreation() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CertificateCache::new(dir.path());
    cache.store(&valid_entry("demo.page.hdd.ink")).unwrap();

    let recreated = CertificateCache::load(dir.path(), SystemTime::now()).unwrap();
    let entry = recreated.lookup("demo.page.hdd.ink");

    assert!(entry.is_some());
}

#[test]
fn certificate_cache_should_report_invalid_entries_by_rejection_class() {
    let dir = tempfile::tempdir().unwrap();
    let cache = CertificateCache::new(dir.path());
    cache.store(&valid_entry("valid.page.hdd.ink")).unwrap();
    cache
        .store(&valid_entry_with_expiry(
            "expired.page.hdd.ink",
            SystemTime::now() - Duration::from_secs(1),
        ))
        .unwrap();
    cache.store(&valid_entry("mismatch.page.hdd.ink")).unwrap();
    std::fs::rename(
        dir.path().join("mismatch.page.hdd.ink.yaml"),
        dir.path().join("other.page.hdd.ink.yaml"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("malformed.page.hdd.ink.yaml"),
        b": not yaml: :",
    )
    .unwrap();
    std::fs::write(dir.path().join("missing.page.hdd.ink.yaml"), b"hostname: missing.page.hdd.ink\nexpires_at_unix: 4102444800\ncertificate_pem: redacted-cert-pem\n").unwrap();

    let loaded = CertificateCache::load(dir.path(), SystemTime::now()).unwrap();
    let classes: Vec<_> = loaded.rejections().iter().map(|r| r.class).collect();

    assert!(classes.contains(&CacheEntryRejection::Expired));
    assert!(classes.contains(&CacheEntryRejection::HostnameMismatch));
    assert!(classes.contains(&CacheEntryRejection::Malformed));
    assert!(classes.contains(&CacheEntryRejection::MissingMaterial));
}

#[test]
fn gateway_runtime_state_should_keep_previous_config_when_reload_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let gatewayfile = dir.path().join("Gatewayfile");
    std::fs::write(&gatewayfile, valid_gatewayfile(dir.path(), "page.hdd.ink")).unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile).unwrap();
    let state = GatewayRuntimeState::new(config, &gatewayfile, SystemTime::now()).unwrap();
    std::fs::write(&gatewayfile, "listeners: {}").unwrap();

    let result = state.reload_config();

    assert!(result.is_err());
    assert_eq!(state.config().routes.wildcard.suffix, "page.hdd.ink");
}

#[test]
fn gateway_runtime_state_should_apply_valid_config_reload() {
    let dir = tempfile::tempdir().unwrap();
    let gatewayfile = dir.path().join("Gatewayfile");
    std::fs::write(&gatewayfile, valid_gatewayfile(dir.path(), "page.hdd.ink")).unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile).unwrap();
    let state = GatewayRuntimeState::new(config, &gatewayfile, SystemTime::now()).unwrap();
    std::fs::write(&gatewayfile, valid_gatewayfile(dir.path(), "other.hdd.ink")).unwrap();

    state.reload_config().unwrap();

    assert_eq!(state.config().routes.wildcard.suffix, "other.hdd.ink");
}

#[test]
fn gateway_runtime_state_should_refresh_certificate_cache_without_restarting() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("cert-cache");
    let gatewayfile = dir.path().join("Gatewayfile");
    std::fs::write(&gatewayfile, valid_gatewayfile(&cache_dir, "page.hdd.ink")).unwrap();
    let config = GatewayConfig::load_from_path(&gatewayfile).unwrap();
    let state = GatewayRuntimeState::new(config, &gatewayfile, SystemTime::now()).unwrap();
    CertificateCache::new(&cache_dir)
        .store(&valid_entry("demo.page.hdd.ink"))
        .unwrap();

    state.reload_certificates(SystemTime::now()).unwrap();

    assert!(state.certificate_for("demo.page.hdd.ink").is_some());
}
