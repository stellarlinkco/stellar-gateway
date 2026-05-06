use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use clap::Parser;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::{Opt, Server, http_proxy_service};
use rcgen::generate_simple_self_signed;
use stellar_gateway::cert_cache::CertificateMaterial;
use stellar_gateway::config::GatewayConfig;
use stellar_gateway::error::{GatewayError, Result};
use stellar_gateway::proxy::GatewayProxy;
use stellar_gateway::reload::GatewayRuntimeState;
use stellar_gateway::tls::tls_accept_callbacks;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "stellar-gateway")]
#[command(about = "A Pingora-based reverse proxy gateway")]
struct Cli {
    #[arg(long, default_value = "Gatewayfile")]
    gatewayfile: PathBuf,
}

struct GeneratedCertificatePaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn generated_certificate_paths(cache_dir: &Path) -> GeneratedCertificatePaths {
    GeneratedCertificatePaths {
        cert_path: cache_dir.join("stellar-gateway-self-signed.crt"),
        key_path: cache_dir.join("stellar-gateway-self-signed.key"),
    }
}

fn fallback_certificate_server_names(wildcard_suffix: &str) -> Vec<String> {
    let suffix = wildcard_suffix.trim().trim_start_matches('.');
    vec![format!("*.{suffix}")]
}

fn read_certificate_material(paths: &GeneratedCertificatePaths) -> Result<CertificateMaterial> {
    let cert_pem = fs::read_to_string(&paths.cert_path).map_err(|err| {
        GatewayError::CertificateCache(format!(
            "failed to read TLS certificate `{}`: {err}",
            paths.cert_path.display()
        ))
    })?;
    let key_pem = fs::read_to_string(&paths.key_path).map_err(|err| {
        GatewayError::CertificateCache(format!(
            "failed to read TLS private key `{}`: {err}",
            paths.key_path.display()
        ))
    })?;
    Ok(CertificateMaterial::new(cert_pem, key_pem))
}

fn ensure_generated_certificate(
    cache_dir: &Path,
    server_names: &[String],
) -> Result<GeneratedCertificatePaths> {
    fs::create_dir_all(cache_dir).map_err(|err| {
        GatewayError::CertificateCache(format!(
            "failed to create certificate cache directory `{}`: {err}",
            cache_dir.display()
        ))
    })?;

    let paths = generated_certificate_paths(cache_dir);
    if paths.cert_path.exists() && paths.key_path.exists() {
        return Ok(paths);
    }

    let cert = generate_simple_self_signed(server_names.to_owned()).map_err(|err| {
        GatewayError::CertificateCache(format!("failed to generate TLS certificate: {err}"))
    })?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    fs::write(&paths.cert_path, cert_pem).map_err(|err| {
        GatewayError::CertificateCache(format!(
            "failed to write TLS certificate `{}`: {err}",
            paths.cert_path.display()
        ))
    })?;
    fs::write(&paths.key_path, key_pem).map_err(|err| {
        GatewayError::CertificateCache(format!(
            "failed to write TLS private key `{}`: {err}",
            paths.key_path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&paths.key_path, fs::Permissions::from_mode(0o600));
    }

    Ok(paths)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = GatewayConfig::load_from_path(&cli.gatewayfile)?;
    let runtime_state = Arc::new(GatewayRuntimeState::new(
        config.clone(),
        &cli.gatewayfile,
        SystemTime::now(),
    )?);

    let mut server = Server::new(Some(Opt::default()))?;
    server.bootstrap();

    let mut proxy = http_proxy_service(
        &server.configuration,
        GatewayProxy::from_runtime_state(Arc::clone(&runtime_state)),
    );
    let http_bind = config.listeners.http.bind.to_string();
    let https_bind = config.listeners.https.bind.to_string();
    let server_names = fallback_certificate_server_names(&config.routes.wildcard.suffix);
    let cert_paths = ensure_generated_certificate(&config.cert_cache.dir, &server_names)?;
    let fallback_material = read_certificate_material(&cert_paths)?;
    let tls_settings =
        TlsSettings::with_callbacks(tls_accept_callbacks(runtime_state, fallback_material))?;

    proxy.add_tcp(http_bind.as_str());
    proxy.add_tls_with_settings(https_bind.as_str(), None, tls_settings);
    server.add_service(proxy);

    tracing::info!(
        gatewayfile = %cli.gatewayfile.display(),
        http_listen = %http_bind,
        https_listen = %https_bind,
        upstream = %config.routes.wildcard.upstream.addr,
        "starting stellar gateway"
    );
    server.run_forever();
}
