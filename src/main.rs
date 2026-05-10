use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use clap::Parser;
use pingora::apps::HttpServerOptions;
use pingora::prelude::{Opt, Server};
use pingora::proxy::ProxyServiceBuilder;
use stellar_gateway::error::Result;
use stellar_gateway::proxy::GatewayProxy;
use stellar_gateway::reload::{GatewayRuntimeState, LoadedGatewayRuntime};
use stellar_gateway::tls::tls_settings;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "stellar-gateway")]
#[command(about = "A Pingora-based reverse proxy gateway")]
struct Cli {
    #[arg(long, default_value = "Gatewayfile")]
    gatewayfile: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let loaded = LoadedGatewayRuntime::load_from_path(&cli.gatewayfile)?;
    let config = loaded.config.clone();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| config.logging.to_env_filter()),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Some(summary) = loaded.plan.startup_compatibility_summary() {
        tracing::warn!(
            event = "startup_compatibility_summary",
            summary = %summary,
            "startup compatibility summary"
        );
    }

    let runtime_state = Arc::new(GatewayRuntimeState::new_loaded(
        loaded,
        &cli.gatewayfile,
        SystemTime::now(),
    )?);

    let mut server = Server::new(Some(Opt::default()))?;
    server.bootstrap();

    let mut server_options = HttpServerOptions::default();
    server_options.h2c = true;
    let mut proxy = ProxyServiceBuilder::new(
        &server.configuration,
        GatewayProxy::from_runtime_state(Arc::clone(&runtime_state)),
    )
    .server_options(server_options)
    .build();
    let http_bind = config.listeners.http.bind.to_string();
    let https_bind = config.listeners.https.bind.to_string();
    let tls_settings = tls_settings(Arc::clone(&runtime_state))?;

    install_reload_handler(Arc::clone(&runtime_state));

    proxy.add_tcp(http_bind.as_str());
    proxy.add_tls_with_settings(https_bind.as_str(), None, tls_settings);
    server.add_service(proxy);

    tracing::info!(
        gatewayfile = %cli.gatewayfile.display(),
        http_listen = %http_bind,
        https_listen = %https_bind,
        apex_host = config.routes.apex.as_ref().map(|route| route.host.as_str()),
        apex_upstream = config.routes.apex.as_ref().map(|route| route.upstream.addr.as_str()),
        wildcard_suffix = %config.routes.wildcard.suffix,
        wildcard_upstream = %config.routes.wildcard.upstream.addr,
        "starting stellar gateway"
    );
    server.run_forever();
}

#[cfg(unix)]
fn install_reload_handler(runtime_state: Arc<GatewayRuntimeState>) {
    if !runtime_state.config().reload.enabled {
        tracing::info!(event = "reload", enabled = false, "reload handler disabled");
        return;
    }

    std::thread::spawn(move || {
        let Ok(mut signals) = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])
        else {
            tracing::warn!(event = "reload", "failed to install SIGHUP reload handler");
            return;
        };
        for _signal in signals.forever() {
            if let Err(err) = runtime_state.reload_if_enabled(SystemTime::now()) {
                tracing::warn!(event = "reload", error = %err, "reload failed");
            }
        }
    });
}

#[cfg(not(unix))]
fn install_reload_handler(_runtime_state: Arc<GatewayRuntimeState>) {}
