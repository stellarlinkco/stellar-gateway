# Agent Guide

## Project map

- `src/main.rs` starts the Pingora server and installs reload handling.
- `src/proxy.rs` handles request filtering, routing, health, metrics, ACME HTTP-01, and upstream selection.
- `src/tls.rs` handles ask endpoint authorization and TLS accept callbacks.
- `src/reload.rs` owns runtime config, certificate cache, ACME issuance, and SIGHUP reload behavior.
- `src/acme_issuer.rs` integrates with ACME providers.
- `tests/` contains Rust integration tests; `tests/acceptance/` contains the Docker Compose acceptance runner.

## Common commands

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
python3 tests/acceptance/docker_compose_acceptance.py
bash scripts/readiness-check.sh
```

## Local run

```bash
python3 -m http.server 3000
cargo run -- --gatewayfile Gatewayfile
curl -v 127.0.0.1:8080/ -H 'Host: demo.page.hdd.ink'
curl -v 127.0.0.1:8080/health
curl -v 127.0.0.1:8080/metrics
```

## Docker

```bash
docker build -t stellar-gateway .
docker run --rm \
  -p 8080:8080 \
  -p 8443:8443 \
  -v "$PWD/Gatewayfile:/app/Gatewayfile:ro" \
  -v "$PWD/cert-cache:/app/cert-cache" \
  stellar-gateway --gatewayfile /app/Gatewayfile
```

## Conventions

- Keep runtime configuration in `Gatewayfile`; do not add required `.env` variables unless a template is also added.
- Do not log certificate material, private keys, ACME key authorization values, or full challenge tokens.
- Preserve wildcard routing semantics: host matching is case-insensitive, ignores port, and does not match the apex suffix.
- Use Rust naming conventions and keep modules focused by gateway concern.
- Add or update tests for behavior changes before reporting completion.

## Pre-commit checklist

Run the common commands above before committing. If Docker is unavailable, state that the acceptance test was skipped and why.
