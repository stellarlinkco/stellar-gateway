# StellarGate (`stellar-gateway`)

StellarGate is a Rust reverse proxy gateway built on Cloudflare Pingora. It routes wildcard tenant hosts such as `*.page.hdd.ink` to a configured upstream and can issue HTTPS certificates on demand through ACME HTTP-01.

## What it does

- Proxies matching wildcard hosts to one upstream.
- Rejects non-matching hosts before they reach the upstream.
- Handles ACME HTTP-01 challenges at `/.well-known/acme-challenge/...`.
- Calls an ask endpoint before issuing a new on-demand certificate.
- Stores issued certificates in `cert_cache.dir` and reuses them after restart.
- Reloads `Gatewayfile` and certificate cache on `SIGHUP` when `reload.enabled: true`.

## Gatewayfile example

```yaml
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
```

For production Let's Encrypt, change `acme.directory_url` to:

```yaml
directory_url: "https://acme-v02.api.letsencrypt.org/directory"
```

## Local HTTP quickstart

Start an upstream:

```bash
python3 -m http.server 3000
```

Start the gateway:

```bash
cargo run -- --gatewayfile Gatewayfile
```

Send a matching request:

```bash
curl -v 127.0.0.1:8080/ -H 'Host: demo.page.hdd.ink'
```

Check health and metrics:

```bash
curl -v 127.0.0.1:8080/health
curl -v 127.0.0.1:8080/metrics
```

Non-matching hosts are rejected:

```bash
curl -v 127.0.0.1:8080/ -H 'Host: example.com'
```

## HTTPS / ACME usage

To issue real certificates, ACME must be able to reach the gateway over public HTTP for the requested hostname.

1. Point DNS for `*.page.hdd.ink` to the gateway server.
2. Expose the HTTP listener on public port `80` and HTTPS listener on public port `443`.
3. Run an ask service at `tls.ask_url`; it should return a 2xx status for allowed hostnames and non-2xx for denied hostnames.
4. Configure `acme.email` and the ACME `directory_url`.
5. Start the gateway.
6. Visit or curl a matching HTTPS hostname; the gateway will call the ask endpoint, issue a certificate, cache it, then serve HTTPS.

Example production listener settings:

```yaml
listeners:
  http:
    bind: "0.0.0.0:80"
  https:
    bind: "0.0.0.0:443"
```

## Ask endpoint contract

The gateway sends a GET request to `tls.ask_url` with the requested hostname as the `domain` query parameter.

Example request:

```text
GET /ask?domain=demo.page.hdd.ink
```

- Return `200` to allow issuance.
- Return `403`, `404`, or another non-2xx status to deny issuance.

## Reload configuration

When `reload.enabled: true`, send `SIGHUP` to reload the `Gatewayfile` and certificate cache without restarting:

```bash
kill -HUP <gateway-pid>
```

If the new `Gatewayfile` is invalid, the gateway keeps serving with the previous valid configuration.

## Docker acceptance test

Run the local end-to-end acceptance test with Pebble ACME:

```bash
python3 tests/acceptance/docker_compose_acceptance.py
```

This builds the gateway image, starts Docker Compose services, verifies HTTP routing, ACME-backed HTTPS issuance, certificate cache reuse, `SIGHUP` reload, invalid reload preservation, and restart behavior.

## Build

```bash
cargo build --release --locked
```

## Docker usage

Build the local image from the `Dockerfile`:

```bash
docker build -t stellar-gateway .
```

Run it with the repository `Gatewayfile` and a persistent certificate cache:

```bash
mkdir -p cert-cache
docker run --rm \
  -p 8080:8080 \
  -p 8443:8443 \
  -v "$PWD/Gatewayfile:/app/Gatewayfile:ro" \
  -v "$PWD/cert-cache:/app/cert-cache" \
  stellar-gateway --gatewayfile /app/Gatewayfile
```

For production, update `Gatewayfile` to bind `0.0.0.0:80` and `0.0.0.0:443`, then publish those ports:

```bash
docker run -d --name stellar-gateway \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /etc/stellar-gateway/Gatewayfile:/app/Gatewayfile:ro \
  -v /var/lib/stellar-gateway/cert-cache:/app/cert-cache \
  ghcr.io/stellarlinkco/stellar-gateway:latest --gatewayfile /app/Gatewayfile
```

The GitHub Actions workflow publishes images to GitHub Container Registry:

```bash
docker pull ghcr.io/stellarlinkco/stellar-gateway:latest
docker pull ghcr.io/stellarlinkco/stellar-gateway:sha-<commit>
```

Git tags such as `v0.1.0` are also published as matching image tags.

## Operations

See `docs/runbooks/operations.md` for deploy, health verification, reload, rollback, ACME troubleshooting, and metrics guidance.

## Validation

Run the quality gate:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
python3 tests/acceptance/docker_compose_acceptance.py
bash scripts/readiness-check.sh
```

