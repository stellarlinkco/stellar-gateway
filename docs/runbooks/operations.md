# Stellar Gateway Operations Runbook

## Deploy with GHCR image

1. Prepare `/etc/stellar-gateway/Gatewayfile`.
2. Ensure DNS for both the apex host and wildcard suffix points to the host.
3. Ensure ports `80` and `443` are reachable by clients and ACME.
4. Start the container:

```bash
docker pull ghcr.io/stellarlinkco/stellar-gateway:latest
docker run -d --name stellar-gateway \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /etc/stellar-gateway/Gatewayfile:/app/Gatewayfile:ro \
  -v /var/lib/stellar-gateway/cert-cache:/app/cert-cache \
  ghcr.io/stellarlinkco/stellar-gateway:latest --gatewayfile /app/Gatewayfile
```

## Verify service health

```bash
curl --fail http://127.0.0.1/health
curl --fail http://127.0.0.1/metrics
curl -v http://127.0.0.1/ -H 'Host: hdd.ink'
curl -v http://127.0.0.1/ -H 'Host: zhirang.hdd.ink'
```

Expected:

- `/health` returns `200 ok`.
- `/metrics` returns Prometheus text counters.
- Matching apex and wildcard hosts proxy to the configured upstream.
- Non-matching hosts return `404`.

## Reload configuration

1. Edit and validate `Gatewayfile`.
2. Send SIGHUP:

```bash
docker kill -s HUP stellar-gateway
```

If the new config is invalid, the gateway keeps the previous valid config and logs `reload failed`.

## Roll back an image

Use the previous `sha-*` image tag from GitHub Actions or GHCR.

```bash
docker pull ghcr.io/stellarlinkco/stellar-gateway:sha-<previous-commit>
docker rm -f stellar-gateway
docker run -d --name stellar-gateway \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /etc/stellar-gateway/Gatewayfile:/app/Gatewayfile:ro \
  -v /var/lib/stellar-gateway/cert-cache:/app/cert-cache \
  ghcr.io/stellarlinkco/stellar-gateway:sha-<previous-commit> --gatewayfile /app/Gatewayfile
```

Verify `/health`, `/metrics`, HTTP routing, and HTTPS certificate reuse after rollback.

## ACME issuance troubleshooting

Check these in order:

1. DNS resolves the tenant hostname to the gateway host.
2. Port `80` reaches the gateway HTTP listener.
3. `tls.ask_url` returns a 2xx response for the hostname.
4. `acme.directory_url` points to staging or production Let's Encrypt as intended.
5. `cert_cache.dir` is writable by the container.
6. Logs contain `tls_acme_issuance` with `decision = "issued"`.

Useful commands:

```bash
docker logs stellar-gateway
docker exec stellar-gateway test -w /app/cert-cache
curl -v http://127.0.0.1/.well-known/acme-challenge/test -H 'Host: zhirang.hdd.ink'
```

## Metrics to watch

- `stellar_gateway_requests_total`
- `stellar_gateway_route_rejections_total`
- `stellar_gateway_upstream_errors_total`
- `stellar_gateway_cert_issuance_failures_total`
- `stellar_gateway_reload_failures_total`

Unexpected growth in rejection, upstream error, issuance failure, or reload failure counters should trigger investigation.
