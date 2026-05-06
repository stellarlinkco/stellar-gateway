# StellarGate (stellar-gateway) — MVP

StellarGate is a Rust reverse proxy gateway built on Cloudflare Pingora. The MVP is configured via a `Gatewayfile` and focuses on wildcard host routing for `*.page.hdd.ink`, fixed-upstream proxying, HTTP-01 challenge handling boundaries, local certificate cache boundaries, reloadable runtime state, and structured operational logs.

## Quickstart

1. Create or edit `Gatewayfile` (example at repo root).
2. Start a local upstream (example):
   - `python3 -m http.server 3000`
3. Run the gateway:
   - `cargo run -- --gatewayfile Gatewayfile`
4. Send a request with a matching host:
   - `curl -v 127.0.0.1:8080/ -H 'Host: demo.page.hdd.ink'`

Non-matching hosts are deterministically rejected and do not reach the upstream:
- `curl -v 127.0.0.1:8080/ -H 'Host: example.com'`

## Routing rules (MVP)

- Wildcard matching is **case-insensitive** and ignores any `Host` header port.
- `*.page.hdd.ink` matches only when there is **at least one label** before the suffix (the apex `page.hdd.ink` does not match unless explicitly configured later).
- Matched requests proxy to the single fixed upstream configured at `routes.wildcard.upstream`.

## TLS / ACME notes (MVP boundaries)

- The ask endpoint logic is modeled as a pure client (`AskClient`) with explicit decision + stable denial reason classes.
- HTTP-01 challenge handling is modeled via an in-memory token store and policy that can respond to `/.well-known/acme-challenge/...` without exposing token values in logs.
- Full ACME issuance and HTTPS listener wiring are out of scope for the current code skeleton.

## Validation

Run the full quality gate:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`

