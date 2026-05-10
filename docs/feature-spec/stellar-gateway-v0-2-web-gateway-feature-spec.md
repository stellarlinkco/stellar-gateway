# Stellar Gateway v0.2 Web Gateway MVP Feature Spec

## Convergence Summary

- **Confirmed goal**: Evolve Stellar Gateway from a single-upstream wildcard reverse proxy into a v0.2 HTTP/gRPC Web Gateway MVP.
- **Confirmed requirements**: Caddy-aligned configuration, nginx-aligned performance architecture, Gateway Plan IR, multi-site routing, static files, HTTP reverse proxy, native gRPC proxy, compatibility warnings, `/health`, `/ready`, and closed-loop validation.
- **Known scope boundaries**: Do not implement FastCGI/uWSGI/SCGI/PHP gateway behavior; do not implement mail proxying or full nginx stream TCP/UDP parity; defer HTTP/3 until Rust ecosystem support is mature enough to adopt directly.
- **Relevant system context**: Current code has `GatewayConfig`, a small Caddyfile subset parser, Pingora `ProxyHttp` adapter, on-demand TLS/ACME, cert cache, reload, health, and metrics.
- **Working assumptions**: v0.2 may preserve existing YAML Gatewayfile behavior while adding the Caddyfile Compatibility Layer and Gateway Plan; unsupported Caddyfile directives warn by default per ADR-0001.
- **Blocking questions**: None; implementation should infer low-level defaults from the documented product principles.

**Readiness score**: 91/100 — Mission-ready. The feature is broad, but scope, architecture seams, validation expectations, and non-goals are explicit.

## Goal

Build v0.2 as an HTTP/gRPC Web Gateway MVP: Caddy-compatible configuration ergonomics compiled into a high-performance Gateway Plan executed through Pingora, supporting static site serving, HTTP reverse proxying, and native gRPC reverse proxying.

## Scope

### In Scope

- Gateway Plan IR as the runtime execution model.
- Caddyfile Compatibility Layer that parses broad Caddyfile syntax and compiles supported behavior into Gateway Plan.
- Multi-site configuration with host/path matching.
- Caddy-compatible handler semantics for supported directives.
- `root` and `file_server` static file serving.
- HTTP `reverse_proxy`.
- Native gRPC reverse proxy for `h2c://` and `grpcs://` upstreams.
- WebSocket and SSE smoke coverage for reverse proxy behavior.
- Config validation, compatibility diagnostics, and startup summary.
- `/health` for liveness and `/ready` for Config Health readiness.
- TDD implementation with closed-loop acceptance testing and CI validation.

### Out of Scope

- FastCGI, uWSGI, SCGI, PHP gateway behavior.
- gRPC-Web or REST transcoding.
- Full nginx stream TCP/UDP parity and mail proxying.
- HTTP/3/QUIC implementation in v0.2.
- Production-grade upstream pools, load balancing, active/passive health checks, proxy cache, compression, auth, rate limiting, and admin API; these are later roadmap items.

## PRD Requirements

- **FR-001 Gateway Plan IR**: Runtime request handling must consume an immutable Gateway Plan instead of raw Gatewayfile/Caddyfile parser structures.
- **FR-002 Caddyfile Compatibility Layer**: Caddyfile input must support broad syntax parsing and compile supported Sites, Matchers, and Handlers into Gateway Plan.
- **FR-003 Permissive Migration Diagnostics**: Recognized-but-unsupported Caddyfile directives must produce startup warnings with site, directive, line number, and impact level instead of hard-failing by default.
- **FR-004 Multi-Site Routing**: Gateway Plan must support multiple Sites and host/path Matchers.
- **FR-005 Handler Semantics**: Supported handlers must follow Caddy-compatible ordering and route/handle semantics where implemented.
- **FR-006 Static Files**: `root` + `file_server` must serve static files with safe path resolution, index handling, and deterministic missing-file behavior.
- **FR-007 HTTP Reverse Proxy**: `reverse_proxy` must continue to proxy HTTP upstream traffic and preserve existing Host/X-Forwarded-Host behavior unless config overrides it.
- **FR-008 Native gRPC Proxy**: `h2c://` and `grpcs://` upstreams must proxy native gRPC over HTTP/2 while preserving streaming and trailers.
- **FR-009 Control Endpoints**: `/health` must report process liveness; `/ready` must report Config Health and return degraded readiness for security-sensitive unsupported directives.
- **FR-010 Existing MVP Preservation**: Existing apex/wildcard reverse proxy, on-demand TLS, ACME HTTP-01/TLS-ALPN, cert cache, reload, metrics, and logging behavior must remain covered unless explicitly replaced by Gateway Plan behavior.

## Technical Plan

### Architecture Direction

- Introduce `gateway_plan` as the deep Module for Sites, Matchers, Handler chains, Upstreams, TLS policy, Config Health, and compatibility diagnostics.
- Split Caddyfile parsing/compatibility from raw config into a dedicated Adapter that compiles into Gateway Plan.
- Keep Pingora code as an outer Adapter; move gateway dispatch into a Gateway-owned dispatch Module.
- Represent upstream transport with typed variants rather than `addr + tls` booleans for new plan paths: HTTP, HTTPS, H2C, GRPCS.
- Prefer immutable `Arc<GatewayPlan>` snapshots for hot-path runtime reads; avoid per-request cloning of large config structures.
- Use typed diagnostics/errors with `thiserror`; avoid stringly typed validation where mission touches new architecture.
- Use enum/static dispatch for built-in handlers unless a real multi-adapter Seam exists.

### Likely Impact Areas

- `src/config.rs`: preserve existing behavior but extract/redirect Caddyfile compatibility toward Gateway Plan compilation.
- `src/routing.rs`: expand or replace apex/wildcard-only routing with Site/Matcher route planning.
- `src/proxy.rs`: thin Pingora adapter and delegate to dispatch/Gateway Plan where possible.
- `src/reload.rs`: load/reload active Gateway Plan snapshot and Config Health.
- `src/tls.rs`, `src/acme*.rs`, `src/cert_cache.rs`: preserve existing TLS paths; integrate route eligibility with Gateway Plan where required.
- `src/observability.rs`, `src/metrics.rs`: add typed events or structured diagnostics for compatibility warnings and readiness.
- `tests/`: add plan compiler, Caddyfile diagnostics, static file, HTTP proxy, gRPC, WebSocket/SSE, readiness, and regression tests.

## Acceptance Criteria

- **AC-001**: A Caddyfile with two Sites compiles into Gateway Plan and routes requests by Host and path.
- **AC-002**: `root` + `file_server` serves an existing `index.html` and rejects path traversal attempts.
- **AC-003**: HTTP `reverse_proxy` still passes existing routing/proxy smoke tests and preserves required forwarding headers.
- **AC-004**: `reverse_proxy h2c://...` and `reverse_proxy grpcs://...` have tests proving native gRPC unary and streaming/trailers behavior.
- **AC-005**: Recognized unsupported Caddyfile directives produce startup compatibility warnings with site, directive, line number, and impact level.
- **AC-006**: Unsupported security-sensitive directives mark Config Health degraded; `/health` remains 200 and `/ready` returns non-200 with diagnostic detail.
- **AC-007**: Existing TLS/ACME/cert-cache/reload tests continue to pass or are intentionally migrated to Gateway Plan equivalents with no behavior loss.
- **AC-008**: CI-relevant validators pass: format, clippy, tests, readiness script, and acceptance checks available in this repo.

## Validation Plan

- **VAL-001 TDD loop**: Use `/tdd`; write failing tests for each feature slice before implementing the slice.
- **VAL-002 Unit tests**: Gateway Plan compiler, Caddyfile diagnostics, matchers, handler ordering, static file path safety, Config Health.
- **VAL-003 Integration tests**: HTTP reverse proxy, static file serving, `/health`, `/ready`, WebSocket, SSE, native gRPC h2c/grpcs.
- **VAL-004 Regression tests**: Existing parser, route matching, TLS ask policy, ACME challenge handling, cert cache, reload, observability log safety.
- **VAL-005 Closed-loop testing**: Use `/closed-loop-testing` after implementation to exercise real gateway flows end-to-end, not only mocked unit tests.
- **VAL-006 CI commands**: Run `cargo fmt --check`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `cargo test`, `bash scripts/readiness-check.sh`, and repo acceptance scripts where environment supports them.
- **VAL-007 Evidence**: Final mission output must include exact commands run, pass/fail results, any environment blockers, and files changed.

## Agent Execution Contract

### Mission Goal

Implement Stellar Gateway v0.2 Web Gateway MVP according to this spec, preserving existing behavior while introducing Gateway Plan, Caddyfile compatibility diagnostics, static files, HTTP reverse proxy, native gRPC proxy, readiness, and test coverage.

### Required Deliverables

- Gateway Plan runtime model and compiler path from Caddyfile/YAML as appropriate.
- Caddyfile Compatibility Layer diagnostics and startup summary.
- Static file handler for `root` + `file_server`.
- HTTP reverse proxy preserved under new dispatch architecture.
- Native gRPC proxy support for `h2c://` and `grpcs://`.
- `/health` liveness and `/ready` Config Health readiness.
- Tests for all acceptance criteria.
- Updated docs only where necessary to describe implemented behavior.

### Suggested Feature Slices

1. Gateway Plan model, Config Health, and compatibility diagnostic types.
2. Caddyfile Compatibility Layer compilation into Gateway Plan for multi-site host/path matching.
3. Dispatch Module and Pingora Adapter thinning while preserving existing reverse proxy tests.
4. Static file handler and path safety tests.
5. HTTP reverse proxy handler under Gateway Plan.
6. Native gRPC h2c/grpcs proxy and streaming/trailer tests.
7. Startup summary, `/ready`, and compatibility warning integration.
8. Closed-loop acceptance and CI cleanup.

### Completion Criteria

- All AC items are implemented or explicitly marked blocked with evidence.
- TDD evidence exists for new behavior.
- Closed-loop testing evidence exists for real gateway flows.
- CI validation commands pass, or environment-specific blockers are documented with the best safe checks completed.
- No unsupported scope creep into FastCGI, HTTP/3, nginx stream, mail proxy, or admin API.

### Non-Completion Traps

- Do not accept unsupported Caddy behavior silently; warnings must be visible and structured.
- Do not interpret raw Caddyfile/Gatewayfile data on request hot paths.
- Do not regress existing TLS/ACME/cert cache/reload behavior.
- Do not treat gRPC as generic HTTP proxying without tests for streaming/trailers.
- Do not claim nginx-like performance without at least preserving hot-path architecture and adding validation hooks; benchmarking depth belongs mainly to v0.5.

## Assumptions and Risks

- **ASSUMP-001**: Existing Caddyfile subset behavior may be migrated to the compatibility layer but must remain user-compatible.
- **ASSUMP-002**: v0.2 can introduce architectural modules incrementally without a full rewrite if tests preserve behavior.
- **RISK-001**: Full Caddyfile syntax compatibility is broad; v0.2 should prioritize parsing/diagnostics plus supported behavior rather than perfect Caddy feature parity.
- **RISK-002**: Native gRPC support depends on Pingora/HTTP2 behavior; mission must validate with real gRPC test fixtures where feasible.
- **RISK-003**: Static file serving creates filesystem security risks; path traversal, symlink behavior, hidden files, and canonicalization must be tested deliberately.
