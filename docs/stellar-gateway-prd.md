# Product Requirements Document: StellarGate / stellar-gateway

**Version**: 1.0
**Date**: 2026-04-28
**Author**: PRD Compiler
**Quality Score**: 94/100
**Status**: Superseded as MVP baseline by the 2026-05-09 architecture direction below

## 2026-05-09 Architecture Direction Update

The product direction has expanded from the original single-upstream wildcard MVP into an **HTTP/gRPC Web Gateway**: Caddy-compatible configuration ergonomics, nginx-aligned performance goals, and broad web gateway functionality on top of Pingora.

### Updated Product Principles

- **Configuration aligns with Caddy**: Caddyfile compatibility is a first-class goal. Site blocks, matchers, handler semantics, directive ordering, snippets/imports, and placeholders should follow Caddy behavior where supported.
- **Performance aligns with nginx**: Caddyfile compatibility must compile into an internal Gateway Plan so request handling executes a high-performance runtime model instead of interpreting raw config per request.
- **Functionality is comprehensive but staged**: Prioritize static sites, HTTP reverse proxy, native gRPC reverse proxy, automatic HTTPS, upstream pools, health checks, caching, compression, security, and observability.

### Updated Scope Boundaries

- Build an HTTP/gRPC Web Gateway, not a full nginx clone.
- Do not implement FastCGI, uWSGI, SCGI, PHP gateway behavior, mail proxying, or full nginx stream TCP/UDP parity.
- Defer HTTP/3 until the Rust ecosystem provides mature libraries that can be integrated directly.
- Native gRPC proxying means preserving HTTP/2 gRPC semantics, including streaming and trailers; it does not mean gRPC-Web or REST transcoding.

### Updated Configuration Compatibility Rule

Stellar Gateway should parse broad Caddyfile syntax for migration friendliness. Unsupported Caddyfile directives should warn clearly and appear in a startup compatibility summary instead of hard-failing startup by default. Security-sensitive unsupported behavior must mark config health as degraded, which affects readiness (`/ready`) but not process liveness (`/health`). See `docs/adr/0001-permissive-caddyfile-migration.md`.

### Target Architecture Shape

Runtime should not consume raw Gatewayfile/Caddyfile structures directly. Configuration adapters compile inputs into an immutable **Gateway Plan** containing Sites, Matchers, Handler Chains, Upstreams, and TLS policy. Pingora remains the outer adapter; routing, dispatch, static file serving, reverse proxying, TLS automation, reload, and observability should live behind gateway-owned modules.

### Updated Roadmap

#### v0.2 — Web Gateway MVP

- New Gateway Plan IR.
- Multi-site configuration.
- Host/path matcher support.
- Caddy-compatible handler semantics for supported directives.
- `root` and `file_server` static serving.
- HTTP `reverse_proxy`.
- Native gRPC reverse proxy through `h2c://` and `grpcs://` upstreams.
- WebSocket and SSE smoke tests.
- Config validation, compatibility warnings, and startup summary.
- `/health` for liveness and `/ready` for config readiness.

#### v0.3 — Production Proxy

- Upstream pools.
- Load balancing.
- Timeout policies.
- Retry policies.
- Active and passive health checks.
- `header_up` and `header_down`.
- Request body and header limits.
- Better access logs.

#### v0.4 — TLS & Multi-tenant

- HTTP to HTTPS redirect.
- Per-site TLS policy.
- ACME issuer fallback.
- DNS-01 interface.
- Shared certificate storage abstraction.
- On-demand TLS hardening.

#### v0.5 — Performance & Cache

- Static file performance path.
- Range and precompressed asset support.
- Proxy cache.
- Compression.
- Benchmark suite covering static files, HTTP proxy, native gRPC, TLS, cache, and reload under traffic.

#### v0.6 — Security & Observability

- Authentication.
- Rate limiting.
- IP policy.
- OpenTelemetry.
- Admin API.
- Route explain/debug.


## Quick Reference (Agent Context)

> **Goal**: Build a Pingora-based reverse proxy and dynamic TLS gateway that can replace the user's current nginx performance gateway and Caddy automatic SSL gateway for the MVP domain workflow.
> **Non-Goals**: Admin UI, full pingap parity, Kubernetes integration, WAF, multi-node certificate synchronization, complex load balancing, generic plugin framework, route authorization in ask endpoint.
> **Primary Workflow**: Operator defines Caddyfile-style apex and wildcard host routing, On-Demand TLS policy, ACME HTTP-01, certificate cache, and upstreams in a Gatewayfile; the gateway serves `hdd.ink` and `*.hdd.ink` over HTTP/HTTPS and proxies matching hosts to one fixed MVP upstream.
> **Success Metric**: A local or staged smoke test proves Gatewayfile load, wildcard host match, ask-based certificate authorization, HTTP-01 challenge handling, certificate cache reuse, reverse proxy forwarding, config hot reload, certificate hot reload, and structured logging.
> **Key Constraints**: Rust + Cloudflare Pingora, Gatewayfile as MVP configuration format, On-Demand TLS restricted by ask endpoint, ask endpoint only authorizes certificate issuance, `hdd.ink` and `*.hdd.ink` map to one fixed upstream in MVP.
> **Verification Path**: Rust unit/integration tests for Gatewayfile parsing, routing, TLS authorization, cache behavior, and hot reload; staged end-to-end test with a controlled domain or local ACME-compatible test setup.
> **Domain**: Rust API/network gateway, public-facing reverse proxy and TLS automation infrastructure.

---

## Executive Summary

StellarGate is a high-performance reverse proxy and dynamic TLS gateway built on Cloudflare Pingora. The MVP replaces the user's split setup where nginx handles performance-sensitive gateway traffic and Caddy handles quick automatic SSL, while avoiding nginx Lua for future business logic.

The first release focuses on one closed loop: route the apex host `hdd.ink` and wildcard dynamic subdomains under `*.hdd.ink`, issue certificates through restricted On-Demand TLS, handle ACME HTTP-01 challenges, cache certificates locally, proxy traffic to a fixed upstream, reload configuration and certificates without restart, and emit useful logs.

The MVP intentionally excludes UI, Kubernetes, WAF, multi-node certificate replication, complex plugins, and complex load balancing so implementation can deliver a reliable gateway core first.

---

## Problem Statement

**Current Situation**: The user currently uses nginx for performance gateway workloads and Caddy for automatic SSL speed. nginx automatic SSL is complex to configure, Caddy has insufficient performance, dynamic-domain ergonomics, and control, and adding business logic through nginx Lua is undesirable.

**Proposed Outcome**: A Rust/Pingora gateway provides one operational path for high-performance reverse proxying, dynamic TLS issuance, local certificate caching, wildcard host routing, hot reload, and future Rust business logic.

**Why Now**: The user's dynamic subdomain use case needs both performance and automated certificate management; maintaining separate nginx and Caddy gateways creates operational complexity and limits future extensibility.

---

## Goals

- Replace the current nginx + Caddy MVP gateway responsibilities with one Pingora-based Rust service.
- Serve `hdd.ink` and dynamic hosts matching `*.hdd.ink` through Caddyfile-style host routing and one fixed MVP upstream.
- Support On-Demand TLS certificate issuance gated by an ask endpoint.
- Support ACME HTTP-01 challenge handling for certificate issuance.
- Cache issued certificates locally and reuse them after restart or reload.
- Reload Gatewayfile configuration and certificate material without process restart.
- Emit logs that allow operators to trace routing, TLS decisions, ACME activity, proxy errors, and reload outcomes.

## Non-Goals

- Do not build an admin UI in the MVP.
- Do not fully replicate `vicanso/pingap`; use it only as product and architecture inspiration.
- Do not implement Kubernetes discovery, ingress controllers, or CRDs.
- Do not implement WAF, bot mitigation, or request security rule engines.
- Do not implement multi-node certificate synchronization in the MVP.
- Do not implement complex load balancing, active health checks, canary routing, or weighted upstream pools.
- Do not implement a generic plugin framework.
- Do not use the ask endpoint for request routing authorization; it only authorizes certificate issuance.
- Do not add nginx-compatible config parsing; Gatewayfile is the MVP config format, with a small Caddyfile-compatible route subset for low-friction migration from Caddy.

---

## Confirmed Facts, Assumptions, and Open Questions

### Confirmed Facts

- Project name: StellarGate / `stellar-gateway`.
- Existing local directory: `/Users/chenwenjie/Downloads/stellar-gateway`.
- The existing Rust skeleton must be reviewed against this PRD before implementation continues.
- The implementation must be based on Cloudflare Pingora.
- MVP configuration format is Gatewayfile.
- The ask endpoint authorizes certificate issuance only.
- `*.hdd.ink` maps to one fixed upstream in MVP.
- MVP hot reload includes configuration and certificates.
- Core scenarios include wildcard host routing, On-Demand TLS, ask endpoint restrictions, ACME HTTP-01, local certificate cache, reverse proxying, hot reload, and logging.
- After PRD completion, the next implementation workflow must create a `/mission`.
- During implementation, `/tdd` and `/rust-best-practices` must be used.

### Working Assumptions

- The primary operator is the project owner or infrastructure engineer configuring and running the gateway.
- The first deploy target is a single-node gateway process.
- The MVP can use one configured ACME account and one local certificate storage directory.
- The fixed upstream for `*.hdd.ink` is configurable in Gatewayfile even though the MVP supports only one upstream for this wildcard.
- Logs can be structured text logs suitable for local development and service log collection.
- The initial Rust skeleton is not authoritative when it conflicts with this PRD.

### Open Questions (Non-Blocking)

- Exact Gatewayfile syntax can be refined during architecture as long as it supports every MVP behavior listed here.
- Exact log field names can be refined during implementation as long as the required events are observable.
- Exact staged ACME test environment can be chosen during testing.

### Build Blockers (Must Resolve Before Build or Verification)

- None. The PRD contains enough product decisions for architecture and MVP implementation to proceed.

---

## Users and Primary Jobs

### Primary User

- **Role**: Gateway operator / developer-operator.
- **Goal**: Run one high-performance gateway that handles reverse proxying and dynamic TLS for wildcard subdomains.
- **Pain Point**: nginx and Caddy split responsibilities, nginx automatic SSL is hard to configure, Caddy lacks the desired performance and control, and nginx Lua is not the preferred extension path.

### Secondary User

- **Role**: Future application developer.
- **Goal**: Add gateway-adjacent business logic in Rust without moving logic into nginx Lua.
- **Pain Point**: Existing gateway stack makes custom business behavior operationally and technically awkward.

---

## User Stories & Acceptance Criteria

### Story 1: Configure the MVP Gateway

**As a** gateway operator  
**I want to** define listeners, wildcard host routing, TLS policy, certificate cache, ACME HTTP-01, ask endpoint, and the fixed upstream in Gatewayfile  
**So that** I can operate the gateway from one readable configuration file

**Acceptance Criteria:**

- [ ] Starting `stellar-gateway` with a valid Gatewayfile loads listener, wildcard host, upstream, TLS, ACME, ask endpoint, cache, and logging settings.
- [ ] Invalid Gatewayfile syntax fails startup with a non-zero exit and an error identifying the invalid section or field.
- [ ] Unsupported MVP features in Gatewayfile fail clearly instead of being silently ignored.

### Story 2: Route Wildcard Dynamic Subdomains

**As a** gateway operator  
**I want to** route hosts matching `*.hdd.ink` to one fixed upstream
**So that** dynamic page subdomains work without per-host route entries

**Acceptance Criteria:**

- [ ] Requests with `Host: any-valid-label.hdd.ink` match the wildcard route and proxy to the configured fixed upstream.
- [ ] Requests outside `*.hdd.ink` do not match the wildcard route and return a deterministic gateway error response.
- [ ] The route match treats the apex `hdd.ink` as non-matching unless Gatewayfile explicitly defines it.

### Story 3: Issue Certificates Through Restricted On-Demand TLS

**As a** gateway operator  
**I want to** authorize dynamic certificate issuance through an ask endpoint  
**So that** unknown or unauthorized hosts cannot trigger certificate issuance

**Acceptance Criteria:**

- [ ] TLS handshakes for uncached `*.hdd.ink` hostnames call the configured ask endpoint before certificate issuance.
- [ ] A positive ask response allows certificate issuance for the requested hostname.
- [ ] A negative, timeout, malformed, or network-failed ask response denies certificate issuance and logs the denial reason.
- [ ] The ask endpoint decision does not authorize or deny HTTP request routing after a certificate exists; routing is decided only by Gatewayfile routes.

### Story 4: Complete ACME HTTP-01 and Cache Certificates Locally

**As a** gateway operator  
**I want to** complete ACME HTTP-01 challenges and reuse issued certificates from local cache  
**So that** dynamic domains can obtain and retain TLS without manual certificate installation

**Acceptance Criteria:**

- [ ] HTTP requests for `/.well-known/acme-challenge/{token}` are served by the ACME challenge handler when a challenge is active.
- [ ] Non-challenge HTTP requests continue through normal routing behavior.
- [ ] Issued certificate and private key material are stored in the configured local cache location.
- [ ] Restarting the process reuses a valid cached certificate without calling ACME issuance again.
- [ ] Expired, missing, unreadable, or hostname-mismatched cached certificates are not served as valid certificates.

### Story 5: Hot Reload Configuration and Certificates

**As a** gateway operator  
**I want to** reload Gatewayfile and certificate material without restarting the process  
**So that** config changes and externally updated certificates can take effect with minimal disruption

**Acceptance Criteria:**

- [ ] A reload trigger refreshes Gatewayfile configuration without stopping the listener process.
- [ ] Valid Gatewayfile changes affect new requests after reload.
- [ ] Invalid Gatewayfile changes are rejected, the previous valid configuration remains active, and the rejection is logged.
- [ ] Certificate cache changes are detected or reloaded by the reload trigger and used for subsequent TLS handshakes.
- [ ] In-flight requests are not deliberately terminated during a successful reload.

### Story 6: Observe Gateway Behavior

**As a** gateway operator  
**I want to** see useful logs for routing, TLS, ACME, proxying, and reloads  
**So that** I can diagnose production and staging behavior

**Acceptance Criteria:**

- [ ] Each proxied request logs host, route decision, upstream target, response status, latency, and request identifier when available.
- [ ] TLS issuance attempts log hostname, ask decision, ACME result, cache hit or miss, and error class.
- [ ] Reload attempts log trigger, result, active config version or checksum, and validation errors when present.
- [ ] Proxy failures log upstream target and error class without logging private keys, tokens, or certificate secrets.

---

## Functional Requirements

### FR-1: Gatewayfile Configuration

- **Description**: Operators can configure MVP listener, route, upstream, TLS, ACME, ask endpoint, certificate cache, reload, and logging settings in Gatewayfile.
- **Trigger**: Process startup or reload trigger reads Gatewayfile.
- **Expected Result**: Valid configuration becomes active; invalid configuration is rejected with actionable errors.
- **Traces to**: Story 1 / Goals 1, 2, 3, 4, 5, 7

### FR-2: Wildcard Host Matching

- **Description**: Requests whose host has exactly one or more labels before `hdd.ink` and end with `.hdd.ink` match the MVP wildcard route.
- **Trigger**: Gateway receives an HTTP request or TLS SNI hostname.
- **Expected Result**: Matching hosts use the configured wildcard route; non-matching hosts are rejected by routing or certificate policy.
- **Traces to**: Story 2 / Goal 2

### FR-3: Fixed MVP Upstream Proxying

- **Description**: The wildcard route proxies all matched hosts to one Gatewayfile-configured upstream.
- **Trigger**: A matched HTTP request passes route selection.
- **Expected Result**: Gateway forwards the request to the fixed upstream and returns the upstream response to the client.
- **Traces to**: Story 2 / Goal 1

### FR-4: On-Demand TLS Ask Authorization

- **Description**: Uncached certificate issuance for a hostname requires a positive ask endpoint decision.
- **Trigger**: TLS handshake needs a certificate that is not already valid in local cache.
- **Expected Result**: Positive ask result permits issuance; negative or failed ask result denies issuance.
- **Traces to**: Story 3 / Goal 3

### FR-5: Routing Authorization Separation

- **Description**: Ask endpoint results apply only to certificate issuance and never replace Gatewayfile route matching.
- **Trigger**: A request arrives with a hostname that has or obtains a certificate.
- **Expected Result**: The request is routed only if Gatewayfile route rules match; ask success alone does not route traffic.
- **Traces to**: Story 3 / Goals 2, 3

### FR-6: ACME HTTP-01 Challenge Handling

- **Description**: Gateway serves active ACME HTTP-01 challenge tokens from the HTTP listener.
- **Trigger**: HTTP request path starts with `/.well-known/acme-challenge/` and token is active.
- **Expected Result**: Active challenge receives the correct response body; inactive challenges do not bypass normal error handling.
- **Traces to**: Story 4 / Goal 4

### FR-7: Local Certificate Cache

- **Description**: Gateway stores and loads certificate material from a configured local cache directory.
- **Trigger**: Certificate issuance completes, process starts, or certificate reload occurs.
- **Expected Result**: Valid cache entries are reused; invalid cache entries are ignored and logged.
- **Traces to**: Story 4 / Goal 5

### FR-8: Config Hot Reload

- **Description**: Gateway can apply a new valid Gatewayfile configuration without process restart.
- **Trigger**: Config reload signal, command, or configured watcher event.
- **Expected Result**: New requests use the new config; invalid config leaves the prior config active.
- **Traces to**: Story 5 / Goal 6

### FR-9: Certificate Hot Reload

- **Description**: Gateway can refresh certificate cache state without process restart.
- **Trigger**: Certificate reload signal, command, or configured watcher event.
- **Expected Result**: Subsequent TLS handshakes use the refreshed valid certificate material.
- **Traces to**: Story 5 / Goals 5, 6

### FR-10: Gateway Observability Logs

- **Description**: Gateway emits structured logs for request routing, proxy result, TLS issuance, ACME challenge handling, cache decisions, and reloads.
- **Trigger**: Request, TLS, ACME, cache, proxy, or reload event occurs.
- **Expected Result**: Logs contain diagnostic fields and exclude private keys, tokens, and certificate secrets.
- **Traces to**: Story 6 / Goal 7

---

## Acceptance Matrix

| ID | Requirement | Priority | How to Verify |
|----|-------------|----------|---------------|
| A1 | Valid Gatewayfile activates all MVP settings | P0 | Config parser test loads a representative Gatewayfile and asserts listener, wildcard, upstream, TLS, ACME, ask, cache, reload, and logging values. |
| A2 | Invalid Gatewayfile fails clearly | P0 | Parser test feeds invalid syntax and unsupported fields, then asserts non-zero startup or rejected reload with field-specific error. |
| A3 | `*.hdd.ink` routes to fixed upstream | P0 | Integration test sends matching Host header and asserts upstream receives request. |
| A4 | Non-matching hosts are rejected | P0 | Integration test sends outside-domain Host header and asserts deterministic gateway error with no upstream request. |
| A5 | Ask endpoint gates certificate issuance only | P0 | TLS authorization test asserts ask is called for uncached issuance and routing still depends on Gatewayfile after ask success. |
| A6 | Ask failures deny certificate issuance | P0 | Tests cover negative, timeout, malformed, and network-failed ask responses. |
| A7 | ACME HTTP-01 challenge path works | P0 | Challenge handler test asserts active token response and inactive token rejection. |
| A8 | Certificate cache is reused | P0 | Cache test writes valid cert material, restarts or recreates gateway state, and asserts cache hit without ACME issuance. |
| A9 | Invalid cache entries are ignored | P0 | Cache tests cover expired, unreadable, missing, and hostname-mismatched entries. |
| A10 | Config reload preserves last valid state on error | P0 | Reload test applies valid config, then invalid config, and asserts active config remains unchanged. |
| A11 | Certificate reload affects new handshakes | P1 | Reload test updates cache material and asserts subsequent lookup uses refreshed state. |
| A12 | Logs cover required operational events without secrets | P1 | Log capture test or manual inspection asserts required fields exist and private key/token values are absent. |

---

## Edge Cases & Failure Handling

- **Case**: Host is `hdd.ink` without a subdomain.
  - Expected behavior: Does not match `*.hdd.ink` unless explicitly configured as a separate route.
- **Case**: Host contains uppercase letters.
  - Expected behavior: Host matching is case-insensitive after safe hostname normalization.
- **Case**: Host includes a port in the HTTP `Host` header.
  - Expected behavior: Route matching ignores the port and evaluates the hostname.
- **Case**: Host is outside the configured wildcard domain.
  - Expected behavior: Gateway rejects routing and does not call upstream.
- **Failure**: Ask endpoint returns deny, times out, returns malformed data, or cannot be reached.
  - Expected behavior: Certificate issuance is denied, the reason class is logged, and no route authorization decision is inferred.
- **Failure**: ACME provider fails or rate-limits issuance.
  - Expected behavior: TLS issuance fails for that hostname, failure class is logged, and existing valid cached certificates remain usable.
- **Failure**: Gatewayfile reload contains invalid syntax or unsupported MVP feature.
  - Expected behavior: Reload fails, previous valid config remains active, and validation errors are logged.
- **Failure**: Certificate cache entry is unreadable, expired, mismatched, or malformed.
  - Expected behavior: Entry is ignored, error class is logged, and issuance may proceed only if ask permits.
- **Failure**: Upstream is unreachable.
  - Expected behavior: Gateway returns a deterministic proxy error response and logs upstream target plus error class.

---

## Technical Constraints & Non-Functional Requirements

### Performance

- The gateway must use Cloudflare Pingora as the proxy foundation.
- MVP request proxying must avoid per-request blocking filesystem or network calls outside the required upstream proxy operation.
- Certificate cache lookup should be memory-indexed or otherwise bounded so normal TLS handshakes do not scan the entire certificate directory.
- Hot reload should not intentionally terminate in-flight requests.

### Security & Compliance

- Ask endpoint is mandatory for On-Demand TLS issuance in the MVP.
- Ask endpoint authorization applies only to certificate issuance.
- Unknown or unauthorized hostnames must not trigger ACME issuance.
- Logs must not include private keys, ACME account secrets, full challenge tokens, or certificate secret material.
- Certificate private keys must be stored in the configured local cache with restrictive file permissions where the platform supports them.

### Integration & Dependencies

- **Pingora**: Provides reverse proxy foundation and service runtime.
- **ACME provider**: Must support HTTP-01 issuance for MVP dynamic TLS.
- **Ask endpoint**: External or local HTTP service that returns certificate issuance authorization.
- **Fixed upstream**: Receives all routed `*.hdd.ink` MVP traffic.
- **Local filesystem**: Stores Gatewayfile and certificate cache.

### Platform Constraints

- Implementation language: Rust.
- MVP config format: Gatewayfile.
- MVP deployment mode: single process, single node.
- Existing project path: `/Users/chenwenjie/Downloads/stellar-gateway`.
- Existing Rust skeleton must be treated as provisional and updated to match this PRD.

---

## MVP Scope & Delivery

### Must Have (MVP)

- Gatewayfile parser and validator for all MVP settings.
- Pingora-based HTTP reverse proxy listener.
- Wildcard host routing for `*.hdd.ink`.
- One fixed upstream for the wildcard route.
- On-Demand TLS authorization through ask endpoint.
- ACME HTTP-01 challenge handling.
- Local certificate cache with validation and reuse.
- Configuration hot reload.
- Certificate hot reload.
- Structured operational logs.
- Tests covering parser, route matching, ask policy, ACME challenge handling, cache behavior, reload behavior, and logging safety.

### Nice to Have (Later)

- Admin UI.
- Multiple wildcard domains and route groups beyond the MVP domain.
- Multiple upstreams, health checks, weighted load balancing, and canary routing.
- Plugin framework.
- WAF and bot protection.
- Kubernetes integration.
- Multi-node certificate synchronization.
- Additional ACME challenge types.
- Metrics dashboard and tracing export integrations.

### Rollout Notes

- Build and verify the MVP locally before staged domain testing.
- Use a staging ACME endpoint or controlled test setup before production issuance.
- Keep Gatewayfile examples aligned with implemented behavior, but do not add unsupported config knobs.
- After this PRD, create a `/mission` for implementation and require `/tdd` plus `/rust-best-practices` during execution.

---

## Examples and Counterexamples

### Good Outcome Example

- Gatewayfile configures `*.hdd.ink`, ask endpoint, ACME HTTP-01, cache directory, reload behavior, and upstream `http://127.0.0.1:3000`. A request to `https://demo.hdd.ink/hello` obtains or reuses an authorized certificate, matches the wildcard route, proxies to the fixed upstream, and logs the route, TLS, cache, and proxy result.

### Counterexample

- Ask endpoint approves certificate issuance for `demo.hdd.ink`, then the gateway routes `demo.hdd.ink` despite no matching Gatewayfile route. This is wrong because ask approval is not route authorization.

### Counterexample

- Gateway accepts a Gatewayfile option for weighted upstream pools but silently ignores it. This is wrong because complex load balancing is outside MVP and unsupported fields must fail clearly.

---

## Risks & Dependencies

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Pingora TLS extension points require deeper integration than the initial skeleton anticipates | Medium | High | Architecture phase must inspect Pingora APIs before committing implementation tasks. |
| ACME HTTP-01 local testing is slower than pure unit testing | Medium | Medium | Use handler-level tests first, then one staged end-to-end issuance test. |
| On-Demand TLS can cause unintended issuance if policy is too permissive | Medium | High | Make ask endpoint mandatory and test deny, timeout, malformed, and network failure paths. |
| Hot reload can produce split-brain config state | Medium | High | Use immutable validated config snapshots and retain the previous snapshot on reload failure. |
| Certificate cache may leak secrets through logs or permissions | Low | High | Add log redaction checks and restrictive file-permission handling. |

**Dependencies:**

- Cloudflare Pingora crate and its TLS/proxy extension points.
- Rust async runtime compatibility required by Pingora and selected ACME client.
- ACME provider or staging ACME service.
- Ask endpoint contract.
- Local filesystem access for Gatewayfile and certificate cache.

---

## Handoff Notes for Implementation and Testing

- Create a `/mission` after this PRD is accepted as the implementation entry point.
- Use `/tdd` during implementation; write failing tests for each MVP behavior before or alongside production code.
- Use `/rust-best-practices` during implementation; prefer explicit error types, small modules, safe concurrency, and testable pure functions for parsing and policy.
- Review `/Users/chenwenjie/Downloads/stellar-gateway` against this PRD before expanding the current skeleton.
- Do not let the existing CLI-only `--listen` and `--upstream` behavior override Gatewayfile as the MVP source of truth.
- Separate certificate issuance authorization from route authorization in code structure and tests.
- Prioritize pure unit tests for Gatewayfile parsing, wildcard matching, ask decision mapping, cache validation, and reload state transitions before full network tests.
- Fastest trustworthy verification path: `cargo fmt --check`, `cargo clippy --all-targets --all-features`, `cargo test`, plus one local or staged smoke test that exercises HTTP routing, TLS authorization, ACME challenge handling, cache reuse, and reload.
- No traceability gaps were found during PRD generation.

---

*This PRD was created through requirements gathering and is optimized for autonomous agent consumption, implementation handoff, testability, and scope clarity.*
