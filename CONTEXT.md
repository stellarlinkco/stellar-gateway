# Stellar Gateway Context

Stellar Gateway is an HTTP/gRPC Web Gateway for serving static sites, reverse proxying HTTP and native gRPC traffic, and automating TLS for multi-tenant hostnames. This context captures product language so architecture discussions do not drift into full nginx clone scope.

## Language

**HTTP/gRPC Web Gateway**:
A gateway that handles HTTP sites, native gRPC services, static files, reverse proxying, and TLS automation at the web edge.
_Avoid_: Full nginx clone, generic L4 gateway, mail proxy, FastCGI gateway

**Gateway Plan**:
The validated runtime description of sites, matchers, handlers, upstreams, and TLS policy that the gateway executes.
_Avoid_: Raw config, parsed file

**Site**:
A hostname-scoped web property whose traffic is matched and handled by the gateway.
_Avoid_: Server block, virtual host when discussing product behavior

**Matcher**:
A rule that decides whether a request belongs to a route within a site.
_Avoid_: Location when discussing the product model

**Handler**:
An action selected by a route, such as serving files, proxying upstream, redirecting, or returning a response.
_Avoid_: Directive when discussing runtime behavior

**Caddy-Compatible Handler Semantics**:
The supported Caddyfile directives execute according to Caddy's directive ordering, route preservation, matcher, and handle behavior.
_Avoid_: Custom simplified handler chain, first-match-only routing

**Caddyfile Compatibility Layer**:
A configuration adapter that parses broad Caddyfile syntax and compiles supported behavior into a Gateway Plan.
_Avoid_: Minimal Caddy-like DSL, nginx config compatibility

**Permissive Caddyfile Migration**:
A compatibility rule where unsupported Caddyfile directives warn clearly but do not prevent gateway startup.
_Avoid_: Strict unsupported-directive failure as the default behavior

**Config Health**:
The readiness state of the active Gateway Plan after validation and compatibility warning classification.
_Avoid_: Process liveness

**Native gRPC Proxy**:
A reverse proxy mode that preserves HTTP/2 gRPC semantics, including streaming and trailers, between clients and upstream services.
_Avoid_: gRPC-Web, REST transcoding

## Relationships

- A **Gateway Plan** contains one or more **Sites**.
- A **Site** contains one or more **Matchers** and **Handlers**.
- A **Handler** may serve static files or invoke a **Native gRPC Proxy**.
- **Caddy-Compatible Handler Semantics** govern supported Caddyfile directives.
- A **Caddyfile Compatibility Layer** compiles Caddyfile input into a **Gateway Plan**.
- **Permissive Caddyfile Migration** changes unsupported directive handling from hard failure to warning.
- **Config Health** affects readiness, not process liveness.
- An **HTTP/gRPC Web Gateway** does not include FastCGI, mail proxying, or generic nginx stream parity.

## Example dialogue

> **Dev:** "Should v0.2 support FastCGI so PHP apps can run behind Stellar Gateway?"
> **Domain expert:** "No — Stellar Gateway is an **HTTP/gRPC Web Gateway**. It should serve static sites and proxy HTTP/native gRPC first; FastCGI is outside the product boundary."

## Flagged ambiguities

- "nginx parity" means nginx-like performance and core web gateway behavior, not complete nginx module compatibility.
- "Caddy parity" means Caddy-like ease for common web gateway workflows, not Caddy plugin compatibility.
- "gRPC support" means **Native gRPC Proxy**, not gRPC-Web or protocol transcoding.
- Old PRD strict unsupported-feature failure is superseded by **Permissive Caddyfile Migration** for Caddyfile compatibility.
- Caddyfile `import` follows Caddy-style local file access: if the gateway process can read the file, the compatibility layer may import it.
