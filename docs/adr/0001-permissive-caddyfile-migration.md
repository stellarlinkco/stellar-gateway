# Use permissive Caddyfile migration by default

Stellar Gateway will parse broad Caddyfile syntax and allow unsupported directives to start with clear warnings instead of failing startup by default. This deliberately supersedes the old PRD rule that unsupported MVP features must hard-fail, because the product direction now prioritizes migrating existing Caddyfile configurations and surfacing gaps through warnings, config reports, and route explanation rather than blocking startup.

## Consequences

- Unsupported directives must be highly visible in a startup summary that includes site, directive, line number, and impact level.
- Unsupported directives should use safety-first impact levels; unsupported security-sensitive behavior such as authentication must mark config health as degraded even though startup continues.
- Config health degradation affects readiness (`/ready`), while liveness (`/health`) remains a process-health endpoint.
- Runtime behavior must never silently pretend unsupported Caddy behavior is implemented.
- Tests should verify warnings are emitted for recognized-but-unsupported Caddyfile directives.
