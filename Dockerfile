FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libcap2-bin libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/stellar-gateway /usr/local/bin/stellar-gateway
COPY tests/fixtures/pebble.minica.pem /app/tests/fixtures/pebble.minica.pem
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/stellar-gateway \
    && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin stellar \
    && chown -R stellar:stellar /app

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:8080/health \
    || curl --fail --silent --show-error http://127.0.0.1:80/health \
    || exit 1

USER stellar

ENTRYPOINT ["stellar-gateway"]
