# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
FROM rust:1.94-bookworm AS builder
WORKDIR /build

# Cache dependencies first.
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates/vault-core/Cargo.toml crates/vault-core/Cargo.toml
COPY crates/vault-server/Cargo.toml crates/vault-server/Cargo.toml
# Minimal stubs so the dependency graph resolves for caching.
RUN mkdir -p crates/vault-core/src crates/vault-server/src \
    && echo "fn main() {}" > crates/vault-server/src/main.rs \
    && echo "" > crates/vault-core/src/lib.rs \
    && cargo build --release -p vault-server 2>/dev/null || true

# Now copy the real sources and build for real.
COPY . .
RUN cargo build --release -p vault-server

# --- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data vault \
    && mkdir -p /data && chown vault:vault /data

COPY --from=builder /build/target/release/vault-server /usr/local/bin/vault-server

USER vault
WORKDIR /data
VOLUME ["/data"]

ENV VAULT_BIND=0.0.0.0:8080 \
    VAULT_DATABASE_URL=sqlite:///data/vault.db \
    VAULT_REGISTRATION=invite \
    RUST_LOG=info \
    VAULT_LOG_FORMAT=json

EXPOSE 8080

# Liveness for orchestrators.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/vault-server"]
