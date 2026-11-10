# IDP-30 (2), B22, OP-156 m.3 (m), OP-49, F-5: the Access Proxy images. Each is the engine's
# official image, pinned by digest, with the static access-proxy tool added; the tool renders
# /etc/access-proxy/access-proxy.toml for its engine and starts the engine on what it rendered.
# The engine is never written here (Ek B 5369). The digests match deploy/proxy/engines.env.
#
#   docker build -f deploy/proxy/Dockerfile --target envoy .
#   docker build -f deploy/proxy/Dockerfile --target caddy .
#
# Both images also carry the MCP gateway, access-mcp-gateway (OP-156 m.3 (n), AG-42), static as
# well. It is the proxy's MCP mode: run it as a second container of the same image next to the
# engine, with the entrypoint access-mcp-gateway and its ACCESS_MCP_GATEWAY_* environment, and
# give the engine its listen address (e.g. http://127.0.0.1:8491) as the MCP app's upstream.

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
# envoyproxy/envoy:distroless-v1.40.2
ARG ENVOY_IMAGE=docker.io/envoyproxy/envoy@sha256:09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded
# caddy:2.11.7-alpine
ARG CADDY_IMAGE=docker.io/library/caddy@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5

FROM ${RUST_IMAGE} AS builder
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/access --remap-path-prefix=/usr/local/cargo=/cargo"
RUN rustup target add x86_64-unknown-linux-musl \
 && cargo install --locked cargo-auditable --version 0.7.6
COPY . .
# F-5: dependency metadata embedded in the binary; static, so it runs on both engine images
RUN cargo auditable build --release --locked --target x86_64-unknown-linux-musl --package access-proxy

# OP-156 m.3 (n), F-5: the MCP gateway, static; aws-lc-rs needs the musl C toolchain
FROM ${RUST_IMAGE} AS mcp-gateway
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/access --remap-path-prefix=/usr/local/cargo=/cargo"
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-unknown-linux-musl \
 && cargo install --locked cargo-auditable --version 0.7.6
COPY . .
RUN cargo auditable build --release --locked --target x86_64-unknown-linux-musl --package access-mcp-gateway

FROM ${ENVOY_IMAGE} AS envoy
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/access-proxy /usr/local/bin/access-proxy
COPY --from=mcp-gateway /src/target/x86_64-unknown-linux-musl/release/access-mcp-gateway /usr/local/bin/access-mcp-gateway
LABEL org.opencontainers.image.title="access-proxy-envoy" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/envoyproxy/envoy:distroless-v1.40.2"
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-proxy", "run", "--engine", "envoy", "--dir", "/tmp"]

FROM ${CADDY_IMAGE} AS caddy
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/access-proxy /usr/local/bin/access-proxy
COPY --from=mcp-gateway /src/target/x86_64-unknown-linux-musl/release/access-mcp-gateway /usr/local/bin/access-mcp-gateway
LABEL org.opencontainers.image.title="access-proxy-caddy" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/library/caddy:2.11.7-alpine"
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-proxy", "run", "--engine", "caddy", "--dir", "/config"]
