# IDP-30 (2), B22, OP-156 m.3 (m), OP-49, F-5: the Access Proxy images. Each is the engine's
# official image, pinned by digest, with the static access-proxy tool added; the tool renders
# /etc/access-proxy/access-proxy.toml for its engine and starts the engine on what it rendered.
# The engine is never written here (Ek B 5369). The digests match deploy/proxy/engines.env.
#
#   docker build -f deploy/proxy/Dockerfile --target envoy .
#   docker build -f deploy/proxy/Dockerfile --target caddy .

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
# envoyproxy/envoy:distroless-v1.40.2
ARG ENVOY_IMAGE=docker.io/envoyproxy/envoy@sha256:09ca6f2140a61ad8df11779a4a30d52b48433d444466328494f9188c9c35eded
# caddy:2.11.9-alpine
ARG CADDY_IMAGE=docker.io/library/caddy@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee

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

FROM ${ENVOY_IMAGE} AS envoy
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/access-proxy /usr/local/bin/access-proxy
LABEL org.opencontainers.image.title="access-proxy-envoy" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/envoyproxy/envoy:distroless-v1.40.2"
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-proxy", "run", "--engine", "envoy", "--dir", "/tmp"]

FROM ${CADDY_IMAGE} AS caddy
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/access-proxy /usr/local/bin/access-proxy
LABEL org.opencontainers.image.title="access-proxy-caddy" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/library/caddy:2.11.9-alpine"
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-proxy", "run", "--engine", "caddy", "--dir", "/config"]
