# OP-49, §14.5, OP-79

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

FROM ${RUST_IMAGE} AS chef
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/access --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo install --locked cargo-chef --version 0.1.78

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --package access-server --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --package access-server

FROM ${RUNTIME_IMAGE}
LABEL org.opencontainers.image.title="access-server" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /src/target/release/access-server /usr/local/bin/access-server
# §14.5, RAUTHY-008
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/access-server"]
