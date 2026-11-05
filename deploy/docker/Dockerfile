# OP-49, §14.5, OP-79, OP-69

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
# trixie-slim, the release the Rust image builds on
ARG LOCAL_IMAGE=debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

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
RUN cargo chef cook --release --locked \
      --package access-server --package access-signer --package access-identity-signer-bin \
      --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked \
      --package access-server --package access-signer --package access-identity-signer-bin

# OP-69, CR-28: the same binaries with SoftHSM as the local PKCS#11 token, provisioning for a
# local deployment (deploy/compose/access.yaml), and the database administrator's setup. Not a
# production image: production runs the distroless image below against a real HSM.
FROM ${LOCAL_IMAGE} AS local
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --groups softhsm --no-create-home --shell /usr/sbin/nologin nonroot \
 && install -d -o 65532 -g 65532 -m 0750 \
      /var/lib/access/certs /var/lib/access/secrets /var/lib/access/initdb \
      /var/lib/access/signer /var/lib/access/identity-signer /var/lib/access/bootstrap /run/access \
 && chown 65532:softhsm /var/lib/softhsm/tokens \
 && install -d -m 0755 /etc/access/local /usr/share/access/postgres
COPY --from=builder /src/target/release/access-server /src/target/release/access-signer \
     /src/target/release/access-identity-signer /usr/local/bin/
COPY --chmod=0755 deploy/compose/access/init.sh /usr/local/bin/access-local-init
COPY --chmod=0644 deploy/compose/access/*.toml deploy/compose/access/softhsm2.conf /etc/access/local/
COPY --chmod=0644 crates/store/bootstrap/roles.sql crates/store/bootstrap/database.sql /usr/share/access/postgres/
COPY --chmod=0755 deploy/compose/access/postgres-init.sh /usr/share/access/postgres/
LABEL org.opencontainers.image.title="access-local" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV SOFTHSM2_CONF=/etc/access/local/softhsm2.conf
USER 65532:65532
EXPOSE 8443
CMD ["access-server"]

FROM ${RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="access-server" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /src/target/release/access-server /src/target/release/access-signer \
     /src/target/release/access-identity-signer /usr/local/bin/
# §14.5, RAUTHY-008
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-server"]
