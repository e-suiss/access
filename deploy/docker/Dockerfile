# OP-49, §14.5, OP-79, OP-69

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian13@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
# trixie-slim, the release the Rust image builds on
ARG LOCAL_IMAGE=debian@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
# node:24.21.0-trixie-slim, the Node release CI builds the web packages with
ARG NODE_IMAGE=node@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66

FROM ${RUST_IMAGE} AS chef
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/access --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo install --locked cargo-chef --version 0.1.78 \
 && cargo install --locked cargo-auditable --version 0.7.6

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked \
      --package access-server --package access-signer --package access-identity-signer-bin \
      --package access-local-client --package access-cli \
      --recipe-path recipe.json
COPY . .
# F-5, SA-23, §14.5: dependency metadata embedded in every binary, and the hardening flags asserted
RUN cargo auditable build --release --locked \
      --package access-server --package access-signer --package access-identity-signer-bin \
      --package access-local-client --package access-cli \
 && scripts/checksec.sh target/release/access-server target/release/access-signer \
      target/release/access-identity-signer target/release/access-local-client target/release/access-cli

# OP-116 m.6: the Kernel's Wasm build the TypeScript SDK loads, as `just wasm` makes it
FROM chef AS wasm
RUN rustup target add wasm32-unknown-unknown \
 && cargo install --locked wasm-bindgen-cli --version 0.2.129
COPY . .
RUN cargo build --release --locked --target wasm32-unknown-unknown -p access-kernel-wasm \
 && wasm-bindgen --target web --out-dir sdks/typescript/wasm \
      target/wasm32-unknown-unknown/release/access_kernel_wasm.wasm

# TN-128, OP-146 m.12 (f), OP-153 m.3 (w): the console, the hosted login and the account pages, built from their lockfiles without
# install scripts (OP-97); the server reads each dist directory once before its lockdown
FROM ${NODE_IMAGE} AS web
WORKDIR /src
COPY sdks/typescript sdks/typescript
COPY --from=wasm /src/sdks/typescript/wasm sdks/typescript/wasm
COPY web/components web/components
COPY web/console web/console
COPY web/login web/login
COPY web/account web/account
COPY locales locales
RUN cd sdks/typescript && npm ci --ignore-scripts \
 && cd /src/web/components && npm ci --ignore-scripts \
 && cd /src/web/console && npm ci --ignore-scripts && npm run build \
 && cd /src/web/login && npm ci --ignore-scripts && npm run build \
 && cd /src/web/account && npm ci --ignore-scripts && npm run build

# OP-69, CR-28: the same binaries with SoftHSM as the local PKCS#11 token, provisioning for a
# local deployment (deploy/compose/access.yaml), the database administrator's setup and the
# headless client of OP-149 m.26 (b), (c). Not a production image: production runs the
# distroless image below against a real HSM, with the three server binaries and the migration
# job's `access-cli` only (m.22 (b), OP-138).
FROM ${LOCAL_IMAGE} AS local
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 openssl ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --groups softhsm --no-create-home --shell /usr/sbin/nologin nonroot \
 && install -d -o 65532 -g 65532 -m 0750 \
      /var/lib/access/certs /var/lib/access/secrets /var/lib/access/initdb \
      /var/lib/access/signer /var/lib/access/identity-signer /var/lib/access/bootstrap \
      /var/lib/access/product-tls /run/access \
 && chown 65532:softhsm /var/lib/softhsm/tokens \
 && chmod 0755 /var/lib/softhsm \
 && install -d -m 0755 /etc/access/local /usr/share/access/postgres
COPY --from=builder /src/target/release/access-server /src/target/release/access-signer \
     /src/target/release/access-identity-signer /src/target/release/access-local-client \
     /src/target/release/access-cli /usr/local/bin/
COPY --chmod=0755 deploy/compose/access/init.sh /usr/local/bin/access-local-init
COPY --chmod=0644 deploy/compose/access/*.toml deploy/compose/access/softhsm2.conf /etc/access/local/
COPY --chmod=0644 crates/store/bootstrap/roles.sql crates/store/bootstrap/database.sql /usr/share/access/postgres/
COPY --chmod=0755 deploy/compose/access/postgres-init.sh /usr/share/access/postgres/
COPY --from=web /src/web/console/dist /usr/share/access/console
COPY --from=web /src/web/login/dist /usr/share/access/login
COPY --from=web /src/web/account/dist /usr/share/access/account
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
     /src/target/release/access-identity-signer /src/target/release/access-cli /usr/local/bin/
COPY --from=web /src/web/console/dist /usr/share/access/console
COPY --from=web /src/web/login/dist /usr/share/access/login
COPY --from=web /src/web/account/dist /usr/share/access/account
# §14.5, RAUTHY-008
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/access-server"]
