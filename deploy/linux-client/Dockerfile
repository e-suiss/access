# OP-156 m.3 (p), OP-49, F-5: the Linux client's package root, an image from scratch holding the
# files a host installs: access-linuxd, libnss_access.so.2, pam_access.so, the systemd unit and
# the example configuration. It is never run; a host's package build copies from it.

ARG RUST_IMAGE=rust@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273

FROM ${RUST_IMAGE} AS builder
WORKDIR /src
ENV RUSTUP_TOOLCHAIN=1.99.0 \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="--remap-path-prefix=/src=/access --remap-path-prefix=/usr/local/cargo=/cargo"
RUN cargo install --locked cargo-auditable --version 0.7.6
COPY . .
RUN cargo auditable build --release --locked \
      --package access-linux-client --package access-linux-nss --package access-linux-pam \
 && scripts/checksec.sh target/release/access-linuxd

FROM scratch AS linux-client
LABEL org.opencontainers.image.title="access-linux-client" \
      org.opencontainers.image.source="https://github.com/e-suiss/access" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /src/target/release/access-linuxd /usr/sbin/access-linuxd
COPY --from=builder /src/target/release/libnss_access.so /usr/lib/x86_64-linux-gnu/libnss_access.so.2
COPY --from=builder /src/target/release/libpam_access.so /usr/lib/access/pam_access.so
COPY deploy/linux-client/access-linuxd.service /usr/lib/systemd/system/access-linuxd.service
COPY deploy/linux-client/access-linuxd.env /usr/share/access-linuxd/access-linuxd.env
COPY deploy/linux-client/nsswitch.conf deploy/linux-client/pam.d/login deploy/linux-client/pam.d/sudo /usr/share/access-linuxd/examples/
