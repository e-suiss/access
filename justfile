# OP-69

set shell := ["bash", "-euo", "pipefail", "-c"]

# CMP-24, MD-1, T41
not_lockdown := "not (package(access-sandbox) and binary(lockdown))"
kernel_targets := "wasm32-unknown-unknown wasm32-wasip1 aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android"

default:
    @just --list

check: fmt-check lint rules deny

# SA-59
test:
    cargo nextest run --workspace --locked --no-tests=pass -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# OP-64
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# OP-62, OP-3
rules:
    cargo fetch --locked
    cargo xtask check

# F-1
deny:
    cargo deny --locked check

cross:
    for t in {{kernel_targets}}; do cargo build --locked -p eesuiss-access-kernel --target "$t"; done
    # OP-76
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-crypto --no-default-features --features verify --target "$t"; done
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-restriction --target "$t"; done
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p eesuiss-access-kernel --target wasm32-wasip1

cross-ios:
    CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER="{{justfile_directory()}}/scripts/ios-sim-runner.sh" cargo test --locked -p eesuiss-access-kernel --target aarch64-apple-ios-sim

cross-android target="x86_64-linux-android":
    CARGO_TARGET_X86_64_LINUX_ANDROID_RUNNER="{{justfile_directory()}}/scripts/android-runner.sh" \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER="{{justfile_directory()}}/scripts/android-runner.sh" \
    cargo test --locked -p eesuiss-access-kernel --target {{target}}

# OP-83
wasm:
    want="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"; \
    have="$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)"; \
    if [ "$have" != "$want" ]; then echo "wasm-bindgen-cli $want required (found '${have:-none}'): cargo install wasm-bindgen-cli --version $want --locked" >&2; exit 1; fi
    cargo build --locked --release --target wasm32-unknown-unknown -p access-kernel-wasm
    wasm-bindgen --target web --out-dir sdks/typescript/wasm target/wasm32-unknown-unknown/release/access_kernel_wasm.wasm

# OP-97
npm_packages := "sdks/typescript web/console"

# OP-83, §14.5
web-install:
    for p in {{npm_packages}}; do (cd "$p" && npm ci); done

web-check: wasm
    for p in {{npm_packages}}; do (cd "$p" && npm run lint && npm run typecheck && npm run format:check); done

web-test: wasm
    cd sdks/typescript && npm test

web-e2e: wasm
    cd web/console && npm run e2e

web-e2e-update-snapshots: wasm
    docker run --rm --ipc=host -v "{{justfile_directory()}}:/work" \
      -v /work/web/console/node_modules -v /work/sdks/typescript/node_modules -w /work \
      "mcr.microsoft.com/playwright:v$(cd web/console && node -p 'require("@playwright/test/package.json").version')-noble" \
      bash -c 'cd sdks/typescript && npm ci && cd ../../web/console && npm ci && npx playwright test --update-snapshots'

# OP-69, RAUTHY-008

compose := "docker compose -f deploy/compose/compose.yaml"
dev_db_password := "local-only-not-a-secret"

dev:
    {{compose}} up --detach --build --wait
    @echo "PostgreSQL     postgres://access_app@127.0.0.1:${ACCESS_DEV_PG_PORT:-5432}/access"
    @echo "NATS           nats://127.0.0.1:${ACCESS_DEV_NATS_PORT:-4222}  (monitor http://127.0.0.1:${ACCESS_DEV_NATS_MONITOR_PORT:-8222})"
    @echo "SoftHSM        PKCS#11 token 'access-dev': just dev-hsm --show-slots"
    @echo "Mailpit        http://127.0.0.1:${ACCESS_DEV_MAIL_UI_PORT:-8025}  (SMTP 127.0.0.1:${ACCESS_DEV_SMTP_PORT:-1025})"
    @echo "Grafana        http://127.0.0.1:${ACCESS_DEV_GRAFANA_PORT:-3300}  (user admin, password local-only-not-a-secret)"
    @echo "Jaeger         http://127.0.0.1:${ACCESS_DEV_JAEGER_UI_PORT:-16686}   Prometheus http://127.0.0.1:${ACCESS_DEV_PROMETHEUS_PORT:-9090}"
    @echo "OTLP           127.0.0.1:${ACCESS_DEV_OTLP_GRPC_PORT:-4317} (gRPC), 127.0.0.1:${ACCESS_DEV_OTLP_HTTP_PORT:-4318} (HTTP)"

dev-down:
    {{compose}} down

dev-status:
    {{compose}} ps

dev-hsm *args:
    {{compose}} exec softhsm softhsm2-util {{args}}

db-reset:
    {{compose}} rm --stop --force postgres
    docker volume rm --force access-dev_pgdata
    {{compose}} up --detach --wait postgres
    just db-seed

db-seed:
    for f in deploy/compose/postgres/seed/*.sql; do \
      [ -e "$f" ] || continue; echo "seed: $f"; \
      {{compose}} exec -T -e PGPASSWORD={{dev_db_password}} postgres \
        psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U access_app -d access < "$f"; \
    done

psql:
    {{compose}} exec -e PGPASSWORD={{dev_db_password}} postgres psql -h 127.0.0.1 -U access_app -d access

image tag="access-server:local":
    docker build -f deploy/docker/Dockerfile -t {{tag}} .

mkcert host:
    mkdir -p target/dev-certs
    mkcert -cert-file "target/dev-certs/{{host}}.pem" -key-file "target/dev-certs/{{host}}-key.pem" "{{host}}"

# OP-68

# SA-23, F-2
sanitizer_nightly := "nightly-2026-10-01"

# SA-59
test-full:
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc
    just test-sandbox

# SA-22, OP-90
test-sandbox:
    #!/usr/bin/env bash
    set -euo pipefail
    bin="$(cargo test --locked -p access-sandbox --test lockdown --no-run --message-format=json | jq -r 'select(.executable != null and .target.name == "lockdown") | .executable')"
    if [[ "$(uname -s)" == Linux && "$(id -u)" != 0 ]]; then
        sudo --preserve-env=ACCESS_SANDBOX_REQUIRE_MEMFD_SECRET "$bin"
    else
        "$bin"
    fi

# F-14
semgrep:
    semgrep scan --config .semgrep/ --error --metrics=off

# F-1
vet:
    cargo vet --locked

# F-1
audit:
    cargo audit

# OP-72, OP-84
bench *args:
    cargo bench --locked -p eesuiss-access-kernel --bench kernel_wallclock -- {{args}}

# OP-72
bench-instructions *args:
    cargo bench --locked -p eesuiss-access-kernel --bench kernel_instructions -- {{args}}

# SA-59
mutants *args:
    cargo mutants --package eesuiss-access-kernel --test-tool nextest {{args}}

# SA-23, §14.5
sanitize kind:
    RUSTFLAGS="-Zsanitizer={{kind}}" RUSTDOCFLAGS="-Zsanitizer={{kind}}" \
      cargo +{{sanitizer_nightly}} test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --lib --tests

# SA-23, §14.5
checksec +binaries:
    scripts/checksec.sh {{binaries}}

# F-4, F-5, OP-79, F-2, SA-34
release-build target:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    if find target/vendor -type d \( -name .vscode -o -name .devcontainer -o -name .githooks -o -name .idea \) | grep .; then echo "vendored IDE/hook directories found (F-2)" >&2; exit 1; fi
    RUSTFLAGS="--remap-path-prefix={{justfile_directory()}}=/access --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
      cargo auditable build --locked --offline --config "{{justfile_directory()}}/target/vendor-config.toml" --release -p access-server --target {{target}}

# F-5
sbom target binary out:
    mkdir -p {{out}}
    cargo cyclonedx --manifest-path bins/access-server/Cargo.toml --format json --spec-version 1.5 --target {{target}}
    find bins crates xtask -name '*.cdx.json' -not -path '*/target/*' -exec mv {} {{out}}/ \;
    syft scan "file:{{binary}}" -o "spdx-json={{out}}/access-server.spdx.json"

# OP-68
changelog:
    git cliff --output CHANGELOG.md

# OP-69
gen: wasm
