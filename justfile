# OP-69

set shell := ["bash", "-euo", "pipefail", "-c"]

# CMP-24, MD-1, T41
not_lockdown := "not (package(access-sandbox) and binary(lockdown))"
kernel_targets := "wasm32-unknown-unknown wasm32-wasip1 aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android"
mobile_targets := "aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android"

default:
    @just --list

check: fmt-check lint rules deny

# SA-59; store tests use DATABASE_URL, or a local cluster (`just pg-up`)
test:
    DATABASE_URL="${DATABASE_URL:-$(scripts/pg-local.sh up)}" cargo nextest run --workspace --locked --no-tests=pass -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc

# OP-66, OP-69: throwaway PostgreSQL 18 under target/pg; prints its superuser URL
pg-up:
    @scripts/pg-local.sh up

pg-down:
    scripts/pg-local.sh down

# OQ-MD3, OP-131: failover and logical-decoding scenarios on a local primary and standby
oq-md3:
    scripts/oq-md3.sh

# OP-66: refresh the committed .sqlx query metadata against a freshly migrated database
sqlx-prepare:
    #!/usr/bin/env bash
    set -euo pipefail
    url="$(scripts/pg-local.sh up)"
    base="${url%/*}"
    db="access_sqlx_prepare"
    psql -X -q "$url" -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
    psql -X -q -v ON_ERROR_STOP=1 "$base/$db" -f crates/store/bootstrap/roles.sql -f crates/store/bootstrap/database.sql
    DATABASE_URL="$base/$db" sqlx migrate run --source crates/store/migrations
    DATABASE_URL="$base/$db" SQLX_OFFLINE=false cargo sqlx prepare --workspace -- --all-targets -p access-store --features testing

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

# CR-14, §10.4.5, G46
no-rsa:
    #!/usr/bin/env bash
    set -euo pipefail
    for manifest in Cargo.toml fuzz/Cargo.toml; do
      if out="$(cargo tree --locked --manifest-path "$manifest" --workspace --target all -e all -i rsa 2>&1)"; then
        echo "$out"
        echo "$manifest: the rsa crate is in the dependency graph (CR-14, §10.4.5)" >&2
        exit 1
      fi
      if ! grep -q 'did not match any packages' <<<"$out"; then
        echo "$out" >&2
        exit 1
      fi
      echo "$manifest: no rsa crate"
    done

cross:
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-access-kernel --target "$t"; done
    # OP-76
    for t in {{kernel_targets}}; do cargo build --locked -p esuiss-crypto --no-default-features --features verify --target "$t"; done
    # OP-104 m.7
    for t in {{kernel_targets}}; do just _ndk "$t" cargo build --locked -p esuiss-restriction --target "$t"; done
    # OP-116 m.3
    for t in {{mobile_targets}}; do just _ndk "$t" cargo build --locked -p access-kernel-uniffi --target "$t"; done
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-access-kernel --target wasm32-wasip1
    # E43
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-restriction --target wasm32-wasip1

[private]
_ndk target +cmd:
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
      *-apple-ios*)
        if [[ "$(uname -s)" != Darwin ]]; then
          echo "{{target}}: needs the iOS SDK (psm, OP-104 m.7); built by cross-ios on macOS" >&2
          exit 0
        fi
        ;;
      *-linux-android)
        var="CC_$(echo '{{target}}' | tr '-' '_')"
        if [[ -z "${!var:-}" ]]; then
          bin="$(ls -d "${ANDROID_NDK_HOME:-/nonexistent}"/toolchains/llvm/prebuilt/*/bin 2>/dev/null | head -1 || true)"
          if [[ ! -x "$bin/{{target}}24-clang" ]]; then
            echo "{{target}}: Android NDK required (OP-104 m.7); set ANDROID_NDK_HOME or $var" >&2
            exit 1
          fi
          export "$var=$bin/{{target}}24-clang" "AR_$(echo '{{target}}' | tr '-' '_')=$bin/llvm-ar"
        fi
        linker="CARGO_TARGET_$(echo '{{target}}' | tr 'a-z-' 'A-Z_')_LINKER"
        if [[ -z "${!linker:-}" ]]; then export "$linker=${!var}"; fi
        ;;
    esac
    {{cmd}}

cross-ios:
    for t in aarch64-apple-ios aarch64-apple-ios-sim; do cargo build --locked -p esuiss-restriction --target "$t"; done
    # OP-116 m.3
    for t in aarch64-apple-ios aarch64-apple-ios-sim; do cargo build --locked -p access-kernel-uniffi --target "$t"; done
    CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER="{{justfile_directory()}}/scripts/ios-sim-runner.sh" cargo test --locked -p esuiss-access-kernel --target aarch64-apple-ios-sim

cross-android target="x86_64-linux-android":
    CARGO_TARGET_X86_64_LINUX_ANDROID_RUNNER="{{justfile_directory()}}/scripts/android-runner.sh" \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER="{{justfile_directory()}}/scripts/android-runner.sh" \
    cargo test --locked -p esuiss-access-kernel --target {{target}}

# OP-116 m.3
android-link-check:
    #!/usr/bin/env bash
    set -euo pipefail
    ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-/nonexistent}}"
    bin="$(ls -d "$ndk"/toolchains/llvm/prebuilt/*/bin 2>/dev/null | head -1 || true)"
    if [[ ! -x "$bin/llvm-nm" ]]; then
      echo "android-link-check: Android NDK required; set ANDROID_NDK_HOME" >&2
      exit 1
    fi
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    printf 'int main(void) { return 0; }\n' > "$work/main.c"
    for t in aarch64-linux-android x86_64-linux-android; do
      just _ndk "$t" cargo build --locked -p access-kernel-uniffi --target "$t"
      dir="target/$t/debug"
      so="$dir/libaccess_kernel_uniffi.so"
      grep -q 'DYN (Shared object file)' <<<"$("$bin/llvm-readelf" -h "$so")"
      syms="$("$bin/llvm-nm" -D --defined-only "$so")"
      for f in api_version evaluate verify_consistency; do
        grep -q " T uniffi_access_kernel_uniffi_fn_func_$f\$" <<<"$syms"
      done
      "$bin/${t}24-clang" "$work/main.c" -o "$work/$t" -L "$dir" \
        -Wl,--no-as-needed -laccess_kernel_uniffi -Wl,--no-allow-shlib-undefined
      echo "$t: $so links against the API 24 NDK sysroot and exports the binding"
    done

# OP-83
wasm:
    want="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"; \
    have="$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)"; \
    if [ "$have" != "$want" ]; then echo "wasm-bindgen-cli $want required (found '${have:-none}'): cargo install wasm-bindgen-cli --version $want --locked" >&2; exit 1; fi
    cargo build --locked --release --target wasm32-unknown-unknown -p access-kernel-wasm
    wasm-bindgen --target web --out-dir sdks/typescript/wasm target/wasm32-unknown-unknown/release/access_kernel_wasm.wasm

# OP-116 m.6
uniffi-test:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --locked -p access-kernel-uniffi
    case "$(uname -s)" in Darwin) ext=dylib ;; *) ext=so ;; esac
    lib="target/debug/libaccess_kernel_uniffi.$ext"
    out="target/uniffi/python"
    rm -rf "$out" && mkdir -p "$out"
    cargo run --locked --quiet -p access-kernel-uniffi --features bindgen --bin uniffi-bindgen -- \
      generate --library "$lib" --language python --out-dir "$out"
    cp "$lib" "$out/"
    python3 -I sdks/bindings/uniffi/tests/vectors.py "$out"

# OP-116 m.6, F-2
uniffi-test-kotlin:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v java >/dev/null || ! java -version >/dev/null 2>&1; then
      echo "uniffi-test-kotlin: a JDK is required (java on PATH)" >&2
      exit 1
    fi
    tools="$(scripts/kotlin-fetch.sh target/kotlin)"
    cargo build --locked -p access-kernel-uniffi
    case "$(uname -s)" in Darwin) ext=dylib ;; *) ext=so ;; esac
    lib="target/debug/libaccess_kernel_uniffi.$ext"
    out="target/uniffi/kotlin"
    rm -rf "$out" && mkdir -p "$out"
    cargo run --locked --quiet -p access-kernel-uniffi --features bindgen --bin uniffi-bindgen -- \
      generate --library "$lib" --language kotlin --no-format --out-dir "$out"
    cp "$lib" "$out/"
    "$tools/kotlinc/bin/kotlinc" -nowarn -cp "$tools/jna.jar" -include-runtime -d "$out/vectors.jar" \
      "$out/uniffi/access_kernel_uniffi/access_kernel_uniffi.kt" sdks/bindings/uniffi/tests/Vectors.kt
    java -Djna.library.path="$out" -cp "$out/vectors.jar:$tools/jna.jar" VectorsKt conformance/vectors/core/1

# OP-116 m.6
uniffi-test-swift:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" != Darwin ]]; then
      echo "uniffi-test-swift: needs macOS (swiftc with CryptoKit)" >&2
      exit 1
    fi
    cargo build --locked -p access-kernel-uniffi
    lib="target/debug/libaccess_kernel_uniffi.dylib"
    out="target/uniffi/swift"
    rm -rf "$out" && mkdir -p "$out"
    cargo run --locked --quiet -p access-kernel-uniffi --features bindgen --bin uniffi-bindgen -- \
      generate --library "$lib" --language swift --out-dir "$out"
    swiftc -parse-as-library -module-name AccessKernelVectors \
      -Xcc -fmodule-map-file="$out/access_kernel_uniffiFFI.modulemap" -I "$out" \
      -L target/debug -laccess_kernel_uniffi -o "$out/vectors" \
      "$out/access_kernel_uniffi.swift" sdks/bindings/uniffi/tests/vectors.swift
    "$out/vectors" conformance/vectors/core/1

# OP-97
npm_packages :="sdks/typescript web/console"

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

# SA-59, OP-105
test-full:
    #!/usr/bin/env bash
    set -euo pipefail
    ACCESS_CVC5="$(scripts/cvc5-fetch.sh target/cvc5)"
    export ACCESS_CVC5
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc
    just test-sandbox

# OP-105, F-2
smt-fetch:
    scripts/cvc5-fetch.sh target/cvc5

# OP-105
smt-test:
    #!/usr/bin/env bash
    set -euo pipefail
    ACCESS_CVC5="$(scripts/cvc5-fetch.sh target/cvc5)"
    export ACCESS_CVC5
    cargo nextest run --locked -p esuiss-restriction-analysis --run-ignored all --no-tests=fail

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

# SA-44, OP-103 criterion 6
fuzz target seconds="60":
    cd fuzz && cargo +{{sanitizer_nightly}} fuzz run {{target}} -- -max_total_time={{seconds}} -rss_limit_mb=2048

fuzz-all seconds="60":
    for t in $(cd fuzz && cargo +{{sanitizer_nightly}} fuzz list); do just fuzz "$t" {{seconds}}; done

# OP-106 m.24
vectors-crosscheck:
    cd conformance/vectors/tools/cbor-crosscheck && go run . ../..
    target/vectors-venv/bin/python -I -c 'import cbor2' 2>/dev/null || (rm -rf target/vectors-venv && python3 -m venv target/vectors-venv && target/vectors-venv/bin/pip install --quiet cbor2==5.7.1)
    target/vectors-venv/bin/python -I conformance/vectors/tools/cbor_crosscheck.py conformance/vectors
    target/vectors-venv/bin/python -I conformance/vectors/tools/record.py --check conformance/vectors/core/1/record.json
    target/vectors-venv/bin/python -I conformance/vectors/tools/fold.py --check conformance/vectors/core/1/record-fold.json

# OP-112, CR-49 m.2
f0:
    target/f0-venv/bin/python -I -c 'import cbor2' 2>/dev/null || (rm -rf target/f0-venv && python3 -m venv target/f0-venv && target/f0-venv/bin/pip install --quiet --require-hashes -r conformance/reference/f0/requirements.txt)
    target/f0-venv/bin/python -I conformance/reference/f0/run.py conformance/vectors

# OP-119 m.3, F-2
lean:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -x "$HOME/.elan/bin/lake" ]]; then
        PATH="$HOME/.elan/bin:$PATH"
    elif ! command -v lake >/dev/null; then
        PATH="$(scripts/lean-fetch.sh target/lean):$PATH"
    fi
    cd conformance/lean
    lake build --wfail AccessAlgebra vectors
    ./check-axioms.sh
    lake exe vectors ../vectors/core/*/*.json

# CR-39 m.5, SA-T13
dudect:
    ACCESS_DUDECT=1 cargo test --locked --release -p access-crypto --test dudect -- --ignored --nocapture

# CR-39 m.5, SA-T13, SAI-42
ctgrind:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" != Linux ]] || ! command -v valgrind >/dev/null; then
      echo "ctgrind needs Valgrind on Linux (CR-39 m.5); natively: cargo test --release -p access-crypto --test ctgrind" >&2
      exit 1
    fi
    bin="$(cargo test --locked --release -p access-crypto --test ctgrind --no-run --message-format=json | jq -r 'select(.executable != null and .target.name == "ctgrind") | .executable')"
    vg=(valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes --quiet)
    "${vg[@]}" "$bin" --test-threads=1
    mkdir -p target
    status=0
    "${vg[@]}" "$bin" --test-threads=1 --ignored --exact control_variable_time_comparison_is_reported 2> target/ctgrind-control.log || status=$?
    if [[ "$status" -ne 99 ]] || ! grep -q "uninitialised value" target/ctgrind-control.log; then
      cat target/ctgrind-control.log >&2
      echo "ctgrind: the variable-time control was not reported (exit $status); the harness is blind" >&2
      exit 1
    fi
    echo "ctgrind: secret comparisons clean; the variable-time control was reported"

# CR-39 m.5, SA-T13
ct-asm *args:
    python3 -I scripts/ct_asm.py {{args}}

# OP-112 m.4, OP-119 m.6
f0-random count="10000" seed="1" summary="":
    rm -rf target/random-vectors
    ACCESS_RANDOM_VECTORS="{{justfile_directory()}}/target/random-vectors" ACCESS_RANDOM_COUNT={{count}} ACCESS_RANDOM_SEED={{seed}} cargo test --locked -q -p esuiss-access-kernel --lib random_inputs_for_f0 -- --ignored
    target/f0-venv/bin/python -I -c 'import cbor2' 2>/dev/null || (rm -rf target/f0-venv && python3 -m venv target/f0-venv && target/f0-venv/bin/pip install --quiet --require-hashes -r conformance/reference/f0/requirements.txt)
    target/f0-venv/bin/python -I conformance/reference/f0/run.py target/random-vectors {{ if summary != "" { "--summary " + quote(summary) } else { "" } }}

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
    cargo bench --locked -p esuiss-access-kernel --bench kernel_wallclock -- {{args}}

# OP-72
bench-instructions *args:
    cargo bench --locked -p esuiss-access-kernel --bench kernel_instructions -- {{args}}

# SA-59
mutants *args:
    cargo mutants --package esuiss-access-kernel --test-tool nextest {{args}}

# SA-23, §14.5, OP-127 m.1
sanitize kind:
    RUSTFLAGS="-Zsanitizer={{kind}}" RUSTDOCFLAGS="-Zsanitizer={{kind}}" \
      cargo +{{sanitizer_nightly}} test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --exclude access-sandbox --lib --tests
    RUSTFLAGS="-Zsanitizer={{kind}}" RUSTDOCFLAGS="-Zsanitizer={{kind}}" \
      cargo +{{sanitizer_nightly}} test --locked -Zbuild-std --target x86_64-unknown-linux-gnu -p access-sandbox --lib

# SA-23, §14.5
checksec +binaries:
    scripts/checksec.sh {{binaries}}

# F-4, F-5, OP-79, F-2, SA-34, OP-127 m.2
release-build target:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    scripts/vendor-ide-check.sh target/vendor supply-chain/vendored-ide-allowlist.txt
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
