# OP-69

set shell := ["bash", "-euo", "pipefail", "-c"]

# CMP-24, MD-1, T41
not_lockdown := "not (package(esuiss-sandbox) and binary(lockdown))"
kernel_targets := "wasm32-unknown-unknown wasm32-wasip1 aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android"
mobile_targets := "aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android"

default:
    @just --list

check: fmt-check lint rules deny

# SA-59; store tests use DATABASE_URL, or a local cluster (`just pg-up`)
test:
    DATABASE_URL="${DATABASE_URL:-$(scripts/pg-local.sh up)}" SOFTHSM2_CONF="$(scripts/softhsm-local.sh)" cargo nextest run --workspace --locked --no-tests=pass -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc

# OP-66, OP-69: throwaway PostgreSQL 18 under target/pg; prints its superuser URL
pg-up:
    @scripts/pg-local.sh up

pg-down:
    scripts/pg-local.sh down

# OQ-MD3, OP-131: failover and logical-decoding scenarios on a local primary and standby
oq-md3:
    scripts/oq-md3.sh

# OP-66, OP-154 m.3 (u): refresh the committed .sqlx query metadata against a freshly migrated database
# (the store's schema and the executor's own)
sqlx-prepare:
    #!/usr/bin/env bash
    set -euo pipefail
    url="$(scripts/pg-local.sh up)"
    base="${url%/*}"
    db="access_sqlx_prepare"
    psql -X -q "$url" -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
    psql -X -q -v ON_ERROR_STOP=1 "$base/$db" -f crates/store/bootstrap/roles.sql -f crates/store/bootstrap/database.sql
    DATABASE_URL="$base/$db" sqlx migrate run --source crates/store/migrations
    DATABASE_URL="$base/$db" sqlx migrate run --source services/executor/migrations --ignore-missing
    DATABASE_URL="$base/$db" sqlx migrate run --source services/vc-verifier/migrations --ignore-missing
    DATABASE_URL="$base/$db" sqlx migrate run --source services/hr-connector/migrations --ignore-missing
    DATABASE_URL="$base/$db" SQLX_OFFLINE=false cargo sqlx prepare --workspace -- --all-targets -p access-store -p access-executor -p access-vc-verifier -p access-hr-connector --features testing

# OP-66: the committed .sqlx query metadata matches the queries against a freshly migrated database
sqlx-check:
    #!/usr/bin/env bash
    set -euo pipefail
    url="${DATABASE_URL:-$(scripts/pg-local.sh up)}"
    base="${url%/*}"
    db="access_sqlx_check_$$"
    trap 'psql -X -q "$url" -c "DROP DATABASE IF EXISTS $db WITH (FORCE)"' EXIT
    psql -X -q -v ON_ERROR_STOP=1 "$url" -c "CREATE DATABASE $db"
    psql -X -q -v ON_ERROR_STOP=1 "$base/$db" -f crates/store/bootstrap/roles.sql -f crates/store/bootstrap/database.sql
    DATABASE_URL="$base/$db" sqlx migrate run --source crates/store/migrations
    DATABASE_URL="$base/$db" sqlx migrate run --source services/executor/migrations --ignore-missing
    DATABASE_URL="$base/$db" sqlx migrate run --source services/vc-verifier/migrations --ignore-missing
    DATABASE_URL="$base/$db" sqlx migrate run --source services/hr-connector/migrations --ignore-missing
    DATABASE_URL="$base/$db" SQLX_OFFLINE=false cargo sqlx prepare --check --workspace -- --all-targets -p access-store -p access-executor -p access-vc-verifier -p access-hr-connector --features testing

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

# F-14, OP-68: the CI helper scripts' own tests
ci-scripts-test:
    python3 -I -m unittest discover -s .github/scripts/tests -p 'test_*.py'

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
    # OP-76, OP-140 m.2: the verify feature is no_std and builds for a microcontroller too
    for t in {{kernel_targets}} thumbv7em-none-eabihf; do cargo build --locked -p esuiss-crypto --no-default-features --features verify --target "$t"; done
    for t in {{kernel_targets}} thumbv7em-none-eabihf; do cargo build --locked -p esuiss-ledger --target "$t"; done
    # OP-147 m.2
    for t in {{kernel_targets}} thumbv7em-none-eabihf; do cargo build --locked -p esuiss-retention --all-features --target "$t"; done
    # OP-104 m.7
    for t in {{kernel_targets}}; do just _ndk "$t" cargo build --locked -p esuiss-restriction --target "$t"; done
    # OP-116 m.3
    for t in {{mobile_targets}}; do just _ndk "$t" cargo build --locked -p access-kernel-uniffi --target "$t"; done
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-access-kernel --target wasm32-wasip1
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-crypto --target wasm32-wasip1
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-ledger --target wasm32-wasip1
    CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test --locked -p esuiss-retention --all-features --target wasm32-wasip1
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
    wasm-bindgen --target web --out-dir sdks/typescript/wasm "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/access_kernel_wasm.wasm"

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
npm_packages :="sdks/typescript web/components web/console web/login web/account"

# OP-83, §14.5
web-install:
    for p in {{npm_packages}}; do (cd "$p" && npm ci); done

# F-1, §14.7: known high or critical advisories in any npm package's lockfile, development tools included
web-audit:
    status=0; for p in {{npm_packages}} conformance/mcp; do echo "$p"; (cd "$p" && npm audit --audit-level=high) || status=1; done; exit "$status"

web-check: wasm
    for p in {{npm_packages}}; do (cd "$p" && npm run lint && npm run typecheck && npm run format:check); done

web-test: wasm
    cd sdks/typescript && npm test
    cd web/components && npm test

# OP-151 m.3 (g), TN-112 item 8: the SDK types are generated from the contracts and committed
sdk-types-check:
    cd sdks/typescript && npm run gen
    git diff --exit-code -- sdks/typescript/src/generated

# OP-151 m.3 (g), T41 item 6: one row of the binding compatibility table (sdks/bindings/README.md)
bindings-row:
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
    vectors="$(cd conformance/vectors/core/1 && find . -type f -name '*.json' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-16)"
    echo "| ${version} | uniffi (Python, Kotlin, Swift), Wasm (Node) | core/1 \`${vectors}\` |"

web-e2e: wasm login-e2e
    cd web/console && npm run e2e

# OP-146 m.4 (g): hosted login against the mocked node endpoints, passkeys on a CDP virtual authenticator
login-e2e:
    cd web/login && npm run e2e

# OP-65: rewrite sdks/openapi/login.json, frontend.json and their examples from crates/identity-ui
login-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-identity-ui --test contract --test frontend_contract

# OP-65, OP-153 m.4: rewrite sdks/openapi/frontend-v1.json from the hosted route table
frontend-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-identity-ui --test frontend_v1_contract

# OP-65, OP-149: rewrite sdks/openapi/access-v1.json and its examples from crates/http
access-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-http --test product

# OP-65, OP-153 m.3 (v): rewrite sdks/openapi/experience-v1.json from services/experience
experience-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-experience --test contract

# OP-65, OP-154 m.3 (u): rewrite sdks/openapi/executor-v1.json from services/executor
executor-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-executor --test contract

# OP-65, OP-155 m.3 (p): rewrite sdks/openapi/vc-verifier-v1.json from services/vc-verifier
vc-verifier-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-vc-verifier --test contract

# OP-65, OP-156 m.4: rewrite sdks/openapi/proxy-v1.json from services/proxy
proxy-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-proxy --test contract

# OP-156 m.3 (p): check the Linux client's socket contract against conformance/cddl/linux-client.cddl
linux-client-contract:
    cargo test --locked -p access-linux-client --test contract

# OP-65, OP-156 m.4: rewrite sdks/openapi/hr-connector-v1.json from services/hr-connector
hr-connector-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-hr-connector --test contract

# OP-65, OP-151 m.4: rewrite sdks/openapi/admin-v1.json and problems.json from crates/http
admin-contract:
    ACCESS_UPDATE_CONTRACTS=1 cargo test --locked -p access-http --test admin_contract

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
    SOFTHSM2_CONF="$(scripts/softhsm-local.sh)"
    export SOFTHSM2_CONF
    cargo nextest run --workspace --locked --no-tests=pass --run-ignored all -E '{{not_lockdown}}'
    cargo test --workspace --locked --doc
    just test-sandbox

# OP-155 m.3 (c), U43, MD-18: the parser worker as real processes under its Linux lockdown, as root
test-parser-worker:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" != Linux ]]; then
        echo "the parser worker's lockdown is Linux-only" >&2
        exit 1
    fi
    bin="$(cargo test --locked -p access-parser-worker --test worker --no-run --message-format=json | jq -r 'select(.executable != null and .target.name == "worker") | .executable')"
    if [[ "$(id -u)" != 0 ]]; then
        sudo "$bin" --ignored --test-threads=1
    else
        "$bin" --ignored --test-threads=1
    fi

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
    bin="$(cargo test --locked -p esuiss-sandbox --test lockdown --no-run --message-format=json | jq -r 'select(.executable != null and .target.name == "lockdown") | .executable')"
    if [[ "$(uname -s)" == Linux && "$(id -u)" != 0 ]]; then
        sudo --preserve-env=ACCESS_SANDBOX_REQUIRE_MEMFD_SECRET "$bin"
    else
        "$bin"
    fi

# OP-155 m.3 (o): the excluded Kerberos workspace (Linux CI only): its own lint, tests and supply
# chain, then the end-to-end run as root with the gateway and parser worker as real processes
kerberos:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" != Linux ]]; then
        echo "the Kerberos gateway builds on Linux only (OP-155 m.3 (o))" >&2
        exit 1
    fi
    (
        cd bins/access-gw-kerberos
        cargo fmt --check
        cargo clippy --locked --all-targets -- -D warnings
        cargo test --locked
        cargo deny --locked --manifest-path Cargo.toml --config ../../deny.toml check
        cargo vet --locked
        cargo build --locked
    )
    cargo build --locked -p access-parser-worker
    bin="$(cargo test --locked -p access-edge-core --test channel --no-run --message-format=json-render-diagnostics | jq -r 'select(.executable != null and .target.name == "channel") | .executable')"
    export ACCESS_TEST_GW_KERBEROS_BIN="$PWD/bins/access-gw-kerberos/target/debug/access-gw-kerberos"
    export ACCESS_TEST_PARSER_BIN="$PWD/target/debug/access-parser-worker"
    if [[ "$(id -u)" != 0 ]]; then
        sudo --preserve-env=DATABASE_URL,ACCESS_TEST_KRB5_REALM,ACCESS_TEST_KDC,ACCESS_TEST_KEYTAB_DIR,ACCESS_TEST_GW_KERBEROS_BIN,ACCESS_TEST_PARSER_BIN \
            "$bin" --ignored --exact kerberos_gateway::spnego_signs_in_falls_back_and_never_writes_the_keytab
    else
        "$bin" --ignored --exact kerberos_gateway::spnego_signs_in_falls_back_and_never_writes_the_keytab
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

# OP-150 m.1 (a), CMP-17, X21: PEP fault cases against `sut`, or the self-test without one
pep-conformance sut="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --locked --quiet -p access-pep-conformance --bins
    bin="${CARGO_TARGET_DIR:-target}/debug"
    if [[ -n "{{sut}}" ]]; then
      exec "$bin/access-pep-conformance" --sut {{quote(sut)}}
    fi
    "$bin/access-pep-conformance" --sut "$bin/pep-reference"
    "$bin/access-pep-conformance" --sut "$bin/pep-sdk"
    status=0
    "$bin/access-pep-conformance" --sut "$bin/pep-reference-leaky" || status=$?
    if [[ "$status" -ne 1 ]]; then
      echo "pep-conformance: the leaky control was not flagged (exit $status); the harness is blind" >&2
      exit 1
    fi
    echo "pep-conformance: the leaky control was flagged"

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

# OP-76, OP-102, OP-139
published := "-p esuiss-crypto -p esuiss-ledger -p esuiss-retention -p esuiss-restriction -p esuiss-sandbox -p esuiss-access-kernel -p esuiss-access-verifier -p esuiss-access-sdk -p esuiss-access-verify"

# OP-140 m.3: copy the shared vectors into the suiss-crypto package and list their SHA-256
shared-vectors:
    #!/usr/bin/env bash
    set -euo pipefail
    cd crates/suiss-crypto/vectors
    for f in $(find . -type f ! -name MANIFEST | sed 's|^\./||' | LC_ALL=C sort); do cp "../../../conformance/vectors/$f" "$f"; done
    find . -type f ! -name MANIFEST | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256 > MANIFEST

crates-package:
    cargo package --locked {{published}}

# OP-140 m.4: every esuiss-crypto feature builds on its own, warnings are errors
crates-features:
    #!/usr/bin/env bash
    set -euo pipefail
    export RUSTFLAGS="-D warnings"
    cargo check --locked -p esuiss-crypto --no-default-features
    for f in $(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "esuiss-crypto") | .features | keys[]'); do
      echo "esuiss-crypto: --features $f"
      cargo check --locked -p esuiss-crypto --no-default-features --features "$f"
    done

crates-publish tag:
    #!/usr/bin/env bash
    set -euo pipefail
    version="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "esuiss-access-kernel") | .version')"
    if [[ "{{tag}}" != "v$version" ]]; then echo "tag {{tag}} does not match workspace version $version" >&2; exit 1; fi
    todo=()
    for crate in $(echo "{{published}}" | sed 's/-p //g'); do
        if curl -fsS -A "e-suiss/access release" "https://crates.io/api/v1/crates/$crate/$version" > /dev/null 2>&1; then
            echo "$crate $version is already on crates.io; skipping"
        else
            todo+=(-p "$crate")
        fi
    done
    if [[ ${#todo[@]} -eq 0 ]]; then echo "every crate is already published"; exit 0; fi
    cargo publish --locked "${todo[@]}"

# F-1
audit:
    cargo audit

# OP-72, OP-84
bench *args:
    cargo bench --locked -p esuiss-access-kernel --bench kernel_wallclock -- {{args}}

# OP-72, AG-22: the Kernel's hot paths and an agent token refresh
bench-instructions *args:
    cargo bench --locked -p esuiss-access-kernel --bench kernel_instructions --bench agent_tokens -- {{args}}

# OP-72: one instruction-count bench
bench-instructions-one bench *args:
    cargo bench --locked -p esuiss-access-kernel --bench {{bench}} -- {{args}}

# OQ-MD4, OP-150 m.1 (c): Kernel call cost direct, on wasm32-wasip1, on Node and through uniffi; informational, not a gate
bench-ffi iters="5000":
    #!/usr/bin/env bash
    set -euo pipefail
    target="${CARGO_TARGET_DIR:-target}"
    out="$target/bench-ffi"
    vectors="conformance/vectors/core/1"
    rm -rf "$out" && mkdir -p "$out"
    cargo build --locked --release -p esuiss-access-kernel --example ffi_cost
    "$target/release/examples/ffi_cost" --vectors "$vectors" --iters {{iters}} --inputs "$out/inputs.json" | tee "$out/rust.jsonl"
    if command -v wasmtime >/dev/null; then
      cargo build --locked --release -p esuiss-access-kernel --example ffi_cost --target wasm32-wasip1
      wasmtime run --dir "$vectors" "$target/wasm32-wasip1/release/examples/ffi_cost.wasm" --vectors "$vectors" --iters {{iters}} | tee "$out/wasip1.jsonl"
    else
      echo "bench-ffi: wasmtime not found; wasm32-wasip1 skipped" >&2
    fi
    want="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')"
    if command -v node >/dev/null && [[ "$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)" == "$want" ]]; then
      cargo build --locked --release --target wasm32-unknown-unknown -p access-kernel-wasm
      wasm-bindgen --target web --out-dir "$out/wasm" "$target/wasm32-unknown-unknown/release/access_kernel_wasm.wasm"
      node scripts/bench_ffi.mjs "$out/wasm" "$out/inputs.json" {{iters}} | tee "$out/node.jsonl"
    else
      echo "bench-ffi: node or wasm-bindgen-cli $want not found; Node skipped" >&2
    fi
    cargo build --locked --release -p access-kernel-uniffi
    case "$(uname -s)" in Darwin) ext=dylib ;; *) ext=so ;; esac
    lib="$target/release/libaccess_kernel_uniffi.$ext"
    cargo run --locked --quiet -p access-kernel-uniffi --features bindgen --bin uniffi-bindgen -- \
      generate --library "$lib" --language python --out-dir "$out/python"
    cp "$lib" "$out/python/"
    python3 -I scripts/bench_ffi.py uniffi "$out/python" "$out/inputs.json" {{iters}} | tee "$out/python.jsonl"
    runs=(); for r in rust wasip1 node python; do if [[ -f "$out/$r.jsonl" ]]; then runs+=("$out/$r.jsonl"); fi; done
    python3 -I scripts/bench_ffi.py summary "${runs[@]}" | tee "$out/summary.md"

# SA-59
mutants *args:
    cargo mutants --package esuiss-access-kernel --test-tool nextest {{args}}

# SA-59, OP-152 m.5 (c): mutants on the lines a change touches in the Kernel and the authority
# core's decision paths, against `base` (a missed or timed-out mutant fails)
mutants-diff base="origin/main":
    #!/usr/bin/env bash
    set -euo pipefail
    diff="$(mktemp)"
    git diff "{{base}}...HEAD" -- crates/kernel/src crates/authority-core/src \
      ':(exclude)crates/authority-core/src/adapters' ':(exclude)crates/authority-core/src/adapters.rs' > "$diff"
    if [ ! -s "$diff" ]; then echo "no Kernel or authority-core decision change"; exit 0; fi
    DATABASE_URL="${DATABASE_URL:-$(scripts/pg-local.sh up)}" cargo mutants --in-diff "$diff" \
      --package esuiss-access-kernel --package access-authority-core --test-tool nextest

# SA-23, §14.5, OP-127 m.1: every test binary runs (--no-fail-fast); reports that are not defects are
# suppressed with their reasons in scripts/sanitizers/; frame pointers give the leak reports whole stacks
sanitize kind:
    #!/usr/bin/env bash
    set -euo pipefail
    supp="{{justfile_directory()}}/scripts/sanitizers"
    export TSAN_OPTIONS="suppressions=$supp/thread.supp" LSAN_OPTIONS="suppressions=$supp/leak.supp"
    export RUSTFLAGS="-Zsanitizer={{kind}} -Cforce-frame-pointers=yes" RUSTDOCFLAGS="-Zsanitizer={{kind}}"
    SOFTHSM2_CONF="$(scripts/softhsm-local.sh)" \
      cargo +{{sanitizer_nightly}} test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --exclude esuiss-sandbox --lib --tests --no-fail-fast
    cargo +{{sanitizer_nightly}} test --locked -Zbuild-std --target x86_64-unknown-linux-gnu -p esuiss-sandbox --lib --no-fail-fast

# SA-23, §14.5
checksec +binaries:
    scripts/checksec.sh {{binaries}}

# F-2, OP-127 m.2
vendor:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    scripts/vendor-ide-check.sh target/vendor supply-chain/vendored-ide-allowlist.txt

# F-4, F-5, OP-79, F-2, SA-34, OP-127 m.2
release-build target: vendor
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
