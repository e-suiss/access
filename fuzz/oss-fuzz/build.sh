#!/bin/bash -eu
# SA-T9, OP-159 m.3 (cc)
cd "$SRC/access/fuzz"
cargo fuzz build -O --debug-assertions
release="target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
    cp "$release/$target" "$OUT/"
    if [[ -d "corpus/$target" ]]; then
        zip -q -j "$OUT/${target}_seed_corpus.zip" "corpus/$target"/*
    fi
done
