#!/usr/bin/env bash
cd /application/src/rustcrypto-ffi
rustup target add wasm32-unknown-unknown wasm32-wasip1
cargo build --release --lib
cargo build --release --lib --target wasm32-unknown-unknown
cargo build --release --lib --target wasm32-wasip1

cd /application/src/nim-rustcrypto
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim
nimble uninstall rustcrypto -yi || true
# nimble install -y 'https://github.com/itsumura-h/nim-rustcrypto?subdir=src/nim-rustcrypto'
nimble install -y
