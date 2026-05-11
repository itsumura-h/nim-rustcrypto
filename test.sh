#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Rust tests"
cd "$repo_root/src/rustcrypto-ffi"
cargo test
cargo build --release --lib
rustup target add wasm32-unknown-unknown wasm32-wasip1
cargo build --release --lib --target wasm32-unknown-unknown
cargo build --release --lib --target wasm32-wasip1
test -s target/release/librust_crypto_ffi.a
test -s target/wasm32-unknown-unknown/release/librust_crypto_ffi.a
test -s target/wasm32-wasip1/release/librust_crypto_ffi.a

echo "==> Sync Rust static library"
cd "$repo_root/src/nim-rustcrypto"
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim

echo "==> Nim tests"
cd "$repo_root/src/nim-rustcrypto"
nimble test -y
