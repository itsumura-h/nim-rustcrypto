#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Rust tests"
cd "$repo_root/src/rustcrypto-ffi"
cargo test
cargo build --release --lib

echo "==> Sync Rust static library"
cd "$repo_root/src/nim-rustcrypto"
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim

echo "==> Nim tests"
cd "$repo_root/src/nim-rustcrypto"
nimble test -y
