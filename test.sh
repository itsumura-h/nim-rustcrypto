#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Rust tests"
cd "$repo_root/src/rustcrypto-ffi"
cargo test
cargo build --release --lib

echo "==> Nim tests"
cd "$repo_root/src/nim-rustcrypto"
nimble test -y
