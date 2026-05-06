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

echo "==> Nim consumer install test"
consumer_dir="$(mktemp -d)"
cd "$consumer_dir"
nimble init -y consumer >/dev/null 2>&1
cd consumer
nimble add -y "https://github.com/itsumura-h/nim-rustcrypto?subdir=src/nim-rustcrypto"

version="$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$repo_root/src/nim-rustcrypto/rustcrypto.nimble")"
rm -f "$HOME/.cache/rustcrypto/ffi/v${version}/linux-x86_64/librust_crypto_ffi.a"

installed_rustcrypto_dir="$(nimble path rustcrypto)"
test -f "$installed_rustcrypto_dir/rustcrypto/vendor/rustcrypto-ffi/linux-x86_64/librust_crypto_ffi.a"

mkdir -p src
cat > src/main.nim <<'EOF'
import rustcrypto

when isMainModule:
  doAssert sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
EOF

nimble c -y src/main.nim
