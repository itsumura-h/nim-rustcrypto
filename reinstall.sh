#!/usr/bin/env bash
cd /application/src/rustcrypto-ffi
cargo build --release --lib

cd /application/src/nim-rustcrypto
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim
nimble uninstall rustcrypto -yi || true
# nimble install -y 'https://github.com/itsumura-h/nim-rustcrypto?subdir=src/nim-rustcrypto'
nimble install -y
