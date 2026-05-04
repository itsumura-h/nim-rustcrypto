cd /application/src/rustcrypto-ffi
cargo build --release --lib

cd /application/src/nim-rustcrypto
nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim
nimble uninstall rustcrypto -iy || true
nimble install -y
