cd /application/src/rustcrypto-ffi
cargo build --release --lib

cd /application/src/nim-rustcrypto
nimble uninstall rustcrypto -iy || true
nimble install -y
