# Package

version       = "0.1.4"
author        = "Anonymous"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
installDirs   = @[
  "../src/rustcrypto",
]
installFiles  = @[
  "../src/rustcrypto.nim",
]


# Dependencies

requires "nim >= 2.0.0"

proc fetchRustFfiCommand(): string =
  "nim r --hints:off --warnings:off src/rustcrypto/tools/fetch_rustcrypto_ffi.nim"

task fetchRustFfi, "Download Rust FFI static archive from GitHub Release":
  exec fetchRustFfiCommand()

when (defined(linux) and defined(amd64)) or (defined(macosx) and defined(arm64)):
  before install:
    exec fetchRustFfiCommand()

task buildRustFfiLocal, "Build Rust FFI static archive locally and sync it":
  when defined(macosx) and defined(arm64):
    exec "rustup target add wasm32-unknown-unknown wasm32-wasip1"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-unknown-unknown"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-wasip1"
    exec "nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim"
  elif defined(linux) and defined(amd64):
    exec "rustup target add wasm32-unknown-unknown wasm32-wasip1"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-unknown-unknown"
    exec "cd ../rustcrypto-ffi && cargo build --release --lib --target wasm32-wasip1"
    exec "nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim"
  else:
    echo "rustcrypto FFI local build supports only Linux x86_64 and macOS arm64 hosts."
    quit(QuitFailure)
