# Package

version       = "0.1.0"
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

requires "nim >= 2.2.10"

task fetchRustFfi, "Download Rust FFI static archive from GitHub Release":
  exec "nim r --hints:off --warnings:off src/rustcrypto/tools/fetch_rustcrypto_ffi.nim"

task buildRustFfiLocal, "Build Rust FFI static archive locally and sync it":
  exec "cd ../rustcrypto-ffi && cargo build --release --lib"
  exec "nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim"
