# Package

version       = "0.1.1"
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

when defined(linux) and defined(amd64):
  before install:
    exec fetchRustFfiCommand()

task buildRustFfiLocal, "Build Rust FFI static archive locally and sync it":
  exec "cd ../rustcrypto-ffi && cargo build --release --lib"
  exec "nim r --hints:off --warnings:off src/rustcrypto/tools/sync_local_rustcrypto_ffi.nim"
