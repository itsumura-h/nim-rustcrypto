import std/[os]

import ./rustcrypto_ffi_paths

when not defined(linux) or not defined(amd64):
  {.error: "rustcrypto FFI local sync currently supports only Linux x86_64.".}
else:
  proc pickExistingArchive(candidates: openArray[string]): string =
    for candidate in candidates:
      if fileExists(candidate):
        return candidate
    ""

  proc syncArchive(
      sourceArchive: string;
      packageRoot: string;
      version: string;
      targetId: string;
      archiveName: string,
  ) =
    let modulePath = moduleVendorArchivePath(packageRoot, targetId, archiveName)
    let cachePath = cacheArchivePath(version, targetId, archiveName)

    createDir(modulePath.parentDir)
    copyFile(sourceArchive, modulePath)

    createDir(cachePath.parentDir)
    copyFile(sourceArchive, cachePath)

    echo modulePath

  let resolvedPackageRoot = packageRoot(currentSourcePath)
  let version = versionFromNimble(resolvedPackageRoot)
  let sourceRoot = resolvedPackageRoot.parentDir

  let linuxSourceArchive = pickExistingArchive([
    sourceRoot / "rustcrypto-ffi" / "target" / "release" / RustCryptoCargoArchiveName,
    sourceRoot / "rustcrypto-ffi" / "target" / "debug" / RustCryptoCargoArchiveName,
  ])
  if linuxSourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI linux archive not found in target/release or target/debug.")
    quit(QuitFailure)

  let wasmSourceArchive = pickExistingArchive([
    sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoWasmTargetId / "release" / RustCryptoCargoArchiveName,
    sourceRoot / "rustcrypto-ffi" / "target" / RustCryptoWasmTargetId / "debug" / RustCryptoCargoArchiveName,
  ])
  if wasmSourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI wasm archive not found in target/wasm32-unknown-unknown/release or target/wasm32-unknown-unknown/debug.")
    quit(QuitFailure)

  syncArchive(linuxSourceArchive, resolvedPackageRoot, version, RustCryptoTargetId, RustCryptoArchiveName)
  syncArchive(wasmSourceArchive, resolvedPackageRoot, version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
