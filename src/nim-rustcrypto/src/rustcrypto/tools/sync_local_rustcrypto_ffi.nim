import std/[os, strutils]

import ./rustcrypto_ffi_paths

when not defined(linux) or not defined(amd64):
  {.error: "rustcrypto FFI local sync currently supports only Linux x86_64.".}
else:
  let packageRoot = packageRoot(currentSourcePath)
  let version = versionFromNimble(packageRoot)
  let sourceRoot = packageRoot.parentDir
  let sourceRelease = sourceRoot / "rustcrypto-ffi" / "target" / "release" / RustCryptoArchiveName
  let sourceDebug = sourceRoot / "rustcrypto-ffi" / "target" / "debug" / RustCryptoArchiveName

  var sourceArchive = ""
  if fileExists(sourceRelease):
    sourceArchive = sourceRelease
  elif fileExists(sourceDebug):
    sourceArchive = sourceDebug

  if sourceArchive.len == 0:
    stderr.writeLine("rustcrypto FFI archive not found in target/release or target/debug.")
    quit(QuitFailure)

  let vendorPath = vendorArchivePath(packageRoot)
  let moduleRoot =
    if dirExists(packageRoot / "src" / "rustcrypto"):
      packageRoot / "src" / "rustcrypto"
    else:
      packageRoot / "rustcrypto"
  let moduleVendorPath = moduleRoot / "vendor" / "rustcrypto-ffi" / RustCryptoTargetId / RustCryptoArchiveName
  let cachePath = cacheArchivePath(version)

  createDir(vendorPath.parentDir)
  copyFile(sourceArchive, vendorPath)

  createDir(moduleVendorPath.parentDir)
  copyFile(sourceArchive, moduleVendorPath)

  createDir(cachePath.parentDir)
  copyFile(sourceArchive, cachePath)

  echo vendorPath
