import std/[os, strutils]

import ./rustcrypto_ffi_paths

let packageRoot = packageRoot(currentSourcePath)
let version = versionFromNimble(packageRoot)
let vendorPath = vendorArchivePath(packageRoot)
let cachePath = cacheArchivePath(version)

when defined(linux) and defined(amd64):
  if fileExists(vendorPath):
    echo vendorPath
  elif fileExists(cachePath):
    echo cachePath
  else:
    let sourceRoot = packageRoot.parentDir / "rustcrypto-ffi"
    let localRelease = sourceRoot / "target" / "release" / RustCryptoArchiveName
    let localDebug = sourceRoot / "target" / "debug" / RustCryptoArchiveName
    if fileExists(localRelease):
      echo localRelease
    elif fileExists(localDebug):
      echo localDebug
    else:
      echo ""
else:
  echo ""
