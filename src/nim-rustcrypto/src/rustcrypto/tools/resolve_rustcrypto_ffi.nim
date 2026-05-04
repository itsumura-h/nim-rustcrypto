import std/[os, osproc, strutils]

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
    let fetchScript = currentSourcePath.parentDir / "fetch_rustcrypto_ffi.nim"
    let fetchResult = execCmdEx(
      "nim r --hints:off --warnings:off " & quoteShell(fetchScript),
      workingDir = packageRoot,
      options = {poUsePath, poStdErrToStdOut},
    )
    if fetchResult.exitCode == 0 and fileExists(vendorPath):
      echo vendorPath
    elif fetchResult.exitCode == 0 and fileExists(cachePath):
      echo cachePath
    else:
      echo ""
else:
  echo ""
