import std/[os, osproc]

import ./rustcrypto_ffi_paths

let resolvedPackageRoot = packageRoot(currentSourcePath)
let version = versionFromNimble(resolvedPackageRoot)
let vendorPath = vendorArchivePath(resolvedPackageRoot)
let cachePath = cacheArchivePath(version)

when defined(linux) and defined(amd64):
  if fileExists(vendorPath):
    echo vendorPath
  elif fileExists(cachePath):
    echo cachePath
  else:
    let fetchTool = currentSourcePath.parentDir / "fetch_rustcrypto_ffi.nim"
    let fetchResult = execCmdEx(
      "nim r --hints:off --warnings:off " & quoteShell(fetchTool) & " -- " & quoteShell(resolvedPackageRoot),
      workingDir = resolvedPackageRoot,
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
