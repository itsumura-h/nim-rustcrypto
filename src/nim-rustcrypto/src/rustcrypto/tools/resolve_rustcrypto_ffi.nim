import std/[os, osproc, strutils]

import ./rustcrypto_ffi_paths

proc normalizeTarget(targetArg: string): tuple[targetId, archiveName: string] =
  case targetArg.strip.toLowerAscii
  of "", "linux", "linux-x86_64":
    (RustCryptoTargetId, RustCryptoArchiveName)
  of "wasm", "wasm32", "wasm32-unknown-unknown":
    (RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
  else:
    ("", "")

proc firstTargetArg(): string =
  for idx in 1 .. paramCount():
    let arg = paramStr(idx).strip
    if arg.len > 0 and arg != "--":
      return arg
  ""

proc resolveArchivePath(packageRoot: string; version: string; targetArg: string): string =
  let (targetId, archiveName) = normalizeTarget(targetArg)
  if targetId.len == 0:
    stderr.writeLine(
      "unsupported rustcrypto FFI target '" & targetArg & "'. " &
      "Use linux, linux-x86_64, wasm, wasm32, or wasm32-unknown-unknown.",
    )
    return ""

  let modulePath = moduleVendorArchivePath(packageRoot, targetId, archiveName)
  if fileExists(modulePath):
    return modulePath

  let cachePath = cacheArchivePath(version, targetId, archiveName)
  if fileExists(cachePath):
    return cachePath

  when defined(linux) and defined(amd64):
    let fetchTool = currentSourcePath.parentDir / "fetch_rustcrypto_ffi.nim"
    let fetchResult = execCmdEx(
      "nim r --hints:off --warnings:off " & quoteShell(fetchTool) & " -- " & quoteShell(packageRoot),
      workingDir = packageRoot,
      options = {poUsePath, poStdErrToStdOut},
    )
    discard fetchResult
    if fileExists(modulePath):
      return modulePath
    if fileExists(cachePath):
      return cachePath

  return ""

proc missingArchiveHint(targetId: string): string =
  if targetId == RustCryptoWasmTargetId:
    "Run `nimble fetchRustFfi` from `/application/src/nim-rustcrypto`, " &
    "or copy the wasm32-unknown-unknown Release asset into vendor/cache before compiling."
  else:
    "Run `nimble fetchRustFfi` or `nimble buildRustFfiLocal` from `/application/src/nim-rustcrypto`."

let resolvedPackageRoot = packageRoot(currentSourcePath)
let version = versionFromNimble(resolvedPackageRoot)
let rawTargetArg = firstTargetArg()
let targetArg = if rawTargetArg.len > 0: rawTargetArg else: "linux-x86_64"
let resolvedArchivePath = resolveArchivePath(resolvedPackageRoot, version, targetArg)

if resolvedArchivePath.len > 0:
  echo resolvedArchivePath
else:
  let (targetId, _) = normalizeTarget(targetArg)
  if targetId.len == 0:
    quit(QuitFailure)

  stderr.writeLine(
    "rustcrypto FFI static archive for target '" & targetId & "' was not found. " &
    missingArchiveHint(targetId),
  )
  quit(QuitFailure)
