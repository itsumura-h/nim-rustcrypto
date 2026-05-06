import std/[os, osproc]

import ./rustcrypto_ffi_paths

when not defined(linux) or not defined(amd64):
  {.error: "rustcrypto FFI download currently supports only Linux x86_64.".}
else:
  let root = packageRoot(currentSourcePath)
  if root.len == 0:
    stderr.writeLine("failed to locate rustcrypto.nimble from " & currentSourcePath)
    quit(QuitFailure)

  let fetchScript = currentSourcePath.parentDir / "fetch_rustcrypto_ffi.sh"
  let fetchResult = execCmdEx(
    "sh " & quoteShell(fetchScript) & " " & quoteShell(root),
    workingDir = root,
    options = {poUsePath, poStdErrToStdOut},
  )

  if fetchResult.output.len > 0:
    stdout.write(fetchResult.output)

  quit(fetchResult.exitCode)
