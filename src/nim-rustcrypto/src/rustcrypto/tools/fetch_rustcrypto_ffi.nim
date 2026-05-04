import std/[os, osproc, strutils]

import ./rustcrypto_ffi_paths

when not defined(linux) or not defined(amd64):
  {.error: "rustcrypto FFI fetch currently supports only Linux x86_64.".}
else:
  proc runChecked(command: string; workingDir = "") =
    let result =
      if workingDir.len > 0:
        execCmdEx(command, workingDir = workingDir, options = {poUsePath, poStdErrToStdOut})
      else:
        execCmdEx(command, options = {poUsePath, poStdErrToStdOut})
    if result.exitCode != 0:
      raise newException(OSError, command & "\n" & result.output)

  let packageRoot = packageRoot(currentSourcePath)
  let version = versionFromNimble(packageRoot)
  let repoSlug = repositorySlug(packageRoot)
  let baseUrl = releaseBaseUrl(repoSlug, version)
  let archiveName = "rustcrypto-ffi-v" & version & "-" & RustCryptoTargetId & ".tar.gz"
  let checksumName = archiveName & ".sha256"
  let archiveUrl = baseUrl & "/" & archiveName
  let checksumUrl = baseUrl & "/" & checksumName
  let destinationArchive = resolveWritableArchivePath(packageRoot, version)
  let destinationDir = destinationArchive.parentDir
  let moduleRoot =
    if dirExists(packageRoot / "src" / "rustcrypto"):
      packageRoot / "src" / "rustcrypto"
    else:
      packageRoot / "rustcrypto"
  let moduleDestinationArchive = moduleRoot / "vendor" / "rustcrypto-ffi" / RustCryptoTargetId / RustCryptoArchiveName
  let moduleDestinationDir = moduleDestinationArchive.parentDir

  if fileExists(destinationArchive):
    echo destinationArchive
    quit(QuitSuccess)

  let tempRoot = getTempDir() / "rustcrypto-ffi" / version / RustCryptoTargetId
  if dirExists(tempRoot):
    removeDir(tempRoot)
  createDir(tempRoot)

  let archivePath = tempRoot / archiveName
  let checksumPath = tempRoot / checksumName

  runChecked("curl -fsSL -o " & quoteShell(archivePath) & " " & quoteShell(archiveUrl))
  runChecked("curl -fsSL -o " & quoteShell(checksumPath) & " " & quoteShell(checksumUrl))
  runChecked("sha256sum -c " & quoteShell(checksumName), tempRoot)

  createDir(destinationDir)
  runChecked(
    "tar -xzf " & quoteShell(archivePath) & " -C " & quoteShell(destinationDir) &
      " --strip-components=1"
  )

  createDir(moduleDestinationDir)
  copyFile(destinationArchive, moduleDestinationArchive)

  echo destinationArchive
