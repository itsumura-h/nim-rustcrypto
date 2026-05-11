import std/[os, osproc, strutils]

import ./rustcrypto_ffi_paths

when not defined(linux) or not defined(amd64):
  {.error: "rustcrypto FFI download currently supports only Linux x86_64.".}
else:
  const
    RustCryptoWasmTargetId = "wasm32-unknown-unknown"
    RustCryptoWasmArchiveName = "librust_crypto_ffi-wasm32-unknown-unknown.a"

  proc runCommand(command: string; workingDir = ""): tuple[success: bool; output: string] =
    let commandResult = execCmdEx(
      command,
      workingDir = workingDir,
      options = {poUsePath, poStdErrToStdOut},
    )
    if commandResult.output.len > 0:
      stdout.write(commandResult.output)
    (commandResult.exitCode == 0, commandResult.output)

  proc downloadFile(url: string; destination: string): bool =
    runCommand("curl -fsSL -o " & quoteShell(destination) & " " & quoteShell(url)).success

  proc checksumFile(workingDir: string; checksumFileName: string): bool =
    runCommand("sha256sum -c " & quoteShell(checksumFileName), workingDir).success

  proc extractArchive(archivePath: string; destinationDir: string): bool =
    createDir(destinationDir)
    runCommand(
      "tar -xzf " & quoteShell(archivePath) & " --strip-components=1",
      destinationDir,
    ).success

  proc copyArchive(sourcePath: string; destinationPath: string): bool =
    createDir(destinationPath.parentDir)
    copyFile(sourcePath, destinationPath)
    true

  proc createWorkRoot(): string =
    let tempDirResult = runCommand("mktemp -d " & quoteShell(getTempDir() / "rustcrypto-ffi.XXXXXX"))
    if not tempDirResult.success:
      return ""
    tempDirResult.output.strip

  proc moduleArchivesExist(packageRoot: string): bool =
    let linuxArchive = moduleVendorArchivePath(packageRoot)
    let wasmArchive = moduleVendorArchivePath(
      packageRoot,
      RustCryptoWasmTargetId,
      RustCryptoWasmArchiveName,
    )
    fileExists(linuxArchive) and fileExists(wasmArchive)

  proc cacheArchivesExist(version: string): bool =
    let linuxArchive = cacheArchivePath(version)
    let wasmArchive = cacheArchivePath(version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
    fileExists(linuxArchive) and fileExists(wasmArchive)

  proc copyCacheToModule(packageRoot: string; version: string) =
    let linuxModuleArchive = moduleVendorArchivePath(packageRoot)
    let wasmModuleArchive = moduleVendorArchivePath(
      packageRoot,
      RustCryptoWasmTargetId,
      RustCryptoWasmArchiveName,
    )
    let linuxCacheArchive = cacheArchivePath(version)
    let wasmCacheArchive = cacheArchivePath(version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)
    createDir(linuxModuleArchive.parentDir)
    createDir(wasmModuleArchive.parentDir)
    copyFile(linuxCacheArchive, linuxModuleArchive)
    copyFile(wasmCacheArchive, wasmModuleArchive)

  proc tryDownloadReleaseArchives(
      packageRoot: string;
      version: string;
      repositorySlugValue: string;
      workRoot: string,
  ): bool =
    let moduleRootPath = moduleRoot(packageRoot)
    let vendorRoot = moduleRootPath / "vendor" / "rustcrypto-ffi"
    let releaseRoot = workRoot / "release"
    createDir(releaseRoot)

    let linuxChecksumFileName = releaseChecksumFileName(version, RustCryptoTargetId)
    let wasmChecksumFileName = releaseChecksumFileName(version, RustCryptoWasmTargetId)

    let linuxChecksumPath = releaseRoot / linuxChecksumFileName
    let wasmChecksumPath = releaseRoot / wasmChecksumFileName
    let linuxArchivePath = releaseRoot / releaseArchiveFileName(version, RustCryptoTargetId)
    let wasmArchivePath = releaseRoot / releaseArchiveFileName(version, RustCryptoWasmTargetId)

    if not downloadFile(releaseArchiveUrl(repositorySlugValue, version, RustCryptoTargetId), linuxArchivePath):
      return false
    if not downloadFile(releaseChecksumUrl(repositorySlugValue, version, RustCryptoTargetId), linuxChecksumPath):
      return false
    if not downloadFile(releaseArchiveUrl(repositorySlugValue, version, RustCryptoWasmTargetId), wasmArchivePath):
      return false
    if not downloadFile(releaseChecksumUrl(repositorySlugValue, version, RustCryptoWasmTargetId), wasmChecksumPath):
      return false

    if not checksumFile(releaseRoot, linuxChecksumFileName):
      return false
    if not checksumFile(releaseRoot, wasmChecksumFileName):
      return false

    if not extractArchive(linuxArchivePath, vendorRoot):
      return false
    if not extractArchive(wasmArchivePath, vendorRoot):
      return false

    let linuxModuleArchive = moduleVendorArchivePath(packageRoot)
    let wasmModuleArchive = moduleVendorArchivePath(
      packageRoot,
      RustCryptoWasmTargetId,
      RustCryptoWasmArchiveName,
    )
    let linuxCacheArchive = cacheArchivePath(version)
    let wasmCacheArchive = cacheArchivePath(version, RustCryptoWasmTargetId, RustCryptoWasmArchiveName)

    if not copyArchive(linuxModuleArchive, linuxCacheArchive):
      return false
    if not copyArchive(wasmModuleArchive, wasmCacheArchive):
      return false

    stdout.writeLine(linuxModuleArchive)
    true

  proc tryBuildLocalArchive(
      packageRoot: string;
      version: string;
      repoSlug: string;
      workRoot: string,
  ): bool =
    let sourceCloneDir = workRoot / "source"
    let sourceRepoUrl = "https://github.com/" & repoSlug & ".git"
    if not runCommand("git clone --depth 1 " & quoteShell(sourceRepoUrl) & " " & quoteShell(sourceCloneDir)).success:
      return false

    let sourceRoot = sourceCloneDir / "src" / "rustcrypto-ffi"
    if not runCommand("cargo build --release --lib", sourceRoot).success:
      return false

    let builtArchive = sourceRoot / "target" / "release" / RustCryptoCargoArchiveName
    if not fileExists(builtArchive):
      stderr.writeLine("rustcrypto FFI archive was not built at " & builtArchive)
      return false

    let linuxModuleArchive = moduleVendorArchivePath(packageRoot)
    let linuxCacheArchive = cacheArchivePath(version)
    if not copyArchive(builtArchive, linuxModuleArchive):
      return false
    if not copyArchive(builtArchive, linuxCacheArchive):
      return false

    stdout.writeLine(linuxModuleArchive)
    true

  proc main() =
    let rootArg = if paramCount() >= 1: paramStr(1).strip else: ""
    let resolvedPackageRoot = if rootArg.len > 0: rootArg else: packageRoot(currentSourcePath)
    if resolvedPackageRoot.len == 0:
      stderr.writeLine("failed to locate rustcrypto.nimble from " & currentSourcePath)
      quit(QuitFailure)

    let version = versionFromNimble(resolvedPackageRoot)
    let repoSlug = repositorySlug(resolvedPackageRoot)
    let workRoot = createWorkRoot()
    if workRoot.len == 0:
      quit(QuitFailure)
    defer:
      discard runCommand("rm -rf " & quoteShell(workRoot))

    if moduleArchivesExist(resolvedPackageRoot):
      stdout.writeLine(moduleVendorArchivePath(resolvedPackageRoot))
      quit(QuitSuccess)

    if cacheArchivesExist(version):
      copyCacheToModule(resolvedPackageRoot, version)
      stdout.writeLine(moduleVendorArchivePath(resolvedPackageRoot))
      quit(QuitSuccess)

    if tryDownloadReleaseArchives(resolvedPackageRoot, version, repoSlug, workRoot):
      quit(QuitSuccess)

    if tryBuildLocalArchive(resolvedPackageRoot, version, repoSlug, workRoot):
      quit(QuitSuccess)

    quit(QuitFailure)

  main()
