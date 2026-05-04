import std/[os, strutils]

proc firstNonEmptyLine(s: string): string =
  for line in s.splitLines:
    let t = line.strip
    if t.len > 0:
      return t
  return ""

proc applicationRootFromMain(mainSourcePath: string): string =
  parentDir(parentDir(parentDir(mainSourcePath)))

let nimbleRustcrypto = firstNonEmptyLine(staticExec("nimble path rustcrypto 2>/dev/null"))

switch("noNimblePath")

if nimbleRustcrypto.len > 0:
  switch("path", nimbleRustcrypto)
else:
  let anchor =
    if projectPath().len > 0:
      projectPath()
    else:
      currentSourcePath
  let repoRustcrypto =
    applicationRootFromMain(anchor) / "src" / "nim-rustcrypto" / "src"
  if dirExists(repoRustcrypto):
    switch("path", repoRustcrypto)

let main = projectPath()
if main.len > 0:
  switch("path", parentDir(main))
# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
