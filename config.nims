import std/[os, strutils]

const
  repoRoot = thisDir()

proc normPath(p: string): string =
  result = p.replace('\\', '/')

proc resolveRepoRoot(name: string): string =
  ## name: declared direct dependency resolved from the pinned submodule only.
  result = joinPath(repoRoot, "submodules", name)
  if not dirExists(result):
    result = ""

proc addPathIfExists(p: string) =
  if p.len > 0 and dirExists(p):
    switch("path", normPath(p))

switch("path", joinPath(repoRoot, "src"))
switch("experimental", "dotOperators")
addPathIfExists(joinPath(repoRoot, "src", "protocols"))
addPathIfExists(joinPath(repoRoot, "src", "client"))
addPathIfExists(joinPath(repoRoot, "src", "server"))
addPathIfExists(joinPath(repoRoot, "submodules", "Otter-RepoEvaluation", "src"))
when not defined(geistAndroidBuild):
  switch("define", "hasLibsodium")

var
  depRoot: string = ""
for dep in ["Fylgia-Utils", "SIMD-Nexus", "Tyr-Crypto", "Eir-CompressionAndECC",
            "Bifrost-ExchangeProtocols"]:
  depRoot = resolveRepoRoot(dep)
  addPathIfExists(depRoot)
  addPathIfExists(joinPath(depRoot, "src"))
  addPathIfExists(joinPath(depRoot, "meta"))
  addPathIfExists(joinPath(depRoot, "tools", "meta"))

## Shared pragma module: one file for the whole workspace, so there is no
## per-repository copy to drift or to collide on the Nim path. The pinned
## submodule is added LAST, because Nim takes the last matching `--path`
## and a fresh clone must build from what this repository pins rather than
## from whatever happens to sit beside it on this machine.
if dirExists(thisDir() & "/../Rune-Pragmas/meta"):
  switch("path", thisDir() & "/../Rune-Pragmas/meta")
addPathIfExists(joinPath(repoRoot, "submodules", "Rune-Pragmas", "meta"))
