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

for dep in ["Fylgia-Utils", "SIMD-Nexus", "Tyr-Crypto", "Eir-CompressionAndECC",
            "Bifrost-ExchangeProtocols"]:
  let depRoot = resolveRepoRoot(dep)
  addPathIfExists(depRoot)
  addPathIfExists(joinPath(depRoot, "src"))
  addPathIfExists(joinPath(depRoot, "meta"))
  addPathIfExists(joinPath(depRoot, "tools", "meta"))

## This repository's own pragma module, named for the repository so no
## other repo on the Nim path can capture it.

## Shared pragma module: one file for the whole workspace, so there is no
## per-repository copy to drift or to collide on the Nim path.
if dirExists(thisDir() & "/../Rune-Pragmas/meta"):
  switch("path", thisDir() & "/../Rune-Pragmas/meta")
if dirExists(thisDir() & "/submodules/Rune-Pragmas/meta"):
  switch("path", thisDir() & "/submodules/Rune-Pragmas/meta")
