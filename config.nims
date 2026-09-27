## ---------------------------------------------------------------------------
## config.nims <- what every `nim` call in this repo is given
## ---------------------------------------------------------------------------
##
##   what                          from where
##   ----------------------------  ------------------------------------------
##   Geist's own modules           src/
##   Geist's dependencies          submodules/<name>/src      (pinned ONLY)
##   runePragmas                   ../Rune-Pragmas, else the submodule
##   var_invariants                ../Var-Invariants, else the submodule
##   compiler flags (mm, threads)  configs/default.toml [nim] and [define],
##                                 then configs/<preset>.toml over it
##
## Two kinds of dependency, two rules:
##
##   code Geist RUNS      Fylgia, SIMD-Nexus, Tyr, Eir, Bifrost, nimsimd,
##                        Otter. Taken from the pinned submodule and nowhere
##                        else, so a build here is the build a fresh clone
##                        gets -- not one that silently picked up whatever a
##                        sibling folder holds today.
##   shared TOOLING       Rune-Pragmas, Var-Invariants, Nimble-Tasks. The
##                        sibling clone wins, so an edit there reaches every
##                        repo at once; the submodule is the fallback.
##
## Exactly one of sibling/submodule is put on the path for each tool: Nim
## takes the LAST matching --path, so adding both would silently reverse
## the preference.

import std/[os, strutils]

const
  repoRoot: string = thisDir()
  pinnedDeps: array[7, string] = ["Fylgia-Utils", "SIMD-Nexus", "Tyr-Crypto",
    "Eir-CompressionAndECC", "Bifrost-ExchangeProtocols", "nimsimd",
    "Otter-RepoEvaluation"]

proc addPathIfExists(p: string) =
  ## p: a folder; put on the Nim path when it is there.
  if dirExists(p):
    switch("path", p.replace('\\', '/'))

proc addSharedTool(name, sub: string) =
  ## name/sub: a shared tooling repo and the folder inside it to put on the
  ## path. The sibling clone wins; the pinned submodule is the fallback.
  if dirExists(repoRoot / ".." / name / sub):
    addPathIfExists(repoRoot / ".." / name / sub)
  elif dirExists(repoRoot / "submodules" / name / sub):
    addPathIfExists(repoRoot / "submodules" / name / sub)
  else:
    echo "config.nims: cannot find " & name & ". Run `git submodule " &
      "update --init` (one level, NOT --recursive), or clone " & name &
      " next to this repository."

addPathIfExists(repoRoot / "src")
switch("experimental", "dotOperators")
for dep in pinnedDeps:
  addPathIfExists(repoRoot / "submodules" / dep / "src")

addSharedTool("Rune-Pragmas", "meta")
addSharedTool("Var-Invariants", "src")

## Build presets: configs/default.toml always, plus configs/<name>.toml when
## the build says -d:preset=<name>. The reader is shared by every repo.
when fileExists(thisDir() & "/../Nimble-Tasks/src/preset.nims"):
  include "../Nimble-Tasks/src/preset.nims"
elif fileExists(thisDir() & "/submodules/Nimble-Tasks/src/preset.nims"):
  include "submodules/Nimble-Tasks/src/preset.nims"
else:
  proc applyPreset() = echo "config.nims: Nimble-Tasks/src/preset.nims " &
    "not found; configs/*.toml are ignored. Update the submodule."
applyPreset()
