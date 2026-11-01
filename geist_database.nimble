## ---------------------------------------------------------------------------
## geist_database.nimble <- only what is special to Geist
## ---------------------------------------------------------------------------
##
## Geist is the storage half: rows, files, keys, backups, one CLI. Talking to
## other machines (sync, relays, daemons, the device monitor) is Nebel's,
## which imports this library. See that repository's .nimble file.
##
## Every generic task -- test, runExamples, runBenchmarks, runCli/buildCli,
## autopush, switch, applyNightly, updateSubmodules, clean, ... -- comes from
## Nimble-Tasks, included at the bottom. `nimble sharedTasks` lists them.
## What stays here:
##
##   task               what it does
##   -----------------  ------------------------------------------------------
##   buildAll           the Geist CLI, for release (replaces the shared one)
##   checkAll           compile-check every public module
##   checkModular       the storage half builds with NO network stack
##   testCore ...       one area of the test suite, for a quick loop
##   bench<Group>       one benchmark group
##   demoCli            a scratch database driven through the CLI
##   runStatistics      Otter's numbers, recorded under evaluation/statistics
##   androidLib/Test    the Android keystore companion
##
## Compiler flags (--mm:orc, --threads:on, -d:hasLibsodium) are NOT written
## here. They live in configs/default.toml and config.nims applies them to
## every `nim` call, so a task cannot drift from the others.

import std/[os, strutils]

## Name, version, description, license and author live in ONE place:
## [project] in configs/default.toml. nix/default.nix reads the same table.
when fileExists(thisDir() & "/../Nimble-Tasks/src/preset.nims"):
  include "../Nimble-Tasks/src/preset.nims"
elif fileExists(thisDir() & "/submodules/Nimble-Tasks/src/preset.nims"):
  include "submodules/Nimble-Tasks/src/preset.nims"
else:
  {.error: "Nimble-Tasks not found: git submodule update --init submodules/Nimble-Tasks".}

version       = projectValue("version")
author        = projectValue("author")
description   = projectValue("description")
license       = projectValue("license")
srcDir        = "src"

## nimsimd is also pinned in submodules/nimsimd and put on the path by
## config.nims, so a fresh clone builds without `nimble install`.
requires "nim >= 2.0.0", "nimsimd >= 1.3.2"

## NOTE: no UI and no network dependencies belong here. Geist is a headless
## library and one CLI. Bifrost (the transport) is Nebel's.

const
  ownTasks: array[2, string] = ["buildAll", "runStatistics"]
  frozenSubmodules: array[1, string] = ["submodules/nimsimd"]
    ## Third-party, pinned at its 1.3.2 release tag -- the same commit
    ## nix/default.nix fetches. `updateSubmodules` must not move it to
    ## whatever its master branch holds today.
  cliEntry: string = "src/clients/geist_cli.nim"
  benchSource: string = "evaluation/benchmarks/bench_geist.nim"
  benchProgram: string = "build/evaluation/bench_geist"

## Shared tasks: the sibling clone wins, so an edit there reaches this repo
## at once; the submodule is what a fresh clone elsewhere falls back on.
## Included HERE, after the settings above and before Geist's own tasks,
## so the helpers below can use its `presetFlag` and `exeName`.
when fileExists(thisDir() & "/../Nimble-Tasks/src/nimbleTasks.nims"):
  include "../Nimble-Tasks/src/nimbleTasks.nims"
elif fileExists(thisDir() & "/submodules/Nimble-Tasks/src/nimbleTasks.nims"):
  include "submodules/Nimble-Tasks/src/nimbleTasks.nims"
else:
  {.error: "Nimble-Tasks not found: git submodule update --init submodules/Nimble-Tasks".}

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

proc buildProgram(entry, name: string) =
  ## entry/name: one Geist program, built for release as build/<name>.
  mkDir("build")
  exec "nim c -d:release" & presetFlag() & " --hints:off -o:build/" &
    exeName(name) & " " & entry
  echo "Built build/" & exeName(name)

proc runTestFiles(A: openArray[string]) =
  ## A: test file names below evaluation/tests, run in order.
  ## -d:release as in Nimble-Tasks' `test`: checks and asserts stay on, and
  ## Argon2id runs ~19x faster than in a debug build.
  mkDir("build/evaluation")
  for f in A:
    exec "nim c -r -d:release --hints:off -o:build/evaluation/" & f & " evaluation/tests/" &
      f & ".nim"

proc runBench(group: string) =
  ## group: one benchmark group name, or "" for all of them.
  mkDir("build/evaluation")
  exec "nim c -d:release --hints:off -o:" & benchProgram & " " & benchSource
  exec benchProgram & (if group.len > 0: " " & group else: "")

# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------
#
#   program        task                entry
#   -------------  ------------------  --------------------------------
#   geist          buildCli (shared)   src/clients/geist_cli.nim

task buildAll, "Build the Geist CLI for release":
  buildProgram(cliEntry, "geist_database_cli")

# ---------------------------------------------------------------------
# Compile checks
# ---------------------------------------------------------------------

task checkAll, "Compile-check every public module":
  for f in listFiles("src/geist") & listFiles("src/geist/crypto") &
      @["src/geist.nim", cliEntry]:
    if f.endsWith(".nim"):
      exec "nim c --compileOnly --hints:off " & f

task checkModular, "Prove the storage half builds with no network stack":
  ## Compiles a disk-only program with Bifrost REMOVED from the search
  ## path. Passing means `import geist` genuinely does not depend on the
  ## exchange stack; failing means something in the storage half started
  ## importing the network half, which no amount of documentation would
  ## have prevented.
  ##
  ## The project config is skipped precisely because it adds every
  ## submodule path, including the one under test -- which is also why the
  ## flags config.nims would give are written out here.
  var
    paths: string = ""
  for p in ["submodules/Fylgia-Utils/src", "submodules/Tyr-Crypto/src",
            "submodules/Eir-CompressionAndECC/src", "submodules/SIMD-Nexus/src",
            "submodules/Rune-Pragmas/meta", "submodules/Var-Invariants/src",
            "submodules/nimsimd/src"]:
    if dirExists(p):
      paths = paths & " --path:" & p
  exec "nim c -r --skipProjCfg --skipParentCfg --mm:orc --threads:on " &
    "--hints:off --warnings:off -d:hasLibsodium --path:src" & paths &
    " --nimcache:build/nimcache-modular -o:build/storage-only " &
    "evaluation/tests/modular/storage_only.nim"

# ---------------------------------------------------------------------
# One area of the test suite (`nimble test` runs all of them)
# ---------------------------------------------------------------------

task testCore, "Run the mapper and format tests only":
  runTestFiles(["test_mapper_roundtrip", "test_format_partial"])

task testCrypto, "Run the crypto, key lifecycle, keyring and backup tests":
  runTestFiles(["test_crypto_batch", "test_keys_backup", "test_keyrings",
    "test_vault_bridge", "test_keyfolder"])

task testApi, "Run the session and settings tests":
  runTestFiles(["test_session_api", "test_settings", "test_presets"])

task testDurability, "Run the generation-swap, lease and restore tests":
  runTestFiles(["test_durability_lease", "test_sidecar_sweep"])

task testApiSurface, "Run the collection, seek, column storage and table file tests":
  runTestFiles(["test_collection_seek", "test_hash_agility",
    "test_column_storage", "test_tabletext"])

task testBlind, "Run the blind store tests (docs/BLIND_STORE.md) and the signed-note tests it builds on":
  runTestFiles(["test_blind", "test_trust"])

# ---------------------------------------------------------------------
# One benchmark group (`nimble runBenchmarks` runs all of them)
# ---------------------------------------------------------------------

task benchCrypto, "Benchmark hash families, digest widths and MAC combiners":
  runBench("crypto")

task benchIo, "Benchmark write throughput, point reads and column scans":
  runBench("io")

task benchColumns, "Benchmark column kinds and collapsing":
  runBench("packed")

task benchRefs, "Benchmark the reference cell encoding":
  runBench("refs")

# ---------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------

task demoCli, "Create a scratch database and exercise the CLI":
  var
    root: string = "build/demo"
    geist: string = "build/geist_database_cli --path " & root
  buildProgram(cliEntry, "geist_database_cli")
  rmDir(root)
  exec geist & " init --schema \"id:int,title:text,body:text\" --type Note"
  exec geist & " put id=1 title=hello body=world"
  exec geist & " put id=2 title=second body=row"
  exec geist & " put id=3 title=third body=gone"
  exec geist & " set @0 title=corrected"
  exec geist & " delete @2"
  exec geist & " list"
  exec geist & " compact"
  exec geist & " list"
  exec geist & " inspect"

# ---------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------

task runStatistics, "Measure the repository with Otter and record the numbers":
  ## Writes evaluation/statistics/otter-stats.txt and otter-gate.txt, so the
  ## shape of the tree is a tracked file and a change to it shows up in a
  ## diff, rather than a number somebody remembers from last month.
  ##
  ## Otter walks a FOLDER, and this folder holds things git does not track
  ## (build output, local databases, reference copies). Measured together
  ## they swamp every count. So the task copies the TRACKED files, as they
  ## are on disk right now, into build/measure, links the pinned submodules
  ## beside them, and measures THAT.
  var
    otter: string = "submodules/Otter-RepoEvaluation/tools/agent_hooks/" &
      "otter-build.sh"
    at: string = "build/measure"
    bin: string = ""
    deps: seq[string] = @["Fylgia-Utils", "SIMD-Nexus", "Tyr-Crypto",
      "Eir-CompressionAndECC", "Rune-Pragmas",
      "Otter-RepoEvaluation", "Nimble-Tasks", "Var-Invariants", "nimsimd"]
    here: string = getCurrentDir()
  if not fileExists(otter):
    echo "Otter is not checked out: git submodule update --init " &
      "submodules/Otter-RepoEvaluation"
    quit(1)
  rmDir(at)
  mkDir(at)
  exec "sh -c 'git ls-files -z | tar --null -T - -cf - | tar -x -C " &
    at & "'"
  mkDir(at & "/submodules")
  for d in deps:
    exec "sh -c 'ln -sfn " & here & "/submodules/" & d & " " & at &
      "/submodules/" & d & "'"
  ## Otter refuses a folder that is not a git workspace, and the copy is
  ## not one until it is told to be.
  exec "sh -c 'cd " & at & " && git init -q && git add -A >/dev/null && " &
    "git -c user.email=stats@local -c user.name=stats commit -qm measured'"
  ## `otter-build.sh` prints the path of a ready program on stdout and its
  ## build chatter on stderr, so the path is the last stdout line.
  bin = gorge("./" & otter & " 2>/dev/null | tail -1").strip()
  if bin.len == 0 or not fileExists(bin):
    echo "Otter would not build; see ~/.cache/otter-agent-hooks/build.log"
    quit(1)
  mkDir("evaluation/statistics")
  exec "sh -c '\"" & bin & "\" stats \"" & at & "\" | sed -e \"s#" &
    here & "/" & at & "#.#\" -e \"s#^Root: " & at & "#Root: .#\" > " &
    "evaluation/statistics/otter-stats.txt'"
  ## The gate exits 1 when it has something to report, which is the normal
  ## case and not a task failure, so its status is discarded on purpose.
  exec "sh -c 'OTTER_CACHE=build/otter-cache " &
    "./submodules/Otter-RepoEvaluation/tools/agent_hooks/otter-gate.sh " &
    "--force \"" & at & "\" | sed -e \"s#" & here & "/" & at &
    "/##g\" -e \"s#" & here & "/" & at & "#.#g\" > " &
    "evaluation/statistics/otter-gate.txt; true'"
  exec "cat evaluation/statistics/otter-stats.txt"

# ---------------------------------------------------------------------
# Android
# ---------------------------------------------------------------------
# The companion is a LIBRARY (Kotlin + JNI), not an app, so the shared
# buildAndroid/installAndroid -- which build and install an APK -- do not
# apply. These two drive its own gradle module instead.

task androidLib, "Build the Android keystore companion (Kotlin + JNI)":
  ## Needs the Android SDK; `local.properties` under android/ points at it.
  exec "cd android && gradle :geistkeystore:assembleDebug --console=plain"

task androidTest, "Run the keystore tests on a connected device":
  ## Requires USB debugging AND, on MIUI/HyperOS, Developer options ->
  ## "Install via USB". Without the latter the install is refused with
  ## INSTALL_FAILED_USER_RESTRICTED and nothing runs; that toggle cannot
  ## be set over adb. See docs/keystore.md.
  exec "cd android && gradle :geistkeystore:connectedDebugAndroidTest " &
    "--console=plain"
