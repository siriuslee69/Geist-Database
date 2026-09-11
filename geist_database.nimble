import std/[os, strutils]

version       = "2.0.0"
author        = "siriuslee69"
description   = "Geist: a packed-row, cluster-addressed encrypted database"
license       = "Unlicense"
srcDir        = "src"

requires "nim >= 2.0.0"

# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------

task buildCli, "Build the geist command line client":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geist src/clients/geist_cli.nim"

task buildDaemon, "Build the geistd daemon":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geistd src/server/geistd.nim"

task buildRelayd, "Build the geist-relayd message relay":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geist-relayd src/server/geist_relayd.nim"

task buildRelay, "Build the geist-relay client":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geist-relay src/clients/geist_relay.nim"

task buildRouted, "Build the geist-routed request router":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geist-routed src/server/geist_routed.nim"

task buildBins, "Build every binary into build/bin":
  exec "nimble buildCli"
  exec "nimble buildDaemon"
  exec "nimble buildRelayd"
  exec "nimble buildRelay"
  exec "nimble buildRouted"

task buildBench, "Build the Otter-based benchmark binary":
  exec "nim c -d:release --mm:orc --threads:on --hints:off " &
    "-o:build/bin/geist-bench evaluation/benchmarks/geist_bench.nim"

task bench, "Run every benchmark group":
  exec "nimble buildBench"
  exec "build/bin/geist-bench"

task benchCrypto, "Benchmark hash families, digest widths and MAC combiners":
  exec "nimble buildBench"
  exec "build/bin/geist-bench crypto"

task benchIo, "Benchmark write throughput, point reads and column scans":
  exec "nimble buildBench"
  exec "build/bin/geist-bench io"

task benchColumns, "Benchmark column kinds and collapsing":
  exec "nimble buildBench"
  exec "build/bin/geist-bench packed"

task benchRefs, "Benchmark the reference cell encoding":
  exec "nimble buildBench"
  exec "build/bin/geist-bench refs"

task checkModular, "Prove the storage half builds with no network stack":
  ## Compiles a disk-only program with Bifrost REMOVED from the search
  ## path. Passing means `import geist` genuinely does not depend on the
  ## exchange stack; failing means something in the storage half started
  ## importing the network half, which no amount of documentation would
  ## have prevented.
  ##
  ## The project config is skipped precisely because it adds every
  ## submodule path, including the one under test.
  var paths = ""
  for p in ["submodules/Fylgia-Utils/src", "submodules/Tyr-Crypto/src",
            "submodules/Rune-Pragmas/meta", "../Rune-Pragmas/meta",
            "submodules/SIMD-Nexus/src", "submodules/Eir-CompressionAndECC/src",
            "submodules/nimsimd/src"]:
    if dirExists(p):
      paths = paths & " --path:" & p
  exec "nim c -r --skipProjCfg --skipParentCfg --mm:orc --threads:on " &
    "--hints:off --warnings:off -d:hasLibsodium --path:src" & paths &
    " --nimcache:build/nimcache-modular -o:build/storage-only " &
    "evaluation/tests/modular/storage_only.nim"

task checkRelay, "Prove the wire half builds with no database in it":
  ## The mirror of checkModular. That one removes Bifrost from the path
  ## and compiles a disk-only program; this one compiles a relay and then
  ## LOOKS AT WHAT THE COMPILER EMITTED. Passing means no module of the
  ## storage half was reachable from `import geist/wire` -- not that a
  ## header comment says so.
  ##
  ## The check is on the C files rather than on the import statements
  ## because an import three modules deep is exactly the kind that gets
  ## added without anyone noticing.
  var storage = ["geist", "geist@ssession", "geist@sstore", "geist@srow",
    "geist@srowid", "geist@skeys", "geist@sconfig", "geist@sbackup",
    "geist@slease", "geist@ssidecar", "geist@scollection", "geist@sseek",
    "geist@sdurable", "geist@smapper", "geist@sdynamic", "geist@ssettings"]
  var leaked: seq[string] = @[]
  exec "nim c -r --mm:orc --threads:on --hints:off --warnings:off " &
    "--nimcache:build/nimcache-relay -o:build/relay-only " &
    "evaluation/tests/modular/relay_only.nim"
  for f in listFiles("build/nimcache-relay"):
    let name = f.extractFilename()
    if not name.endsWith(".nim.c"):
      continue
    for m in storage:
      if name == "@p" & m & ".nim.c" or name == "@m" & m & ".nim.c":
        leaked.add name
  if leaked.len > 0:
    echo "The relay build pulled in the database: " & leaked.join(", ")
    echo "Something under src/geist/wire.nim now imports the storage half."
    quit(1)
  echo "relay build: no database module compiled"

task checkRouter, "Prove the router forwards without compiling a store":
  ## Same proof as checkRelay, aimed at the router. A daemon that could
  ## open a database would eventually be given one to open, so the fact
  ## that it CANNOT is worth a build failure rather than a comment.
  var storage = ["geist", "geist@ssession", "geist@sstore", "geist@srow",
    "geist@srowid", "geist@skeys", "geist@sconfig", "geist@sbackup",
    "geist@slease", "geist@ssidecar", "geist@scollection", "geist@sseek",
    "geist@sdurable", "geist@smapper", "geist@sdynamic", "geist@ssettings"]
  var leaked: seq[string] = @[]
  exec "nim c --mm:orc --threads:on --hints:off --warnings:off " &
    "--nimcache:build/nimcache-router -o:build/router-only " &
    "src/server/geist_routed.nim"
  for f in listFiles("build/nimcache-router"):
    let name = f.extractFilename()
    if not name.endsWith(".nim.c"):
      continue
    for m in storage:
      if name == "@p" & m & ".nim.c" or name == "@m" & m & ".nim.c":
        leaked.add name
  if leaked.len > 0:
    echo "The router build pulled in the database: " & leaked.join(", ")
    quit(1)
  echo "router build: no database module compiled"

task buildAll, "Build every public module as a compile check":
  for m in ["src/geist.nim", "src/geist/session.nim", "src/geist/transport.nim",
            "src/geist/masks.nim", "src/geist/keys.nim", "src/geist/backup.nim",
            "src/geist/dynamic.nim", "src/geist/identity.nim",
            "src/clients/geist_cli.nim", "src/server/geistd.nim",
            "src/geist/collection.nim", "src/geist/seek.nim",
            "src/geist/answer.nim", "src/geist/need.nim",
            "src/geist/relay.nim", "src/geist/wire.nim",
            "src/geist/show.nim", "src/geist/transpose.nim",
            "src/server/geist_relayd.nim", "src/clients/geist_relay.nim",
            "src/server/geist_routed.nim", "src/geist/address.nim",
            "src/geist/route.nim", "src/geist/link.nim",
            "src/geist/doc.nim", "src/geist/reconcile.nim",
            "src/geist/keystore.nim", "src/geist/layout.nim",
            "src/geist/registry.nim", "src/geist/offer.nim",
            "src/geist/secrets.nim", "src/geist/users.nim",
            "src/geist/network.nim", "src/geist/toml_read.nim",
            "src/geist/transport_settings.nim",
            "src/geist/settings.nim",
            "src/geist/rowid.nim", "src/geist/lease.nim",
            "src/geist/durable.nim",
            "src/geist/crypto/hashing.nim"]:
    exec "nim c --mm:orc --threads:on --compileOnly --hints:off " & m

# ---------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------

task exampleQuickstart, "Run the quickstart example":
  exec "nim c -r --mm:orc --threads:on --hints:off examples/geist_quickstart.nim"

task exampleEncrypted, "Run the encrypted-database example":
  exec "nim c -r --mm:orc --threads:on --hints:off examples/geist_encrypted.nim"

task exampleObserve, "Run the passive-observation example":
  exec "nim c -r --mm:orc --threads:on --hints:off examples/geist_observe.nim"

task exampleFastSearch, "Run the printing and column-copy example":
  exec "nim c -r -d:release --mm:orc --threads:on --hints:off " &
    "examples/geist_fast_search.nim"

task examples, "Run every example in order":
  exec "nimble exampleQuickstart"
  exec "nimble exampleEncrypted"
  exec "nimble exampleObserve"
  exec "nimble exampleFastSearch"

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

task test, "Run the full test suite":
  for f in listFiles("evaluation/tests"):
    if f.endsWith(".nim") and f.extractFilename().startsWith("test_"):
      echo "--- " & f
      exec "nim c -r --mm:orc --threads:on --hints:off --warnings:off " & f

task testCore, "Run the mapper and format tests only":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_mapper_roundtrip.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_format_partial.nim"

task testCrypto, "Run the crypto, key lifecycle and backup tests":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_crypto_batch.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_keys_backup.nim"

task testApi, "Run the session, transport and settings tests":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_session_api.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_masks_transport.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_settings.nim"

task testDurability, "Run the generation-swap, lease and restore tests":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_durability_lease.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_sidecar_sweep.nim"

task testExchange, "Run the live-socket daemon and identity tests":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_daemon_live.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_row_identity.nim"

task testApiSurface, "Run the collection, seek and column storage tests":
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_collection_seek.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_hash_agility.nim"
  exec "nim c -r --mm:orc --threads:on --hints:off evaluation/tests/test_column_storage.nim"

task demoCli, "Create a scratch database and exercise the CLI":
  exec "nimble buildCli"
  let root = "build/demo"
  rmDir(root)
  exec "build/bin/geist --path " & root &
    " init --schema \"id:int,title:text,body:text\" --type Note"
  exec "build/bin/geist --path " & root & " put id=1 title=hello body=world"
  exec "build/bin/geist --path " & root & " put id=2 title=second body=row"
  exec "build/bin/geist --path " & root & " put id=3 title=third body=gone"
  exec "build/bin/geist --path " & root & " set @0 title=corrected"
  exec "build/bin/geist --path " & root & " delete @2"
  exec "build/bin/geist --path " & root & " list"
  exec "build/bin/geist --path " & root & " compact"
  exec "build/bin/geist --path " & root & " list"
  exec "build/bin/geist --path " & root & " inspect"

# ---------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------

task stats, "Measure the repository with Otter and record the numbers":
  ## Writes evaluation/statistics/otter-stats.txt so the shape of the tree
  ## is a tracked file and a change to it shows up in a diff, rather than
  ## a number somebody remembers from last month.
  ##
  ## The measurement is of the TRACKED tree. Untracked leftovers -- the
  ## `.geist-legacy/` reference copy above all -- would otherwise dominate
  ## every count and make the report useless.
  var
    otter: string = "submodules/Otter-RepoEvaluation/tools/agent_hooks/" &
      "otter-build.sh"
  if not fileExists(otter):
    echo "Otter is not checked out: git submodule update --init " &
      "submodules/Otter-RepoEvaluation"
    quit(1)
  mkDir("evaluation/statistics")
  exec "sh -c '\"$(" & otter & ")\" stats . > " &
    "evaluation/statistics/otter-stats.txt'"
  exec "cat evaluation/statistics/otter-stats.txt"

# ---------------------------------------------------------------------
# Git workflow (copied verbatim from Proto-RepoTemplate per conventions)
# ---------------------------------------------------------------------

proc resolveProgressPath(): string =
  var
    ts: seq[string] = @[
      "agents/PROGRESS.md",
      "agents/progress.md"
    ]
  for t in ts:
    if fileExists(t):
      return t
  result = ts[0]

proc resolveWebUiEntryPath(): string =
  var
    ts: seq[string] = @[
      "src/client/frontend/webui/app.nim",
      "src/client/frontend/webui_ui/app.nim"
    ]
  for t in ts:
    if fileExists(t):
      return t
  result = ts[0]

proc resolveGitIndexLockPath(): string =
  result = joinPath(".git", "index.lock")

proc resolveAutopushMessagePath(): string =
  result = joinPath(".git", "autopush-commit-message.txt")

proc resolveCommitMessage(progressPath: string): string =
  var msg: string = ""
  if fileExists(progressPath):
    var content = readFile(progressPath)
    for line in content.splitLines:
      if line.startsWith("Commit Message:"):
        msg = line["Commit Message:".len .. ^1].strip()
        break
  if msg.len == 0:
    msg = "No specific commit message given."
  result = msg

proc captureGit(args: string): string =
  ## args: one git subcommand line; output is returned, failure quits.
  var t = gorgeEx("git " & args)
  if t.exitCode != 0:
    if t.output.len > 0:
      echo t.output
    quit(t.exitCode)
  result = t.output

proc isGeneratedOrLocalArtifact(path: string): bool =
  ## path: one staged repo-relative path checked against local/generated outputs.
  var p = path.replace('\\', '/')
  result = splitPath(p).tail.startsWith(".fuse_hidden") or
    p.startsWith("nimcache") or
    p.startsWith("build/") or p.startsWith("builds/") or
    p.startsWith(".gradle/") or p.startsWith(".kotlin/") or
    p.endsWith(".exe") or p.endsWith(".dll") or p.endsWith(".so") or
    p.endsWith(".dylib") or p.endsWith(".o") or p.endsWith(".obj") or
    p.endsWith(".a") or p.endsWith(".lib") or p.endsWith(".pdb") or
    p == "local.properties" or p == "userconfig.toml" or
    p == "nimble.paths" or p == "nimble.develop" or
    p.startsWith(".iron/")

## ---------------------------------------------------------------------------
## Canonical git workflow tasks <- copy autopush/switch/applynightly verbatim
## into every repo's .nimble file. Repos work on `nightly` day to day;
## `applynightly` promotes the tested state onto `main` by fast-forward.
##
##   autopush     -> stage all, refuse generated/local artifacts, commit
##                   with the message from agents/PROGRESS.md, then push
##   switch       -> toggle the checkout between nightly and main
##   applynightly -> fast-forward main to nightly locally and on origin
## ---------------------------------------------------------------------------

task autopush, "Add, commit, and push after rejecting generated/local artifacts":
  var
    progressPath: string = resolveProgressPath()
    lockPath: string = resolveGitIndexLockPath()
    msg: string = resolveCommitMessage(progressPath)
    msgPath: string = resolveAutopushMessagePath()
    staged: string = ""
  if fileExists(lockPath):
    quit(
      "Refusing to run autopush because Git lock exists at " & lockPath &
      ". If no Git process is active, remove the stale lock and retry."
    )
  exec "git add -A ."
  staged = captureGit("diff --cached --name-only").strip()
  if staged.len == 0:
    echo "No staged changes. Skipping commit."
  else:
    for stagedPath in staged.splitLines:
      if isGeneratedOrLocalArtifact(stagedPath):
        echo "Refusing autopush: generated/local artifact staged: " & stagedPath
        echo "Remove it from the index or extend .gitignore before committing."
        quit(1)
    writeFile(msgPath, msg & "\n")
    exec "git commit --file " & msgPath
  exec "git push"

task switch, "Toggle the working branch between nightly and main":
  var
    branch: string = captureGit("branch --show-current").strip()
    target: string = "nightly"
  if branch == "nightly":
    target = "main"
  echo "Switching from '" &
    (if branch.len > 0: branch else: "(detached HEAD)") &
    "' to '" & target & "'."
  exec "git checkout " & target

task applynightly, "Promote nightly onto main by fast-forward and push":
  var
    branch: string = captureGit("branch --show-current").strip()
  if branch == "main":
    quit "On 'main'. Run `nimble switch` to move to nightly before applying."
  exec "git fetch . nightly:main"
  exec "git push origin nightly:main"
  echo "main is now at the nightly state; nightly branch left intact."

task find, "Use local clones for submodules in parent folder":
  let modulesPath = ".gitmodules"
  if not fileExists(modulesPath):
    echo "No .gitmodules found."
  else:
    let root = parentDir(getCurrentDir())
    var current = ""
    for line in readFile(modulesPath).splitLines:
      let s = line.strip()
      if s.startsWith("[submodule"):
        let start = s.find('"')
        let stop = s.rfind('"')
        if start >= 0 and stop > start:
          current = s[start + 1 .. stop - 1]
      elif current.len > 0 and s.startsWith("path"):
        let parts = s.split("=", maxsplit = 1)
        if parts.len == 2:
          let subPath = parts[1].strip()
          let tail = splitPath(subPath).tail
          let localDir = joinPath(root, tail)
          if dirExists(localDir):
            let localUrl = localDir.replace('\\', '/')
            exec "git config -f .gitmodules submodule." & current & ".url " & localUrl
            exec "git config submodule." & current & ".url " & localUrl
    exec "git submodule sync --recursive"

# NOTE: no UI dependencies belong here. Geist is a headless library, a CLI
# and a daemon; a stray `requires "owlkettle", "illwill", "webui"` used to
# sit at the bottom of this file and made every install of the database pull
# in a GTK stack it never calls.

# ---------------------------------------------------------------------
# Android
# ---------------------------------------------------------------------

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
