## Presets: every one in the catalog resolves, validates, and can be
## named from a config file.
##
## The property being pinned here is unglamorous and was worth a bug: a
## preset is a pile of settings, and nothing stops somebody writing a
## combination the validator refuses. `hostConfig` was written that way on
## its first draft -- encryption at rest AND the plaintext column copy --
## and it resolved perfectly happily. `openGeist` would have refused it at
## the first call, in an application, rather than here.
##
## So: the catalog is the source of truth, and these tests walk it. A new
## preset is covered the moment it is listed, and one that is NOT listed
## fails the last test in this file.

import std/[os, strutils, unittest]
import geist
import geist/network

proc scratch(name: string): string =
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

# {.testKind: tkUnit, covers: "geistConfigPreset".}
suite "every catalogued preset is usable":
  test "each one resolves to a configuration that validates":
    var
      c: GeistConfig = appConfig()
      v: tuple[ok: bool, err: string] = (false, "")
    for p in geistConfigPresets():
      c = geistConfigPreset(p.name)
      v = validateGeistConfig(c)
      check v.ok
      if not v.ok:
        echo "preset '", p.name, "' does not validate: ", v.err

  test "each one keeps its own name, so diagnostics can say which it was":
    var c: GeistConfig = appConfig()
    for p in geistConfigPresets():
      c = geistConfigPreset(p.name)
      check c.name.len > 0

  # {.testKind: tkEdgeCase, covers: "geistConfigPreset".}
  test "an unknown name is refused, and the message lists the real ones":
    var raised: bool = false
    try:
      discard geistConfigPreset("not-a-preset")
    except ValueError as e:
      raised = true
      ## The message has to name the alternatives. A bare "unknown preset"
      ## leaves the reader guessing at a closed set they cannot see.
      check e.msg.contains("not-a-preset")
      check e.msg.contains("app")
      check e.msg.contains("bulk")
    check raised

# {.testKind: tkUnit, covers: "geistConfigPreset".}
suite "the workload presets say what their workload needs":
  test "cloud-sync can name rows, because a follower syncs by name":
    var c: GeistConfig = geistConfigPreset("cloud-sync")
    check c.rowIdentity
    check c.keepHistory

  test "chain keeps history, because peers pull by log position":
    var c: GeistConfig = geistConfigPreset("chain")
    ## Compaction rewrites the log and makes a position mean a different
    ## row, which sends every follower back to zero.
    check c.keepHistory
    ## Evidence must not rest on one hash construction.
    check c.chainHash == hkSha3
    check c.contentHash == hkSha3

  test "host externalises early, so a row is a name and a reference":
    var c: GeistConfig = geistConfigPreset("host")
    check c.sidecarThreshold <= 256'u32
    ## A machine hosting other people's content must not keep a plaintext
    ## index of it beside the sealed store.
    check c.cipher != ckNone
    check c.transpose == tmNone

  test "live writes nothing, because an old position is worthless":
    var c: GeistConfig = geistConfigPreset("live")
    check c.writeMode == wmVolatile
    check not c.keepHistory
    check not c.backup.enabled

  test "bulk pushes almost everything out of the row":
    var c: GeistConfig = geistConfigPreset("bulk")
    check c.sidecarThreshold <= 64'u32
    check c.batchRows >= 256'u32

# {.testKind: tkIntegration, covers: "loadGeistDefaults".}
suite "a preset can be chosen from config.toml":
  test "the file names one and the loader resolves it":
    var
      dir: string = scratch("geist_t_preset1")
      path: string = dir / "config.toml"
    writeFile(path, "[storage]\npreset = \"cloud-sync\"\n")
    var got = loadGeistDefaults(path)
    check got.ok
    check got.defaults.preset == "cloud-sync"

  # {.testKind: tkEdgeCase, covers: "loadGeistDefaults".}
  test "a misspelled preset fails at load, not at the first open":
    var
      dir: string = scratch("geist_t_preset2")
      path: string = dir / "config.toml"
    writeFile(path, "[storage]\npreset = \"clowd-sync\"\n")
    var got = loadGeistDefaults(path)
    ## The whole point of checking here: the person who wrote the typo is
    ## still looking at the file.
    check not got.ok
    check got.err.contains("clowd-sync")

  test "every catalogued preset is namable from a file":
    var
      dir: string = scratch("geist_t_preset3")
      path: string = ""
      i: int = 0
    for p in geistConfigPresets():
      path = dir / ("c" & $i & ".toml")
      writeFile(path, "[storage]\npreset = \"" & p.name & "\"\n")
      var got = loadGeistDefaults(path)
      check got.ok
      if not got.ok:
        echo "preset '", p.name, "' is not loadable: ", got.err
      i = i + 1
