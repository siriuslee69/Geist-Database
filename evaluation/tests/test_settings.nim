## configs/default.toml and userconfig.toml: what they set, and what they
## refuse.
##
## The property that matters most here is the unfriendly one: a misspelled
## setting must be an ERROR. A settings file that silently ignores what it
## does not recognise is indistinguishable from one that took effect, and
## the person who wrote it will believe it did.

import runePragmas
import std/[json, os, strutils, unittest]
import geist/network
import geist/toml_read

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

suite "library defaults":
  test "an absent file leaves the built-in defaults alone":
    var
      dir = scratch("geist_t_cfg1")
      got = loadGeistDefaults(dir / "config.toml")
    check got.ok
    check got.defaults.preset == "app"
    check got.defaults.sidecarThreshold == defaultSidecarThreshold
    check got.defaults.rowIdentity
    check got.defaults.loadedFrom == ""

  test "the file replaces exactly what it names":
    var
      dir = scratch("geist_t_cfg2")
      path = dir / "config.toml"
    writeFile(path, """
[runtime.storage]
preset = "secure-app"
sidecarThreshold = 4096
rowIdentity = false

[runtime.backup]
copies = 3
""")
    var got = loadGeistDefaults(path)
    check got.ok
    check got.defaults.preset == "secure-app"
    check got.defaults.sidecarThreshold == 4096'u32
    check not got.defaults.rowIdentity
    check got.defaults.backupCopies == 3'u8
    # Untouched by the file, so still the built-in value.
    check got.defaults.backupEverySeconds == 0'u32
    check got.defaults.loadedFrom == path

  test "a misspelled setting is refused, not ignored":
    var
      dir = scratch("geist_t_cfg3")
      path = dir / "config.toml"
    writeFile(path, "[runtime.storage]\nsidecarTreshold = 4096\n")
    var got = loadGeistDefaults(path)
    check not got.ok
    check got.err.contains("sidecarTreshold")
    check got.err.contains("known:")

  test "a preset that does not exist fails at the file, not at the open":
    var
      dir = scratch("geist_t_cfg4")
      path = dir / "config.toml"
    writeFile(path, "[runtime.storage]\npreset = \"turbo\"\n")
    var got = loadGeistDefaults(path)
    check not got.ok
    check got.err.contains("turbo")

  test "defaults apply over a preset without replacing it":
    var d = builtinDefaults()
    d.sidecarThreshold = 512'u32
    d.backupCopies = 4'u8
    var c = applyDefaults(secureAppConfig(), d)
    # The named settings moved...
    check c.sidecarThreshold == 512'u32
    check c.backup.copies == 4'u8
    # ...and everything the preset chose for itself did not.
    check c.cipher == secureAppConfig().cipher
    check c.mac == secureAppConfig().mac
    check c.batchRows == secureAppConfig().batchRows

  test "a database opened with those defaults stores by them":
    var dir = scratch("geist_t_cfg5")
    type Note = object
      noteId: int
      title: string
    var d = builtinDefaults()
    d.rowIdentity = false
    d.rowIdentityNamed = true
    var db = openGeist[Note](dir / "store", applyDefaults(appConfig(), d))
    discard db.put(Note(noteId: 1, title: "x"))
    check not db.hasIdentity()
    db.close()

  test "defaults do not overrule a preset that was not asked about":
    # `iotConfig` turns rowIdentity OFF on purpose. The built-in default is
    # ON, and a bool has no "absent" value, so this used to silently double
    # the row size of every telemetry database: 32 bytes where the preset
    # asked for 16.
    check not iotConfig().rowIdentity
    check not streamConfig().rowIdentity
    check builtinDefaults().rowIdentity
    check not builtinDefaults().rowIdentityNamed
    check not applyDefaults(iotConfig(), builtinDefaults()).rowIdentity
    check not applyDefaults(streamConfig(), builtinDefaults()).rowIdentity
    # A preset that wants identity still gets it.
    check applyDefaults(appConfig(), builtinDefaults()).rowIdentity

  test "a file that names rowIdentity still wins over the preset":
    # The override has to keep working, or turning identity ON for a
    # telemetry store would become impossible.
    var
      dir = scratch("geist_t_cfg5b")
      path = dir / "config.toml"
    writeFile(path, "[runtime.storage]\nrowIdentity = true\n")
    var got = loadGeistDefaults(path)
    check got.ok
    check got.defaults.rowIdentityNamed
    check applyDefaults(iotConfig(), got.defaults).rowIdentity
    # And naming it false is honoured rather than read as "absent".
    writeFile(path, "[runtime.storage]\nrowIdentity = false\n")
    got = loadGeistDefaults(path)
    check got.ok
    check got.defaults.rowIdentityNamed
    check not applyDefaults(appConfig(), got.defaults).rowIdentity

suite "user configuration":
  test "sections are read and an absent file is not an error":
    var
      dir = scratch("geist_t_ucfg1")
      path = dir / "userconfig.toml"
    check loadUserConfig(path).ok
    writeFile(path, """
[database]
path = "data/notes"
preset = "chat"
passwordFile = "secrets/db.pw"

[daemon]
listen = "dac://0.0.0.0:47655"
identity = "keys/geistd.id"
trust = ["peers/a.pin", "peers/b.pin"]
allowWrite = ["peers/c.pin"]

[client]
remote = "dac://desk:47655"
peerPin = "peers/geistd.pin"
limit = 50
""")
    var got = loadUserConfig(path)
    check got.ok
    check got.user.path == "data/notes"
    check got.user.preset == "chat"
    check got.user.listen == "dac://0.0.0.0:47655"
    check got.user.trust.len == 2
    check got.user.trust[1] == "peers/b.pin"
    check got.user.allowWrite == @["peers/c.pin"]
    check got.user.remote == "dac://desk:47655"
    check got.user.limit == 50

  test "one pin may be written without a list around it":
    var
      dir = scratch("geist_t_ucfg2")
      path = dir / "userconfig.toml"
    writeFile(path, "[daemon]\ntrust = \"peers/only.pin\"\n")
    var got = loadUserConfig(path)
    check got.ok
    check got.user.trust == @["peers/only.pin"]

  test "an unknown key in any section is refused":
    var
      dir = scratch("geist_t_ucfg3")
      path = dir / "userconfig.toml"
    writeFile(path, "[client]\nremoteHost = \"desk\"\n")
    var got = loadUserConfig(path)
    check not got.ok
    check got.err.contains("remoteHost")

  test "a file that is not TOML fails rather than being skipped":
    var
      dir = scratch("geist_t_ucfg4")
      path = dir / "userconfig.toml"
    writeFile(path, "[database\npath = ")
    var got = loadUserConfig(path)
    check not got.ok
    check got.err.contains(path)

suite "transport settings":
  test "the tier policy comes from the file and still validates":
    var
      dir = scratch("geist_t_cfg6")
      path = dir / "config.toml"
    writeFile(path, """
[runtime.transport]
startTier = "secret"
secretAtMiB = 16
archiveAtMiB = 256
""")
    var got = loadTransportDefaults(path)
    check got.ok
    check got.defaults.startTier == gtSecret
    var policy = defaultsTriggerPolicy(got.defaults)
    check policy.startTier == gtSecret
    check policy.rows[gtSecret].threshold == 16'u64
    check policy.rows[gtArchive].threshold == 256'u64
    # A policy a settings file produced must still be one the transport
    # will accept, or the failure surfaces at connect time instead.
    check validateTriggerPolicy(policy).ok

  test "an unknown tier name is refused":
    var
      dir = scratch("geist_t_cfg7")
      path = dir / "config.toml"
    writeFile(path, "[runtime.transport]\nstartTier = \"paranoid\"\n")
    var got = loadTransportDefaults(path)
    check not got.ok
    check got.err.contains("paranoid")

  test "the shipped configs/default.toml parses and validates":
    # The file in configs/ is what a new user reads first. If it drifts
    # from the parser, every one of them starts with an error.
    var got = loadTransportDefaults(currentSourcePath().parentDir() / ".." /
      ".." / "configs" / "default.toml")
    check got.ok
    # Found and read, not skipped as missing -- a missing file is also ok.
    check got.defaults.loadedFrom.len > 0
    check validateTriggerPolicy(defaultsTriggerPolicy(got.defaults)).ok

suite "build presets at run time":
  # {.testKind: tkUnit, covers: "runtimeOf".}
  test "a preset file replaces only the keys it names":
    var
      dir = scratch("geist_t_layer1")
      base = dir / "default.toml"
      over = dir / "iot.toml"
    writeFile(base, "[project]\nname = \"x\"\n\n[runtime.storage]\n" &
      "preset = \"app\"\nsidecarThreshold = 1024\n\n[runtime.backup]\n" &
      "copies = 2\n")
    writeFile(over, "[nim]\nopt = \"size\"\n\n[runtime.storage]\n" &
      "preset = \"iot\"\n")
    var got = runtimeOf(base, @[over])
    check got.ok
    check got.node["storage"]["preset"].getStr() == "iot"
    check got.node["storage"]["sidecarThreshold"].getInt() == 1024
    check got.node["backup"]["copies"].getInt() == 2
    # Build tables never leak into what the program reads.
    check not got.node.hasKey("project")
    check not got.node.hasKey("nim")

  # {.testKind: tkEdgeCase, covers: "runtimeOf".}
  test "a preset file that will not parse stops the load":
    var
      dir = scratch("geist_t_layer2")
      base = dir / "default.toml"
      over = dir / "broken.toml"
    writeFile(base, "[runtime.storage]\npreset = \"app\"\n")
    writeFile(over, "[runtime.storage\npreset = \n")
    var got = runtimeOf(base, @[over])
    check not got.ok
    check got.err.contains("broken.toml")

  # {.testKind: tkUnit, covers: "overlayNames".}
  test "only the library default file is ever overlaid":
    check overlayNames("somewhere/else.toml").len == 0

  # {.testKind: tkSmoke, covers: "loadGeistDefaults, loadTransportDefaults".}
  test "every shipped configs/*.toml loads without a complaint":
    var
      dir = currentSourcePath().parentDir() / ".." / ".." / "configs"
      n = 0
    for f in walkFiles(dir / "*.toml"):
      var
        storage = loadGeistDefaults(dir / "default.toml")
        layered = runtimeOf(dir / "default.toml", @[f])
        transport = loadTransportDefaults(f)
      check storage.ok
      check storage.defaults.loadedFrom.len > 0
      check layered.ok
      check transport.ok
      n = n + 1
    check n >= 1
