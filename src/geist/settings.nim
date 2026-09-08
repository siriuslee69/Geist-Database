## ---------------------------------------------------------------------
## Settings <- config.toml for the library, userconfig.toml for a client
## ---------------------------------------------------------------------
##
##   config.toml      what the LIBRARY defaults to     -> geistDefaults()
##   userconfig.toml  what THIS installation does      -> loadUserConfig()
##
## Two files because they answer to different people. `config.toml` ships
## with the project and sets the defaults every embedding application
## inherits: which preset, how large a value has to be before it moves to
## the sidecar, how many backup copies to keep. `userconfig.toml` belongs
## to whoever runs the CLI or the daemon on this machine: where the
## database is, what to listen on, which peers to trust.
##
## Neither is required. A missing file means "use the built-in defaults",
## which is why an application that never writes one still runs -- and why
## these are settings rather than configuration a program cannot start
## without.
##
## The TOML parsing is Fylgia's (`parseTomlNode`), not another hand-rolled
## one. What is here is the mapping from names to meanings, and the rule
## that an unknown key is an ERROR rather than a shrug: a typo in a
## setting file otherwise looks exactly like a setting that had no effect.

import std/[json, os]

import geistPragmas
import ./config
import ./toml_read
import ./layout
import ./types

const
  userConfigName* = "userconfig.toml"

type
  GeistDefaults* {.role: configurator, metaTags: {tagConfig, tagTypes}.} = object
    ## Library-wide defaults, read once and used wherever a caller does not
    ## say otherwise. Deliberately small: anything that varies per database
    ## belongs in `GeistConfig`, which a caller passes explicitly.
    preset*: string
    sidecarThreshold*: uint32
    backupCopies*: uint8
    backupEverySeconds*: uint32
    rowIdentity*: bool
    ## rowIdentityNamed: whether the FILE said anything about rowIdentity.
    ##
    ## The other settings here carry their own "absent" value -- a zero
    ## threshold or zero copies means the file did not mention it, so
    ## `applyDefaults` can leave the preset's choice alone. A bool has no
    ## such value: `false` and "not mentioned" are the same bit. Without
    ## this flag the built-in `true` silently overrode every preset that
    ## turns identity OFF, which doubled the row size of exactly the
    ## telemetry workloads those presets exist to shrink.
    rowIdentityNamed*: bool
    ## transpose: the column-first search copy, named the way the enum is
    ## written without its prefix -- "none", "onSave", "interval",
    ## "manual". Empty means the file said nothing and the preset keeps
    ## its choice, the same rule rowIdentity needs a flag for.
    transpose*: string
    transposeEverySeconds*: uint32
    loadedFrom*: string

  UserConfig* {.role: configurator, metaTags: {tagCli, tagConfig,
      tagTypes}.} = object
    ## What one installation does. Every field maps to a command line
    ## option, and the option WINS: a config file is a way to stop typing,
    ## not a way to override what was typed.
    path*: string
    preset*: string
    passwordFile*: string
    listen*: string
    identity*: string
    identityPasswordFile*: string
    trust*: seq[string]
    allowWrite*: seq[string]
    remote*: string
    peerPin*: string
    limit*: int
    loadedFrom*: string

proc builtinDefaults*(): GeistDefaults {.role: configurator,
    metaTags: {tagConfig}.} =
  ## What the library does with no config.toml at all. These are the same
  ## values the presets carry, restated here so a reader can see them
  ## without reading config.nim.
  result.preset = "app"
  result.sidecarThreshold = defaultSidecarThreshold
  result.backupCopies = 2'u8
  result.backupEverySeconds = 0'u32
  result.rowIdentity = true

proc loadGeistDefaults*(path: string = libraryConfigName): tuple[ok: bool,
    defaults: GeistDefaults, err: string] {.role: configurator,
    metaTags: {tagConfig, tagParsing, tagRead}.} =
  ## path: `config.toml`, relative to the working directory unless given.
  ##
  ##   [storage]
  ##   preset = "secure-app"
  ##   sidecarThreshold = 1024
  ##   rowIdentity = true
  ##
  ##   [backup]
  ##   copies = 3
  ##   everySeconds = 3600
  ##
  ## `[transport]` is read by `transport_settings.nim` instead, out of the
  ## same file. That section names algorithm tiers, and a storage-only
  ## build has no algorithms to name -- keeping it here is what used to
  ## drag the whole AME stack into a program that only writes rows.
  var
    doc: tuple[ok: bool, node: JsonNode, err: string]
    storage: JsonNode
    backup: JsonNode
    complaint: string = ""
  result.defaults = builtinDefaults()
  doc = tomlOf(path)
  if not doc.ok:
    return (false, result.defaults, doc.err)
  storage = doc.node.section("storage")
  backup = doc.node.section("backup")
  complaint = checkKeys(storage,
    ["preset", "sidecarThreshold", "rowIdentity", "transpose",
     "transposeEverySeconds"], "[storage]")
  if complaint.len > 0:
    return (false, result.defaults, complaint)
  complaint = checkKeys(backup, ["copies", "everySeconds"], "[backup]")
  if complaint.len > 0:
    return (false, result.defaults, complaint)
  result.defaults.preset = storage.setting("preset", result.defaults.preset)
  result.defaults.sidecarThreshold = storage.setting("sidecarThreshold",
    result.defaults.sidecarThreshold)
  result.defaults.rowIdentity = storage.setting("rowIdentity",
    result.defaults.rowIdentity)
  result.defaults.rowIdentityNamed = storage.hasKey("rowIdentity")
  result.defaults.transpose = storage.setting("transpose",
    result.defaults.transpose)
  result.defaults.transposeEverySeconds = storage.setting(
    "transposeEverySeconds", result.defaults.transposeEverySeconds)
  result.defaults.backupCopies = backup.setting("copies",
    result.defaults.backupCopies)
  result.defaults.backupEverySeconds = backup.setting("everySeconds",
    result.defaults.backupEverySeconds)
  # A preset name that does not exist must fail HERE, not at the first
  # open: the file is where the mistake is. Same for a transpose mode --
  # a misspelling that silently left the copy switched off would look
  # exactly like the feature not working.
  try:
    discard geistConfigPreset(result.defaults.preset)
  except ValueError as exc:
    return (false, builtinDefaults(), path & ": " & exc.msg)
  if result.defaults.transpose notin ["", "none", "onSave", "interval",
      "manual"]:
    return (false, builtinDefaults(), path &
      ": [storage] transpose must be none, onSave, interval or manual, got '" &
      result.defaults.transpose & "'")
  result.defaults.loadedFrom = if fileExists(path): path else: ""
  result.ok = true

proc applyDefaults*(c: GeistConfig, d: GeistDefaults): GeistConfig {.
    role: configurator, metaTags: {tagAppApi, tagConfig}.} =
  ## c: a configuration, usually straight from a preset.
  ## d: the library defaults read from config.toml.
  ##
  ## Only the settings config.toml actually names are applied. Everything
  ## else the preset chose stays chosen -- a defaults file is a nudge, not
  ## a replacement for the preset a caller asked for by name.
  result = c
  if d.sidecarThreshold > 0'u32:
    result.sidecarThreshold = d.sidecarThreshold
  # Only when the file actually said so. `iotConfig` and `streamConfig`
  # turn identity off on purpose -- 16 bytes of id on a 32-byte sensor row
  # is half again as much disk for a feature append-only telemetry never
  # uses -- and a built-in default has no business overruling the preset
  # the caller asked for by name.
  if d.rowIdentityNamed:
    result.rowIdentity = d.rowIdentity
  if d.backupCopies > 0'u8:
    result.backup.copies = d.backupCopies
  if d.backupEverySeconds > 0'u32:
    result.backup.everySeconds = d.backupEverySeconds
  # An empty name is the file staying silent, exactly like a zero
  # threshold. A name it does not know is a mistake worth stopping for,
  # but `applyDefaults` has no way to report one -- so it is checked when
  # the file is READ, in loadGeistDefaults, and here it can only be one of
  # the four.
  case d.transpose
  of "none": result.transpose = tmNone
  of "onSave": result.transpose = tmOnSave
  of "interval": result.transpose = tmInterval
  of "manual": result.transpose = tmManual
  else: discard
  if d.transposeEverySeconds > 0'u32:
    result.transposeEverySeconds = d.transposeEverySeconds
  result = normalizeGeistConfig(result)

## ------------------------ the library's own copy --------------------
##
## One process-wide set of defaults, so an application that reads
## config.toml at startup does not have to thread the result through every
## call. Set it ONCE, before opening anything: it is read on every
## `defaultGeistConfig`, and moving it underneath a running program would
## make two databases opened the same way behave differently.

var
  activeDefaults: GeistDefaults = builtinDefaults()

proc useGeistDefaults*(d: GeistDefaults) {.role: stateController,
    metaTags: {tagConfig, tagLifecycle}.} =
  ## d: defaults every later `defaultGeistConfig` is built from.
  {.gcsafe.}:
    activeDefaults = d

proc geistDefaults*(): GeistDefaults {.role: parser,
    metaTags: {tagConfig, tagRead}.} =
  ## The defaults in force, built-in unless a config.toml replaced them.
  {.gcsafe.}:
    result = activeDefaults

proc initGeistDefaults*(path: string = libraryConfigName): tuple[ok: bool,
    err: string] {.role: configurator,
    metaTags: {tagConfig, tagLifecycle, tagRead}.} =
  ## path: config.toml, read and adopted in one step. A missing file is
  ## success -- the built-in defaults ARE the answer in that case.
  var
    got: tuple[ok: bool, defaults: GeistDefaults, err: string]
  got = loadGeistDefaults(path)
  if not got.ok:
    return (false, got.err)
  useGeistDefaults(got.defaults)
  result = (true, "")

proc defaultGeistConfig*(): GeistConfig {.role: configurator,
    metaTags: {tagAppApi, tagConfig}.} =
  ## The preset config.toml names, with the settings it names applied. This
  ## is what a caller who has no opinion should open with.
  result = applyDefaults(geistConfigPreset(geistDefaults().preset),
    geistDefaults())

proc loadUserConfig*(path: string = userConfigName): tuple[ok: bool,
    user: UserConfig, err: string] {.role: configurator,
    metaTags: {tagCli, tagConfig, tagParsing, tagRead}.} =
  ## path: `userconfig.toml`.
  ##
  ##   [database]
  ##   path = "data/notes"
  ##   preset = "secure-app"
  ##   passwordFile = "secrets/db.pw"
  ##
  ##   [daemon]
  ##   listen = "dac://0.0.0.0:47655"
  ##   identity = "keys/geistd.id"
  ##   trust = ["peers/laptop.pin"]
  ##   allowWrite = ["peers/desktop.pin"]
  ##
  ##   [client]
  ##   remote = "dac://desktop.local:47655"
  ##   peerPin = "peers/desktop.pin"
  ##   limit = 50
  var
    doc: tuple[ok: bool, node: JsonNode, err: string]
    db: JsonNode
    daemon: JsonNode
    client: JsonNode
    complaint: string = ""
  doc = tomlOf(path)
  if not doc.ok:
    return (false, UserConfig(), doc.err)
  db = doc.node.section("database")
  daemon = doc.node.section("daemon")
  client = doc.node.section("client")
  complaint = checkKeys(db, ["path", "preset", "passwordFile"], "[database]")
  if complaint.len > 0:
    return (false, UserConfig(), complaint)
  complaint = checkKeys(daemon,
    ["listen", "identity", "identityPasswordFile", "trust", "allowWrite"],
    "[daemon]")
  if complaint.len > 0:
    return (false, UserConfig(), complaint)
  complaint = checkKeys(client, ["remote", "peerPin", "limit"], "[client]")
  if complaint.len > 0:
    return (false, UserConfig(), complaint)
  result.user.path = db.setting("path", "")
  result.user.preset = db.setting("preset", "")
  result.user.passwordFile = db.setting("passwordFile", "")
  result.user.listen = daemon.setting("listen", "")
  result.user.identity = daemon.setting("identity", "")
  result.user.identityPasswordFile = daemon.setting("identityPasswordFile", "")
  result.user.trust = daemon.setting("trust", newSeq[string]())
  result.user.allowWrite = daemon.setting("allowWrite", newSeq[string]())
  result.user.remote = client.setting("remote", "")
  result.user.peerPin = client.setting("peerPin", "")
  result.user.limit = client.setting("limit", 0)
  result.user.loadedFrom = if fileExists(path): path else: ""
  result.ok = true

proc firstExisting*(candidates: openArray[string]): string {.role: parser,
    metaTags: {tagCli, tagConfig, tagRead}.} =
  ## candidates: paths tried in order; the first that exists is returned,
  ## and an empty string when none does.
  var
    i: int = 0
  while i < candidates.len:
    if candidates[i].len > 0 and fileExists(candidates[i]):
      return candidates[i]
    i = i + 1

proc userConfigCandidates*(explicit: string = "",
    role: NodeRole = nrClient): seq[string] {.role: parser,
    metaTags: {tagCli, tagConfig, tagRead}.} =
  ## explicit: a path named on the command line, which always wins.
  ## role: which Geist folder to look in when nothing was named.
  ##
  ## The order, and why:
  ##
  ##   1. what was typed             an argument beats everything
  ##   2. ./userconfig.toml          a project-local file is what someone
  ##                                 editing it expects to take effect
  ##   3. <geist home>/config/       THE machine's config folder
  ##   4. ~/.config/geist/           where it used to be
  ##
  ## Step 4 is kept so an installation that predates the Geist folder
  ## keeps working. It is last, so a machine that has both uses the one
  ## inside the folder -- which is the one a backup of that folder
  ## contains.
  var
    home: tuple[ok: bool, home: GeistHome, err: string]
  if explicit.len > 0:
    return @[explicit]
  result = @[userConfigName]
  home = openHome("", role)
  if home.ok:
    result.add home.home.configPath(userConfigName)
  result.add getConfigDir() / "geist" / userConfigName
