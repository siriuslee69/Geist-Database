## ---------------------------------------------------------------------
## Layout <- one Geist folder per machine, not one per corner of it
## ---------------------------------------------------------------------
##
##   $GEIST_HOME, or the platform default
##   |
##   +-- config/          every TOML anything on this machine reads
##   |     geist.toml         library defaults
##   |     userconfig.toml    this installation
##   |     router.toml        geist-routed
##   |     fjord.toml         one per app
##   |     eris.toml
##   +-- keys/            signing identities, and the keystore
##   |     <node>.id
##   |     keystore/
##   +-- peers/           the pins of everyone this node trusts
##   |     vps-1.pin
##   +-- db/              every store, under the app that owns it
##   |     fjord/accounts/
##   |     fjord/mail/alice/inbox/
##   |     eris/messages/
##   |     eris/games/alderreach/
##   +-- spool/           things in flight
##   +-- logs/
##
## THE PROBLEM THIS SOLVES. `openGeist` takes a directory, so before this
## module every application chose one, and three applications chose three
## differently: a store next to the binary, a store under the user's home,
## a store wherever the working directory happened to be. Backing a
## machine up meant knowing all of them. Moving an installation meant
## finding all of them.
##
## One root. Everything a Geist deployment owns is under it, and the only
## thing an operator has to know is where it is.
##
## WHERE IT IS, by platform and role:
##
##   $GEIST_HOME               always wins, everywhere
##   Linux   client            $XDG_DATA_HOME/geist, else ~/.local/share/geist
##   Linux   server            /var/lib/geist
##   Windows client            %APPDATA%\geist
##   Windows server            %PROGRAMDATA%\geist
##   Android                   must be given: the app-private directory,
##                             which only the runtime knows
##
## HOW MUCH TO SPLIT. Only where something forces it, and exactly two
## things do:
##
##   ONE STORE PER RECORD TYPE. `openGeist[T]` derives its schema from T,
##   so two record types are two stores. Not a policy -- an engine fact.
##
##   ONE STORE PER SYNC CURSOR. A cursor is a log position in ONE store.
##   Two things that must be "caught up" independently -- an Inbox and an
##   Archive, one game and another -- cannot share a store, because they
##   would share the number that says how far a follower has read.
##
## Everything else is a subfolder, not a store. A per-account setting is a
## column, not a database; a mailbox flag is a field, not a directory.

import std/[os, strutils]

import runePragmas
import ./address

const
  geistHomeEnv* = "GEIST_HOME"
    ## The override, checked before anything else on every platform. One
    ## variable rather than one per directory: an operator relocating a
    ## deployment moves the whole thing or none of it.
  configDirName* = "config"
  keysDirName* = "keys"
  peersDirName* = "peers"
  dbDirName* = "db"
  spoolDirName* = "spool"
  logDirName* = "logs"
  keystoreDirName* = "keystore"
  defaultHomeName* = "geist"
  libraryConfigFile* = "geist.toml"
  userConfigFile* = "userconfig.toml"
  routerConfigFile* = "router.toml"

type
  NodeRole* {.role: configurator, tag: "config|types".} = enum
    ## Which kind of thing this process is, which is the only input to the
    ## default location besides the platform.
    ##
    ##   nrClient  one person's data, under their own home
    ##   nrServer  a service's data, under the system's state directory
    ##
    ## A server that defaulted to a home directory would put a mail spool
    ## somewhere `systemd` cleans up; a client that defaulted to
    ## /var/lib would need root to read its own mail.
    nrClient, nrServer

  GeistHome* {.role: truthState, tag: "config|storageIo|types".} = object
    ## One machine's Geist folder.
    ##
    ## `explicit` records whether the base came from the caller or the
    ## environment rather than from the platform default -- which is worth
    ## printing in a status line, because "not where you expected" is the
    ## first thing to check when a store looks empty.
    base*: string
    role*: NodeRole
    explicit*: bool

proc defaultHomeFor*(r: NodeRole): string {.role: configurator,
    tag: "config|compat".} =
  ## r: where this kind of process keeps its Geist folder by default.
  ##
  ## Android is deliberately absent: an app's private directory is only
  ## known to the runtime, so there is nothing to guess and a guess would
  ## be a path the app cannot write. `openHome` refuses rather than
  ## inventing one -- see the note there.
  when defined(android):
    result = ""
  elif defined(windows):
    if r == nrServer:
      result = getEnv("PROGRAMDATA", "C:\\ProgramData") / defaultHomeName
    else:
      result = getEnv("APPDATA", getHomeDir() / "AppData" / "Roaming") /
        defaultHomeName
  else:
    if r == nrServer:
      result = "/var/lib" / defaultHomeName
    else:
      result = getEnv("XDG_DATA_HOME",
        getHomeDir() / ".local" / "share") / defaultHomeName

proc openHome*(base: string = "",
    r: NodeRole = nrClient): tuple[ok: bool, home: GeistHome, err: string] {.
    role: configurator, tag: "config|storageIo".} =
  ## base: an explicit root, or nothing to use $GEIST_HOME or the default.
  ## r: client or server.
  ##
  ## Creates nothing. Resolving where the folder IS and making sure it
  ## exists are separate steps, because a `--help` that created a
  ## directory tree would be a surprising `--help`.
  var
    t: string = base
  result.home.role = r
  if t.len == 0:
    t = getEnv(geistHomeEnv, "")
  else:
    result.home.explicit = true
  if t.len > 0:
    result.home.explicit = true
  if t.len == 0:
    t = defaultHomeFor(r)
  if t.len == 0:
    return (false, result.home,
      "no Geist folder: this platform has no default, so one must be " &
      "given -- pass it, or set " & geistHomeEnv)
  result.home.base = t.absolutePath()
  result.ok = true

proc configDir*(h: GeistHome): string {.role: helper, inline,
    tag: "config".} =
  ## h: every TOML file this machine reads.
  result = h.base / configDirName

proc keysDir*(h: GeistHome): string {.role: helper, inline,
    tag: "cryptoBoundary".} =
  ## h: signing identities and the keystore.
  result = h.base / keysDirName

proc keystoreDir*(h: GeistHome): string {.role: helper, inline,
    tag: "cryptoBoundary".} =
  ## h: what `openKeystore` should be given.
  result = h.keysDir() / keystoreDirName

proc peersDir*(h: GeistHome): string {.role: helper, inline,
    tag: "peerDirectory".} =
  ## h: the pins of everyone this node trusts.
  result = h.base / peersDirName

proc dbDir*(h: GeistHome): string {.role: helper, inline,
    tag: "storageIo".} =
  ## h: every store, under the app that owns it.
  result = h.base / dbDirName

proc spoolDir*(h: GeistHome): string {.role: helper, inline,
    tag: "storageIo".} =
  ## h: things in flight, which survive a restart but are not content.
  result = h.base / spoolDirName

proc logDir*(h: GeistHome): string {.role: helper, inline,
    tag: "storageIo".} =
  ## h: where a daemon writes, when it writes to a file at all.
  result = h.base / logDirName

proc configPath*(h: GeistHome, name: string): string {.role: helper,
    tag: "config".} =
  ## h/name: one config file. `name` may be bare (`fjord`) or carry its
  ## extension (`fjord.toml`); a bare one gets `.toml`, because that is
  ## the house format and every caller writing it out would be noise.
  var
    t: string = name
  if not (t.toLowerAscii().endsWith(".toml") or
      t.toLowerAscii().endsWith(".json")):
    t = t & ".toml"
  result = h.configDir() / t

proc identityPath*(h: GeistHome, node: string): string {.role: helper,
    tag: "cryptoBoundary".} =
  ## h/node: this node's signing key.
  result = h.keysDir() / node & ".id"

proc pinPath*(h: GeistHome, peer: string): string {.role: helper,
    tag: "peerDirectory".} =
  ## h/peer: one peer's pin.
  result = h.peersDir() / peer & ".pin"

proc appDir*(h: GeistHome; app: string; instance: string = ""): string {.
    role: helper, tag: "storageIo".} =
  ## h/app/instance: everything one application stores.
  ##
  ## The instance is part of the DIRECTORY NAME rather than a level of its
  ## own, so `fjord` and `fjord.staging` sit side by side and a listing of
  ## `db/` reads as the list of what is deployed here.
  var
    t: string = app.toLowerAscii()
  if instance.len > 0:
    t = t & "." & instance.toLowerAscii()
  result = h.dbDir() / t

proc storePath*(h: GeistHome, app, instance: string,
    target: string): tuple[ok: bool, path: string, err: string] {.
    role: helper, tag: "storageIo".} =
  ## h/app/instance: whose store.
  ## target: the address target, `mail/alice/inbox` or `accounts`.
  ##
  ## THE PATH IS THE ADDRESS. A store reached as
  ## `geist://fjord/mail/alice/inbox` lives at
  ## `db/fjord/mail/alice/inbox`, so an operator who has one can find the
  ## other without a lookup table. That is the whole reason this takes a
  ## target string rather than a list of components.
  ##
  ## The target is validated here even though callers normally build it
  ## with `address.nim`: this is the function that turns it into a
  ## filesystem path, so this is where `..` has to be impossible.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string]
  if target.len == 0:
    return (false, "", "a store needs a target")
  parsed = parseAddress(target)
  if not parsed.ok:
    return (false, "", parsed.err)
  if parsed.a.isRouted():
    # A whole address was passed where a target was wanted. Take the
    # target out of it rather than refusing: the caller had the right
    # value in the wrong shape, and this is unambiguous.
    return (true, h.appDir(app, instance) / parsed.a.forLeaf(), "")
  result = (true, h.appDir(app, instance) / parsed.a.forLeaf(), "")

proc storeFor*(h: GeistHome,
    a: GeistAddress): tuple[ok: bool, path: string, err: string] {.
    role: helper, tag: "storageIo".} =
  ## h/a: the folder for whatever this address names, on this machine.
  ##
  ## The short form of `storePath` for the common case: a daemon that has
  ## just parsed a request already holds the address, and taking it apart
  ## to pass three strings back in would be an opportunity to pass them in
  ## the wrong order.
  if a.app.len == 0:
    return (false, "", "address '" & $a & "' names no app, so there is " &
      "no folder for it")
  result = (true, h.appDir(a.app, a.instance) / a.forLeaf(), "")

proc ensureHome*(h: GeistHome): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "lifecycle|storageIo".} =
  ## h: create the folder and its six fixed subdirectories.
  ##
  ## Called once at startup. The app directories under `db/` are NOT
  ## created here: they appear when a store is opened, so `db/` lists what
  ## this machine actually holds rather than every app it could hold.
  var
    dirs: seq[string] = @[h.base, h.configDir(), h.keysDir(),
      h.keystoreDir(), h.peersDir(), h.dbDir(), h.spoolDir(), h.logDir()]
    i: int = 0
  while i < dirs.len:
    try:
      createDir(dirs[i])
    except CatchableError as exc:
      return (false, dirs[i] & ": " & exc.msg)
    i = i + 1
  result = (true, "")

proc appNames*(h: GeistHome): seq[string] {.role: parser,
    tag: "status|storageIo".} =
  ## h: the applications that have actually stored something here.
  var
    t: string = ""
  result = @[]
  if not dirExists(h.dbDir()):
    return
  for kind, path in walkDir(h.dbDir()):
    if kind == pcDir:
      t = path.extractFilename()
      if t.len > 0 and not t.startsWith("."):
        result.add t

proc describeHome*(h: GeistHome): string {.role: helper,
    tag: "docs|status".} =
  ## h: the folder drawn as a tree, for a status line or a `--help`.
  ##
  ## Prints what is THERE, marking what is not, so the answer to "why is
  ## my database empty" is one command rather than an `ls` of six paths.
  var
    L: seq[string] = @[]
    apps: seq[string] = h.appNames()
    i: int = 0
  L.add h.base & (if h.explicit: "   (explicit)" else: "   (default for " &
    (if h.role == nrServer: "a server)" else: "a client)"))
  L.add "  config/   " & (if dirExists(h.configDir()): "" else: "-- missing")
  L.add "  keys/     " & (if dirExists(h.keysDir()): "" else: "-- missing")
  L.add "  peers/    " & (if dirExists(h.peersDir()): "" else: "-- missing")
  L.add "  db/       " & (if dirExists(h.dbDir()): "" else: "-- missing")
  while i < apps.len:
    L.add "    " & apps[i] & "/"
    i = i + 1
  if apps.len == 0 and dirExists(h.dbDir()):
    L.add "    (no application has stored anything yet)"
  L.add "  spool/    " & (if dirExists(h.spoolDir()): "" else: "-- missing")
  L.add "  logs/     " & (if dirExists(h.logDir()): "" else: "-- missing")
  result = L.join("\n")
