## ---------------------------------------------------------------------
## geistd config <- what the operator asked for, from flags and file
## ---------------------------------------------------------------------
##
##   command line --parseArgs--> DaemonConfig --withUserConfig--> checked
##                                               (userconfig.toml fills in
##                                                only what was not typed)
##
## Everything here decides WHAT the daemon will do; nothing here does it.
## `geistd.nim` takes the finished DaemonConfig and runs.
##
## A daemon plays up to two parts, each switched on by its own options:
##
##   part      options                         what it means
##   --------  ------------------------------  ---------------------------
##   server    --trust, --allow-write          peers dial in, read, write
##   client    --pull, --push, --sync,         this daemon dials peers on a
##             --sync-every                    timer, reads and/or writes
##
## Either, or both. A daemon with neither has nothing to do and refuses to
## start.

import std/[os, strutils]

import runePragmas
import ../geist/network

type
  DaemonConfig* {.
      role: configurator, tag: "config|entrypoint|server|types".} = object
    path*: string
    listen*: string
    preset*: string
    password*: string
    passwordFile*: string
    subject*: string
    identity*: string
    identityPassword*: string
    identityPasswordFile*: string
    trust*: seq[string]
    allowWrite*: seq[string]
    pinOut*: string
    maxRequests*: int
    timeoutMs*: int
    idleSeconds*: int
    pull*: seq[string]
    push*: seq[string]
    sync*: seq[string]
      ## pull/push/sync: peers THIS daemon dials, each
      ##   `<pin file>@dac://host:port`. Repeatable flags.
    syncEvery*: int
      ## seconds between two visits to every sync peer.
    configFile*: string
    oneshot*: bool
    quiet*: bool
    help*: bool
      ## --help was asked for: print the usage and stop, before anything
      ## is checked or opened.
    ## given: the long option names ACTUALLY TYPED. `--preset app` and
    ## `--listen dac://127.0.0.1:47655` are both things an operator writes
    ## on purpose, and both happen to equal the built-in default, so the
    ## value alone cannot say whether a config file may overwrite them.
    given*: seq[string]


const
  usageText* = """
geistd --path <dir> [options]

  --path <dir>              database directory to serve
  --listen dac://host:port  endpoint to bind, default dac://127.0.0.1:47655
  --preset <name>           config preset, default app
  --password <text>         at-rest password (prefer --password-file)
  --password-file <file>    read the password from a file
  --subject <name>          local identity subject, default geistd
  --identity <file>         signing identity; created on first start
  --identity-password <t>   password sealing the identity's secret keys
  --identity-password-file <file>  read that password from a file
  --trust <file>            peer pin allowed to READ; repeatable
  --allow-write <file>      peer pin allowed to read AND send rows;
                            repeatable. Implies the write lease.
  --pin-out <file>          write this daemon's shareable pin and exit
  --max-requests <n>        stop after n requests, 0 means forever
  --timeout-ms <n>          socket poll window, default 1000
  --idle-seconds <n>        drop a silent peer session, default 900

  as a client too -- this daemon dials these peers itself, every --sync-every:
  --pull <pin>@dac://h:p    fetch that peer's rows into this database
  --push <pin>@dac://h:p    send this database's rows to that peer (it must
                            list this daemon under --allow-write)
  --sync <pin>@dac://h:p    both; each of the three is repeatable
  --sync-every <seconds>    default 60

  --config <file>           userconfig.toml to read; defaults to the one in
                            the working directory, then ~/.config/geist
  --oneshot                 serve exactly one request and exit
  --quiet                   suppress per-request logging
"""

proc parseArgs*(argv: openArray[string]): DaemonConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    at: int = 0
  result.listen = "dac://127.0.0.1:47655"
  result.preset = "app"
  result.subject = "geistd"
  # A poll window, not a request deadline: the loop now waits this long for
  # any frame from any peer and goes round again, so a short value costs
  # nothing but a wakeup and keeps shutdown responsive.
  result.timeoutMs = 1000
  result.idleSeconds = 900
  result.syncEvery = 60
  while i < argv.len:
    if not argv[i].startsWith("--"):
      raise newException(ValueError, "unexpected argument '" & argv[i] & "'")
    key = argv[i][2 .. ^1]
    value = ""
    at = key.find('=')
    if at > 0:
      value = key[at + 1 .. ^1]
      key = key[0 ..< at]
    elif key notin ["oneshot", "quiet", "help", "print-pin"]:
      if i + 1 >= argv.len:
        raise newException(ValueError, "option --" & key & " needs a value")
      value = argv[i + 1]
      i = i + 1
    case key
    of "path": result.path = value
    of "listen": result.listen = value
    of "preset": result.preset = value
    of "password": result.password = value
    of "password-file": result.passwordFile = value
    of "subject": result.subject = value
    of "identity": result.identity = value
    of "identity-password": result.identityPassword = value
    of "identity-password-file": result.identityPasswordFile = value
    # Repeatable, because a desktop trusts however many other desktops it
    # trusts. Each pin arrives with the rights the flag itself grants.
    of "trust": result.trust.add value
    of "allow-write": result.allowWrite.add value
    of "pin-out": result.pinOut = value
    of "max-requests": result.maxRequests = parseInt(value)
    of "timeout-ms": result.timeoutMs = parseInt(value)
    of "idle-seconds": result.idleSeconds = parseInt(value)
    of "pull": result.pull.add value
    of "push": result.push.add value
    of "sync": result.sync.add value
    of "sync-every": result.syncEvery = parseInt(value)
    of "config": result.configFile = value
    of "oneshot": result.oneshot = true
    of "quiet": result.quiet = true
    of "help": result.help = true
    else:
      raise newException(ValueError, "unknown option --" & key)
    result.given.add key
    i = i + 1

proc withUserConfig(c: DaemonConfig): DaemonConfig {.role: configurator,
    tag: "config|parsing|server".} =
  ## c: options straight off the command line.
  ##
  ## Fills in only what was NOT given. A daemon is the thing most likely
  ## to be started by a service manager with no arguments at all, so the
  ## file carries the whole deployment -- but an argument still wins, or
  ## debugging one by hand would be impossible.
  var
    where: string = ""
    loaded: tuple[ok: bool, user: UserConfig, err: string] =
      (false, default(UserConfig), "")
  result = c
  where = firstExisting(userConfigCandidates(c.configFile))
  if where.len == 0:
    if c.configFile.len > 0:
      raise newException(IOError, "no config file at " & c.configFile)
    return
  loaded = loadUserConfig(where)
  if not loaded.ok:
    raise newException(ValueError, loaded.err)
  # "Was it typed?", not "does it still look like the default?".
  if "path" notin result.given:
    result.path = loaded.user.path
  if "preset" notin result.given and loaded.user.preset.len > 0:
    result.preset = loaded.user.preset
  if "password-file" notin result.given:
    result.passwordFile = loaded.user.passwordFile
  if "listen" notin result.given and loaded.user.listen.len > 0:
    result.listen = loaded.user.listen
  if "identity" notin result.given:
    result.identity = loaded.user.identity
  if "identity-password-file" notin result.given:
    result.identityPasswordFile = loaded.user.identityPasswordFile
  if "trust" notin result.given:
    result.trust = loaded.user.trust
  if "allow-write" notin result.given:
    result.allowWrite = loaded.user.allowWrite
  if "pull" notin result.given:
    result.pull = loaded.user.pull
  if "push" notin result.given:
    result.push = loaded.user.push
  if "sync" notin result.given:
    result.sync = loaded.user.sync
  if "sync-every" notin result.given and loaded.user.syncEverySeconds > 0:
    result.syncEvery = loaded.user.syncEverySeconds

proc isServer*(c: DaemonConfig): bool {.role: parser, inline,
    tag: "config|server".} =
  ## c: does any peer get to dial in? Then a socket is bound.
  result = c.trust.len > 0 or c.allowWrite.len > 0

proc isClient*(c: DaemonConfig): bool {.role: parser, inline,
    tag: "config|server|sync".} =
  ## c: does this daemon dial any peer itself?
  result = c.pull.len + c.push.len + c.sync.len > 0

proc needsWriting*(c: DaemonConfig): bool {.role: parser, inline,
    tag: "config|server".} =
  ## c: will rows land in this database -- from a peer allowed to write,
  ## or from a peer this daemon pulls from? Then it holds the write lease.
  result = c.allowWrite.len > 0 or c.pull.len > 0 or c.sync.len > 0

proc resolveConfig*(argv: openArray[string]): DaemonConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line, merged with userconfig.toml and then checked.
  ## The check happens AFTER the merge, or a setting supplied by the file
  ## would be reported missing.
  result = withUserConfig(parseArgs(argv))
  if result.help:
    return
  if result.path.len == 0:
    raise newException(ValueError,
      "--path is required (or [database] path in userconfig.toml)")
  if not result.isServer() and not result.isClient() and
      result.pinOut.len == 0:
    raise newException(ValueError,
      "nothing to do: give --trust or --allow-write to serve peers, and/or " &
      "--pull, --push or --sync to visit them")

proc resolvePassword*(c: DaemonConfig): string {.role: sanitizer,
    tag: "cryptoBoundary|server".} =
  ## c: daemon config. A password file wins over the inline form, which is
  ## visible in the process list.
  if c.passwordFile.len > 0:
    if not fileExists(c.passwordFile):
      raise newException(IOError, "no password file at " & c.passwordFile)
    return readFile(c.passwordFile).strip()
  result = c.password

proc resolveIdentityPassword*(c: DaemonConfig): string {.role: sanitizer,
    tag: "cryptoBoundary|server".} =
  ## c: daemon config. Falls back to the at-rest password so a simple
  ## deployment needs one secret, but keeping them separate is better.
  if c.identityPasswordFile.len > 0:
    if not fileExists(c.identityPasswordFile):
      raise newException(IOError,
        "no identity password file at " & c.identityPasswordFile)
    return readFile(c.identityPasswordFile).strip()
  if c.identityPassword.len > 0:
    return c.identityPassword
  result = resolvePassword(c)

proc storeParts*(path: string): tuple[dir, name: string] {.role: parser,
    tag: "parsing|server|storageIo".} =
  ## path: directory, or a `<dir>/<name>` stem.
  result.dir = path
  result.name = "main"
  if path.splitFile().ext.len > 0:
    result.dir = path.parentDir()
    result.name = path.splitFile().name

proc peerAt(P: openArray[TrustedPeer], subject: string): int {.role: parser,
    tag: "cryptoBoundary|server".} =
  ## P/subject: where that pin already sits in the list, or -1.
  var
    j: int = 0
  while j < P.len:
    if P[j].pin.subject == subject:
      return j
    j = j + 1
  result = -1

proc collectTrust*(c: DaemonConfig): tuple[ok: bool, peers: seq[TrustedPeer],
    err: string] {.role: configurator,
    tag: "cryptoBoundary|server".} =
  ## c: daemon config whose pin files become the trust list.
  ##
  ## The FLAG grants the right, not the peer: `--trust` may read,
  ## `--allow-write` may also send rows. A pin listed under both gets the
  ## union, because the operator clearly meant to allow the wider one.
  var
    i: int = 0
    loaded: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    at: int = -1
  while i < c.trust.len + c.allowWrite.len:
    loaded = loadPin(if i < c.trust.len: c.trust[i]
                     else: c.allowWrite[i - c.trust.len])
    if not loaded.ok:
      return (false, @[], loaded.err)
    at = peerAt(result.peers, loaded.pin.subject)
    if at >= 0:
      if i >= c.trust.len:
        result.peers[at].rights.incl prWrite
    else:
      result.peers.add TrustedPeer(pin: loaded.pin,
        rights: if i < c.trust.len: {prRead} else: {prRead, prWrite})
    i = i + 1
  result.ok = true

proc daemonConfigFor*(c: DaemonConfig): GeistConfig {.role: configurator,
    tag: "config|server".} =
  ## c: daemon options resolved to the configuration a session opens with.
  ## The preset the operator named, adjusted by whatever configs/default.toml sets
  ## for this installation.
  result = applyDefaults(geistConfigPreset(c.preset), geistDefaults())


proc syncPlanFor*(c: DaemonConfig): tuple[ok: bool, plan: SyncPlan,
    err: string] {.role: dataFetcher, tag: "config|server|sync".} =
  ## c: the client part of the daemon as a plan, pins read from disk.
  result = syncPlanFrom(c.pull, c.push, c.sync, c.syncEvery)
