## ---------------------------------------------------------------------
## geistd <- serve one database over Bifrost AME/DAC
## ---------------------------------------------------------------------
##
##   geistd --path data/notes --listen dac://127.0.0.1:47655
##
##   client Query --DAC--> geistd --> handleQuery --> Reply --DAC--> client
##
## The daemon holds the session, so the password never leaves the host it
## runs on. Re-keying, backup and restore stay direct-mode CLI work: they
## are local file operations, and sending key material to a daemon to have
## it do them would widen the trust boundary for nothing.
##
## WHAT A PEER MAY DO comes from its pin, not from its request:
##
##   --trust  <file.pin>       may read
##   --allow-write <file.pin>  may read AND send rows
##
## Two desktops exchanging a database is the point. Each runs a geistd,
## each lists the other's pin, and each pushes what it has:
##
##   desktop A                          desktop B
##   ---------                          ---------
##   geistd --allow-write B.pin  <-->   geistd --allow-write A.pin
##        ^                                  ^
##        |  qoSync "from my cursor"         |
##        +----------------------------------+
##        |  qoPut  "here are my rows"       |
##        +----------------------------------+
##
## Rows carry their own identity, so applying one reproduces the sender's
## operation exactly -- an add, a replacement or a removal, all the same
## call. See `applyRow` in session.nim.
##
## The daemon FOLLOWS its database rather than owning it: it opens
## read-only when it only serves reads, so `geist put` on the same machine
## keeps working, and it re-reads the file when it changes underneath. That
## check costs one index read, a few hundred bytes, not a full load.
##
## Serving a write needs the write lease, so `--allow-write` opens the
## database for writing and a direct CLI write is refused while the daemon
## runs. One writer per store root, whoever it is.

import std/[os, strutils, tables, times]

import runePragmas
import ../geist/network

type
  DaemonConfig* {.role: configurator, tag: "config|entrypoint|server|types".} = object
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
    configFile*: string
    oneshot*: bool
    quiet*: bool
    ## given: the long option names ACTUALLY TYPED. `--preset app` and
    ## `--listen dac://127.0.0.1:47655` are both things an operator writes
    ## on purpose, and both happen to equal the built-in default, so the
    ## value alone cannot say whether a config file may overwrite them.
    given*: seq[string]

  DaemonState* {.role: truthState, tag: "server|status|types".} = object
    ## session: the database, open for the whole life of the daemon.
    ## cursors: one log position per named subscription, kept HERE rather
    ##   than in the session, because a reload replaces the session and a
    ##   subscriber's position must survive that.
    ## writable: whether any peer was granted write rights, which decides
    ##   whether the session takes the write lease at all.
    session*: Session
    seen*: GeistFile
    dataPath*: string
    cursors*: Table[string, uint64]
    served*: int
    reloads*: int
    applied*: int
    writable*: bool

const
  usageText = """
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
  --config <file>           userconfig.toml to read; defaults to the one in
                            the working directory, then ~/.config/geist
  --oneshot                 serve exactly one request and exit
  --quiet                   suppress per-request logging
"""

var
  shutdownRequested: bool = false

proc requestShutdown*() {.role: actor,
    tag: "entrypoint|lifecycle|server".} =
  ## Ask the serve loop to stop after the request in flight.
  shutdownRequested = true

when defined(posix):
  import std/posix

  proc onSignal(sig: cint) {.noconv.} =
    ## sig: SIGTERM or SIGINT; only used to leave the loop cleanly.
    requestShutdown()

proc installSignalHandlers*() {.role: orchestrator,
    tag: "entrypoint|lifecycle|server".} =
  ## Make SIGTERM and SIGINT request a graceful stop.
  when defined(posix):
    signal(SIGTERM, onSignal)
    signal(SIGINT, onSignal)

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
    of "config": result.configFile = value
    of "oneshot": result.oneshot = true
    of "quiet": result.quiet = true
    of "help":
      echo usageText
      quit(0)
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
    loaded: tuple[ok: bool, user: UserConfig, err: string]
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

proc resolveConfig*(argv: openArray[string]): DaemonConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line, merged with userconfig.toml and then checked.
  ## The check happens AFTER the merge, or a setting supplied by the file
  ## would be reported missing.
  result = withUserConfig(parseArgs(argv))
  if result.path.len == 0:
    raise newException(ValueError,
      "--path is required (or [database] path in userconfig.toml)")

proc resolvePassword(c: DaemonConfig): string {.role: sanitizer,
    tag: "cryptoBoundary|server".} =
  ## c: daemon config. A password file wins over the inline form, which is
  ## visible in the process list.
  if c.passwordFile.len > 0:
    if not fileExists(c.passwordFile):
      raise newException(IOError, "no password file at " & c.passwordFile)
    return readFile(c.passwordFile).strip()
  result = c.password

proc resolveIdentityPassword(c: DaemonConfig): string {.role: sanitizer,
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

proc storeParts(path: string): tuple[dir, name: string] {.role: parser,
    tag: "parsing|server|storageIo".} =
  ## path: directory, or a `<dir>/<name>` stem.
  result.dir = path
  result.name = "main"
  if path.splitFile().ext.len > 0:
    result.dir = path.parentDir()
    result.name = path.splitFile().name

proc collectTrust(c: DaemonConfig): tuple[ok: bool, peers: seq[TrustedPeer],
    err: string] {.role: configurator,
    tag: "cryptoBoundary|server".} =
  ## c: daemon config whose pin files become the trust list.
  ##
  ## The FLAG grants the right, not the peer: `--trust` may read,
  ## `--allow-write` may also send rows. A pin listed under both gets the
  ## union, because the operator clearly meant to allow the wider one.
  var
    i: int = 0
    loaded: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string]
    at: int = -1
    j: int = 0
  while i < c.trust.len + c.allowWrite.len:
    loaded = loadPin(if i < c.trust.len: c.trust[i]
                     else: c.allowWrite[i - c.trust.len])
    if not loaded.ok:
      return (false, @[], loaded.err)
    at = -1
    j = 0
    while j < result.peers.len:
      if result.peers[j].pin.subject == loaded.pin.subject:
        at = j
      j = j + 1
    if at >= 0:
      if i >= c.trust.len:
        result.peers[at].rights.incl prWrite
    else:
      result.peers.add TrustedPeer(pin: loaded.pin,
        rights: if i < c.trust.len: {prRead} else: {prRead, prWrite})
    i = i + 1
  result.ok = true

proc daemonConfigFor(c: DaemonConfig): GeistConfig {.role: configurator,
    tag: "config|server".} =
  ## c: daemon options resolved to the configuration a session opens with.
  ## The preset the operator named, adjusted by whatever config.toml sets
  ## for this installation.
  result = applyDefaults(geistConfigPreset(c.preset), geistDefaults())

proc reloadIfChanged*(S: var DaemonState,
    c: DaemonConfig): bool {.role: actor,
    tag: "server|status|storageIo".} =
  ## S: daemon state whose session is refreshed when the file moved.
  ## c: config supplying the preset and password to reopen with.
  ## Costs ONE index read per call -- header plus cluster index -- so it
  ## is cheap enough to run before every request. This is the fix for the
  ## previous daemon, which loaded a snapshot once and then wrote it back
  ## over whatever had changed underneath.
  var
    now: tuple[ok: bool, f: GeistFile, err: string]
    parts: tuple[dir, name: string]
    changed: seq[int] = @[]
  parts = storeParts(c.path)
  # A writable daemon IS the writer: its own saves move the file, and
  # reopening would throw away rows a peer just pushed and has been told
  # were stored. Only a follower reloads.
  if S.writable:
    return false
  # Resolve the live generation every time: a writer publishes a NEW file on
  # every save, so a remembered path stops existing rather than changing.
  now = observe(liveDataPath(parts.dir, parts.name))
  if not now.ok:
    return false
  changed = changedClusters(S.seen, now.f)
  if changed.len == 0 and S.seen.header.generation == now.f.header.generation:
    return false
  S.session.close()
  S.session = openSessionWithSchema(parts.dir, parts.name, Schema(),
    daemonConfigFor(c), resolvePassword(c), readOnly = true)
  S.dataPath = S.session.dataPath()
  S.seen = now.f
  S.reloads = S.reloads + 1
  result = true

proc handleQuery*(S: var DaemonState, q: Query, p: PeerContext): Reply {.
    role: actor, tag: "appApi|db|read|server".} =
  ## S/q/p: the daemon's thin wrapper around `answerQuery`.
  ##
  ## What the protocol MEANS lives in the library (geist/answer.nim), so an
  ## application embedding Geist gets the same semantics without importing a
  ## program. All the daemon adds is its own accounting.
  result = answerQuery(S.session, S.cursors, q, p)
  if q.op in {qoPut, qoDelete} and result.ok:
    S.applied = S.applied + int(result.matched)

proc runGeistd*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    c: DaemonConfig
    S: DaemonState
    parts: tuple[dir, name: string]
    address: tuple[ok: bool, a: GeistDacAddress]
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string]
    trusted: tuple[ok: bool, peers: seq[TrustedPeer], err: string]
    written: tuple[ok: bool, err: string]
    server: tuple[ok: bool, server: GeistServer, err: string]
    step: tuple[ok: bool, served: bool, err: string]
    seen: tuple[ok: bool, f: GeistFile, err: string]
  try:
    c = resolveConfig(argv)
    installSignalHandlers()
    # config.toml carries the library defaults every preset is adjusted by.
    written = initGeistNetworkDefaults()
    if not written.ok:
      raise newException(ValueError, written.err)
    address = parseDacAddress(c.listen)
    if not address.ok:
      raise newException(ValueError,
        "--listen must be dac://host:port, got '" & c.listen & "'")
    if c.identity.len == 0:
      raise newException(ValueError,
        "--identity is required: a daemon that mints a fresh key on every " &
        "start can never be pinned by a client")
    mine = loadOrCreateIdentity(c.identity, resolveIdentityPassword(c),
      c.subject, geistSignatureSlots())
    if not mine.ok:
      raise newException(IOError, mine.err)
    if c.pinOut.len > 0:
      written = savePin(c.pinOut, pinOf(mine.key))
      if not written.ok:
        raise newException(IOError, written.err)
      echo "wrote ", c.pinOut, "  <- hand this to clients"
      echo ""
      echo describePin(pinOf(mine.key))
      return 0
    if c.trust.len == 0 and c.allowWrite.len == 0:
      raise newException(ValueError,
        "--trust <peer.pin> (or --allow-write) is required: without a pin " &
        "there is no peer to trust, and every handshake would be refused")
    trusted = collectTrust(c)
    if not trusted.ok:
      raise newException(IOError, trusted.err)
    parts = storeParts(c.path)
    # A daemon that may only be READ follows the database and takes no
    # lease, so `geist put` on the same machine keeps working. One that may
    # be written to IS a writer and must hold the lease like any other.
    S.writable = c.allowWrite.len > 0
    S.cursors = initTable[string, uint64]()
    S.session = openSessionWithSchema(parts.dir, parts.name, Schema(),
      daemonConfigFor(c), resolvePassword(c),
      readOnly = not S.writable)
    if S.writable and S.session.readOnly:
      raise newException(IOError,
        "--allow-write needs the write lease, and " &
        S.session.leaseHolder)
    S.dataPath = S.session.dataPath()
    seen = observe(S.dataPath)
    if seen.ok:
      S.seen = seen.f
    server = initGeistServer(address.a, mine.key, trusted.peers,
      defaultTierPolicy(), int64(c.idleSeconds))
    if not server.ok:
      raise newException(IOError, server.err)
    if not c.quiet:
      echo "geistd serving ", S.dataPath
      echo "  rows:    ", S.session.entryCount(), " visible, ",
        S.session.logCount(), " stored"
      echo "  listen:  ", c.listen
      echo "  subject: ", mine.key.subject
      echo "  mode:    ", (if S.writable: "read-write (holds the write lease)"
        else: "read-only (takes no lease)")
      for t in trusted.peers:
        echo "  trusts:  ", t.pin.subject,
          (if prWrite in t.rights: "  (may write)" else: "  (read only)")
    while not shutdownRequested:
      if reloadIfChanged(S, c) and not c.quiet:
        echo "reloaded: file changed underneath (", S.session.entryCount(),
          " rows)"
      step = serveOnce(server.server,
        proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
          {.cast(gcsafe).}:
            result = handleQuery(S, q, p),
        c.timeoutMs)
      if step.served:
        S.served = S.served + 1
        if not c.quiet:
          echo "[", now().format("HH:mm:ss"), "] served request ", S.served,
            " (", server.server.peerCount(), " peer session(s))"
      elif not step.ok and not c.quiet:
        # An idle window is ok = true with served = false, so only a real
        # failure reaches this line.
        echo "request failed: ", step.err
      if c.oneshot and step.served:
        break
      if c.maxRequests > 0 and S.served >= c.maxRequests:
        break
    server.server.closeServer()
    S.session.close()
    if not c.quiet:
      echo "stopped after ", S.served, " request(s), ", S.applied,
        " row(s) applied from peers, ", S.reloads, " reload(s)"
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geistd: " & exc.msg)
    result = 1

when isMainModule:
  quit(runGeistd(commandLineParams()))
