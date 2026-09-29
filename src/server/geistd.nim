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

import ./geistd_config

export geistd_config

type
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
    pushed*: int
    writable*: bool

var
  shutdownRequested: bool = false

proc requestShutdown*() {.role: actor,
    tag: "entrypoint|lifecycle|server".} =
  ## Ask the serve loop to stop after the request in flight.
  shutdownRequested = true

when defined(posix):
  import std/posix

  proc onSignal(sig: cint) {.role: actor, noconv.} =
    ## sig: SIGTERM or SIGINT; only used to leave the loop cleanly.
    requestShutdown()

proc installSignalHandlers*() {.role: orchestrator,
    tag: "entrypoint|lifecycle|server".} =
  ## Make SIGTERM and SIGINT request a graceful stop.
  when defined(posix):
    signal(SIGTERM, onSignal)
    signal(SIGINT, onSignal)

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
    now: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    parts: tuple[dir, name: string] = ("", "")
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

## ------------------------------ starting ----------------------------
##
##   resolveConfig -> daemonIdentity -> openDaemonState
##                                   -> startServer   (when it serves)
##                                   -> startAgent    (when it visits)
##                 -> the loop: serveStep and/or syncStep, until stopped

proc daemonIdentity(c: DaemonConfig): AmeIdentityKey {.role: dataFetcher,
    tag: "cryptoBoundary|server".} =
  ## c: this daemon's signing identity, created on first start. Raises
  ## when there is none to use.
  var
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
  if c.identity.len == 0:
    raise newException(ValueError,
      "--identity is required: a daemon that mints a fresh key on every " &
      "start can never be pinned by a peer")
  mine = loadOrCreateIdentity(c.identity, resolveIdentityPassword(c),
    c.subject, geistSignatureSlots())
  if not mine.ok:
    raise newException(IOError, mine.err)
  result = mine.key

proc writePinOut(c: DaemonConfig, key: AmeIdentityKey) {.role: dataWriter,
    tag: "cryptoBoundary|server|write".} =
  ## c/key: the shareable half of this daemon's identity, to --pin-out.
  var
    written: tuple[ok: bool, err: string] = savePin(c.pinOut, pinOf(key))
  if not written.ok:
    raise newException(IOError, written.err)
  echo "wrote ", c.pinOut, "  <- hand this to peers"
  echo ""
  echo describePin(pinOf(key))

proc openDaemonState(c: DaemonConfig): DaemonState {.role: orchestrator,
    tag: "server|storageIo".} =
  ## c: the database this daemon holds.
  ##
  ## A daemon rows only ever LEAVE follows its database and takes no lease,
  ## so `geist put` on the same machine keeps working. One rows ARRIVE at --
  ## a peer allowed to write, or a peer it pulls from -- is a writer and
  ## holds the lease like any other.
  var
    parts: tuple[dir, name: string] = storeParts(c.path)
    seen: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  result.writable = c.needsWriting()
  result.cursors = initTable[string, uint64]()
  result.session = openSessionWithSchema(parts.dir, parts.name, Schema(),
    daemonConfigFor(c), resolvePassword(c), readOnly = not result.writable)
  if result.writable and result.session.readOnly:
    raise newException(IOError, "receiving rows needs the write lease, and " &
      result.session.leaseHolder)
  result.dataPath = result.session.dataPath()
  seen = observe(result.dataPath)
  if seen.ok:
    result.seen = seen.f

proc startServer(c: DaemonConfig, key: AmeIdentityKey): GeistServer {.
    role: orchestrator, tag: "networkSurface|server".} =
  ## c/key: the bound socket and its trust list. Raises on failure.
  var
    address: tuple[ok: bool, a: GeistDacAddress] = parseDacAddress(c.listen)
    trusted: tuple[ok: bool, peers: seq[TrustedPeer], err: string] =
      (false, @[], "")
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
  if not address.ok:
    raise newException(ValueError,
      "--listen must be dac://host:port, got '" & c.listen & "'")
  trusted = trustListFrom(c.trust, c.allowWrite)
  if not trusted.ok:
    raise newException(IOError, trusted.err)
  server = initGeistServer(address.a, key, trusted.peers,
    defaultTierPolicy(), int64(c.idleSeconds),
    transportDefaults().requireCookie)
  if not server.ok:
    raise newException(IOError, server.err)
  result = server.server

proc startAgent(c: DaemonConfig, key: AmeIdentityKey): SyncAgent {.
    role: orchestrator, tag: "networkSurface|server|sync".} =
  ## c/key: the peers this daemon visits itself. Raises on a bad spec or
  ## an unreadable pin -- at start, not an hour later on the first visit.
  var
    plan: tuple[ok: bool, plan: SyncPlan, err: string] = syncPlanFor(c)
  if not plan.ok:
    raise newException(ValueError, plan.err)
  # --timeout-ms is how long the SERVER waits for a frame, a poll window; a
  # request to a peer needs a whole handshake, so it keeps its own limit.
  result = initSyncAgent(key, plan.plan, defaultTierPolicy())

proc announce(S: DaemonState, c: DaemonConfig, key: AmeIdentityKey,
    server: GeistServer, agent: SyncAgent) {.role: dataWriter,
    tag: "server|status".} =
  ## S/c/key/server/agent: one screen saying what this daemon will do.
  echo "geistd holding ", S.dataPath
  echo "  rows:    ", S.session.entryCount(), " visible, ",
    S.session.logCount(), " stored"
  echo "  subject: ", key.subject
  echo "  mode:    ", (if S.writable: "read-write (holds the write lease)"
    else: "read-only (takes no lease)")
  if c.isServer():
    echo "  listen:  ", c.listen
  for t in server.trusted:
    echo "  trusts:  ", t.pin.subject,
      (if prWrite in t.rights: "  (may write)" else: "  (read only)")
  for p in agent.plan.peers:
    echo "  visits:  ", p.name, " at ", p.endpoint, " (", p.way,
      ") every ", agent.plan.everySeconds, "s"

## ------------------------------ running -----------------------------

proc serveStep(S: var DaemonState, c: DaemonConfig,
    server: var GeistServer): bool {.role: orchestrator,
    tag: "networkSurface|server".} =
  ## S/c/server: wait up to --timeout-ms for one frame and answer it.
  ## Returns true when --oneshot or --max-requests says to stop.
  var
    state: ptr DaemonState = addr S
    step: tuple[ok: bool, served: bool, err: string] = serveOnce(server,
      proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
        {.cast(gcsafe).}:
          result = handleQuery(state[], q, p),
      c.timeoutMs)
  if step.served:
    S.served = S.served + 1
  if step.served and not c.quiet:
    echo "[", now().format("HH:mm:ss"), "] served request ", S.served,
      " (", server.peerCount(), " peer session(s))"
  # An idle window is ok = true with served = false, so only a real
  # failure reaches this line.
  if not step.ok and not c.quiet:
    echo "request failed: ", step.err
  result = (c.oneshot and step.served) or
    (c.maxRequests > 0 and S.served >= c.maxRequests)

proc syncStep(S: var DaemonState, c: DaemonConfig, agent: var SyncAgent) {.
    role: orchestrator, tag: "networkSurface|server|sync".} =
  ## S/c/agent: visit every planned peer when the plan is due.
  for r in S.session.tick(agent):
    S.applied = S.applied + r.pulled
    S.pushed = S.pushed + r.pushed
    if not c.quiet:
      echo "[", now().format("HH:mm:ss"), "] ", r.peer, ": pulled ",
        r.pulled, ", pushed ", r.pushed,
        (if r.ok: "" else: "  FAILED: " & r.err)

proc runLoop(S: var DaemonState, c: DaemonConfig, server: var GeistServer,
    agent: var SyncAgent) {.role: metaOrchestrator,
    tag: "networkSurface|server|sync".} =
  ## S/c/server/agent: until a signal, --oneshot or --max-requests. A
  ## client-only daemon has no socket to wait on, so it waits --timeout-ms
  ## between turns instead.
  var
    stop: bool = false
  while not shutdownRequested and not stop:
    if reloadIfChanged(S, c) and not c.quiet:
      echo "reloaded: file changed underneath (", S.session.entryCount(),
        " rows)"
    if c.isServer():
      stop = serveStep(S, c, server)
    else:
      sleep(c.timeoutMs)
    if c.isClient():
      syncStep(S, c, agent)

proc runGeistd*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    c: DaemonConfig = default(DaemonConfig)
    S: DaemonState = default(DaemonState)
    key: AmeIdentityKey = default(AmeIdentityKey)
    server: GeistServer = default(GeistServer)
    agent: SyncAgent = default(SyncAgent)
    written: tuple[ok: bool, err: string] = (false, "")
  # A fresh run: a stop asked of an EARLIER run in this process (a test,
  # or a program that embeds the daemon) must not end this one at once.
  shutdownRequested = false
  try:
    c = resolveConfig(argv)
    if c.help:
      echo usageText
      return 0
    installSignalHandlers()
    # configs/default.toml carries the library defaults every preset is
    # adjusted by.
    written = initGeistNetworkDefaults()
    if not written.ok:
      raise newException(ValueError, written.err)
    key = daemonIdentity(c)
    if c.pinOut.len > 0:
      writePinOut(c, key)
      return 0
    if c.isClient():
      agent = startAgent(c, key)
    S = openDaemonState(c)
    if c.isServer():
      server = startServer(c, key)
    if not c.quiet:
      announce(S, c, key, server, agent)
    runLoop(S, c, server, agent)
    agent.closeAgent()
    if c.isServer():
      server.closeServer()
    S.session.close()
    if not c.quiet:
      echo "stopped after ", S.served, " request(s); ", S.applied,
        " row(s) received, ", S.pushed, " sent, ", S.reloads, " reload(s)"
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geistd: " & exc.msg)
    result = 1

when isMainModule:
  quit(runGeistd(commandLineParams()))
