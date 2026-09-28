## Keeping stores in step: same process, the agent over a real socket, and
## geistd visiting peers on its own.
##
##   suite                      what it holds down
##   -------------------------  ---------------------------------------------
##   same process               needLocal / offerLocal move rows, and a
##                              second call moves nothing (positions kept)
##   plans from text            `<pin>@dac://host:port`, the name it gets,
##                              and every way to write one wrong
##   the agent                  pull + push over a real socket; `tick` waits
##                              for the interval; a refused push is reported
##                              without losing the pull
##   geistd as a client         a daemon with no --trust, only --sync,
##                              catches up with a server on its own
##   geistd options             something to do is required; --pin-out alone
##                              still works

import std/[os, strutils, unittest]

import runePragmas
import geist/network
import server/geistd

type
  Note = object
    noteId: int
    title: string

  DeskArgs = object
    ## The serving side, run on its own thread. `ready`/`stop` are the only
    ## fields both threads touch, each written by one side.
    root: string
    listen: string
    identity: AmeIdentityKey
    peers: seq[TrustedPeer]
    ready: bool
    stop: bool
    rows: int
    err: string

  DaemonArgs = object
    ## geistd run on its own thread, and its exit code.
    argv: seq[string]
    code: int

proc deskAt(name: string, port: int, deskKey: AmeIdentityKey,
    guest: AmePinnedPeerIdentity, rights: set[PeerRight]): DeskArgs {.
    role: configurator.} =
  ## name/port: a fresh store and where it listens.
  ## deskKey/guest/rights: who the desk is, and the one peer it trusts.
  result = DeskArgs(root: getTempDir() / name,
    listen: "dac://127.0.0.1:" & $port, identity: deskKey,
    peers: @[TrustedPeer(pin: guest, rights: rights)])
  removeDir(result.root)
  createDir(result.root)

proc freshRoot(name: string): string {.role: helper.} =
  ## name: an empty folder under the temp folder.
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc seed(root: string, titles: openArray[string]) {.role: dataWriter.} =
  ## root/titles: a store with one Note per title.
  var
    db: Session = openGeist[Note](root, appConfig())
    i: int = 0
  while i < titles.len:
    discard db.put(Note(noteId: i + 1, title: titles[i]))
    i = i + 1
  doAssert db.save().ok
  db.close()

proc countIn(root: string): int {.role: parser.} =
  ## root: how many visible rows a store holds, read without a lease.
  var
    db: Session = openGeist[Note](root, appConfig(), readOnly = true)
  result = int(db.entryCount())
  db.close()

proc runDesk(a: ptr DeskArgs) {.role: orchestrator.} =
  ## a: one store, served with `serveStore` until told to stop.
  var
    desk: Session = openGeist[Note](a.root, appConfig())
    cursors: SyncCursors = initSyncCursors()
    server: tuple[ok: bool, server: GeistServer, err: string] =
      initGeistServer(parseDacAddress(a.listen).a, a.identity, a.peers,
        defaultTriggerPolicy(), 900'i64, false)
  if not server.ok:
    a.err = server.err
    a.ready = true
    return
  a.ready = true
  while not a.stop:
    discard serveStore(desk, cursors, server.server, 50)
  a.rows = int(desk.entryCount())
  server.server.closeServer()
  desk.close()

proc deskThread(a: ptr DeskArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    runDesk(a)

proc daemonThread(a: ptr DaemonArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    a.code = runGeistd(a.argv)

proc startDesk(a: ptr DeskArgs, t: var Thread[ptr DeskArgs]) {.
    role: orchestrator.} =
  ## a/t: start the desk and wait until it listens.
  var
    spins: int = 0
  createThread(t, deskThread, a)
  while not a.ready and spins < 500:
    sleep(10)
    spins = spins + 1
  doAssert a.ready and a.err.len == 0, a.err

proc stopDesk(a: ptr DeskArgs, t: var Thread[ptr DeskArgs]) {.role: actor.} =
  ## a/t: stop the desk and wait for its thread.
  a.stop = true
  joinThread(t)

suite "same process":
  # {.testKind: tkIntegration, covers: "needLocal, offerLocal".}
  test "rows move both ways, and a second call moves nothing":
    var
      a: Session = openGeist[Note](freshRoot("geist_t_sa_local_a"), appConfig())
      b: Session = openGeist[Note](freshRoot("geist_t_sa_local_b"), appConfig())
      pulled: NeedOutcome = default(NeedOutcome)
      pushed: OfferOutcome = default(OfferOutcome)
    discard a.put(Note(noteId: 1, title: "from a"))
    check a.save().ok
    pulled = b.needLocal(a, "a")
    check pulled.ok
    check pulled.applied == 1
    check b.entryCount() == 1'u32
    discard b.put(Note(noteId: 2, title: "from b"))
    check b.save().ok
    pushed = b.offerLocal(a, "a")
    check pushed.ok
    check a.entryCount() == 2'u32
    # Positions are kept: nothing new, nothing moves.
    check b.needLocal(a, "a").applied == 0
    check b.offerLocal(a, "a").sent == 0
    a.close()
    b.close()

  # {.testKind: tkEdgeCase, covers: "needLocal".}
  test "a read-only store cannot be pulled into":
    var
      root: string = freshRoot("geist_t_sa_local_ro")
      src: Session = openGeist[Note](freshRoot("geist_t_sa_local_src"),
        appConfig())
      ro: Session = default(Session)
    seed(root, ["x"])
    ro = openGeist[Note](root, appConfig(), readOnly = true)
    discard src.put(Note(noteId: 1, title: "y"))
    check src.save().ok
    check not ro.needLocal(src, "src").ok
    ro.close()
    src.close()

suite "plans from text":
  # {.testKind: tkUnit, covers: "parseSyncSpec".}
  test "a spec names its pin, its endpoint, and itself":
    var
      p: SyncSpec = parseSyncSpec("peers/desk.pin@dac://10.0.0.2:47655")
    check p.ok
    check p.name == "desk"
    check p.pinPath == "peers/desk.pin"
    check p.endpoint == "dac://10.0.0.2:47655"

  # {.testKind: tkEdgeCase, covers: "parseSyncSpec".}
  test "a spec written wrong says how to write it":
    check not parseSyncSpec("desk.pin").ok
    check not parseSyncSpec("@dac://h:1").ok
    check not parseSyncSpec("desk.pin@").ok
    check parseSyncSpec("desk.pin@10.0.0.2:47655").err.contains("dac://")

  # {.testKind: tkEdgeCase, covers: "syncPlanFrom".}
  test "a pin that is not there stops the plan at start":
    var
      plan: tuple[ok: bool, plan: SyncPlan, err: string] =
        syncPlanFrom([], [], ["/nowhere/desk.pin@dac://127.0.0.1:1"], 30)
    check not plan.ok
    check plan.err.contains("desk.pin")

suite "the agent":
  # {.testKind: tkIntegration, covers: "syncOnce, tick, serveStore".}
  test "pull and push over a real socket, then wait for the interval":
    var
      phoneKey: AmeIdentityKey = geistIdentity("phone")
      deskKey: AmeIdentityKey = geistIdentity("desk")
      desk: DeskArgs = deskAt("geist_t_sa_desk1", 47941, deskKey,
        geistPeerPin(phoneKey), {prRead, prWrite})
      t: Thread[ptr DeskArgs] = default(Thread[ptr DeskArgs])
      phone: Session = default(Session)
      agent: SyncAgent = default(SyncAgent)
      reports: seq[SyncReport] = @[]
    seed(desk.root, ["on the desk"])
    phone = openGeist[Note](freshRoot("geist_t_sa_phone1"), appConfig())
    discard phone.put(Note(noteId: 9, title: "on the phone"))
    check phone.save().ok
    startDesk(addr desk, t)
    agent = initSyncAgent(phoneKey, SyncPlan(everySeconds: 3600,
      peers: @[SyncPeer(name: "desk", endpoint: desk.listen,
        pin: geistPeerPin(deskKey), way: swBoth)]))
    reports = phone.tick(agent, 1000'i64)
    check reports.len == 1
    check reports[0].ok
    check reports[0].pulled == 1
    check reports[0].pushed >= 1
    check phone.entryCount() == 2'u32
    # Not due again until the interval has passed.
    check phone.tick(agent, 1001'i64).len == 0
    check agent.syncDue(1000'i64 + 3600'i64)
    agent.closeAgent()
    phone.close()
    stopDesk(addr desk, t)
    check desk.rows == 2

  # {.testKind: tkEdgeCase, covers: "syncOnce".}
  test "a push the peer refuses is reported, and the pull still counts":
    var
      phoneKey: AmeIdentityKey = geistIdentity("phone")
      deskKey: AmeIdentityKey = geistIdentity("desk")
      desk: DeskArgs = deskAt("geist_t_sa_desk2", 47942, deskKey,
        geistPeerPin(phoneKey), {prRead})
      t: Thread[ptr DeskArgs] = default(Thread[ptr DeskArgs])
      phone: Session = default(Session)
      agent: SyncAgent = default(SyncAgent)
      reports: seq[SyncReport] = @[]
    seed(desk.root, ["readable"])
    phone = openGeist[Note](freshRoot("geist_t_sa_phone2"), appConfig())
    discard phone.put(Note(noteId: 9, title: "cannot be sent"))
    check phone.save().ok
    startDesk(addr desk, t)
    agent = initSyncAgent(phoneKey, SyncPlan(peers: @[SyncPeer(name: "desk",
      endpoint: desk.listen, pin: geistPeerPin(deskKey), way: swBoth)]))
    reports = phone.syncOnce(agent)
    check reports.len == 1
    check not reports[0].ok
    check reports[0].err.startsWith("push:")
    check reports[0].pulled == 1
    agent.closeAgent()
    phone.close()
    stopDesk(addr desk, t)
    check desk.rows == 1

suite "geistd as a client":
  # {.testKind: tkIntegration, covers: "runGeistd, syncStep".}
  test "a daemon with only --sync catches up with a server by itself":
    var
      keys: string = freshRoot("geist_t_sa_keys")
      mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
        loadOrCreateIdentity(keys / "node.id", "node-pw", "node",
          geistSignatureSlots())
      deskKey: AmeIdentityKey = geistIdentity("desk")
      desk: DeskArgs = default(DeskArgs)
      t: Thread[ptr DeskArgs] = default(Thread[ptr DeskArgs])
      node: DaemonArgs = default(DaemonArgs)
      td: Thread[ptr DaemonArgs] = default(Thread[ptr DaemonArgs])
      nodeRoot: string = freshRoot("geist_t_sa_node")
      spins: int = 0
    check mine.ok
    check savePin(keys / "desk.pin", geistPeerPin(deskKey)).ok
    desk = deskAt("geist_t_sa_desk3", 47943, deskKey, pinOf(mine.key),
      {prRead, prWrite})
    seed(desk.root, ["one", "two", "three"])
    startDesk(addr desk, t)
    node.argv = @["--path", nodeRoot, "--identity", keys / "node.id",
      "--identity-password", "node-pw",
      "--sync", keys / "desk.pin@" & desk.listen, "--sync-every", "0",
      "--timeout-ms", "100", "--quiet"]
    createThread(td, daemonThread, addr node)
    while spins < 300 and countIn(nodeRoot) < 3:
      sleep(50)
      spins = spins + 1
    requestShutdown()
    joinThread(td)
    stopDesk(addr desk, t)
    check node.code == 0
    check countIn(nodeRoot) == 3

suite "geistd options":
  # {.testKind: tkEdgeCase, covers: "resolveConfig".}
  test "a daemon with nothing to do refuses to start":
    expect ValueError:
      discard resolveConfig(@["--path", "x"])

  # {.testKind: tkUnit, covers: "resolveConfig, isClient, needsWriting".}
  test "--sync alone is a client, and a client that pulls holds the lease":
    var
      c: DaemonConfig = resolveConfig(@["--path", "x", "--sync",
        "a.pin@dac://127.0.0.1:1"])
    check c.isClient()
    check not c.isServer()
    check c.needsWriting()

  # {.testKind: tkRegression, pins: "--pin-out refused as nothing to do".}
  test "--pin-out alone is still enough":
    var
      c: DaemonConfig = resolveConfig(@["--path", "x", "--pin-out", "p.pin"])
    check c.pinOut == "p.pin"
