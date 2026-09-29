## Client -> VPS -> Home with ONE handshake: the forwarder moves bytes.
##
##   suite                 what it holds down
##   --------------------  ------------------------------------------------
##   the ping words        exact words only: a prefix, a suffix or a pong
##                         is not a ping
##   a server and a ping   a ping is answered and touches no session
##   the forwarder         bytes arrive unchanged; an answer finds the
##                         client that asked; a stranger answering is
##                         dropped and counted; a quiet client's socket is
##                         closed; nonsense bounds and unknown homes are
##                         refused
##   through the forwarder a real sync agent reaches a real server, and the
##                         server saw exactly ONE handshake

import std/[os, strutils, unittest]

import runePragmas
import geist/network
import geist/forward
import geist/ping
import bifrost_exchange_protocols as bfx except ByteSeq

type
  Note = object
    noteId: int
    title: string

  DeskArgs = object
    ## The serving side, run on its own thread.
    root: string
    listen: string
    identity: AmeIdentityKey
    peers: seq[TrustedPeer]
    ready: bool
    stop: bool
    rows: int
    handshakes: int
    err: string

  ForwarderArgs = object
    ## The forwarding side, run on its own thread.
    listen: bfx.DacAddress
    home: bfx.DacAddress
    ready: bool
    stop: bool
    counts: ForwardCounts
    err: string

proc freshRoot(name: string): string {.role: helper.} =
  ## name: an empty folder under the temp folder.
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc address(port: int): bfx.DacAddress {.role: helper.} =
  ## port: a loopback address.
  result = bfx.initDacAddress("127.0.0.1", uint16(port))

proc waitFor(sock: bfx.DacSocket, F: var Forwarder,
    rounds: int = 30): bfx.DacFrameBytesResult {.role: helper.} =
  ## sock/F: run the forwarder in short passes until `sock` has a datagram.
  var
    i: int = 0
  while i < rounds and not result.ok:
    discard F.forwardStep(20)
    result = bfx.recvDacFrameBytes(sock, 2048, 10)
    i = i + 1

proc nextAtHome(home: bfx.DacSocket, F: var Forwarder): bfx.DacFrameBytesResult {.
    role: helper.} =
  ## home/F: run the forwarder until a datagram that is NOT a ping reaches
  ## home. The forwarder pings on its own, and a real server answers those;
  ## this test socket only skips them.
  var
    i: int = 0
  while i < 60 and not (result.ok and not isPing(result.payload)):
    discard F.forwardStep(20)
    result = bfx.recvDacFrameBytes(home, 2048, 10)
    i = i + 1

proc runDesk(a: ptr DeskArgs) {.role: orchestrator.} =
  ## a: one store, served until told to stop.
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
  a.handshakes = server.server.handshakes
  server.server.closeServer()
  desk.close()

proc deskThread(a: ptr DeskArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    runDesk(a)

proc runForwarder(a: ptr ForwarderArgs) {.role: orchestrator.} =
  ## a: forward until told to stop.
  var
    made: tuple[ok: bool, f: Forwarder, err: string] = initForwarder(a.listen,
      a.home)
  if not made.ok:
    a.err = made.err
    a.ready = true
    return
  a.ready = true
  while not a.stop:
    discard made.f.forwardStep(20)
  a.counts = made.f.forwardCounts()
  made.f.closeForwarder()

proc forwarderThread(a: ptr ForwarderArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    runForwarder(a)

suite "the ping words":
  # {.testKind: tkUnit, covers: "isPing, isPong".}
  test "only the exact word is a ping":
    check isPing(pingBytes())
    check isPong(pongBytes())
    check not isPing(pongBytes())
    check not isPong(pingBytes())

  # {.testKind: tkEdgeCase, covers: "isPing".}
  test "a prefix, a suffix and nothing at all are not a ping":
    var
      longer: seq[uint8] = pingBytes()
      shorter: seq[uint8] = pingBytes()
    longer.add 0'u8
    shorter.setLen(shorter.len - 1)
    check not isPing(longer)
    check not isPing(shorter)
    check not isPing(newSeq[uint8](0))

suite "a server and a ping":
  # {.testKind: tkIntegration, covers: "serveOnce".}
  test "a ping is answered with a pong and opens no session":
    var
      key: AmeIdentityKey = geistIdentity("pingee")
      made: tuple[ok: bool, server: GeistServer, err: string] =
        initGeistServer(address(47961), key, @[TrustedPeer(
          pin: geistPeerPin(geistIdentity("someone")), rights: {prRead})],
          defaultTriggerPolicy())
      client: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress(
        "127.0.0.1", 0'u16))
      step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
      got: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    check made.ok
    bfx.sendDacFrameBytes(client, address(47961), pingBytes())
    step = made.server.serveOnce(proc (q: Query, p: PeerContext): Reply {.
      gcsafe.} = Reply(ok: true), 500)
    check step.ok
    check not step.served
    got = bfx.recvDacFrameBytes(client, 2048, 500)
    check got.ok
    check isPong(got.payload)
    check made.server.peerCount() == 0
    check made.server.handshakes == 0
    bfx.closeDac(client)
    made.server.closeServer()

suite "the forwarder":
  setup:
    var
      home: bfx.DacSocket = bfx.openDacListener(address(47962))
      made: tuple[ok: bool, f: Forwarder, err: string] = initForwarder(
        address(47963), address(47962))
      client: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress(
        "127.0.0.1", 0'u16))
      hello: seq[uint8] = @[1'u8, 2, 3, 250, 251, 252]

  teardown:
    made.f.closeForwarder()
    bfx.closeDac(home)
    bfx.closeDac(client)

  # {.testKind: tkIntegration, covers: "forwardStep".}
  test "bytes reach home unchanged and the answer finds the client":
    var
      atHome: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
      back: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    check made.ok
    bfx.sendDacFrameBytes(client, address(47963), hello)
    atHome = nextAtHome(home, made.f)
    check atHome.payload == hello
    bfx.sendDacFrameBytes(home, atHome.remote, @[9'u8, 8, 7])
    back = waitFor(client, made.f)
    check back.ok
    check back.payload == @[9'u8, 8, 7]
    check made.f.forwardCounts().clients == 1
    check made.f.forwardCounts().foreign == 0

  # {.testKind: tkEdgeCase, covers: "forwardStep".}
  test "two clients get two sockets, and each hears only its own answer":
    var
      other: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress(
        "127.0.0.1", 0'u16))
      first: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
      second: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
      heard: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    bfx.sendDacFrameBytes(client, address(47963), @[1'u8])
    first = nextAtHome(home, made.f)
    bfx.sendDacFrameBytes(other, address(47963), @[2'u8])
    second = nextAtHome(home, made.f)
    check first.remote.port != second.remote.port
    bfx.sendDacFrameBytes(home, second.remote, @[22'u8])
    heard = waitFor(other, made.f)
    check heard.payload == @[22'u8]
    check not bfx.recvDacFrameBytes(client, 2048, 50).ok
    bfx.closeDac(other)

  # {.testKind: tkEdgeCase, covers: "fromHomeSide".}
  test "a stranger writing to a client's socket is dropped and counted":
    var
      atHome: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
      stranger: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress(
        "127.0.0.1", 0'u16))
      heard: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    bfx.sendDacFrameBytes(client, address(47963), hello)
    atHome = nextAtHome(home, made.f)
    bfx.sendDacFrameBytes(stranger, atHome.remote, @[66'u8])
    heard = waitFor(client, made.f, 8)
    check not heard.ok
    check made.f.forwardCounts().foreign == 1
    bfx.closeDac(stranger)

  # {.testKind: tkEdgeCase, covers: "releaseIdleSockets".}
  test "a quiet client's place and socket are given back":
    var
      quick: tuple[ok: bool, f: Forwarder, err: string] = default(
        tuple[ok: bool, f: Forwarder, err: string])
      options: ForwardOptions = forwardDefaults()
      atHome: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
      i: int = 0
    options.clientIdleSeconds = 0
    quick = initForwarder(address(47964), address(47962), options)
    check quick.ok
    bfx.sendDacFrameBytes(client, address(47964), hello)
    atHome = nextAtHome(home, quick.f)
    check quick.f.forwardCounts().sockets == 1
    while i < 40 and quick.f.forwardCounts().clients > 0:
      sleep(5)
      discard quick.f.forwardStep(5)
      i = i + 1
    check quick.f.forwardCounts().clients == 0
    check quick.f.forwardCounts().sockets == 0
    quick.f.closeForwarder()

  # {.testKind: tkEdgeCase, covers: "initForwarder".}
  test "bounds that make no sense and a home that cannot be found are refused":
    var
      options: ForwardOptions = forwardDefaults()
      bad: tuple[ok: bool, f: Forwarder, err: string] = default(
        tuple[ok: bool, f: Forwarder, err: string])
    options.silentSeconds = 5
    options.pingSeconds = 20
    bad = initForwarder(address(47965), address(47962), options)
    check not bad.ok
    check bad.err.contains("poke")
    bad = initForwarder(address(47966), bfx.initDacAddress(
      "no-such-host.invalid", 47962'u16))
    check not bad.ok

suite "through the forwarder":
  # {.testKind: tkIntegration, covers: "forwardStep, syncOnce".}
  test "a sync agent reaches a real server and the server sees one handshake":
    var
      phoneKey: AmeIdentityKey = geistIdentity("phone")
      deskKey: AmeIdentityKey = geistIdentity("desk")
      desk: DeskArgs = DeskArgs(root: freshRoot("geist_t_fw_desk"),
        listen: "dac://127.0.0.1:47967", identity: deskKey,
        peers: @[TrustedPeer(pin: geistPeerPin(phoneKey),
          rights: {prRead, prWrite})])
      fwd: ForwarderArgs = ForwarderArgs(listen: address(47968),
        home: address(47967))
      td: Thread[ptr DeskArgs] = default(Thread[ptr DeskArgs])
      tf: Thread[ptr ForwarderArgs] = default(Thread[ptr ForwarderArgs])
      phone: Session = default(Session)
      seeded: Session = openGeist[Note](desk.root, appConfig())
      agent: SyncAgent = default(SyncAgent)
      reports: seq[SyncReport] = @[]
      spins: int = 0
    discard seeded.put(Note(noteId: 1, title: "at home"))
    check seeded.save().ok
    seeded.close()
    createThread(td, deskThread, addr desk)
    createThread(tf, forwarderThread, addr fwd)
    while not (desk.ready and fwd.ready) and spins < 500:
      sleep(10)
      spins = spins + 1
    check desk.err.len == 0
    check fwd.err.len == 0
    phone = openGeist[Note](freshRoot("geist_t_fw_phone"), appConfig())
    discard phone.put(Note(noteId: 9, title: "on the phone"))
    check phone.save().ok
    agent = initSyncAgent(phoneKey, SyncPlan(peers: @[SyncPeer(name: "home",
      endpoint: "dac://127.0.0.1:47968", pin: geistPeerPin(deskKey),
      way: swBoth)]))
    reports = phone.syncOnce(agent)
    check reports.len == 1
    check reports[0].ok
    check reports[0].pulled == 1
    check phone.entryCount() == 2'u32
    agent.closeAgent()
    phone.close()
    desk.stop = true
    fwd.stop = true
    joinThread(td)
    joinThread(tf)
    check desk.rows == 2
    check desk.handshakes == 1
    check fwd.counts.forwarded > 0'u64
    check fwd.counts.foreign == 0
