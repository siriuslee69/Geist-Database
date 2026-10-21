## Session keys (SK): the store on its own, then the chain over real AM1P+S
## links between one server and two devices that share one group key.
import std/[os, atomics, unittest]
import runePragmas
import geist/network

type
  ServerArgs = object
    root: string
    ready: Atomic[bool]
    stop: Atomic[bool]
    failed: Atomic[bool]
    accepted: Atomic[int]

const
  port = "dac://127.0.0.1:48863"

proc groupKey(): seq[uint8] =
  result = newSeq[uint8](32)
  result[0] = 7'u8

proc runServer(A: ptr ServerArgs) {.thread, role: orchestrator.} =
  ## A: two trusted devices; SKs kept in <root>/server-sk, required.
  {.cast(gcsafe).}:
    var
      key = loadIdentity(A.root / "server.id", "pw")
      pinA = loadPin(A.root / "a.pin")
      pinB = loadPin(A.root / "b.pin")
      shared = initGeistSharedKey("group", groupKey(),
        initSessionKeyStore(A.root / "server-sk", required = true))
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
    try:
      server = initGeistServer(parseDacAddress(port).a, key.key,
        [TrustedPeer(pin: pinA.pin, rights: {prRead}),
         TrustedPeer(pin: pinB.pin, rights: {prRead})],
        defaultTriggerPolicy(), shared = shared)
      if not server.ok: raise newException(IOError, server.err)
      A.ready.store(true)
      while not A.stop.load():
        discard serveOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            Reply(ok: true, rows: @[Row(data: q.payload)]), 50)
        A.accepted.store(server.server.handshakes)
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine(exc.msg)
      A.failed.store(true)
      A.ready.store(true)

proc session(id: AmeIdentityKey, serverPin: AmePinnedPeerIdentity,
    store: SessionKeyStore, sid: uint64, ask: bool = true): bool =
  ## id/serverPin/store: one device's connection; true when it opened and,
  ## with `ask`, answered one request (which confirms the new SK).
  var
    made: tuple[ok: bool, link: GeistLink, err: string] = connectGeist(
      parseDacAddress(port).a, id, serverPin, defaultTriggerPolicy(), sid,
      3000, shared = initGeistSharedKey("group", groupKey(), store))
    r: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
  if not made.ok:
    return false
  result = true
  if ask:
    r = made.link.send(Query(op: qoGet, collection: "x", payload: @[1'u8]),
      5000)
    result = r.ok
  made.link.close()

suite "Geist session key store":
  # {.testKind: tkUnit, covers: "keepServerSessionKey|keepClientSessionKey|sessionKeyCandidates".}
  test "the server keeps C and P; the client keeps one":
    var
      dir: string = getTempDir() / ("geist-sk-" & $getCurrentProcessId())
      S: SessionKeyStore = initSessionKeyStore(dir)
      k1: seq[uint8] = newSeq[uint8](32)
      k2: seq[uint8] = newSeq[uint8](32)
      k3: seq[uint8] = newSeq[uint8](32)
    k1[0] = 1
    k2[0] = 2
    k3[0] = 3
    check not S.holdsSessionKey("phone")
    S.keepServerSessionKey("phone", sksNone, k1)          # first contact
    check S.sessionKeyCandidates("phone") == @[(sksPending, k1)]
    S.keepServerSessionKey("phone", sksConfirmed, k2)     # P never seen
    check S.loadSessionKeys("phone").pending == k2
    S.keepServerSessionKey("phone", sksPending, k3)       # P seen in use
    check S.loadSessionKeys("phone").confirmed == k2
    check S.loadSessionKeys("phone").pending == k3
    # From disk, in a fresh store:
    check initSessionKeyStore(dir).sessionKeyCandidates("phone") ==
      @[(sksPending, k3), (sksConfirmed, k2)]
    S.keepClientSessionKey("server", k1)
    check initSessionKeyStore(dir).loadSessionKeys("server").confirmed == k1
    S.forgetSessionKey("phone")
    check not initSessionKeyStore(dir).holdsSessionKey("phone")
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "loadSessionKeys".}
  test "a damaged file is an error, not an empty slot":
    var
      dir: string = getTempDir() / ("geist-sk-bad-" & $getCurrentProcessId())
      S: SessionKeyStore = initSessionKeyStore(dir)
      k: seq[uint8] = newSeq[uint8](32)
      path: string = ""
    S.keepClientSessionKey("server", k)
    for f in walkFiles(dir / "*.sk"):
      path = f
    writeFile(path, readFile(path)[0 .. ^2])
    expect ValueError:
      discard initSessionKeyStore(dir).loadSessionKeys("server")
    removeDir(dir)

suite "Geist session keys over AM1P+S":
  # {.testKind: tkIntegration, covers: "answerHello|judgeFinish|finishPeer|connectGeist|send".}
  test "the chain moves on, survives a lost answer, and refuses copies":
    var
      root: string = getTempDir() / ("geist-skl-" & $getCurrentProcessId())
      server = loadOrCreateIdentity(root / "server.id", "pw", "server",
        geistSignatureSlots())
      devA = loadOrCreateIdentity(root / "a.id", "pw", "dev-a",
        geistSignatureSlots())
      devB = loadOrCreateIdentity(root / "b.id", "pw", "dev-b",
        geistSignatureSlots())
      skA: SessionKeyStore = initSessionKeyStore(root / "a-sk")
      skB: SessionKeyStore = initSessionKeyStore(root / "b-sk")
      args: ServerArgs = default(ServerArgs)
      thread: Thread[ptr ServerArgs] = default(Thread[ptr ServerArgs])
      serverPin: AmePinnedPeerIdentity = default(AmePinnedPeerIdentity)
      first: seq[uint8] = @[]
      spins: int = 0
    require server.ok and devA.ok and devB.ok
    check savePin(root / "a.pin", pinOf(devA.key)).ok
    check savePin(root / "b.pin", pinOf(devB.key)).ok
    serverPin = pinOf(server.key)
    args.root = root
    createThread(thread, runServer, addr args)
    while not args.ready.load() and spins < 1000:
      sleep(10)
      spins = spins + 1
    require args.ready.load() and not args.failed.load()

    # 1. first contact: no SK yet; the answer confirms the new one
    check session(devA.key, serverPin, skA, 31)
    first = skA.loadSessionKeys("server").confirmed
    check first.len == 32
    # 2. next session uses it, and hands out another
    check session(devA.key, serverPin, skA, 32)
    check skA.loadSessionKeys("server").confirmed != first
    # 3. a session whose answer never came: the client keeps its SK ...
    check session(devA.key, serverPin, skA, 33, ask = false)
    # ... and the server still takes it
    check session(devA.key, serverPin, skA, 34)
    # 4. a copy of device A from step 1 is refused
    check not session(devA.key, serverPin, initSessionKeyStore(""), 35)
    var old = initSessionKeyStore("")
    old.keepClientSessionKey("server", first)
    check not session(devA.key, serverPin, old, 36)
    # 5. device B on an older build (no SK at all): never locked out
    check session(devB.key, serverPin, nil, 40)
    check session(devB.key, serverPin, nil, 41)
    #    then B with SK support; A's SK under B's identity does not work
    check session(devB.key, serverPin, skB, 37)
    var stolen = initSessionKeyStore("")
    stolen.keepClientSessionKey("server",
      skA.loadSessionKeys("server").confirmed)
    check not session(devB.key, serverPin, stolen, 38)
    # and A, untouched by all of that, still gets in
    check session(devA.key, serverPin, skA, 39)

    args.stop.store(true)
    joinThread(thread)
    check not args.failed.load()
    removeDir(root)
