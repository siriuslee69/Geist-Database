## AM1P+S through public Geist APIs: recovery, wrong PSK, wrong pin, no downgrade.
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

proc runDualServer(A: ptr ServerArgs) {.thread, role: orchestrator.} =
  ## A: own identity files; atomic flags coordinate the real socket test.
  {.cast(gcsafe).}:
    var
      key = loadIdentity(A.root / "server.id", "test-password")
      peer = loadPin(A.root / "client.pin")
      policy = defaultTriggerPolicy()
      address = parseDacAddress("dac://127.0.0.1:48857")
      shared = initGeistSharedKey("test-group", newSeq[uint8](32))
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
      step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    try:
      policy.startTier = gtRecovery
      server = initGeistServer(address.a, key.key,
        [TrustedPeer(pin: peer.pin, rights: {prRead, prWrite})], policy,
        shared = shared)
      if not server.ok: raise newException(IOError, server.err)
      A.ready.store(true)
      while not A.stop.load():
        step = serveOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            Reply(ok: true, rows: @[Row(data: q.payload)]), 50)
        A.accepted.store(server.server.handshakes)
        if not step.ok: stderr.writeLine("server: " & step.err)
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine(exc.msg)
      A.failed.store(true)
      A.ready.store(true)

suite "Geist dual authentication":
  # {.testKind: tkIntegration, covers: "connectGeist|initGeistServer|beginPeer|finishPeer".}
  test "recovery needs both PSK and every pinned signing slot":
    var
      root: string = getTempDir() / ("geist-dual-" & $getCurrentProcessId())
      serverKey: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
        (false, default(AmeIdentityKey), false, "")
      clientKey: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
        (false, default(AmeIdentityKey), false, "")
      peer: AmePinnedPeerIdentity = default(AmePinnedPeerIdentity)
      args: ServerArgs = default(ServerArgs)
      thread: Thread[ptr ServerArgs] = default(Thread[ptr ServerArgs])
      policy = defaultTriggerPolicy()
      shared = initGeistSharedKey("test-group", newSeq[uint8](32))
      wrong: seq[uint8] = newSeq[uint8](32)
      address = parseDacAddress("dac://127.0.0.1:48857")
      made: tuple[ok: bool, link: GeistLink, err: string] =
        (false, default(GeistLink), "")
      reply: tuple[ok: bool, reply: Reply, err: string] = (false, default(Reply), "")
      spins: int = 0
    createDir(root)
    serverKey = loadOrCreateIdentity(root / "server.id", "test-password", "server", geistSignatureSlots())
    clientKey = loadOrCreateIdentity(root / "client.id", "test-password", "client", geistSignatureSlots())
    check serverKey.ok and clientKey.ok
    check savePin(root / "client.pin", pinOf(clientKey.key)).ok
    peer = pinOf(serverKey.key)
    args.root = root
    createThread(thread, runDualServer, addr args)
    while not args.ready.load() and spins < 1000:
      sleep(10)
      spins = spins + 1
    require args.ready.load() and not args.failed.load()
    policy.startTier = gtRecovery
    wrong[0] = 1
    made = connectGeist(address.a, clientKey.key, peer, policy, 11, 1200,
      shared = initGeistSharedKey("test-group", wrong))
    check not made.ok
    check args.accepted.load() == 0
    made = connectGeist(address.a, clientKey.key, peer, policy, 12, 1200)
    check not made.ok
    check args.accepted.load() == 0
    peer.signingKeys[0].publicKey[0] = peer.signingKeys[0].publicKey[0] xor 1
    made = connectGeist(address.a, clientKey.key, peer, policy, 13, 10000, shared = shared)
    check not made.ok
    check args.accepted.load() == 0
    peer = pinOf(serverKey.key)
    made = connectGeist(address.a, clientKey.key, peer, policy, 14, 10000, shared = shared)
    check made.ok
    if made.ok:
      reply = made.link.send(Query(op: qoPut, collection: "echo", payload: @[1'u8, 2, 3]), 10000)
      check reply.ok and reply.reply.ok
      if not reply.ok: stderr.writeLine("client: " & reply.err)
      if reply.reply.rows.len > 0:
        check reply.reply.rows[0].data == @[1'u8, 2, 3]
      made.link.close()
    policy.startTier = gtStandard
    made = connectGeist(address.a, clientKey.key, peer, policy, 15, 1200, shared = shared)
    check not made.ok
    args.stop.store(true)
    joinThread(thread)
    check not args.failed.load()
    check args.accepted.load() == 1
    removeDir(root)
