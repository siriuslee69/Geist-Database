## Lane jumps over a real Geist link: a lane that fell behind recovers.
##
##   direction 1: the SERVER cannot follow the client's lane
##     the client seals 100 frames it never sends; the next request arrives
##     100 ahead of the server's window -> server asks -> client answers
##     and sends the request again -> reply
##
##   direction 2: the CLIENT cannot follow the server's lane
##     the client's copy of the server's lane is put back 20 messages; the
##     next reply is refused -> client asks -> server proves its position ->
##     that reply is lost (the request times out), the next one opens
import std/[os, atomics, unittest]
import bifrost_exchange_protocols as bfx except ByteSeq
import runePragmas
import geist/network

type
  ServerArgs = object
    root: string
    ready: Atomic[bool]
    stop: Atomic[bool]
    failed: Atomic[bool]

var
  clientSteps: seq[string] = @[]

proc noteStep(e: GeistNetworkEvent) {.gcsafe.} =
  ## e: client-side network event; only the step name is kept.
  {.cast(gcsafe).}:
    clientSteps.add(e.step)

proc runServer(A: ptr ServerArgs) {.thread, role: orchestrator.} =
  ## A: identity files and flags; answers every request with its payload.
  {.cast(gcsafe).}:
    var
      key = loadIdentity(A.root / "server.id", "test-password")
      peer = loadPin(A.root / "client.pin")
      address = parseDacAddress("dac://127.0.0.1:48861")
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
      step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    try:
      server = initGeistServer(address.a, key.key,
        [TrustedPeer(pin: peer.pin, rights: {prRead, prWrite})],
        defaultTriggerPolicy())
      if not server.ok: raise newException(IOError, server.err)
      A.ready.store(true)
      while not A.stop.load():
        step = serveOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            Reply(ok: true, rows: @[Row(data: q.payload)]), 50)
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine(exc.msg)
      A.failed.store(true)
      A.ready.store(true)

proc echoOk(L: var GeistLink, b: uint8, timeoutMs: int): bool =
  ## L/b: one echo request; true when the answer came back intact.
  var
    r: tuple[ok: bool, reply: Reply, err: string] = L.send(
      Query(op: qoPut, collection: "echo", payload: @[b]), timeoutMs)
  result = r.ok and r.reply.ok and r.reply.rows.len == 1 and
    r.reply.rows[0].data == @[b]

suite "Geist lane jumps":
  # {.testKind: tkIntegration, covers: "handleLaneFrame|jumpAskIfBehind|send|answerPeer".}
  test "a lane that fell behind recovers, in both directions":
    var
      root: string = getTempDir() / ("geist-lane-" & $getCurrentProcessId())
      serverKey: tuple[ok: bool, key: AmeIdentityKey, created: bool,
        err: string] = (false, default(AmeIdentityKey), false, "")
      clientKey: tuple[ok: bool, key: AmeIdentityKey, created: bool,
        err: string] = (false, default(AmeIdentityKey), false, "")
      args: ServerArgs = default(ServerArgs)
      thread: Thread[ptr ServerArgs] = default(Thread[ptr ServerArgs])
      address = parseDacAddress("dac://127.0.0.1:48861")
      made: tuple[ok: bool, link: GeistLink, err: string] =
        (false, default(GeistLink), "")
      saved: bfx.FomkeChainState = default(bfx.FomkeChainState)
      spins: int = 0
      i: int = 0
    createDir(root)
    serverKey = loadOrCreateIdentity(root / "server.id", "test-password",
      "server", geistSignatureSlots())
    clientKey = loadOrCreateIdentity(root / "client.id", "test-password",
      "client", geistSignatureSlots())
    require serverKey.ok and clientKey.ok
    check savePin(root / "client.pin", pinOf(clientKey.key)).ok
    args.root = root
    createThread(thread, runServer, addr args)
    while not args.ready.load() and spins < 1000:
      sleep(10)
      spins = spins + 1
    require args.ready.load() and not args.failed.load()
    made = connectGeist(address.a, clientKey.key, pinOf(serverKey.key),
      defaultTriggerPolicy(), 21, 10000, observer = noteStep)
    require made.ok
    check made.link.echoOk(1, 10000)

    # Direction 1: 100 frames the server never sees.
    while i < 100:
      discard bfx.sealAmeDacFrame(made.link.client.connection, @[0'u8])
      i = i + 1
    check made.link.echoOk(2, 10000)
    check "lane.jump.answered" in clientSteps

    # Direction 2: our copy of the server's lane (lane 2) goes back 20.
    saved = bfx.cloneFomkeChain(made.link.client.connection.fomke.lane2)
    i = 0
    while i < 20:
      check made.link.echoOk(uint8(10 + i), 10000)
      i = i + 1
    made.link.client.connection.fomke.lane2 = saved
    check not made.link.echoOk(40, 1500)
    check "lane.jump.asked" in clientSteps
    check "lane.jump.applied" in clientSteps
    check made.link.echoOk(41, 10000)

    made.link.close()
    args.stop.store(true)
    joinThread(thread)
    check not args.failed.load()
    removeDir(root)
