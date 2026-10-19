## Overlay integration <- real AM1P+S DAC sessions, aliases and outbound service.
import std/[os, atomics, unittest, strutils]
import runePragmas
import geist/wire

type
  RelayArgs = object
    root: string
    ready: Atomic[bool]
    stop: Atomic[bool]
    failed: Atomic[bool]

proc openTestRelay(root: string): tuple[ok: bool, server: GeistServer,
    err: string] {.role: configurator.} =
  ## root: build the loopback server using three locally provisioned identities.
  var
    key = loadIdentity(root / "relay.id", "test-password")
    owner = loadPin(root / "owner.pin")
    caller = loadPin(root / "caller.pin")
    policy = defaultTriggerPolicy()
    shared = initGeistSharedKey("overlay-test", newSeq[uint8](32))
    address = parseDacAddress("dac://127.0.0.1:48858")
  policy.startTier = gtRecovery
  result = initGeistServer(address.a, key.key,
    [TrustedPeer(pin: owner.pin, rights: {prRead, prWrite}),
     TrustedPeer(pin: caller.pin, rights: {prRead, prWrite})], policy, shared = shared)

proc relayLoop(A: ptr RelayArgs) {.thread, role: orchestrator.} =
  ## A: this thread owns all relay state; only flags cross threads.
  {.cast(gcsafe).}:
    var
      relay = initOverlayRelay([
        OverlayGrant(subject: "owner", aliases: @["node.geist", "alias.geist", "10.76.0.1:8080"]),
        OverlayGrant(subject: "caller", aliases: @["caller.geist", "10.76.0.1:8081"])])
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
      step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    try:
      server = openTestRelay(A.root)
      if not server.ok: raise newException(IOError, server.err)
      A.ready.store(true)
      while not A.stop.load():
        step = serveOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            {.cast(gcsafe).}: result = relay.answerOverlay(q, p), 20)
        if not step.ok: stderr.writeLine(step.err)
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine(exc.msg)
      A.failed.store(true)
      A.ready.store(true)

suite "overlay over real Geist sessions":
  # {.testKind: tkIntegration, covers: "connectGeist|resolveOverlay|submitOverlay|serveOverlayOnce|overlayResult|forgetOverlay".}
  test "two identities share an IP, keep ports, migrate and exchange checked queries":
    var
      root = getTempDir() / ("geist-overlay-" & $getCurrentProcessId())
      relayKey = loadOrCreateIdentity(root / "relay.id", "test-password", "relay", geistSignatureSlots())
      ownerKey = loadOrCreateIdentity(root / "owner.id", "test-password", "owner", geistSignatureSlots())
      callerKey = loadOrCreateIdentity(root / "caller.id", "test-password", "caller", geistSignatureSlots())
      args: RelayArgs = default(RelayArgs)
      thread: Thread[ptr RelayArgs] = default(Thread[ptr RelayArgs])
      policy = defaultTriggerPolicy()
      shared = initGeistSharedKey("overlay-test", newSeq[uint8](32))
      endpoint = parseDacAddress("dac://127.0.0.1:48858")
      owner: tuple[ok: bool, link: GeistLink, err: string] = (false, GeistLink(), "")
      caller: tuple[ok: bool, link: GeistLink, err: string] = (false, GeistLink(), "")
      service = OverlayService(allowedCallers: @[OverlayAccess(subject: "caller", rights: {prRead})])
      step: OverlayServiceStep = default(OverlayServiceStep)
      first: OverlayResolution = default(OverlayResolution)
      second: OverlayResolution = default(OverlayResolution)
      submitted: OverlaySubmission = default(OverlaySubmission)
      response: OverlayResult = default(OverlayResult)
      calls: int = 0
      spins: int = 0
      handler: ServedHandler = nil
    require relayKey.ok and ownerKey.ok and callerKey.ok
    check savePin(root / "owner.pin", pinOf(ownerKey.key)).ok
    check savePin(root / "caller.pin", pinOf(callerKey.key)).ok
    args.root = root
    createThread(thread, relayLoop, addr args)
    defer:
      args.stop.store(true)
      joinThread(thread)
      owner.link.close()
      caller.link.close()
      removeDir(root)
    while not args.ready.load() and spins < 1000:
      sleep(10)
      inc spins
    require args.ready.load() and not args.failed.load()
    policy.startTier = gtRecovery
    owner = connectGeist(endpoint.a, ownerKey.key, pinOf(relayKey.key), policy, 101, 10000, shared = shared)
    caller = connectGeist(endpoint.a, callerKey.key, pinOf(relayKey.key), policy, 102, 10000, shared = shared)
    require owner.ok and caller.ok
    handler = proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
      {.cast(gcsafe).}:
        inc calls
        doAssert p.subject == "caller" and p.rights == {prRead}
        result = Reply(ok: true, rows: @[Row(data: q.payload)])
    step = serveOverlayOnce(owner.link, service, handler)
    check step.renewed and not step.served
    discard caller.link.renewOverlay()
    first = caller.link.resolveOverlay("ALIAS.GEIST.")
    second = caller.link.resolveOverlay("10.76.0.1:8081")
    check first.subject == "owner" and second.subject == "caller"
    check first.observedEndpoint.startsWith("dac://127.0.0.1:")
    check first.observedEndpoint != second.observedEndpoint
    submitted = caller.link.submitOverlay("10.76.0.1:8080", Query(op: qoGet,
      collection: "echo", payload: @[42'u8]))
    check not caller.link.overlayResult(submitted.ticket).ready
    owner.link.close()
    owner = connectGeist(endpoint.a, ownerKey.key, pinOf(relayKey.key), policy, 103, 10000, shared = shared)
    require owner.ok
    step = serveOverlayOnce(owner.link, service, handler)
    check step.renewed and step.served
    second = caller.link.resolveOverlay("node.geist")
    check second.subject == first.subject and second.revision > first.revision
    response = caller.link.overlayResult(submitted.ticket)
    check response.ready and response.reply.ok
    check response.reply.rows[0].data == @[42'u8]
    check calls == 1
    caller.link.forgetOverlay(submitted.ticket)
    submitted = caller.link.submitOverlay("node.geist", Query(op: qoPut, collection: "echo"))
    step = serveOverlayOnce(owner.link, service, handler)
    response = caller.link.overlayResult(submitted.ticket)
    check response.ready and not response.reply.ok
    check calls == 1
    caller.link.forgetOverlay(submitted.ticket)
    check not args.failed.load()
