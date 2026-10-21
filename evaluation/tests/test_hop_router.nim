## geist-hopd's router, a geistd behind it, and a phone, over real sockets:
##
##   phone 0x30 ==link==> router 0x10 <==link== nas 0x20 (dials out)
##      |                                          |
##      +---- end-to-end Geist link, inside -------+
##
##   1. the phone asks the router whom it may reach -> [0x20 "nas"]
##   2. it opens an end-to-end link to the NAS through the router and
##      sends a request; the NAS answers
##   3. a target it may not see is refused, not timed out
import std/[os, atomics, unittest]
import bifrost_exchange_protocols as bfx except ByteSeq
import runePragmas
import geist/network
import geist/hop_router

const
  routerAt = "dac://127.0.0.1:48871"
  nasAt = "dac://127.0.0.1:48872"
  idRouter = 0x10'u64
  idNas = 0x20'u64
  idPhone = 0x30'u64

type
  Shared = object
    root: string
    routerUp: Atomic[bool]
    linked: Atomic[int]
    nasUp: Atomic[bool]
    stop: Atomic[bool]
    failed: Atomic[bool]

proc load(root, name: string): AmeIdentityKey =
  result = loadIdentity(root / (name & ".id"), "pw").key

proc pin(root, name: string): AmePinnedPeerIdentity =
  result = loadPin(root / (name & ".pin")).pin

proc runRouter(A: ptr Shared) {.thread, role: orchestrator.} =
  ## A: the router: phone and NAS as neighbours, the NAS visible to phone.
  {.cast(gcsafe).}:
    var
      made: tuple[ok: bool, node: HopNode, err: string] =
        (false, default(HopNode), "")
    try:
      made = initHopNode(parseDacAddress(routerAt).a, load(A.root, "router"),
        idRouter,
        [HopNeighbour(pin: pin(A.root, "phone"), id: idPhone),
         HopNeighbour(pin: pin(A.root, "nas"), id: idNas)],
        [bfx.AmeRouteTarget(id: idNas, name: "nas", visibleTo: @["phone"])],
        defaultTriggerPolicy())
      if not made.ok: raise newException(IOError, made.err)
      A.routerUp.store(true)
      while not A.stop.load():
        made.node.hopStep(50)
        A.linked.store(made.node.linked)
      made.node.closeHopNode()
    except CatchableError as exc:
      stderr.writeLine("router: " & exc.msg)
      A.failed.store(true)
      A.routerUp.store(true)

proc runNas(A: ptr Shared) {.thread, role: orchestrator.} =
  ## A: a Geist server with its own socket AND a hop link to the router;
  ## echoes every request.
  {.cast(gcsafe).}:
    var
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
      hop: tuple[ok: bool, hop: HopLink, err: string] = (false, nil, "")
    try:
      server = initGeistServer(parseDacAddress(nasAt).a, load(A.root, "nas"),
        [TrustedPeer(pin: pin(A.root, "phone"), rights: {prRead})],
        defaultTriggerPolicy())
      if not server.ok: raise newException(IOError, server.err)
      hop = connectHop(parseDacAddress(routerAt).a, load(A.root, "nas"),
        pin(A.root, "router"), defaultTriggerPolicy(), 77, 10000)
      if not hop.ok: raise newException(IOError, "nas uplink: " & hop.err)
      server.server.attachHop(hop.hop)
      A.nasUp.store(true)
      while not A.stop.load():
        discard serveAnyOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            Reply(ok: true, rows: @[Row(data: q.payload)]), 50)
      server.server.hop.closeHop()
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine("nas: " & exc.msg)
      A.failed.store(true)
      A.nasUp.store(true)

proc waitFor(flag: var Atomic[bool]) =
  var
    spins: int = 0
  while not flag.load() and spins < 3000:
    sleep(10)
    spins = spins + 1

suite "Geist through a hop router":
  # {.testKind: tkIntegration, covers: "hopStep|connectHop|routeDirectory|connectGeistVia|serveAnyOnce|attachHop".}
  test "directory, an end-to-end link through the router, and a refusal":
    var
      root: string = getTempDir() / ("geist-hop-" & $getCurrentProcessId())
      A: Shared = default(Shared)
      tr: Thread[ptr Shared] = default(Thread[ptr Shared])
      tn: Thread[ptr Shared] = default(Thread[ptr Shared])
      hop: tuple[ok: bool, hop: HopLink, err: string] = (false, nil, "")
      dir: tuple[ok: bool, entries: seq[bfx.AmeRouteEntry], err: string] =
        (false, @[], "")
      made: tuple[ok: bool, link: GeistLink, err: string] =
        (false, default(GeistLink), "")
      reply: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
      spins: int = 0
    createDir(root)
    for name in ["router", "nas", "phone"]:
      check loadOrCreateIdentity(root / (name & ".id"), "pw", name,
        geistSignatureSlots()).ok
      check savePin(root / (name & ".pin"),
        pinOf(load(root, name))).ok
    A.root = root
    createThread(tr, runRouter, addr A)
    waitFor(A.routerUp)
    require not A.failed.load()
    createThread(tn, runNas, addr A)
    waitFor(A.nasUp)
    require not A.failed.load()
    while A.linked.load() < 1 and spins < 500:
      sleep(10)
      spins = spins + 1

    hop = connectHop(parseDacAddress(routerAt).a, load(root, "phone"),
      pin(root, "router"), defaultTriggerPolicy(), 78, 10000)
    require hop.ok
    dir = hop.hop.routeDirectory()
    check dir.ok
    check dir.entries == @[bfx.AmeRouteEntry(id: idNas, name: "nas")]

    made = connectGeistVia(hop.hop, idNas, load(root, "phone"),
      pin(root, "nas"), defaultTriggerPolicy(), 79, 10000)
    if not made.ok: stderr.writeLine("via: " & made.err)
    require made.ok
    reply = made.link.send(Query(op: qoGet, collection: "x",
      payload: @[7'u8, 8, 9]), 10000)
    if not reply.ok: stderr.writeLine("send: " & reply.err)
    check reply.ok and reply.reply.ok
    check reply.reply.rows.len == 1 and reply.reply.rows[0].data == @[7'u8, 8, 9]
    made.link.close()

    made = connectGeistVia(hop.hop, 0x99'u64, load(root, "phone"),
      pin(root, "nas"), defaultTriggerPolicy(), 80, 10000)
    check not made.ok
    check made.err == "route refused: arrNoRoute"

    hop.hop.closeHop()
    A.stop.store(true)
    joinThread(tn)
    joinThread(tr)
    check not A.failed.load()
    removeDir(root)

## ------------------------------ two routers ------------------------------
##
##   phone 0x30 ==> R1 0x10 ==(R1 dials)==> R2 0x11 <== nas 0x20 (dials R2)
##
## R1 lists the NAS "via 0x11"; R2 lists it for R1. The answer finds its way
## back by the return note R2 makes when R1 hands it the phone's frames.

const
  r1At = "dac://127.0.0.1:48873"
  r2At = "dac://127.0.0.1:48874"
  nas2At = "dac://127.0.0.1:48875"
  idR2 = 0x11'u64

type
  TwoRouters = object
    root: string
    r1Up, r2Up, nasUp: Atomic[bool]
    r1Linked, r2Linked: Atomic[int]
    stop: Atomic[bool]
    failed: Atomic[bool]

proc runR1(A: ptr TwoRouters) {.thread, role: orchestrator.} =
  ## A: router 1 -- the phone links here; it dials router 2.
  {.cast(gcsafe).}:
    var
      made: tuple[ok: bool, node: HopNode, err: string] =
        (false, default(HopNode), "")
    try:
      made = initHopNode(parseDacAddress(r1At).a, load(A.root, "router"),
        idRouter,
        [HopNeighbour(pin: pin(A.root, "phone"), id: idPhone),
         HopNeighbour(pin: pin(A.root, "router2"), id: idR2, router: true,
           endpoint: r2At)],
        [bfx.AmeRouteTarget(id: idNas, name: "nas", visibleTo: @["phone"],
          via: idR2)],
        defaultTriggerPolicy())
      if not made.ok: raise newException(IOError, made.err)
      A.r1Up.store(true)
      while not A.stop.load():
        made.node.hopStep(20)
        A.r1Linked.store(made.node.linked)
      made.node.closeHopNode()
    except CatchableError as exc:
      stderr.writeLine("r1: " & exc.msg)
      A.failed.store(true)
      A.r1Up.store(true)

proc runR2(A: ptr TwoRouters) {.thread, role: orchestrator.} =
  ## A: router 2 -- router 1 and the NAS link here.
  {.cast(gcsafe).}:
    var
      made: tuple[ok: bool, node: HopNode, err: string] =
        (false, default(HopNode), "")
    try:
      made = initHopNode(parseDacAddress(r2At).a, load(A.root, "router2"),
        idR2,
        [HopNeighbour(pin: pin(A.root, "router"), id: idRouter, router: true),
         HopNeighbour(pin: pin(A.root, "nas"), id: idNas)],
        [bfx.AmeRouteTarget(id: idNas, name: "nas", visibleTo: @["router"])],
        defaultTriggerPolicy())
      if not made.ok: raise newException(IOError, made.err)
      A.r2Up.store(true)
      while not A.stop.load():
        made.node.hopStep(20)
        A.r2Linked.store(made.node.linked)
      made.node.closeHopNode()
    except CatchableError as exc:
      stderr.writeLine("r2: " & exc.msg)
      A.failed.store(true)
      A.r2Up.store(true)

proc runNas2(A: ptr TwoRouters) {.thread, role: orchestrator.} =
  ## A: the NAS, linked to router 2; echoes every request.
  {.cast(gcsafe).}:
    var
      server: tuple[ok: bool, server: GeistServer, err: string] =
        (false, default(GeistServer), "")
      hop: tuple[ok: bool, hop: HopLink, err: string] = (false, nil, "")
    try:
      server = initGeistServer(parseDacAddress(nas2At).a, load(A.root, "nas"),
        [TrustedPeer(pin: pin(A.root, "phone"), rights: {prRead})],
        defaultTriggerPolicy())
      if not server.ok: raise newException(IOError, server.err)
      hop = connectHop(parseDacAddress(r2At).a, load(A.root, "nas"),
        pin(A.root, "router2"), defaultTriggerPolicy(), 81, 10000)
      if not hop.ok: raise newException(IOError, "nas uplink: " & hop.err)
      server.server.attachHop(hop.hop)
      A.nasUp.store(true)
      while not A.stop.load():
        discard serveAnyOnce(server.server,
          proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
            Reply(ok: true, rows: @[Row(data: q.payload)]), 20)
      server.server.hop.closeHop()
      server.server.closeServer()
    except CatchableError as exc:
      stderr.writeLine("nas: " & exc.msg)
      A.failed.store(true)
      A.nasUp.store(true)

proc waitAtLeast(counter: var Atomic[int], n: int) =
  var
    spins: int = 0
  while counter.load() < n and spins < 1500:
    sleep(10)
    spins = spins + 1

suite "Geist through two hop routers":
  # {.testKind: tkIntegration, covers: "hopStep|connectGeistVia|serveAnyOnce".}
  test "a router dials the next; the answer finds its way back":
    var
      root: string = getTempDir() / ("geist-hop2-" & $getCurrentProcessId())
      A: TwoRouters = default(TwoRouters)
      t1: Thread[ptr TwoRouters] = default(Thread[ptr TwoRouters])
      t2: Thread[ptr TwoRouters] = default(Thread[ptr TwoRouters])
      tn: Thread[ptr TwoRouters] = default(Thread[ptr TwoRouters])
      hop: tuple[ok: bool, hop: HopLink, err: string] = (false, nil, "")
      made: tuple[ok: bool, link: GeistLink, err: string] =
        (false, default(GeistLink), "")
      reply: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
    createDir(root)
    for name in ["router", "router2", "nas", "phone"]:
      check loadOrCreateIdentity(root / (name & ".id"), "pw", name,
        geistSignatureSlots()).ok
      check savePin(root / (name & ".pin"), pinOf(load(root, name))).ok
    A.root = root
    createThread(t2, runR2, addr A)
    waitFor(A.r2Up)
    createThread(tn, runNas2, addr A)
    waitFor(A.nasUp)
    createThread(t1, runR1, addr A)
    waitFor(A.r1Up)
    require not A.failed.load()
    waitAtLeast(A.r1Linked, 1)
    waitAtLeast(A.r2Linked, 2)
    require A.r2Linked.load() >= 2

    hop = connectHop(parseDacAddress(r1At).a, load(root, "phone"),
      pin(root, "router"), defaultTriggerPolicy(), 82, 10000)
    require hop.ok
    made = connectGeistVia(hop.hop, idNas, load(root, "phone"),
      pin(root, "nas"), defaultTriggerPolicy(), 83, 10000)
    if not made.ok: stderr.writeLine("via: " & made.err)
    require made.ok
    reply = made.link.send(Query(op: qoGet, collection: "x",
      payload: @[4'u8, 2]), 10000)
    if not reply.ok: stderr.writeLine("send: " & reply.err)
    check reply.ok and reply.reply.ok
    check reply.reply.rows.len == 1 and reply.reply.rows[0].data == @[4'u8, 2]
    made.link.close()
    hop.hop.closeHop()
    A.stop.store(true)
    joinThread(t1)
    joinThread(tn)
    joinThread(t2)
    check not A.failed.load()
    removeDir(root)
