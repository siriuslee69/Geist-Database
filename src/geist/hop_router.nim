## ---------------------------------------------------------------------
## Hop router <- what geist-hopd does: hand frames on, read none of them
## ---------------------------------------------------------------------
##
##   phone ==link==> [ hop router 0x10 ] ==link==> nas (geistd, dials out)
##                         |
##                   ==link==> [ hop router 0x11 ] ==link==> cam
##
## Every neighbour -- a phone, a geistd behind a home router, another hop
## router -- makes ONE ordinary Geist handshake with this router, a LINK.
## Through it they send Bifrost route frames ("ART", Bifrost
## docs/routing.md): the router opens the 16-byte address with the
## incoming link, seals it again for the outgoing one, and hands the
## payload on unread. The payload is an end-to-end Geist link between
## the two ends, which no router holds a key for.
##
## ╭─ ❧ What it decides, and who decides it 🌊
##
##   who may connect at all     the pins in the config (`peer`)
##   which route id each has    the config, by pin subject -- never a claim
##   who may reach whom         Bifrost's rules over the `target` list
##                              (Bifrost docs/routing.md, section 6)
##   where a frame goes next    the same, plus `via` for targets behind
##                              another router
##
## ╭─ ❧ One turn 🐦‍🔥
##
##   wait for a datagram on the listen socket or a dialled router's socket
##        |
##        +-- from a linked neighbour -> route frame, directory question,
##        |                             or lane jump of that link
##        +-- a handshake record      -> the ordinary Geist server
##        |                             handshake; when it finishes, the
##        |                             session moves into the router
##        +-- a ping                  -> pong
##   then: dial routers that are due, ask silent outbound links something,
##         forget links nobody has heard from in `idleSeconds`
##
## No threads. A dial blocks the turn for up to `timeoutMs`; routers are
## few and dialled rarely.

import std/[nativesockets, net, random, tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./masks
import ./transport
import ./peers
import ./handshake
import ./ping
import ./lane_recovery
import ./hop_link

const
  hopRedialSeconds* = 10.0
    ## How long a router that could not be dialled waits for the next try.

type
  HopNeighbour* {.role: configurator, tag: "networkSurface|types".} = object
    ## One configured neighbour. `endpoint`: set for a router this node
    ## DIALS; empty for anyone who dials this node.
    pin*: bfx.AmePinnedPeerIdentity
    id*: uint64
    router*: bool
    endpoint*: string

  HopWire {.role: memory, expectedCount: [0, 512],
      lifeCycle: lcSession.} = object
    ## How to reach the neighbour in one router slot.
    used: bool
    sock: bfx.DacSocket
    remote: bfx.DacAddress
    key: string
    owned: bool
      ## true: a socket this node opened to dial a router; closed with it
    lastHeardAt: float
    lastSentAt: float

  HopDial {.role: memory, expectedCount: [0, 16],
      lifeCycle: lcForever.} = object
    ## A router this node keeps a link to by dialling it.
    neighbour: int
    slot: int
    nextTryAt: float

  HopNode* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = object
    ## The whole router. `server` only ever runs handshakes; once one
    ## finishes, the session lives in `router`.
    server*: GeistServer
    router*: bfx.AmeRouter
    neighbours*: seq[HopNeighbour]
    identity: bfx.AmeIdentityKey
    policy: TriggerPolicy
    wires: seq[HopWire]
    slotOf: Table[string, int]
    dials: seq[HopDial]
    idleSeconds*: float
    timeoutMs*: int
    forwarded*: int
    linked*: int
    dropped*: int
    lastErr*: string

proc nowMs(): uint32 {.role: helper, inline.} =
  ## The router's millisecond clock; it only ever compares differences, so
  ## wrapping every 49 days is harmless.
  result = uint32(int64(epochTime() * 1000.0) and 0xffff_ffff'i64)

proc initHopNode*(listen: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    selfId: uint64, neighbours: openArray[HopNeighbour],
    targets: openArray[bfx.AmeRouteTarget], policy: TriggerPolicy,
    idleSeconds: float = 900.0, timeoutMs: int = 2000): tuple[ok: bool,
    node: HopNode, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## listen: where neighbours dial in. identity: this router's key.
  ## selfId: its own route id. neighbours/targets: the config.
  ## policy: tier policy for every link. idleSeconds: when a silent link
  ## is forgotten. timeoutMs: per dial.
  var
    trusted: seq[TrustedPeer] = @[]
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
    i: int = 0
  for n in neighbours:
    trusted.add(TrustedPeer(pin: n.pin, rights: {}))
  server = initGeistServer(listen, identity, trusted, policy,
    int64(idleSeconds))
  if not server.ok:
    return (false, default(HopNode), server.err)
  result.node.server = server.server
  result.node.router = bfx.initAmeRouter(selfId, max(4, neighbours.len * 2))
  result.node.wires = newSeq[HopWire](result.node.router.peers.len)
  result.node.slotOf = initTable[string, int]()
  result.node.neighbours = @neighbours
  result.node.identity = identity
  result.node.policy = policy
  result.node.idleSeconds = idleSeconds
  result.node.timeoutMs = timeoutMs
  try:
    for t in targets:
      result.node.router.addAmeRouteTarget(t.id, t.name, t.visibleTo, t.via)
  except CatchableError as exc:
    return (false, default(HopNode), exc.msg)
  while i < neighbours.len:
    if neighbours[i].endpoint.len > 0:
      result.node.dials.add(HopDial(neighbour: i, slot: -1, nextTryAt: 0.0))
    i = i + 1
  result.ok = true

proc neighbourOf(N: HopNode, subject: string): int {.role: parser.} =
  ## N/subject: index of the configured neighbour with that pin, or -1.
  var
    i: int = 0
  result = -1
  while i < N.neighbours.len:
    if N.neighbours[i].pin.subject == subject:
      return i
    i = i + 1

proc releaseSlot(N: var HopNode, slot: int) {.role: actor,
    tag: "ame|networkSurface|server".} =
  ## N/slot: the neighbour in that slot is gone: session erased, socket
  ## closed when this node had opened it.
  if slot < 0 or slot >= N.wires.len or not N.wires[slot].used:
    return
  if N.wires[slot].owned:
    bfx.closeDac(N.wires[slot].sock)
  N.slotOf.del(N.wires[slot].key)
  N.wires[slot] = default(HopWire)
  N.router.releaseAmeRoutePeer(slot)

proc admit(N: var HopNode, n: int, S: bfx.AmeSession, key: string,
    sock: bfx.DacSocket, remote: bfx.DacAddress, owned: bool): int {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## N: the router. n: which configured neighbour. S: its finished session.
  ## key/sock/remote/owned: how to reach it. Returns the slot, or -1.
  ## A neighbour that links again replaces its old link.
  var
    got: tuple[ok: bool, slot: int, err: string] = (false, -1, "")
  N.releaseSlot(N.router.findAmeRoutePeer(N.neighbours[n].id))
  got = N.router.admitAmeRoutePeer(S, N.neighbours[n].id,
    N.neighbours[n].pin.subject, bfx.acrDac, N.neighbours[n].router)
  if not got.ok:
    N.lastErr = got.err
    return -1
  N.wires[got.slot] = HopWire(used: true, sock: sock, remote: remote,
    key: key, owned: owned, lastHeardAt: epochTime(),
    lastSentAt: epochTime())
  N.slotOf[key] = got.slot
  N.linked = N.linked + 1
  result = got.slot

proc emit(N: var HopNode, sends: openArray[bfx.AmeRouteSend]) {.
    role: dataWriter, tag: "ame|networkSurface|write".} =
  ## N/sends: frames the router produced, each to its slot's neighbour.
  for s in sends:
    try:
      bfx.sendDacFrameBytes(N.wires[s.slot].sock, N.wires[s.slot].remote,
        s.frame)
      N.wires[s.slot].lastSentAt = epochTime()
    except CatchableError as exc:
      N.lastErr = exc.msg

proc sendTo(N: var HopNode, slot: int, frame: ByteSeq) {.role: dataWriter.} =
  ## N/slot/frame: one frame of this node's own to a neighbour.
  N.emit([bfx.AmeRouteSend(slot: slot, frame: frame)])

proc linkedFrame(N: var HopNode, slot: int, payload: ByteSeq) {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## N/slot/payload: one datagram from a linked neighbour.
  ##
  ##   ART frame          -> the router decides (forward, refuse, drop)
  ##   AME 0x14           -> a directory question, answered
  ##   AME 0x15 / 0x16    -> a lane jump of THIS link
  ##   anything else      -> dropped: a router serves no data of its own
  var
    step: bfx.AmeRouteStep = default(bfx.AmeRouteStep)
    lane: LaneOutcome = (lsNone, @[], 0'u64, "")
  N.wires[slot].lastHeardAt = epochTime()
  if bfx.isAmeRouteFrame(payload):
    step = N.router.feedAmeRouteFrame(slot, payload, nowMs())
    N.forwarded = N.forwarded + int(step.event == bfx.areForwarded)
  else:
    lane = handleLaneFrame(N.router.peers[slot].session, payload)
    if lane.step == lsAnswered:
      N.sendTo(slot, lane.reply)
    if lane.step == lsNone:
      step = N.router.feedAmeRouteAsk(slot, payload)
  if step.event == bfx.areDropped:
    N.dropped = N.dropped + 1
    N.lastErr = step.err
  N.emit(step.send)

proc finishedLink(N: var HopNode, key: string,
    remote: bfx.DacAddress) {.role: orchestrator.} =
  ## N/key/remote: a handshake on the listen socket just finished; its
  ## session moves out of the handshake server and into the router.
  var
    link: PeerLink = N.server.peers[key]
    n: int = N.neighbourOf(link.subject)
  N.server.peers.del(key)
  if n < 0:
    N.lastErr = "linked peer " & link.subject & " is not a configured neighbour"
    return
  discard N.admit(n, link.session, key, N.server.sock, remote, false)

proc handshakeRecord(N: var HopNode, payload: ByteSeq, remote: bfx.DacAddress,
    key: string) {.role: orchestrator, tag: "ame|networkSurface|server".} =
  ## N/payload/remote/key: one whole handshake record on the listen socket.
  var
    frame: bfx.AmeHandshakeFrame = bfx.decodeAmeHandshakeFrame(payload)
    step: tuple[ok: bool, err: string] = (false, "")
  if frame.kind == bfx.ampkClientHello:
    N.server.peers.del(key)
    step = N.server.beginPeer(frame, remote, key)
  elif frame.kind == bfx.ampkClientFinish and N.server.peers.hasKey(key):
    step = N.server.finishPeer(frame, key)
  if step.ok and frame.kind == bfx.ampkClientFinish:
    N.finishedLink(key, remote)
  if not step.ok and step.err.len > 0:
    N.lastErr = step.err

proc listenDatagram(N: var HopNode, raw: bfx.DacFrameBytesResult) {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## N/raw: one datagram on the listen socket. A handshake record from an
  ## address that is already linked is a neighbour starting over.
  var
    key: string = bfx.formatDacAddress(raw.remote)
    fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
    kind: bfx.AmePacketKind = bfx.ampkUnknown
  if isPing(raw.payload):
    bfx.sendDacFrameBytes(N.server.sock, raw.remote, pongBytes())
    return
  if not bfx.isAmeRouteFrame(raw.payload):
    kind = bfx.decodeAmeFrameHeader(raw.payload).packetKind
  if N.slotOf.hasKey(key) and not bfx.ameHandshakeKindValid(kind) and
      kind != bfx.ampkHandshakePackage:
    N.linkedFrame(N.slotOf[key], raw.payload)
    return
  fed = bfx.feedAmeHandshakeDatagram(N.server.handshakePackages, raw.payload,
    key)
  if not fed.ok:
    N.lastErr = fed.err
    return
  if fed.done:
    N.handshakeRecord(fed.payload, raw.remote, key)

proc dial(N: var HopNode, d: int) {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## N/d: make the link to one router this node dials.
  var
    n: int = N.dials[d].neighbour
    address: tuple[ok: bool, a: bfx.DacAddress] =
      bfx.parseDacAddress(N.neighbours[n].endpoint)
    made: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  N.dials[d].nextTryAt = epochTime() + hopRedialSeconds
  if not address.ok:
    N.lastErr = "bad endpoint " & N.neighbours[n].endpoint
    return
  made = connectGeist(address.a, N.identity, N.neighbours[n].pin, N.policy,
    rand(1'u64 .. high(uint64)), N.timeoutMs)
  if not made.ok:
    N.lastErr = "dialling " & N.neighbours[n].endpoint & ": " & made.err
    return
  N.dials[d].slot = N.admit(n, made.link.client.connection,
    "dial:" & N.neighbours[n].endpoint, made.link.client.socket,
    made.link.client.remote, true)

proc dialDue(N: var HopNode, now: float) {.role: orchestrator.} =
  ## N/now: dial every router whose link is missing and whose time came.
  var
    d: int = 0
  while d < N.dials.len:
    if N.dials[d].slot >= 0 and not N.wires[N.dials[d].slot].used:
      N.dials[d].slot = -1
    if N.dials[d].slot < 0 and now >= N.dials[d].nextTryAt:
      N.dial(d)
    d = d + 1

proc keepDialsAlive(N: var HopNode, now: float) {.role: actor.} =
  ## N/now: a dialled link that has sent nothing for a while asks the
  ## router at the other end something, so that router keeps it.
  for d in N.dials:
    if d.slot < 0 or now - N.wires[d.slot].lastSentAt < hopKeepaliveSeconds:
      continue
    try:
      N.sendTo(d.slot, bfx.sealAmeRouteAsk(N.router.peers[d.slot].session,
        bfx.acrDac))
    except CatchableError as exc:
      N.lastErr = exc.msg

proc forgetSilent(N: var HopNode, now: float) {.role: actor.} =
  ## N/now: links nobody has heard from in `idleSeconds` are released.
  var
    i: int = 0
  while i < N.wires.len:
    if N.wires[i].used and now - N.wires[i].lastHeardAt > N.idleSeconds:
      N.releaseSlot(i)
    i = i + 1

proc dialledReady(N: var HopNode, fds: seq[SocketHandle]) {.
    role: orchestrator.} =
  ## N/fds: sockets select said are readable; one datagram from each
  ## dialled router among them.
  var
    raw: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
  for d in N.dials:
    if d.slot < 0 or N.wires[d.slot].sock.getFd() notin fds:
      continue
    raw = bfx.recvDacFrameBytes(N.wires[d.slot].sock, hopFrameMaxBytes, 0)
    if raw.ok:
      N.linkedFrame(d.slot, raw.payload)

proc watchedSockets(N: HopNode): seq[SocketHandle] {.role: parser.} =
  ## N: the listen socket and every dialled router's socket.
  result.add(N.server.sock.getFd())
  for d in N.dials:
    if d.slot >= 0:
      result.add(N.wires[d.slot].sock.getFd())

proc hopStep*(N: var HopNode, timeoutMs: int = 1000) {.role: metaOrchestrator,
    tag: "ame|networkSurface|orchestrator|server".} =
  ## N: the router. timeoutMs: the longest one turn waits for a datagram.
  ## One turn (see the module note). Never raises.
  var
    fds: seq[SocketHandle] = @[]
    raw: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    now: float = epochTime()
  try:
    N.dialDue(now)
    N.keepDialsAlive(now)
    N.forgetSilent(now)
    fds = N.watchedSockets()
    if selectRead(fds, timeoutMs) <= 0:
      return
    N.dialledReady(fds)
    if N.server.sock.getFd() notin fds:
      return
    raw = bfx.recvDacFrameBytes(N.server.sock, hopFrameMaxBytes, 0)
    if raw.ok:
      N.listenDatagram(raw)
  except CatchableError as exc:
    N.lastErr = exc.msg

proc closeHopNode*(N: var HopNode) {.role: actor, tag: "ame|lifecycle".} =
  ## N: every link released, every socket closed.
  var
    i: int = 0
  while i < N.wires.len:
    N.releaseSlot(i)
    i = i + 1
  N.server.closeServer()
