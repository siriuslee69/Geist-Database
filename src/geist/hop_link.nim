## ---------------------------------------------------------------------
## Hop link <- one AME link to a geist-hopd router, and frames sent THROUGH it
## ---------------------------------------------------------------------
##
##   phone ==hop link==> geist-hopd ==hop link==> nas (geistd)
##     |                                            |
##     +------- end-to-end Geist link, inside -------+
##
## A HOP LINK is an ordinary AME session with a router (made with
## `connectHop`, ./hop_client). Over it go two kinds of frame:
##
##   "AME"  for the router itself: "whom may I reach?" (`routeDirectory`),
##          lane jumps of the hop link, nothing else
##   "ART"  for someone behind the router: only the target/origin address
##          is sealed, per link; the payload is an end-to-end AME frame
##          (Bifrost docs/routing.md)
##
## This file moves bytes over a hop link. It does not know what the
## end-to-end frames mean -- ./transport (asking end) and ./serve (answering
## end) put their ordinary handshake records and session frames in, and get
## them back out, exactly as they would over a socket of their own.
##
## ╭─ ❧ Who a frame is from 🌊
##
## The router writes the id its handshake proved into every frame it hands
## on, so `origin` is the peer, never a claim. A server keys peers that
## arrive this way as `hop:<origin in hex>` (`hopKey`) instead of by
## address, and answers them through the same hop link.
##
## ╭─ ❧ Several conversations on one hop link 🐦‍🔥
##
## Frames from an origin nobody is reading right now are queued, at most 64
## per origin, oldest dropped first -- datagram loss the transport above
## already survives.

import std/[deques, strutils, tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./lane_recovery

export bfx.AmeRouteEntry, bfx.AmeRouteTarget

const
  hopQueueFrames* = 64
    ## Frames held per origin until someone reads them.
  hopKeyPrefix* = "hop:"
    ## How a server names a peer that reached it through a hop link.
  hopKeepaliveSeconds* = 60.0
    ## How often an idle hop link asks the router something, so the router
    ## does not drop it as silent.
  hopFrameMaxBytes* = 65_507

type
  HopLink* {.role: truthState, expectedCount: [0, 4],
      lifeCycle: lcSession.} = ref object
    ## socket/remote: this link's own socket and the router's address.
    ## session: the AME session with the router (NOT end to end).
    ## subject: the router's pinned subject.
    socket*: bfx.DacSocket
    remote*: bfx.DacAddress
    session*: bfx.AmeSession
    subject*: string
    open*: bool
    lastJumpAskAt*: float
    lastSentAt*: float
    lastHeardAt*: float
      ## When the router last sent anything. A hop link that has heard
      ## nothing for three keepalive periods is dead (`hopSilent`).
    queue: Table[uint64, Deque[ByteSeq]]
    refusals: Table[uint64, bfx.AmeRouteRefusal]

  HopFrame* {.role: preparedData, tag: "ame|networkSurface|types".} = tuple
    ## One datagram from the router, read. `frame` is an end-to-end frame
    ## from `origin` when `ok`; nothing for the caller otherwise.
    ok: bool
    origin: uint64
    frame: ByteSeq
    err: string

proc initHopLink*(socket: bfx.DacSocket, remote: bfx.DacAddress,
    session: bfx.AmeSession, subject: string): HopLink {.
    role: configurator, tag: "ame|networkSurface".} =
  ## socket/remote/session/subject: a finished AME session with a router,
  ## and the socket it ran on. The hop link owns both from now on.
  result = HopLink(socket: socket, remote: remote, session: session,
    subject: subject, open: true, lastSentAt: epochTime(),
    lastHeardAt: epochTime(),
    queue: initTable[uint64, Deque[ByteSeq]](),
    refusals: initTable[uint64, bfx.AmeRouteRefusal]())

proc hopKey*(origin: uint64): string {.role: helper, tag: "ame".} =
  ## origin: a route id; the key a server files that peer under.
  result = hopKeyPrefix & toHex(origin)

proc hopOrigin*(key: string): tuple[ok: bool, origin: uint64] {.
    role: parser, tag: "ame".} =
  ## key: a peer key; its route id when it is a hop key.
  if not key.startsWith(hopKeyPrefix):
    return (false, 0'u64)
  try:
    result = (true, fromHex[uint64](key[hopKeyPrefix.len .. ^1]))
  except ValueError:
    result = (false, 0'u64)

proc fromRouter(H: HopLink, raw: bfx.DacFrameBytesResult): bool {.
    role: parser, inline.} =
  ## H/raw: true when the datagram came from this link's router.
  result = bfx.formatDacAddress(raw.remote) == bfx.formatDacAddress(H.remote)

proc sendToRouter(H: HopLink, frame: openArray[uint8]) {.role: dataWriter.} =
  ## H/frame: one frame onto the hop link's own socket.
  bfx.sendDacFrameBytes(H.socket, H.remote, @frame)
  H.lastSentAt = epochTime()

proc forwardVia*(H: HopLink, target: uint64, frame: openArray[uint8]) {.
    role: dataWriter, tag: "ame|networkSurface|write".} =
  ## H: the hop link. target: the route id the frame is for.
  ## frame: one end-to-end frame (a handshake datagram or a session frame).
  H.sendToRouter(bfx.sealAmeRouteForward(H.session, target, frame))

proc forwardHandshakeVia*(H: HopLink, target: uint64,
    record: openArray[uint8]) {.role: dataWriter,
    tag: "ame|networkSurface|write".} =
  ## H/target/record: one whole handshake record; a large one goes as the
  ## same MTU-sized pieces it would take on a socket of its own.
  for piece in bfx.ameHandshakeDatagrams(record):
    H.forwardVia(target, piece)

proc enqueue(H: HopLink, origin: uint64, frame: ByteSeq) {.role: actor.} =
  ## H/origin/frame: kept for whoever reads this origin next.
  if not H.queue.hasKey(origin):
    H.queue[origin] = initDeque[ByteSeq]()
  if H.queue[origin].len >= hopQueueFrames:
    H.queue[origin].popFirst()
  H.queue[origin].addLast(frame)

proc routerFrame(H: HopLink, payload: ByteSeq): HopFrame {.
    role: orchestrator.} =
  ## H/payload: an AME frame from the router itself -- a lane ask or jump
  ## of the hop link, or a directory answer nobody is waiting for.
  var
    lane: LaneOutcome = handleLaneFrame(H.session, payload)
  result = (false, 0'u64, @[], "")
  if lane.step == lsAnswered:
    H.sendToRouter(lane.reply)
  if lane.step != lsNone:
    return
  discard bfx.openAmeRouteDirectory(H.session, bfx.acrDac, payload)

proc routeFrame(H: HopLink, payload: ByteSeq): HopFrame {.
    role: orchestrator.} =
  ## H/payload: an ART frame from the router.
  var
    m: bfx.AmeRouteFrame = bfx.openAmeRouteFrame(H.session, payload)
  if not m.ok:
    return (false, 0'u64, @[], m.err)
  if m.kind == bfx.arkRefuse:
    H.refusals[m.target] = m.refusal
    return (false, m.target, @[], "route refused: " & $m.refusal)
  result = (true, m.origin, m.payload, "")

proc nextHopFrame*(H: HopLink, timeoutMs: int): HopFrame {.
    role: dataFetcher, tag: "ame|networkSurface|read".} =
  ## H/timeoutMs: read ONE datagram from the router and make sense of it.
  ## Anything that is not an end-to-end frame is dealt with here (lane
  ## frames of the hop link answered) and reported as not ok.
  var
    raw: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
  result = (false, 0'u64, @[], "")
  raw = bfx.recvDacFrameBytes(H.socket, hopFrameMaxBytes, timeoutMs)
  if not raw.ok:
    return (false, 0'u64, @[], raw.err)
  if not H.fromRouter(raw):
    return (false, 0'u64, @[], "datagram not from the router")
  H.lastHeardAt = epochTime()
  if bfx.isAmeRouteFrame(raw.payload):
    return H.routeFrame(raw.payload)
  result = H.routerFrame(raw.payload)

proc takeQueued(H: HopLink, origin: uint64): tuple[ok: bool,
    frame: ByteSeq] {.role: actor.} =
  ## H/origin: the oldest queued frame from this origin, if any.
  if not H.queue.hasKey(origin) or H.queue[origin].len == 0:
    return (false, @[])
  result = (true, H.queue[origin].popFirst())

proc refusedTarget(H: HopLink, origin: uint64): string {.role: actor.} =
  ## H/origin: why the router refused frames for this target, once.
  if not H.refusals.hasKey(origin):
    return ""
  result = "route refused: " & $H.refusals[origin]
  H.refusals.del(origin)

proc recvVia*(H: HopLink, origin: uint64,
    timeoutMs: int): bfx.DacFrameBytesResult {.role: dataFetcher,
    tag: "ame|networkSurface|read".} =
  ## H: the hop link. origin: whose frames the caller is waiting for.
  ## timeoutMs: how long to wait. Returns one end-to-end frame from that
  ## origin, as a socket read would (`remote` is the router), or the
  ## router's refusal of that target.
  var
    q: tuple[ok: bool, frame: ByteSeq] = H.takeQueued(origin)
    f: HopFrame = (false, 0'u64, @[], "")
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
    refused: string = ""
  if q.ok:
    return bfx.DacFrameBytesResult(ok: true, payload: q.frame,
      remote: H.remote)
  while epochTime() < deadline:
    f = H.nextHopFrame(max(1, int((deadline - epochTime()) * 1000)))
    refused = H.refusedTarget(origin)
    if refused.len > 0:
      return bfx.DacFrameBytesResult(err: refused)
    if f.ok and f.origin == origin:
      return bfx.DacFrameBytesResult(ok: true, payload: f.frame,
        remote: H.remote)
    if f.ok:
      H.enqueue(f.origin, f.frame)
  result = bfx.DacFrameBytesResult(err: "timed out waiting for route " &
    toHex(origin))

proc stashRouteFrame(H: HopLink, payload: ByteSeq) {.role: actor.} =
  ## H/payload: an ART frame that arrived while waiting for something else,
  ## queued for its origin when it is one.
  var
    f: HopFrame = H.routeFrame(payload)
  if f.ok:
    H.enqueue(f.origin, f.frame)

proc directoryPage(H: HopLink, start: uint16,
    timeoutMs: int): bfx.AmeRouteDirectory {.role: dataFetcher.} =
  ## H/start/timeoutMs: one page of the router's answer.
  var
    raw: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
  H.sendToRouter(bfx.sealAmeRouteAsk(H.session, bfx.acrDac, start))
  while epochTime() < deadline:
    raw = bfx.recvDacFrameBytes(H.socket, hopFrameMaxBytes,
      max(1, int((deadline - epochTime()) * 1000)))
    if not raw.ok or not H.fromRouter(raw):
      continue
    H.lastHeardAt = epochTime()
    if bfx.isAmeRouteFrame(raw.payload):
      H.stashRouteFrame(raw.payload)
      continue
    if handleLaneFrame(H.session, raw.payload).step != lsNone:
      continue
    result = bfx.openAmeRouteDirectory(H.session, bfx.acrDac, raw.payload)
    if result.ok and result.kind == bfx.araDirectory:
      return
  result = bfx.AmeRouteDirectory(err: "the router did not answer")

proc routeDirectory*(H: HopLink, timeoutMs: int = 4000): tuple[ok: bool,
    entries: seq[bfx.AmeRouteEntry], err: string] {.role: dataFetcher,
    tag: "ame|appApi|networkSurface".} =
  ## H: the hop link. Every target the router lets this side see, read
  ## page by page (24 per page).
  var
    page: bfx.AmeRouteDirectory = default(bfx.AmeRouteDirectory)
  result.ok = true
  while true:
    page = H.directoryPage(uint16(result.entries.len), timeoutMs)
    if not page.ok:
      return (false, result.entries, page.err)
    result.entries.add(page.entries)
    if page.entries.len == 0 or result.entries.len >= int(page.total):
      return

proc keepHopAlive*(H: HopLink, now: float) {.role: actor,
    tag: "ame|networkSurface".} =
  ## H/now: when the link has sent nothing for a while, ask the router for
  ## the first directory page; the answer is read and dropped. A router
  ## forgets links that stay silent.
  if not H.open or now - H.lastSentAt < hopKeepaliveSeconds:
    return
  try:
    H.sendToRouter(bfx.sealAmeRouteAsk(H.session, bfx.acrDac, 0'u16))
  except CatchableError:
    H.open = false

proc hopSilent*(H: HopLink, now: float): bool {.role: parser,
    tag: "ame|networkSurface".} =
  ## H/now: true when the hop link is closed or the router has said nothing
  ## for three keepalive periods -- time to make a new one.
  result = H == nil or not H.open or
    now - H.lastHeardAt > 3.0 * hopKeepaliveSeconds

proc closeHop*(H: HopLink) {.role: actor, tag: "ame|lifecycle".} =
  ## H: socket closed, session erased. Every end-to-end link through it is
  ## then dead too.
  if H == nil or not H.open:
    return
  H.open = false
  try:
    bfx.closeDac(H.socket)
  except CatchableError:
    discard
  bfx.clearAmeSession(H.session)
