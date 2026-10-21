## ---------------------------------------------------------------------
## Serve <- one socket, many peers: the answering end of a link
## ---------------------------------------------------------------------
##
##   initGeistServer(address, identity, trusted) -> serveOnce(handler)
##
## The asking end is ./transport (connectGeist, send). Both use the same
## wire codec (./transport), the same payload envelope (./payload) and the
## same handshake, seen from the other side:
##
##   client (transport)                          server (this file)
##   ------------------                          ------------------
##   hello   (key material only)     ------->    beginPeer    (./handshake)
##   finish  (our identity SEALED)   ------->    finishPeer   (./handshake)
##   Query                           ------->    answerPeer -> bytecheck
##                                   <-------      -> handler -> Reply
## Who may dial in, and the server's own state, are ./peers; how a
## stranger becomes a peer is ./handshake. ./peers is re-exported here.

import std/[nativesockets, net, tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./address
import ./bytecheck
import ./payload
import ./transport
import ./peers
import ./handshake
import ./ping
import ./lane_recovery

export peers

proc answerPayload(S: GeistServer, payload: ByteSeq, p: PeerContext,
    handler: ServedHandler): Reply {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## S/payload/p: one whole request from an authenticated peer, and who
  ##   that peer is.
  ## handler: what this server does with a request.
  ##
  ##   payload --checkQueryBytes--> malformed? -> Reply(ok: false), no decode
  ##                            \-> decodeQuery -> delegation -> handler
  ##
  ## A malformed request is ANSWERED, not dropped: the sender learns why,
  ## and the session survives. What it must never do is reach the decoder,
  ## which trusts every length it reads.
  ##
  ## Delegation is applied HERE, not in the handler, so no daemon can
  ## forget to do it: a handler always receives rights that have already
  ## been intersected with whatever the address claimed. A malformed
  ## address carries no claim, so the connecting peer's own rights stand.
  var
    complaint: string = checkQueryBytes(payload)
    q: Query = Query()
    ctx: PeerContext = p
    parsed: tuple[ok: bool, a: GeistAddress, err: string] = (false,
      GeistAddress(), "")
  if complaint.len > 0:
    return Reply(ok: false, err: "malformed request: " & complaint)
  q = decodeQuery(payload)
  parsed = parseAddress(q.collection)
  if parsed.ok:
    ctx = S.delegatedContext(ctx, parsed.a)
  result = handler(q, ctx)

proc laneFrame(S: var GeistServer, link: var PeerLink,
    payload: openArray[uint8], remote: bfx.DacAddress,
    key: string): LaneOutcome {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## S/link/payload/remote/key: one frame of an open session, handled when it
  ## is a lane ask or jump (./lane_recovery); lsNone otherwise.
  result = handleLaneFrame(link.session, payload)
  case result.step
  of lsNone:
    discard
  of lsAnswered:
    S.emitTo(key, remote, result.reply)
    reportNetwork(S.observer, "lane.jump.answered", key, link.subject,
      S.shared.authenticationName(), S.policy.startTier, link.sessionId)
  of lsJumped:
    reportNetwork(S.observer, "lane.jump.applied", key, link.subject,
      S.shared.authenticationName(), S.policy.startTier, link.sessionId,
      bytes = int(result.gaveUp))
  of lsRefused:
    reportNetwork(S.observer, "lane.jump.refused", key, link.subject,
      S.shared.authenticationName(), S.policy.startTier, link.sessionId,
      error = result.err)

proc askJump(S: var GeistServer, link: var PeerLink, remote: bfx.DacAddress,
    key: string) {.role: actor, tag: "ame|networkSurface|server".} =
  ## S/link/remote/key: the peer's last frame did not open; ask it to prove
  ## where its lane is, when it looked like a gap and we did not just ask.
  var
    ask: ByteSeq = jumpAskIfBehind(link.session, link.lastJumpAskAt,
      epochTime())
  if ask.len == 0:
    return
  S.emitTo(key, remote, ask)
  reportNetwork(S.observer, "lane.jump.asked", key, link.subject,
    S.shared.authenticationName(), S.policy.startTier, link.sessionId)

proc answerPeer(S: var GeistServer, payload: openArray[uint8],
    remote: bfx.DacAddress, key: string,
    handler: ServedHandler): tuple[ok: bool, served: bool, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## S/payload/remote/key/handler: one frame on an established session.
  ##
  ## `served` distinguishes a completed request from a chunk of one that is
  ## still arriving: a caller counting requests must not count the pieces.
  var
    link: PeerLink = PeerLink()
    opened: bfx.AmeOpenResult = default(bfx.AmeOpenResult)
    ctx: PeerContext = PeerContext()
    reply: Reply = Reply()
    fed: FeedOutcome = (false, false, @[], "")
    sent: SendOutcome = (false, 0, "")
    lane: LaneOutcome = (lsNone, @[], 0'u64, "")
  link = S.peers[key]
  lane = S.laneFrame(link, payload, remote, key)
  if lane.step != lsNone:
    link.lastSeenAt = getTime().toUnix()
    S.peers[key] = link
    return (lane.step != lsRefused, false, lane.err)
  opened = bfx.openAmeDacFrame(link.session, payload, remote)
  if not opened.ok:
    S.askJump(link, remote, key)
    # Keep the session: a single frame failing to open is a replay, a
    # truncated datagram or a stray packet, none of which is a reason to
    # make the peer handshake again.
    S.peers[key] = link
    return (false, false, "frame from " & key & " did not open: " & opened.err)
  link.lastSeenAt = getTime().toUnix()
  fed = feedPayload(link.inbox, opened.packet.payload)
  if not fed.ok:
    S.peers[key] = link
    return (false, false, "frame from " & key & ": " & fed.err)
  if not fed.done:
    # Part of a request that has not all arrived. Nothing to answer yet.
    S.peers[key] = link
    return (true, false, "")
  ctx.subject = link.subject
  ctx.address = key
  ctx.rights = link.rights
  reply = S.answerPayload(fed.payload, ctx, handler)
  link.nextPackage = link.nextPackage + 1'u64
  sent = S.emitPayloadTo(key, remote, link.session, encodeReply(reply),
    link.nextPackage)
  link.requests = link.requests + 1
  S.peers[key] = link
  if not sent.ok:
    return (false, false, "reply to " & key & " failed: " & sent.err)
  S.served = S.served + 1
  result = (true, true, "")
  reportNetwork(S.observer, "request.served", key, link.subject,
    S.shared.authenticationName(), S.policy.startTier,
    sessionId = link.sessionId, bytes = fed.payload.len, error = reply.err)

proc dispatchFrame(S: var GeistServer, payload: ByteSeq,
    remote: bfx.DacAddress, key: string, handler: ServedHandler): tuple[
    ok: bool, served: bool, err: string] {.role: orchestrator.} =
  ## S/payload/remote/key/handler: one complete handshake record or session frame.
  var
    frame: bfx.AmeHandshakeFrame = default(bfx.AmeHandshakeFrame)
    step: tuple[ok: bool, err: string] = (false, "")
    isHandshake: bool = false
  try:
    frame = bfx.decodeAmeHandshakeFrame(payload)
    isHandshake = true
  except CatchableError:
    isHandshake = false
  if not isHandshake:
    if not S.peers.hasKey(key) or S.peers[key].phase != ppOpen:
      return (false, false, "data frame from " & key & " with no session")
    return S.answerPeer(payload, remote, key, handler)
  if frame.kind == bfx.ampkClientHello:
    S.peers.del(key)
    step = S.beginPeer(frame, remote, key)
    return (step.ok, false, step.err)
  if frame.kind == bfx.ampkClientFinish:
    if not S.peers.hasKey(key) or S.peers[key].phase != ppHandshaking:
      return (false, false, "handshake finish from " & key &
        " with no handshake under way")
    step = S.finishPeer(frame, key)
    return (step.ok, false, step.err)
  result = (false, false, "a server does not answer " & $frame.kind & " from " & key)

proc serveOnce*(S: var GeistServer, handler: ServedHandler,
    timeoutMs: int = 1000): tuple[ok: bool, served: bool, err: string] {.
    role: metaOrchestrator, tag: "ame|networkSurface|orchestrator|server".} =
  ## S: bound server.
  ## handler: Query -> Reply, told which peer is asking.
  ## timeoutMs: how long to wait for a frame. A timeout is NOT a failure --
  ##   it is an idle server -- so it returns ok with served = false.
  ##
  ## Handles exactly one frame, which may be any step of any peer's
  ## conversation. A caller loops on this and gets a working multi-peer
  ## server without threads.
  ##
  ## A frame says for itself what it is. Handshake records carry one of
  ## four packet kinds; anything else is session data. So the step is read
  ## off the frame rather than guessed from what this side remembers:
  ##
  ##   client hello    -> begin (or a cookie challenge, remembering nothing)
  ##   client finish   -> finish, if we are mid-handshake with this address
  ##   anything else   -> data, if this address has an open session
  var
    got: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    key: string = ""
    fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
  if not S.open:
    return (false, false, "server is not bound")
  S.dropIdlePeers()
  try:
    got = bfx.recvDacFrameBytes(S.sock, geistDacFrameMaxBytes, timeoutMs)
  except CatchableError as exc:
    return (false, false, exc.msg)
  if not got.ok:
    # Nothing arrived within the window. Ordinary.
    return (true, false, "")
  if isPing(got.payload):
    # A forwarder asking "still there?". Answered before anything is
    # decoded and without touching a session; see ./ping.
    try:
      bfx.sendDacFrameBytes(S.sock, got.remote, pongBytes())
    except CatchableError as exc:
      return (false, false, "pong to " & bfx.formatDacAddress(got.remote) &
        " failed: " & exc.msg)
    return (true, false, "")
  key = bfx.formatDacAddress(got.remote)
  fed = bfx.feedAmeHandshakeDatagram(S.handshakePackages, got.payload, key)
  if not fed.ok:
    return (false, false, fed.err)
  if not fed.done:
    return (true, false, "")
  try:
    result = S.dispatchFrame(fed.payload, got.remote, key, handler)
  except CatchableError as exc:
    result = (false, false, "frame from " & key & ": " & exc.msg)


## ------------------------ peers through a router --------------------
##
## A server behind a router it dials out to (geist-hopd, ./hop_link):
##
##   geistd ==hop link==> geist-hopd <==hop link== phone
##      |                                            |
##      +------ end-to-end handshake and session ----+
##
## Frames from the phone arrive on the hop link, the phone named by the id
## the router proved. They are handled by the SAME code as frames on the
## server's own socket -- handshake, rights, handler -- under the key
## `hop:<id>`, and the answers go back through the hop link (`emitTo`).

proc attachHop*(S: var GeistServer, H: HopLink) {.role: configurator,
    tag: "ame|networkSurface|server".} =
  ## S/H: serve peers that arrive through this hop link too. A previous
  ## hop link is closed, and the peers that came through it are forgotten:
  ## their sessions were tied to it.
  var
    gone: seq[string] = @[]
  if S.hop != nil and S.hop != H:
    S.hop.closeHop()
  for key in S.peers.keys:
    if hopOrigin(key).ok:
      gone.add key
  for key in gone:
    S.peers.del(key)
  S.hop = H

proc serveHopOnce*(S: var GeistServer, handler: ServedHandler,
    timeoutMs: int = 1000): tuple[ok: bool, served: bool, err: string] {.
    role: metaOrchestrator, tag: "ame|networkSurface|orchestrator|server".} =
  ## S/handler/timeoutMs: like `serveOnce`, for ONE frame from the hop link.
  ## A frame that is not from a peer (the router's own traffic) or none at
  ## all within the window is an idle turn, not a failure.
  var
    f: HopFrame = (false, 0'u64, @[], "")
    key: string = ""
    fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
  if S.hop == nil or not S.hop.open:
    return (false, false, "no hop link attached")
  S.dropIdlePeers()
  S.hop.keepHopAlive(epochTime())
  f = S.hop.nextHopFrame(timeoutMs)
  if not f.ok:
    return (true, false, "")
  key = hopKey(f.origin)
  fed = bfx.feedAmeHandshakeDatagram(S.handshakePackages, f.frame, key)
  if not fed.ok:
    return (false, false, fed.err)
  if not fed.done:
    return (true, false, "")
  try:
    result = S.dispatchFrame(fed.payload, S.hop.remote, key, handler)
  except CatchableError as exc:
    result = (false, false, "frame from " & key & ": " & exc.msg)

proc serveAnyOnce*(S: var GeistServer, handler: ServedHandler,
    timeoutMs: int = 1000): tuple[ok: bool, served: bool, err: string] {.
    role: metaOrchestrator, tag: "ame|networkSurface|orchestrator|server".} =
  ## S/handler/timeoutMs: one frame from the server's own socket OR from its
  ## hop link, whichever has one first. Without a hop link this is
  ## `serveOnce`.
  var
    fds: seq[SocketHandle] = @[]
  if S.hop == nil or not S.hop.open:
    return S.serveOnce(handler, timeoutMs)
  fds = @[S.sock.getFd(), S.hop.socket.getFd()]
  if selectRead(fds, timeoutMs) <= 0:
    S.hop.keepHopAlive(epochTime())
    return (true, false, "")
  if S.hop.socket.getFd() in fds:
    return S.serveHopOnce(handler, 0)
  result = S.serveOnce(handler, 0)
