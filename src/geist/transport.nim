## ---------------------------------------------------------------------
## Transport <- Query/Reply over Bifrost AME/DAC
## ---------------------------------------------------------------------
##
##   connectGeist -> send(Query) -> Reply -> close
##
## The ASKING end of a link, and the wire codec both ends share. The
## answering end is ./serve; the envelope that lets one payload span many
## datagrams is ./payload.
##
## Geist owns NOTHING of the transport except the masks in ./masks. This
## module is a shim: it serialises a Query, hands the bytes to Bifrost, and
## deserialises the Reply. The handshake, identity certificates, framing,
## packaging, replay defence and tier transitions are all Bifrost calls.
##
##   Geist                         Bifrost
##   -----                         -------
##   masks / tier policy   ---->   beginAmeHandshake / answerAmeHandshake
##   Query bytes           ---->   sendAmeDac
##   Reply bytes           <----   openAmeDacFrame
##
## The handshake is AME's PRIVATE one: the first message names nobody.
##
##   client                                     server
##   ------                                     ------
##   hello   (key material only)     ------->   who sent this? unknown
##                                   <-------   retry (cookie), if asked for
##   hello   (same, plus cookie)     ------->   cookie checks out
##                                   <-------   server hello: key answer in
##                                              the clear, our identity
##                                              SEALED under it
##   finish  (our identity SEALED)   ------->   open it, then choose the pin
##                                              it matches
##
## Two consequences for the code below. The server cannot look up a peer's
## pin when the hello arrives -- nothing in the hello says who sent it --
## so it picks the pin at the last step instead; see `finishPeer` in
## ./serve. And a hello costs the server nothing until a cookie has proved
## the sender can receive at the address it claims; see `beginPeer`.
##
## A serialised `Query` IS the request body. That is why there is no
## separate exchange-kind enum, no per-operation encode/decode pair, and
## no second wire codec: `qoSubscribe` is just another op.

import std/[strutils, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import var_invariants
import ./types
import ./format
import ./masks
import ./bytecheck
import ./payload
import ./lane_recovery
import ./hop_link
import ./authentication
import ./network_events

export authentication, network_events, hop_link

export payload.geistDacFrameMaxBytes, payload.geistWholeMaxBytes

type
  GeistLink* {.role: truthState, tag: "ame|networkSurface|types".} = object
    ## An open session. `client` is Bifrost's; Geist only moves payloads.
    ## nextPackage: package identity counter, so two large requests on one
    ##   link are never mistaken for each other's chunks.
    client*: bfx.AmeDacClient
    hop*: HopLink
    target*: uint64
    ownsHop*: bool
      ## true: closing this link closes `hop` too (a one-shot client that
      ## made the hop link only for this one).
      ## A link through a geist-hopd router (`connectGeistVia`): its frames
      ## go through `hop`, addressed to route id `target`, and
      ## `client.socket` is nil. nil for a link with a socket of its own.
    tier*: GeistTier
    open*: bool
    nextPackage*: uint64
    observer*: GeistNetworkObserver
    mode*: string
    subject*: string
    sessionId*: uint64
    confirmed*: bool
    lastJumpAskAt*: float
      ## When this link last asked the server for a lane jump (./lane_recovery).
    sessionKeys*: SessionKeyStore
    pendingSessionKey*: ByteSeq
      ## The SK this session handed out, kept until the server's first
      ## answer proves it holds it too; then it becomes the one the next
      ## handshake sends (./session_keys, "When a new SK counts").

## A handler type without a peer context used to live here. It is gone:
## anything deciding what a request MAY do has to know who is asking, and
## that is not something the request can say. See `ServedHandler` below.

## ---------------------------- wire codec ----------------------------

proc encodeQuery*(q: Query): ByteSeq {.role: encryptor,
    tag: "codecBoundary|networkSurface|write".} =
  ## q: query serialised as the DAC request body.
  var
    i: int = 0
  result = @[]
  result.add uint8(ord(q.op))
  result.addText(q.collection)
  result.addU32(uint32(q.where.len))
  while i < q.where.len:
    result.addText(q.where[i].field)
    result.add uint8(ord(q.where[i].isText))
    result.addText(q.where[i].text)
    result.addU64(cast[uint64](q.where[i].num))
    i = i + 1
  result.addU32(q.limit)
  result.addU64(q.cursor)
  result.addText(q.subscriptionId)
  result.addU32(uint32(q.payload.len))
  result.addBytes(q.payload)

proc decodeQuery*(A: openArray[uint8]): Query {.role: parser,
    tag: "codecBoundary|networkSurface|read".} =
  ## A: bytes produced by `encodeQuery`.
  var
    o: int = 1
    n: int = 0
    i: int = 0
    p: Predicate = Predicate()
  if A.len < 1:
    return
  result.op = QueryOp(A[0])
  result.collection = A.readText(o)
  n = int(A.getU32(o)); o = o + 4
  while i < n:
    p = Predicate()
    p.field = A.readText(o)
    p.isText = A[o] != 0'u8; o = o + 1
    p.text = A.readText(o)
    p.num = cast[int64](A.getU64(o)); o = o + 8
    result.where.add p
    i = i + 1
  result.limit = A.getU32(o); o = o + 4
  result.cursor = A.getU64(o); o = o + 8
  result.subscriptionId = A.readText(o)
  n = int(A.getU32(o)); o = o + 4
  result.payload = newSeq[uint8](n)
  i = 0
  while i < n:
    result.payload[i] = A[o + i]
    i = i + 1

proc encodeRows*(R: openArray[Row]): ByteSeq {.role: encryptor,
    tag: "codecBoundary|networkSurface|write".} =
  ## R: rows serialised as `count | (schemaId | length | bytes)*`.
  ##
  ## One row codec for both directions: a reply carries rows this way and
  ## so does a `qoPut` payload, because a row travelling to a peer and a
  ## row travelling from one are the same thing.
  var
    i: int = 0
  result.addU32(uint32(R.len))
  while i < R.len:
    result.addU16(R[i].schemaId)
    result.addU32(uint32(R[i].data.len))
    result.addBytes(R[i].data)
    i = i + 1

proc decodeRows*(A: openArray[uint8], o: var int): seq[Row] {.role: parser,
    tag: "codecBoundary|networkSurface|read",
    needs: o >= 0 and o <= A.len,
    gives: o <= A.len.} =
  ## A/o: buffer and cursor advanced past an encoded row list.
  ##
  ## Every length is checked against what is actually there: these bytes
  ## come off a socket, and a count of four billion rows must produce an
  ## empty answer rather than an allocation.
  var
    n: int = 0
    i: int = 0
    j: int = 0
    row: Row = Row()
  if o + 4 > A.len:
    return @[]
  n = int(A.getU32(o)); o = o + 4
  while i < n:
    if o + 6 > A.len:
      return result
    row = Row()
    row.schemaId = A.getU16(o); o = o + 2
    j = int(A.getU32(o)); o = o + 4
    if j < 0 or o + j > A.len:
      return result
    row.data = newSeq[uint8](j)
    j = 0
    while j < row.data.len:
      row.data[j] = A[o + j]
      j = j + 1
    o = o + row.data.len
    result.add row
    i = i + 1

proc encodeReply*(r: Reply): ByteSeq {.role: encryptor,
    tag: "codecBoundary|networkSurface|write".} =
  ## r: reply serialised as the DAC response body.
  result = @[]
  result.add uint8(ord(r.ok))
  result.addText(r.err)
  result.addU64(r.cursor)
  result.addU32(r.matched)
  result.addU64(r.epoch)
  result.addBytes(encodeSchema(r.schema))
  result.addBytes(encodeRows(r.rows))

proc decodeReply*(A: openArray[uint8]): Reply {.role: parser,
    tag: "codecBoundary|networkSurface|read".} =
  ## A: bytes produced by `encodeReply`.
  var
    o: int = 1
  if A.len < 1:
    return
  result.ok = A[0] != 0'u8
  result.err = A.readText(o)
  result.cursor = A.getU64(o); o = o + 8
  result.matched = A.getU32(o); o = o + 4
  result.epoch = A.getU64(o); o = o + 8
  result.schema = decodeSchema(A, o)
  result.rows = decodeRows(A, o)

## ---------------------------- identity ------------------------------

proc geistIdentity*(subject: string): bfx.AmeIdentityKey {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## subject: stable local name. The signing stack comes from the Geist
  ## signature slots, so an identity always carries every algorithm the
  ## highest configured tier can demand.
  result = bfx.initAmeIdentityKey(subject, geistSignatureSlots())

proc geistPeerPin*(i: bfx.AmeIdentityKey): bfx.AmePinnedPeerIdentity {.
    role: configurator, tag: "ame|cryptoBoundary|networkSurface".} =
  ## i: identity whose public half becomes the pin a peer checks against.
  result = bfx.pinnedPeerIdentity(i)

const
  geistIdentityValidSeconds* = 365'i64 * 24'i64 * 3600'i64
    ## How long the descriptor a Geist node sends about itself stays good.
    ##
    ## A pinned identity is not a certificate -- nobody signed it -- but it
    ## still carries a validity window, and Bifrost checks it. Leaving the
    ## window open forever would mean a key that can never be retired
    ## without visiting every peer that pinned it. One year is short enough
    ## that a forgotten node stops working rather than staying reachable,
    ## and long enough that nobody re-keys a desktop weekly.

proc geistDescriptor*(i: bfx.AmeIdentityKey,
    nowUnix: int64): bfx.AmeIdentityCertificate {.role: truthBuilder,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## i: the local identity, described the way a peer receives it.
  ## nowUnix: the wall clock the window is measured from.
  ##
  ## This is what travels inside the sealed block of a handshake. It names
  ## no authority, because a pinned peer checks the KEYS, not a signature
  ## over them.
  result = bfx.pinnedIdentityDescriptor(i, nowUnix,
    nowUnix + geistIdentityValidSeconds)

## --------------------------- handshake ------------------------------

type
  LinkPath {.role: configurator, tag: "ame|networkSurface|types".} = object
    ## How a link's frames travel, which is the one thing a link through a
    ## router does differently:
    ##
    ##   hop == nil   own socket, straight to `remote`
    ##   hop != nil   through that hop link, addressed to route id `target`
    ##                (./hop_link); `socket` stays nil, `remote` is the router
    socket: bfx.DacSocket
    remote: bfx.DacAddress
    hop: HopLink
    target: uint64

proc sendRecord(P: LinkPath, record: ByteSeq) {.role: dataWriter,
    tag: "ame|networkSurface|write".} =
  ## P/record: one whole handshake record on its way.
  if P.hop == nil:
    bfx.sendAmeHandshakeDac(P.socket, P.remote, record)
    return
  P.hop.forwardHandshakeVia(P.target, record)

proc recvRecordVia(P: LinkPath, timeoutMs: int): bfx.DacFrameBytesResult {.
    role: dataFetcher, tag: "ame|networkSurface|read".} =
  ## P/timeoutMs: one whole handshake record through the router, put back
  ## together from its pieces as it would be on a socket of its own.
  var
    inbox: bfx.AmeHandshakePackages = default(bfx.AmeHandshakePackages)
    got: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    fed: bfx.AmeHandshakeFeed = default(bfx.AmeHandshakeFeed)
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
  while epochTime() < deadline:
    got = P.hop.recvVia(P.target, max(1, int((deadline - epochTime()) * 1000)))
    if not got.ok:
      return got
    fed = inbox.feedAmeHandshakeDatagram(got.payload, hopKey(P.target))
    if not fed.ok:
      return bfx.DacFrameBytesResult(err: fed.err)
    if fed.done:
      return bfx.DacFrameBytesResult(ok: true, payload: fed.payload,
        remote: P.remote)
  result = bfx.DacFrameBytesResult(err: "AME handshake deadline expired")

proc recvRecord(P: LinkPath, timeoutMs: int): bfx.DacFrameBytesResult {.
    role: dataFetcher, tag: "ame|networkSurface|read".} =
  ## P/timeoutMs: the other side's next whole handshake record.
  if P.hop == nil:
    return bfx.recvAmeHandshakeDac(P.socket, P.remote, timeoutMs)
  result = P.recvRecordVia(timeoutMs)

proc helloAgain(P: LinkPath,
    hs: var bfx.AmeClientHandshake, retry: bfx.AmeHelloRetry, sessionId: uint64,
    L: bfx.AmeSuiteLayout, start: bfx.AmeMaskTier, auth: bfx.AmeAuthentication,
    timeoutMs: int): bfx.DacFrameBytesResult {.role: orchestrator,
    tag: "ame|networkSurface".} =
  ## P/hs: the link being opened and its half-done handshake.
  ## retry: the server's cookie challenge.
  ## sessionId/L/start/auth/timeoutMs: as for the first hello.
  ##
  ## The server wants proof this address can receive before it spends a
  ## post-quantum key exchange on us. A retried hello is a WHOLE new hello
  ## -- new keys, new transcript -- carrying the cookie it sent. Returns the
  ## server's next frame.
  bfx.clearAmeClientHandshake(hs)
  hs = bfx.beginAmeHandshake(sessionId, L, start, 1'u32, retry.cookie, auth)
  P.sendRecord(bfx.encodeAmeClientHelloFrame(hs.hello, retried = true))
  result = P.recvRecord(timeoutMs)

proc handshakeOn(P: LinkPath, identity: bfx.AmeIdentityKey,
    peer: bfx.AmePinnedPeerIdentity, policy: TriggerPolicy,
    sessionId: uint64, timeoutMs: int, shared: GeistSharedKey,
    observer: GeistNetworkObserver): tuple[ok: bool, link: GeistLink,
    err: string] {.role: orchestrator, tag: "ame|networkSurface|orchestrator".} =
  ## P: where the frames go (own socket, or through a router).
  ## identity/peer: local signing identity and the pinned remote key.
  ## policy: Geist tier policy; only the masks and the start tier are ours.
  ## The handshake is the same either way; only `P` differs.
  ## Every cryptographic step below is a Bifrost call.
  var
    L: bfx.AmeSuiteLayout = default(bfx.AmeSuiteLayout)
    start: bfx.AmeMaskTier = default(bfx.AmeMaskTier)
    hs: bfx.AmeClientHandshake = default(bfx.AmeClientHandshake)
    got: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    frame: bfx.AmeHandshakeFrame = default(bfx.AmeHandshakeFrame)
    serverHello: bfx.AmeServerHello = default(bfx.AmeServerHello)
    finished: bfx.AmeHandshakeResult = default(bfx.AmeHandshakeResult)
    session: bfx.AmeSession = default(bfx.AmeSession)
    auth: bfx.AmeAuthentication = default(bfx.AmeAuthentication)
    validated: tuple[ok: bool, err: string] = (false, "")
    now: int64 = 0
    endpoint: string = bfx.formatDacAddress(P.remote)
  validated = validateTriggerPolicy(policy)
  if not validated.ok:
    return (false, GeistLink(), validated.err)
  L = geistLayout()
  start = tierOf(L, policy.startTier)
  now = getTime().toUnix()
  if P.hop != nil:
    endpoint = endpoint & "#" & toHex(P.target)
  defer:
    bfx.clearAmeClientHandshake(hs)
    if not result.ok:
      reportNetwork(observer, "handshake.failed", endpoint,
        peer.subject, shared.authenticationName(), policy.startTier,
        sessionId, error = result.err)
  try:
    if shared.keepsSessionKeys():
      auth = shared.authenticationFor(peer,
        shared.sessionKeys.loadSessionKeys(peer.subject).confirmed)
    else:
      auth = shared.authenticationFor(peer)
    reportNetwork(observer, "handshake.begin", endpoint,
      peer.subject, shared.authenticationName(), policy.startTier, sessionId)
    hs = bfx.beginAmeHandshake(sessionId, L, start, 1'u32, [], auth)
    P.sendRecord(bfx.encodeAmeClientHelloFrame(hs.hello))
    got = P.recvRecord(timeoutMs)
    if not got.ok:
      return (false, GeistLink(), got.err)
    frame = bfx.decodeAmeHandshakeFrame(got.payload)
    if frame.kind == bfx.ampkHelloRetry:
      reportNetwork(observer, "handshake.cookie", endpoint,
        peer.subject, shared.authenticationName(), policy.startTier, sessionId)
      got = P.helloAgain(hs, bfx.decodeAmeHelloRetry(frame.record),
        sessionId, L, start, auth, timeoutMs)
    if not got.ok:
      return (false, GeistLink(), got.err)
    frame = bfx.decodeAmeHandshakeFrame(got.payload)
    bfx.requireHandshakeFrame(frame, bfx.ampkServerHello,
      bfx.ameHandshakeStepServerHello, sessionId)
    serverHello = bfx.decodeAmeServerHello(L, frame.record)
    reportNetwork(observer, "handshake.answer", endpoint,
      peer.subject, shared.authenticationName(), policy.startTier, sessionId,
      bytes = got.payload.len)
    # Who we are travels HERE, sealed, not in the hello. `finishAmeHandshake`
    # erases the client's KEM secrets whatever the outcome.
    finished = bfx.finishAmeHandshake(hs, serverHello, auth,
      geistDescriptor(identity, now), identity, now)
    if not finished.ok:
      return (false, GeistLink(), finished.err)
    P.sendRecord(bfx.encodeAmeClientFinishFrame(sessionId, finished.finish))
    # The handshake's peerTrust must ride into the session: initAmeSession
    # requires trust by default, and dropping it here fails every request
    # AFTER a handshake that actually succeeded.
    session = bfx.initAmeSession(finished.auth, supportedTierPath(policy),
      sessionId, 1'u32, 5'u32, bfx.dplCleanPath, bfx.amcUserdata,
      bfx.defaultAmeInboxCapacity, true, finished.peerTrust)
    # KEEP the handshake socket. The server keys its sessions by source
    # address, so opening a second socket for the data would arrive as a
    # stranger -- which is exactly what used to force a reply to be aimed
    # at the AME packet's own source rather than the handshake's.
    result.link.client.socket = P.socket
    result.link.client.connection = session
    result.link.client.remote = P.remote
    result.link.hop = P.hop
    result.link.target = P.target
    result.link.tier = policy.startTier
    result.link.open = true
    result.link.observer = observer
    result.link.mode = shared.authenticationName()
    result.link.subject = peer.subject
    result.link.sessionId = sessionId
    if shared.keepsSessionKeys():
      result.link.sessionKeys = shared.sessionKeys
      result.link.pendingSessionKey = bfx.ameSessionKey(session)
    result.ok = true
    reportNetwork(observer, "handshake.finish.sent", endpoint,
      peer.subject, result.link.mode, policy.startTier, sessionId)
  except CatchableError as exc:
    result = (false, GeistLink(), exc.msg)

proc connectGeist*(remote: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    peer: bfx.AmePinnedPeerIdentity, policy: TriggerPolicy,
    sessionId: uint64 = 1'u64,
    timeoutMs: int = 4000, shared: GeistSharedKey = nil,
    observer: GeistNetworkObserver = nil): tuple[ok: bool, link: GeistLink, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|orchestrator".} =
  ## remote: `dac://host:port` peer endpoint.
  ## identity/peer: local signing identity and the pinned remote key.
  ## policy: Geist tier policy; only the masks and the start tier are ours.
  ## The link gets a socket of its own, kept for its whole life.
  var
    P: LinkPath = LinkPath(remote: remote)
  try:
    P.socket = bfx.openDacPeer(remote, timeoutMs)
  except CatchableError as exc:
    return (false, GeistLink(), exc.msg)
  result = handshakeOn(P, identity, peer, policy, sessionId, timeoutMs,
    shared, observer)
  if not result.ok:
    bfx.closeDac(P.socket)

proc connectGeistVia*(hop: HopLink, target: uint64,
    identity: bfx.AmeIdentityKey, peer: bfx.AmePinnedPeerIdentity,
    policy: TriggerPolicy, sessionId: uint64 = 1'u64, timeoutMs: int = 4000,
    shared: GeistSharedKey = nil, observer: GeistNetworkObserver = nil): tuple[
    ok: bool, link: GeistLink, err: string] {.role: orchestrator,
    tag: "ame|appApi|networkSurface|orchestrator".} =
  ## hop: an open hop link to a geist-hopd router (`connectHop`).
  ## target: the route id of the Geist server to reach (`routeDirectory`).
  ## identity/peer/policy/...: exactly as for `connectGeist` -- the
  ## handshake runs END TO END with the target, so `peer` is the TARGET's
  ## pin, not the router's. The router sees ids and lengths, never content.
  ##
  ## The link uses the hop link's socket and does not own it: closing this
  ## link leaves the hop link open for others.
  result = handshakeOn(LinkPath(remote: hop.remote, hop: hop, target: target),
    identity, peer, policy, sessionId, timeoutMs, shared, observer)

proc connectHop*(remote: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    routerPin: bfx.AmePinnedPeerIdentity, policy: TriggerPolicy,
    sessionId: uint64 = 1'u64, timeoutMs: int = 4000,
    shared: GeistSharedKey = nil, observer: GeistNetworkObserver = nil): tuple[
    ok: bool, hop: HopLink, err: string] {.role: orchestrator,
    tag: "ame|appApi|networkSurface|orchestrator".} =
  ## remote/routerPin: a geist-hopd router and its pin.
  ## identity/policy/...: as for `connectGeist`.
  ## An ordinary handshake with the router; the session and socket then
  ## become a hop link (./hop_link) instead of a Geist link.
  var
    made: tuple[ok: bool, link: GeistLink, err: string] = connectGeist(remote,
      identity, routerPin, policy, sessionId, timeoutMs, shared, observer)
  if not made.ok:
    return (false, nil, made.err)
  result = (true, initHopLink(made.link.client.socket, made.link.client.remote,
    made.link.client.connection, routerPin.subject), "")

proc replyFrom(payload: ByteSeq): tuple[ok: bool, reply: Reply,
    err: string] {.role: parser, tag: "codecBoundary|networkSurface|read".} =
  ## payload: one whole answer from a peer -> the Reply, or why it is not
  ## one. Checked by `checkReplyBytes` before the decoder, which trusts
  ## every length it reads, ever sees it.
  var
    complaint: string = checkReplyBytes(payload)
  if complaint.len > 0:
    return (false, Reply(), "malformed answer: " & complaint)
  result = (true, decodeReply(payload), "")

proc emitFrame(S: GeistLink, frame: ByteSeq) {.role: dataWriter,
    tag: "ame|networkSurface|write".} =
  ## S/frame: one sealed frame to the other end, however this link travels.
  if S.hop == nil:
    bfx.sendDacFrameBytes(S.client.socket, S.client.remote, frame)
    return
  S.hop.forwardVia(S.target, frame)

proc receiveFrame(S: GeistLink, timeoutMs: int): bfx.DacFrameBytesResult {.
    role: dataFetcher, tag: "ame|networkSurface|read".} =
  ## S/timeoutMs: the next frame from the other end, however this link
  ## travels. Through a router, `remote` is the router.
  if S.hop == nil:
    return bfx.recvDacFrameBytes(S.client.socket, geistDacFrameMaxBytes,
      timeoutMs)
  result = S.hop.recvVia(S.target, timeoutMs)

proc sendQuery(S: var GeistLink, payload: ByteSeq): SendOutcome {.
    role: orchestrator, tag: "ame|networkSurface|write".} =
  ## S/payload: one encoded Query as one frame or a package of them.
  S.nextPackage = S.nextPackage + 1'u64
  if S.hop == nil:
    return sendPayload(S.client.socket, S.client.remote, S.client.connection,
      payload, S.nextPackage)
  try:
    for frame in sealPayloadFrames(S.client.connection, payload,
        S.nextPackage):
      S.emitFrame(frame)
      result.frames = result.frames + 1
    result.ok = true
  except CatchableError as exc:
    result = (false, result.frames, exc.msg)

proc laneFrame(S: var GeistLink, raw: bfx.DacFrameBytesResult,
    resend: var bool): bool {.role: orchestrator,
    tag: "ame|networkSurface|read".} =
  ## S/raw: one datagram from the server. True when it was a lane frame
  ## (./lane_recovery) and has been dealt with; `resend` is set when the
  ## server could not follow OUR lane, so the request it was reading is
  ## lost and must go out again.
  var
    lane: LaneOutcome = handleLaneFrame(S.client.connection, raw.payload)
    endpoint: string = bfx.formatDacAddress(S.client.remote)
  case lane.step
  of lsNone:
    return false
  of lsAnswered:
    S.emitFrame(lane.reply)
    resend = true
    reportNetwork(S.observer, "lane.jump.answered", endpoint, S.subject,
      S.mode, S.tier, S.sessionId)
  of lsJumped:
    reportNetwork(S.observer, "lane.jump.applied", endpoint, S.subject,
      S.mode, S.tier, S.sessionId, bytes = int(lane.gaveUp))
  of lsRefused:
    reportNetwork(S.observer, "lane.jump.refused", endpoint, S.subject,
      S.mode, S.tier, S.sessionId, error = lane.err)
  result = true

proc askJump(S: var GeistLink) {.role: actor, tag: "ame|networkSurface".} =
  ## S: a link whose last frame did not open. Asks the server to prove where
  ## its lane is, when the frame looked like a gap and we did not just ask.
  var
    ask: ByteSeq = jumpAskIfBehind(S.client.connection, S.lastJumpAskAt,
      epochTime())
  if ask.len == 0:
    return
  S.emitFrame(ask)
  reportNetwork(S.observer, "lane.jump.asked",
    bfx.formatDacAddress(S.client.remote), S.subject, S.mode, S.tier,
    S.sessionId)

proc awaitReply(S: var GeistLink, timeoutMs: int, resend: var bool): tuple[
    ok: bool, reply: Reply, err: string] {.role: dataFetcher,
    tag: "ame|networkSurface|read".} =
  ## S/timeoutMs: frames read until one whole answer has arrived -- one
  ## frame, or a package of many -- and that answer checked and decoded.
  ## resend: set, and the wait ended, when the server asked for a lane
  ## jump: the request it was reading never arrived whole.
  var
    got: bfx.AmeOpenResult = default(bfx.AmeOpenResult)
    fed: FeedOutcome = (false, false, @[], "")
    inbox: PackageAssembly = PackageAssembly()
    frames: int = 0
    raw: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    header: bfx.AmeFrameHeader = default(bfx.AmeFrameHeader)
    deadline: float = epochTime() + float(timeoutMs) / 1000.0
    remaining: int = 0
    isLane: bool = false
  # A package whose chunks never finish arriving must not spin here. The
  # count is generous: a megabyte at MTU-sized chunks is ~900.
  while frames <= 65_536:
    remaining = int((deadline - epochTime()) * 1000)
    if remaining <= 0:
      return (false, Reply(), "Geist reply deadline expired")
    raw = S.receiveFrame(remaining)
    if not raw.ok: return (false, Reply(), raw.err)
    frames = frames + 1
    if bfx.formatDacAddress(raw.remote) != bfx.formatDacAddress(S.client.remote): continue
    header = bfx.decodeAmeFrameHeader(raw.payload)
    if header.packetKind == bfx.ampkHandshakePackage or
        bfx.ameHandshakeKindValid(header.packetKind): continue
    isLane = S.laneFrame(raw, resend)
    if resend:
      return (false, Reply(), "server could not follow this lane; jump sent")
    if isLane:
      continue
    got = bfx.openAmeDacFrame(S.client.connection, raw.payload, raw.remote)
    if not got.ok and bfx.ameSessionBehind(S.client.connection):
      # A gap too wide for the reorder window. Ask for a jump and keep
      # reading: the frames after it will open once the jump is in.
      S.askJump()
      continue
    if not got.ok:
      return (false, Reply(), got.err)
    fed = feedPayload(inbox, got.packet.payload)
    if not fed.ok:
      return (false, Reply(), fed.err)
    if fed.done:
      return replyFrom(fed.payload)
  result = (false, Reply(), "package never completed")

proc replyTo(S: var GeistLink, sent: SendOutcome, timeoutMs: int,
    resend: var bool): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|networkSurface".} =
  ## S/sent/timeoutMs/resend: the answer to a request that went out, or why
  ## there is none -- the send itself failed.
  if not sent.ok:
    return (false, Reply(), sent.err)
  result = S.awaitReply(timeoutMs, resend)

proc send*(S: var GeistLink, q: Query,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|orchestrator".} =
  ## S: open link.
  ## q: request; the serialised Query is the whole body.
  ##
  ## Either side may need more than one frame -- a push of large rows going
  ## out, a sync answer coming back -- so the reply is read until the
  ## payload is complete rather than assumed to arrive whole. See the
  ## package note above.
  var
    sent: SendOutcome = (false, 0, "")
    resend: bool = false
    attempts: int = 0
  if not S.open:
    return (false, Reply(), "link is closed")
  defer:
    reportNetwork(S.observer, if result.ok: "reply.received" else: "request.failed",
      bfx.formatDacAddress(S.client.remote), S.subject, S.mode, S.tier,
      S.sessionId, bytes = q.payload.len, error = result.err)
  try:
    # Twice at most: the second time only when the server proved it could
    # not read the first (it asked for a lane jump, which we answered).
    while attempts < 2:
      resend = false
      sent = S.sendQuery(encodeQuery(q))
      result = S.replyTo(sent, timeoutMs, resend)
      attempts = if resend: attempts + 1 else: 2
    if result.ok and S.pendingSessionKey.len > 0:
      keepClientSessionKey(S.sessionKeys, S.subject, S.pendingSessionKey)
      S.pendingSessionKey = @[]
    if result.ok and not S.confirmed:
      S.confirmed = true
      reportNetwork(S.observer, "handshake.confirmed", bfx.formatDacAddress(S.client.remote),
        S.subject, S.mode, S.tier, S.sessionId)
  except CatchableError as exc:
    result = (false, Reply(), exc.msg)

proc subscribeRemote*(S: var GeistLink, id: string,
    collection: string = "", fromCursor: uint64 = 0'u64,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync".} =
  ## S: open link.
  ## id: subscription name, stable across reconnects so a resumed session
  ##   continues from its own cursor rather than replaying.
  ## fromCursor: resume point; the server decides what it can still serve.
  result = S.send(Query(op: qoSubscribe, collection: collection,
    subscriptionId: id, cursor: fromCursor), timeoutMs)

proc pollRemote*(S: var GeistLink, id: string, limit: uint32 = 64'u32,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync".} =
  ## S/id/limit: link, subscription and maximum rows per poll.
  ##
  ## The reply CARRIES the rows. The server remembers this subscription's
  ## cursor, so a caller polls without tracking a position itself; the
  ## trade is that the server must have been told the name before.
  result = S.send(Query(op: qoPoll, subscriptionId: id, limit: limit),
    timeoutMs)

proc syncRemote*(S: var GeistLink, cursor: uint64, limit: uint32 = 256'u32,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync".} =
  ## S: open link.
  ## cursor: how many rows of the peer's log this side already holds.
  ## limit: maximum rows in one answer, so it fits one datagram.
  ##
  ## The stateless half of following a peer: the CALLER keeps the cursor,
  ## so nothing has to be remembered on the other side and a follower that
  ## has been away for a week catches up with the same call it uses when it
  ## has been away for a second.
  ##
  ## Check `reply.epoch` against the last one seen. A change means the
  ## peer's log was rewritten and this cursor now counts different rows --
  ## start again from zero.
  result = S.send(Query(op: qoSync, cursor: cursor, limit: limit), timeoutMs)

proc pushRemote*(S: var GeistLink, R: openArray[Row],
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync|write".} =
  ## S: open link.
  ## R: rows to store on the PEER, exactly as this side holds them --
  ##   identity included, so the peer reproduces the operation rather than
  ##   guessing at it: a new id adds, a known id supersedes, a tombstone
  ##   removes.
  ##
  ## Refused unless the peer granted this pin `prWrite`. Sending the rows
  ## themselves rather than a command is what keeps the write path the same
  ## code as the read path.
  result = S.send(Query(op: qoPut, payload: encodeRows(R)), timeoutMs)

proc fetchRemote*(S: var GeistLink, id: RowId,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync".} =
  ## S/id: one row of the peer, by the name both sides use for it.
  result = S.send(Query(op: qoFetch, cursor: id), timeoutMs)

proc deleteRemote*(S: var GeistLink, id: RowId,
    timeoutMs: int = 4000): tuple[ok: bool, reply: Reply, err: string] {.
    role: orchestrator, tag: "ame|appApi|networkSurface|sync|write".} =
  ## S/id: ask the peer to remove one row. Needs `prWrite` there.
  result = S.send(Query(op: qoDelete, cursor: id), timeoutMs)

proc close*(S: var GeistLink) {.role: actor,
    tag: "ame|lifecycle|networkSurface".} =
  ## S: link closed and its Bifrost session cleared.
  if S.open:
    bfx.close(S.client)
    if S.ownsHop:
      S.hop.closeHop()
    S.open = false

