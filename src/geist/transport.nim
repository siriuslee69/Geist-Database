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

import std/times

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import var_invariants
import ./types
import ./format
import ./masks
import ./bytecheck
import ./payload

export payload.geistDacFrameMaxBytes, payload.geistWholeMaxBytes

type
  GeistLink* {.role: truthState, tag: "ame|networkSurface|types".} = object
    ## An open session. `client` is Bifrost's; Geist only moves payloads.
    ## nextPackage: package identity counter, so two large requests on one
    ##   link are never mistaken for each other's chunks.
    client*: bfx.AmeDacClient
    tier*: GeistTier
    open*: bool
    nextPackage*: uint64

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

proc connectGeist*(remote: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    peer: bfx.AmePinnedPeerIdentity, policy: TriggerPolicy,
    sessionId: uint64 = 1'u64,
    timeoutMs: int = 4000): tuple[ok: bool, link: GeistLink, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|orchestrator".} =
  ## remote: `dac://host:port` peer endpoint.
  ## identity/peer: local signing identity and the pinned remote key.
  ## policy: Geist tier policy; only the masks and the start tier are ours.
  ## Every cryptographic step below is a Bifrost call.
  var
    L: bfx.AmeSuiteLayout = default(bfx.AmeSuiteLayout)
    start: bfx.AmeMaskTier = default(bfx.AmeMaskTier)
    hs: bfx.AmeClientHandshake = default(bfx.AmeClientHandshake)
    sock: bfx.DacSocket = nil
    got: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
    frame: bfx.AmeHandshakeFrame = default(bfx.AmeHandshakeFrame)
    retry: bfx.AmeHelloRetry = default(bfx.AmeHelloRetry)
    serverHello: bfx.AmeServerHello = default(bfx.AmeServerHello)
    finished: bfx.AmeHandshakeResult = default(bfx.AmeHandshakeResult)
    session: bfx.AmeSession = default(bfx.AmeSession)
    auth: bfx.AmeAuthentication = default(bfx.AmeAuthentication)
    validated: tuple[ok: bool, err: string] = (false, "")
    now: int64 = 0
  validated = validateTriggerPolicy(policy)
  if not validated.ok:
    return (false, GeistLink(), validated.err)
  L = geistLayout()
  start = tierOf(L, policy.startTier)
  now = getTime().toUnix()
  try:
    # AM1S: we believe exactly one public key, provisioned out of band.
    auth = bfx.initAmePinnedAuthentication(peer)
    hs = bfx.beginAmeHandshake(sessionId, L, start, 1'u32, [], auth)
    sock = bfx.openDacPeer(remote, timeoutMs)
    bfx.sendDacFrameBytes(sock, remote, bfx.encodeAmeClientHelloFrame(hs.hello))
    got = bfx.recvDacFrameBytes(sock, geistDacFrameMaxBytes, timeoutMs)
    if not got.ok:
      bfx.closeDac(sock)
      return (false, GeistLink(), got.err)
    frame = bfx.decodeAmeHandshakeFrame(got.payload)
    if frame.kind == bfx.ampkHelloRetry:
      # The server wants proof this address can receive before it spends a
      # post-quantum key exchange on us. A retried hello is a WHOLE new
      # hello -- new keys, new transcript -- carrying the cookie it sent.
      retry = bfx.decodeAmeHelloRetry(frame.record)
      bfx.clearAmeClientHandshake(hs)
      hs = bfx.beginAmeHandshake(sessionId, L, start, 1'u32, retry.cookie,
        auth)
      bfx.sendDacFrameBytes(sock, remote,
        bfx.encodeAmeClientHelloFrame(hs.hello, retried = true))
      got = bfx.recvDacFrameBytes(sock, geistDacFrameMaxBytes, timeoutMs)
      if not got.ok:
        bfx.closeDac(sock)
        return (false, GeistLink(), got.err)
      frame = bfx.decodeAmeHandshakeFrame(got.payload)
    bfx.requireHandshakeFrame(frame, bfx.ampkServerHello,
      bfx.ameHandshakeStepServerHello, sessionId)
    serverHello = bfx.decodeAmeServerHello(L, frame.record)
    # Who we are travels HERE, sealed, not in the hello. `finishAmeHandshake`
    # erases the client's KEM secrets whatever the outcome.
    finished = bfx.finishAmeHandshake(hs, serverHello, auth,
      geistDescriptor(identity, now), identity, now)
    if not finished.ok:
      bfx.closeDac(sock)
      return (false, GeistLink(), finished.err)
    bfx.sendDacFrameBytes(sock, remote,
      bfx.encodeAmeClientFinishFrame(sessionId, finished.finish))
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
    result.link.client.socket = sock
    result.link.client.connection = session
    result.link.client.remote = remote
    result.link.tier = policy.startTier
    result.link.open = true
    result.ok = true
  except CatchableError as exc:
    if sock != nil:
      bfx.closeDac(sock)
    result = (false, GeistLink(), exc.msg)

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
    got: bfx.AmeOpenResult = default(bfx.AmeOpenResult)
    sent: SendOutcome = (false, 0, "")
    fed: FeedOutcome = (false, false, @[], "")
    inbox: PackageAssembly = PackageAssembly()
    frames: int = 0
  if not S.open:
    return (false, Reply(), "link is closed")
  try:
    S.nextPackage = S.nextPackage + 1'u64
    sent = sendPayload(S.client.socket, S.client.remote, S.client.connection,
      encodeQuery(q), S.nextPackage)
    if not sent.ok:
      return (false, Reply(), sent.err)
    while true:
      got = bfx.receive(S.client, timeoutMs)
      if not got.ok:
        return (false, Reply(), got.err)
      fed = feedPayload(inbox, got.packet.payload)
      if not fed.ok:
        return (false, Reply(), fed.err)
      if fed.done:
        return replyFrom(fed.payload)
      frames = frames + 1
      # A package whose chunks never finish arriving must not spin here.
      # The count is generous: a megabyte at MTU-sized chunks is ~900.
      if frames > 65_536:
        return (false, Reply(), "package never completed")
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
    S.open = false

