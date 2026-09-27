## ---------------------------------------------------------------------
## Transport <- Query/Reply over Bifrost AME/DAC
## ---------------------------------------------------------------------
##
##   connectGeist -> send(Query) -> Reply -> close
##   initGeistServer(address, identity, trusted) -> serveOnce(handler)
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
## so it picks the pin at the last step instead; see `finishPeer`. And a
## hello costs the server nothing until a cookie has proved the sender can
## receive at the address it claims; see `beginPeer`.
##
## A serialised `Query` IS the request body. That is why there is no
## separate exchange-kind enum, no per-operation encode/decode pair, and
## no second wire codec: `qoSubscribe` is just another op.

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import var_invariants
import ./types
import ./format
import ./masks
import ./address
import ./bytecheck

const
  geistDacFrameMaxBytes* = 65_507
    ## One DAC datagram. Bifrost exposes no such constant, so Geist pins it
    ## here. Handshakes at gtArchive and above exceed this because the
    ## code-based KEM public keys are ~1.3 MB; those tiers must use DAC
    ## package transfer. `./masks.nim` says which tiers those are and why.

type
  SendOutcome* {.tag: "ame|networkSurface|types".} = tuple
    ## What one outgoing payload did. `frames` counts datagrams actually
    ## put on the wire, which is 1 for a whole payload and 1 + chunks for
    ## a packaged one -- a caller measuring cost wants the frames, not the
    ## calls.
    ok: bool
    frames: int
    err: string

  FeedOutcome* {.tag: "ame|networkSurface|types".} = tuple
    ## What one incoming frame did to a half-built payload. `done` is the
    ## distinction that matters: false means "read another frame", not
    ## "something went wrong".
    ok: bool
    done: bool
    payload: ByteSeq
    err: string

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

## ------------------------ payloads too big to send ------------------
##
## A datagram has a ceiling and a database does not. One row with a 200 KB
## text column, or a sync answer carrying a hundred rows, does not fit a
## frame -- and a transport that silently truncates at that point would
## hand back a Reply that decodes to fewer rows than were sent.
##
## So every payload travels under a one-byte envelope:
##
##   0  whole      the rest of this frame IS the payload
##   1  manifest   a package follows: how many chunks, how long, its digest
##   2  chunk      one piece, addressed by index
##
## Splitting and reassembly are Bifrost's `planDacPackage` and
## `DacPackageReceiver`; Geist only decides WHEN to use them and carries
## the pieces inside ordinary AME frames, so every chunk is sealed and
## authenticated exactly like a small reply. The manifest's digest is
## checked on assembly, so a package that arrives wrong is refused rather
## than decoded.
##
##   sender                              receiver
##   ------                              --------
##   fits?  -> [0][payload] ------------> payload
##   too big-> [1][manifest] -----------> open a receiver
##             [2][chunk 0] ------------> accept
##             [2][chunk 1] ------------> accept ... digest ok -> payload
##
## Chunks are MTU-sized, so this path is slower than one frame by design:
## it is the fallback, not the norm. The server keeps replies inside one
## frame whenever it can by answering with fewer rows -- see `rowBudget`.

const
  envWhole = 0'u8
  envManifest = 1'u8
  envChunk = 2'u8
  geistWholeMaxBytes* = 32_000
    ## Above this a payload is packaged. Well under the 65507-byte datagram
    ## ceiling: AME framing, the epoch header and the tag all ride in the
    ## same datagram, and guessing that overhead wrong would turn a large
    ## reply into a send error rather than a package.

type
  PackageAssembly* {.role: truthState, tag: "ame|networkSurface|types".} = object
    ## Half a package. `active` is false between packages, which is also
    ## how a stray chunk with no manifest is recognised and dropped.
    active*: bool
    receiver*: bfx.DacPackageReceiver

proc packageDefaults(): bfx.DacScenarioDefaults {.role: configurator,
    tag: "ame|networkSurface".} =
  ## MTU-sized chunks with XOR repair groups. The same-room profile's
  ## 32 KB chunks would be faster on loopback and would fragment on any
  ## real network between two desktops, which is the case this exists for.
  ##
  ## Bifrost used to spell this `cleanLanDacDefaults()`. The twelve
  ## per-scenario procs are now one table read by name, so the scenario is
  ## an argument rather than part of the call.
  result = bfx.dacDefaultsFor(bfx.dscCleanLan)

proc sendPayload(sock: bfx.DacSocket, remote: bfx.DacAddress,
    session: var bfx.AmeSession, payload: openArray[uint8],
    packageId: uint64): SendOutcome {.
    role: orchestrator, tag: "ame|networkSurface|write".} =
  ## sock/remote/session: an established AME session.
  ## payload: the encoded Query or Reply.
  ## packageId: nonzero, distinct per package on this session.
  var
    body: ByteSeq = @[]
    plan: bfx.DacPackagePlan = default(bfx.DacPackagePlan)
    i: int = 0
  try:
    if payload.len <= geistWholeMaxBytes:
      body = @[envWhole]
      body.addBytes(payload)
      bfx.sendAmeDac(sock, remote, session, body)
      return (true, 1, "")
    plan = bfx.planDacPackage(packageId, payload, packageDefaults())
    body = @[envManifest]
    body.addBytes(bfx.encodeDacPackageManifest(plan.manifest))
    bfx.sendAmeDac(sock, remote, session, body)
    result.frames = 1
    while i < plan.chunks.len:
      body = @[envChunk]
      body.addBytes(bfx.encodeDacPackageChunk(plan.chunks[i]))
      bfx.sendAmeDac(sock, remote, session, body)
      result.frames = result.frames + 1
      i = i + 1
    result.ok = true
  except CatchableError as exc:
    result = (false, result.frames, exc.msg)

proc feedPayload(A: var PackageAssembly,
    frame: openArray[uint8]): FeedOutcome {.role: parser,
    tag: "ame|networkSurface|read".} =
  ## A: assembly state for ONE sender.
  ## frame: the decrypted body of one AME frame.
  ##
  ## Returns done = false for a chunk that leaves the package incomplete,
  ## which is the caller's cue to read another frame rather than to answer.
  var
    assembled: bfx.DacPackageResult = default(bfx.DacPackageResult)
  if frame.len < 1:
    return (false, false, @[], "empty frame")
  case frame[0]
  of envWhole:
    return (true, true, @frame[1 .. ^1], "")
  of envManifest:
    try:
      A.receiver = bfx.initDacPackageReceiver(
        bfx.decodeDacPackageManifest(frame[1 .. ^1]))
      A.active = true
    except CatchableError as exc:
      A.active = false
      return (false, false, @[], "bad package manifest: " & exc.msg)
    return (true, false, @[], "")
  of envChunk:
    if not A.active:
      # A chunk with no manifest is either a stray from a package we gave
      # up on or a peer confused about its own state. Dropping it is right;
      # accepting it would build a payload nobody described.
      return (false, false, @[], "package chunk arrived without a manifest")
    try:
      bfx.acceptDacPackageChunk(A.receiver,
        bfx.decodeDacPackageChunk(frame[1 .. ^1]))
    except CatchableError as exc:
      A.active = false
      return (false, false, @[], "bad package chunk: " & exc.msg)
    if bfx.missingChunkIds(A.receiver).len > 0:
      return (true, false, @[], "")
    assembled = bfx.finishDacPackage(A.receiver)
    A.active = false
    if not assembled.ok:
      return (false, false, @[], assembled.err)
    return (true, true, assembled.payload, "")
  else:
    return (false, false, @[], "unknown transport envelope " & $frame[0])

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

proc handshakeParams(): bfx.AmeRuntimeParams {.role: configurator, inline,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## The tunables the responder imposes on the first epoch. Both halves of
  ## Geist name them in one place so a client and a server built from this
  ## file never disagree about the tag length.
  result = bfx.AmeRuntimeParams(authTagLen: bfx.aatl32)

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

## ----------------------------- serving ------------------------------
##
## ONE socket, MANY peers, sessions that outlive a request.
##
##   bind once
##     |
##     +-- frame from an unknown address  -> client hello -> server hello
##     +-- frame from a handshaking one   -> client finish -> session open
##     +-- frame from an open one         -> Query -> handler -> Reply
##
## The previous server bound a socket, performed a whole post-quantum
## handshake, answered ONE query and closed. That made every request cost a
## handshake, and a second desktop could not be served at all while the
## first was mid-exchange.
##
## Peers are keyed by their source address and each carries its own AME
## session, so two desktops interleave freely. Requests are still handled
## one at a time -- there is no thread per client and no work queue -- but
## nothing is serialised behind another peer's handshake, and a session
## costs one handshake for its whole life rather than one per question.
##
## What a peer is ALLOWED to do travels with its pin: rights are decided
## when the operator lists a peer as trusted, not by the peer.

## `PeerRight` and `PeerContext` are NOT here: they live in ./types with
## the rest of the vocabulary a handler speaks. Every handler is told who
## is asking, and not every handler owns a socket -- the relay in
## ./relay.nim answers with no database and no store, and it must be able
## to check a right without compiling a handshake to do it.

type
  TrustedPeer* {.role: configurator, tag: "ame|networkSurface|server|types".} = object
    ## pin: the peer's public identity, exchanged out of band.
    ## rights: what it may do once it has proved that identity.
    pin*: bfx.AmePinnedPeerIdentity
    rights*: set[PeerRight]

  PeerPhase = enum
    ppHandshaking, ppOpen

  AnsweredHello {.tag: "ame|server|types".} = tuple
    ## What answering one client hello produced: the half-finished
    ## responder state, or a reason it was refused.
    ok: bool
    state: bfx.AmeServerHandshake
    err: string

  JudgedFinish {.tag: "ame|server|types".} = tuple
    ## Which pin the sealed finish turned out to belong to. `at` indexes
    ## the trusted list, or is -1 when none of them matched.
    ok: bool
    at: int
    accepted: bfx.AmeHandshakeResult

  PeerLink* {.role: truthState, tag: "ame|networkSurface|server|types".} = object
    ## One remote desktop, for as long as it keeps talking to us.
    ##
    ## `subject` is empty while the peer is handshaking. It has to be: the
    ## private handshake does not say who is calling until the last step,
    ## so until then this entry is "someone at this address", nothing more.
    subject*: string
    address*: string
    phase*: PeerPhase
    pending*: bfx.AmeServerHandshake
    answer*: ByteSeq
      ## The server hello we already sent, kept byte for byte. A client
      ## that did not hear it repeats its hello, and the answer to that is
      ## THIS frame again -- recomputing it would pick fresh key material
      ## and orphan the transcript the client is already committed to.
    peerTrust*: bfx.AmePeerTrustResult
    session*: bfx.AmeSession
    rights*: set[PeerRight]
    lastSeenAt*: int64
    requests*: int
    ## inbox: half-received request package, if this peer is sending one.
    ## nextPackage: identity counter for packages sent BACK to it.
    inbox*: PackageAssembly
    nextPackage*: uint64

  ServedHandler* = proc (q: Query, p: PeerContext): Reply {.gcsafe.}

  GeistServer* {.role: truthState, tag: "ame|networkSurface|server|types".} = object
    ## The bound socket and everyone currently connected to it.
    sock*: bfx.DacSocket
    identity*: bfx.AmeIdentityKey
    descriptor*: bfx.AmeIdentityCertificate
      ## What this server says about itself, sealed into every server
      ## hello. Built once at bind time so the validity window does not
      ## move under a long-running daemon.
    cookieSecret*: bfx.AmeCookieSecret
      ## Never leaves this machine. Only tags computed with it go out, so
      ## an anti-flood cookie costs the server no per-client memory.
    requireCookie*: bool
    trusted*: seq[TrustedPeer]
    policy*: TriggerPolicy
    peers*: Table[string, PeerLink]
    open*: bool
    served*: int
    handshakes*: int
    refused*: int
    idleSeconds*: int64

const
  defaultPeerIdleSeconds* = 900'i64
    ## A session with nothing to say for this long is dropped. DAC is
    ## connectionless, so a peer that vanishes never says so -- without an
    ## idle sweep the table would only ever grow.

proc initGeistServer*(a: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    trusted: openArray[TrustedPeer], policy: TriggerPolicy,
    idleSeconds: int64 = defaultPeerIdleSeconds,
    requireCookie: bool = true): tuple[ok: bool,
    server: GeistServer, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|orchestrator|server".} =
  ## a: local endpoint, bound ONCE for the life of the server.
  ## identity: this node's signing identity.
  ## trusted: every peer allowed to connect, with what each may do. An
  ##   empty list is refused: pinned trust with nobody pinned would reject
  ##   every handshake, which is a configuration mistake worth naming.
  ## policy/idleSeconds: tier policy and how long a quiet session is kept.
  ## requireCookie: answer a first hello with a cookie challenge instead of
  ##   a key exchange. Leave it ON for anything a stranger can reach.
  ##   Nothing proves a source address on a datagram socket, so a server
  ##   without this will happily do post-quantum key work for packets that
  ##   never came from anybody. The cost is one extra round trip per
  ##   connection, paid once per session rather than per request.
  var
    validated: tuple[ok: bool, err: string] = (false, "")
    now: int64 = 0
  validated = validateTriggerPolicy(policy)
  if not validated.ok:
    return (false, GeistServer(), validated.err)
  if trusted.len == 0:
    return (false, GeistServer(),
      "a server needs at least one trusted peer pin; with none, every " &
      "handshake would be refused")
  now = getTime().toUnix()
  result.server.identity = identity
  result.server.trusted = @trusted
  result.server.policy = policy
  result.server.requireCookie = requireCookie
  result.server.peers = initTable[string, PeerLink]()
  result.server.idleSeconds = idleSeconds
  try:
    result.server.descriptor = geistDescriptor(identity, now)
    result.server.cookieSecret = bfx.initAmeCookieSecret()
    result.server.sock = bfx.openDacListener(a)
    result.server.open = true
    result.ok = true
  except CatchableError as exc:
    result = (false, GeistServer(), exc.msg)

proc pinFor(S: GeistServer, subject: string): int {.role: parser,
    tag: "ame|server".} =
  ## S/subject: index of the trusted peer with this subject, or -1.
  ##
  ## This no longer chooses a pin for a handshake -- `finishPeer` does
  ## that, by trying them. It answers a different question: "if somebody
  ## called themselves this, what would they be allowed?" That is what
  ## `delegatedContext` needs in order to narrow a router's rights down to
  ## those of the subject it is forwarding for, and the subject there is a
  ## CLAIM in an address rather than anything a handshake proved.
  var
    i: int = 0
  result = -1
  while i < S.trusted.len:
    if S.trusted[i].pin.subject == subject:
      return i
    i = i + 1

proc rightsFor*(s: GeistServer, subject: string): set[PeerRight] {.
    role: parser, tag: "ame|server".} =
  ## s/subject: what a peer with this name would be allowed, or nothing
  ## when this server has never heard of it.
  var
    i: int = s.pinFor(subject)
  if i < 0:
    return {}
  result = s.trusted[i].rights

proc delegatedContext*(s: GeistServer, p: PeerContext,
    a: GeistAddress): PeerContext {.role: sanitizer,
    tag: "ame|server".} =
  ## s: this server and its trust list.
  ## p: who actually connected -- proved by the handshake.
  ## a: the address, which may carry `?as=` because a ROUTER forwarded
  ##   this on someone else's behalf.
  ##
  ## RIGHTS CAN ONLY NARROW. The result is the intersection of what the
  ## connecting peer may do and what the claimed subject may do:
  ##
  ##   effective = rights(connected pin) AND rights(claimed subject)
  ##
  ## `as` is a CLAIM. The peer that sent it proved only its own identity,
  ## so treating the claim as an assertion of identity would let any
  ## trusted router impersonate every peer the server knows. Intersecting
  ## instead means a router with write rights forwarding for a read-only
  ## client gets read; a router forwarding for a subject this server has
  ## never heard of gets nothing; and a read-only router can never hand
  ## out write however it addresses the request.
  ##
  ## The subject reported to the handler is the CLAIMED one, so a store
  ## attributes the row to the person who wrote it rather than to the
  ## machine that carried it -- while the rights that decided whether it
  ## could be written came from the pin.
  result = p
  if a.onBehalfOf.len == 0:
    return
  result.subject = a.onBehalfOf
  result.rights = p.rights * s.rightsFor(a.onBehalfOf)

proc dropIdlePeers*(S: var GeistServer) {.role: actor,
    tag: "ame|lifecycle|server".} =
  ## S: server whose silent sessions are forgotten. Called on every serve,
  ## so a long-running daemon's peer table stays the size of its actual
  ## traffic.
  var
    now: int64 = 0
    stale: seq[string] = @[]
    i: int = 0
  now = getTime().toUnix()
  for key, link in S.peers.pairs:
    if now - link.lastSeenAt > S.idleSeconds:
      stale.add key
  while i < stale.len:
    S.peers.del(stale[i])
    i = i + 1

proc peerIdOf(key: string): ByteSeq {.role: helper, inline,
    tag: "ame|server".} =
  ## key: the printed remote address, as the bytes a cookie is bound to.
  ## A cookie proves "whoever asked for this can receive at this address",
  ## so the address is exactly what it has to be tied to.
  result = @[]
  for c in key:
    result.add uint8(c)

proc challengePeer(S: var GeistServer, hello: bfx.AmeClientHello,
    remote: bfx.DacAddress, key: string,
    now: int64): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## S/hello/remote/key/now: answer a first hello with a cookie challenge.
  ##
  ## NOTHING is remembered about this peer. That is the point: the cookie
  ## is a tag over the address and the time, recomputed when it comes back,
  ## so a flood of spoofed helloes costs this server one small reply each
  ## and no memory at all.
  var
    retry: bfx.AmeHelloRetry = default(bfx.AmeHelloRetry)
  retry.sessionId = hello.sessionId
  retry.cookie = bfx.issueAmeCookie(S.cookieSecret, peerIdOf(key), now,
    hello.sessionId)
  bfx.sendDacFrameBytes(S.sock, remote, bfx.encodeAmeHelloRetryFrame(retry))
  result = (true, "")

proc beginPeer(S: var GeistServer, frame: bfx.AmeHandshakeFrame,
    remote: bfx.DacAddress, key: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## S: server accepting a new conversation.
  ## frame/remote/key: the handshake record, its source and the table key.
  ##
  ## Answers a client hello and remembers the half-finished handshake. The
  ## reply goes back to the SAME address it came from, which is also the
  ## address the session will be keyed by -- the client keeps one socket
  ## for the handshake and everything after it.
  ##
  ## WHO is calling is not known here and cannot be: the hello carries key
  ## material and nothing else. Any of the pinned peers might be behind it,
  ## so this side proves ITSELF now and judges the caller at the finish.
  var
    hello: bfx.AmeClientHello = default(bfx.AmeClientHello)
    answered: AnsweredHello = (false, default(bfx.AmeServerHandshake), "")
    link: PeerLink = PeerLink()
    now: int64 = 0
  try:
    hello = bfx.decodeAmeClientHello(frame.record)
  except CatchableError as exc:
    return (false, "not a client hello from " & key & ": " & exc.msg)
  now = getTime().toUnix()
  if S.requireCookie and
      not bfx.ameCookieValid(S.cookieSecret, peerIdOf(key), now,
        hello.sessionId, hello.cookie):
    return S.challengePeer(hello, remote, key, now)
  # `initAmePinnedAuthentication` needs one pin, and answering needs only
  # the MODE it carries -- AM1S adds nothing to the key schedule, and the
  # expected peer is read at the finish, not here. The first pin therefore
  # stands in for "we speak pinned-key"; every pin is tried in `finishPeer`.
  answered = bfx.answerAmeHandshake(hello, [supportedTierPath(S.policy)],
    bfx.initAmePinnedAuthentication(S.trusted[0].pin), S.descriptor,
    S.identity, handshakeParams())
  if not answered.ok:
    S.refused = S.refused + 1
    return (false, "handshake refused from " & key & ": " & answered.err)
  link.answer = bfx.encodeAmeServerHelloFrame(hello.sessionId,
    answered.state.serverHello)
  bfx.sendDacFrameBytes(S.sock, remote, link.answer)
  link.address = key
  link.phase = ppHandshaking
  link.pending = answered.state
  link.lastSeenAt = now
  S.peers[key] = link
  result = (true, "")

proc judgeFinish(S: var GeistServer, link: var PeerLink,
    finish: bfx.AmeClientFinish, now: int64): JudgedFinish {.role: orchestrator,
    tag: "ame|cryptoBoundary|server".} =
  ## S/link/finish/now: try the finish against every pin this server holds
  ## and report which one it was, or -1.
  ##
  ## Trying them all is cheap. `verifyPinnedPeerIdentity` compares the name
  ## and the public keys FIRST and only then verifies signatures, so a pin
  ## that is not the caller costs a string compare. Opening the sealed
  ## block is symmetric work and is repeated per attempt, which is why the
  ## loop stops at the first pin that works.
  ##
  ## `acceptAmeHandshake` erases the state it is given, so each attempt
  ## gets its own copy of it.
  var
    attempt: bfx.AmeServerHandshake = default(bfx.AmeServerHandshake)
    i: int = 0
  result = (false, -1, default(bfx.AmeHandshakeResult))
  while i < S.trusted.len:
    attempt = link.pending
    # Bifrost opens the finish with the authentication the answer stored.
    # The answer stored the FIRST pin as a stand-in, so each attempt's copy
    # is given the pin it is testing instead.
    attempt.authentication = bfx.initAmePinnedAuthentication(S.trusted[i].pin)
    result.accepted = bfx.acceptAmeHandshake(attempt, finish, now)
    if result.accepted.ok:
      return (true, i, result.accepted)
    i = i + 1
  bfx.clearAmeServerHandshake(link.pending)

proc finishPeer(S: var GeistServer, frame: bfx.AmeHandshakeFrame,
    key: string): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## S/frame/key: the client's finish record, completing one handshake.
  ##
  ## This is where the server learns who it has been talking to.
  var
    judged: JudgedFinish = (false, -1, default(bfx.AmeHandshakeResult))
    finish: bfx.AmeClientFinish = default(bfx.AmeClientFinish)
    link: PeerLink = PeerLink()
    now: int64 = 0
    sessionId: uint64 = 0'u64
  link = S.peers[key]
  now = getTime().toUnix()
  try:
    finish = bfx.decodeAmeClientFinish(frame.record)
  except CatchableError as exc:
    S.peers.del(key)
    return (false, "malformed handshake finish from " & key & ": " & exc.msg)
  judged = S.judgeFinish(link, finish, now)
  if not judged.ok:
    S.peers.del(key)
    S.refused = S.refused + 1
    return (false, "no pinned peer matched the identity sent from " & key &
      "; add its .pin to the trusted list (last reason: " &
      judged.accepted.err & ")")
  link.subject = S.trusted[judged.at].pin.subject
  link.rights = S.trusted[judged.at].rights
  link.peerTrust = judged.accepted.peerTrust
  sessionId = link.pending.clientHello.sessionId
  # The handshake's trust result must ride into the session: initAmeSession
  # requires trust, and dropping it here fails every request AFTER a
  # handshake that actually succeeded.
  link.session = bfx.initAmeSession(judged.accepted.auth,
    supportedTierPath(S.policy), sessionId, 1'u32, 5'u32,
    bfx.dplCleanPath, bfx.amcUserdata, bfx.defaultAmeInboxCapacity, true,
    link.peerTrust)
  # The handshake is over, so everything it needed is now key material
  # nobody will read again: the responder's KEM secrets and a copy of its
  # signing keys. `acceptAmeHandshake` erased the COPY it was handed --
  # `judgeFinish` gives it one per attempt -- so the original here is the
  # last thing holding them, and it is erased rather than kept for the
  # life of the session. The same applies to the stored server hello,
  # which only existed in case the client asked for it again.
  bfx.clearAmeServerHandshake(link.pending)
  link.answer = @[]
  link.phase = ppOpen
  link.lastSeenAt = now
  S.peers[key] = link
  S.handshakes = S.handshakes + 1
  result = (true, "")

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
  link = S.peers[key]
  opened = bfx.openAmeDacFrame(link.session, payload, remote)
  if not opened.ok:
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
  sent = sendPayload(S.sock, remote, link.session, encodeReply(reply),
    link.nextPackage)
  link.requests = link.requests + 1
  S.peers[key] = link
  if not sent.ok:
    return (false, false, "reply to " & key & " failed: " & sent.err)
  S.served = S.served + 1
  result = (true, true, "")

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
    frame: bfx.AmeHandshakeFrame = default(bfx.AmeHandshakeFrame)
    key: string = ""
    step: tuple[ok: bool, err: string] = (false, "")
    answered: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    isHandshake: bool = false
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
  key = bfx.formatDacAddress(got.remote)
  try:
    frame = bfx.decodeAmeHandshakeFrame(got.payload)
    isHandshake = true
  except CatchableError:
    isHandshake = false
  if not isHandshake:
    if not S.peers.hasKey(key) or S.peers[key].phase != ppOpen:
      return (false, false, "data frame from " & key & " with no session")
    answered = S.answerPeer(got.payload, got.remote, key, handler)
    return (answered.ok, answered.served, answered.err)
  if frame.kind == bfx.ampkClientHello:
    # A hello from an address we already know is a peer that restarted.
    # Its old session is gone whatever we think, so drop it and start over.
    S.peers.del(key)
    step = S.beginPeer(frame, got.remote, key)
    return (step.ok, false, step.err)
  if frame.kind == bfx.ampkClientFinish:
    if not S.peers.hasKey(key) or S.peers[key].phase != ppHandshaking:
      return (false, false, "handshake finish from " & key &
        " with no handshake under way")
    step = S.finishPeer(frame, key)
    return (step.ok, false, step.err)
  result = (false, false, "a server does not answer " & $frame.kind &
    " from " & key)

proc peerCount*(s: GeistServer): int {.role: parser, inline,
    tag: "ame|server|status".} =
  ## s: how many peers are currently connected, handshaking included.
  result = s.peers.len

proc closeServer*(S: var GeistServer) {.role: actor,
    tag: "ame|lifecycle|networkSurface|server".} =
  ## S: server whose socket is released and whose sessions are forgotten.
  if not S.open:
    return
  try:
    bfx.closeDac(S.sock)
  except CatchableError:
    discard
  S.sock = nil
  S.peers.clear()
  S.open = false

