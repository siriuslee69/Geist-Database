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
##   masks / tier policy   ---->   beginAmePinnedHandshake
##   Query bytes           ---->   connectAmeDacClient / send / receive
##   Reply bytes           <----   openAmeDacFrame
##
## A serialised `Query` IS the request body. That is why there is no
## separate exchange-kind enum, no per-operation encode/decode pair, and
## no second wire codec: `qoSubscribe` is just another op.

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./format
import ./masks
import ./address

const
  geistDacFrameMaxBytes* = 65_507
    ## One DAC datagram. Bifrost exposes no such constant, so Geist pins it
    ## here. Handshakes at gtArchive and above exceed this because the
    ## code-based KEM public keys are ~1.3 MB; those tiers must use DAC
    ## package transfer, which `handshakeFitsFrame` reports on.

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
    p: Predicate
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
    tag: "codecBoundary|networkSurface|read".} =
  ## A/o: buffer and cursor advanced past an encoded row list.
  ##
  ## Every length is checked against what is actually there: these bytes
  ## come off a socket, and a count of four billion rows must produce an
  ## empty answer rather than an allocation.
  var
    n: int = 0
    i: int = 0
    j: int = 0
    row: Row
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
  ## MTU-sized chunks with XOR repair groups. The super-clean profile's
  ## 32 KB chunks would be faster on loopback and would fragment on any
  ## real network between two desktops, which is the case this exists for.
  result = bfx.cleanLanDacDefaults()

proc sendPayload(sock: bfx.DacSocket, remote: bfx.DacAddress,
    session: var bfx.AmeSession, payload: openArray[uint8],
    packageId: uint64): tuple[ok: bool, frames: int, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|write".} =
  ## sock/remote/session: an established AME session.
  ## payload: the encoded Query or Reply.
  ## packageId: nonzero, distinct per package on this session.
  var
    body: ByteSeq = @[]
    plan: bfx.DacPackagePlan
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
    frame: openArray[uint8]): tuple[ok: bool, done: bool, payload: ByteSeq,
    err: string] {.role: parser,
    tag: "ame|networkSurface|read".} =
  ## A: assembly state for ONE sender.
  ## frame: the decrypted body of one AME frame.
  ##
  ## Returns done = false for a chunk that leaves the package incomplete,
  ## which is the caller's cue to read another frame rather than to answer.
  var
    assembled: bfx.DacPackageResult
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
    L: bfx.AmeSuiteLayout
    start: bfx.AmeMaskTier
    hs: bfx.AmeClientHandshake
    sock: bfx.DacSocket = nil
    got: bfx.DacFrameBytesResult
    serverHello: bfx.AmeServerHello
    finished: bfx.AmeHandshakeResult
    session: bfx.AmeSession
    validated: tuple[ok: bool, err: string]
  validated = validateTriggerPolicy(policy)
  if not validated.ok:
    return (false, GeistLink(), validated.err)
  L = geistLayout()
  start = tierOf(L, policy.startTier)
  try:
    hs = bfx.beginAmePinnedHandshake(sessionId, L, start, identity)
    sock = bfx.openDacPeer(remote, timeoutMs)
    bfx.sendDacFrameBytes(sock, remote, bfx.encodeAmeClientHello(hs.hello))
    got = bfx.recvDacFrameBytes(sock, geistDacFrameMaxBytes, timeoutMs)
    if not got.ok:
      bfx.closeDac(sock)
      return (false, GeistLink(), got.err)
    serverHello = bfx.decodeAmeServerHello(L, got.payload)
    finished = bfx.finishAmePinnedHandshake(hs, serverHello, peer, identity)
    if not finished.ok:
      bfx.closeDac(sock)
      return (false, GeistLink(), finished.err)
    bfx.sendDacFrameBytes(sock, remote,
      bfx.encodeAmeClientFinish(finished.finish))
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
    got: bfx.AmeOpenResult
    sent: tuple[ok: bool, frames: int, err: string]
    fed: tuple[ok: bool, done: bool, payload: ByteSeq, err: string]
    inbox: PackageAssembly
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
        result.reply = decodeReply(fed.payload)
        result.ok = true
        return
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

  PeerLink* {.role: truthState, tag: "ame|networkSurface|server|types".} = object
    ## One remote desktop, for as long as it keeps talking to us.
    subject*: string
    address*: string
    phase*: PeerPhase
    pending*: bfx.AmeServerHandshake
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
    idleSeconds: int64 = defaultPeerIdleSeconds): tuple[ok: bool,
    server: GeistServer, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|orchestrator|server".} =
  ## a: local endpoint, bound ONCE for the life of the server.
  ## identity: this node's signing identity.
  ## trusted: every peer allowed to connect, with what each may do. An
  ##   empty list is refused: pinned trust with nobody pinned would reject
  ##   every handshake, which is a configuration mistake worth naming.
  ## policy/idleSeconds: tier policy and how long a quiet session is kept.
  var
    validated: tuple[ok: bool, err: string]
  validated = validateTriggerPolicy(policy)
  if not validated.ok:
    return (false, GeistServer(), validated.err)
  if trusted.len == 0:
    return (false, GeistServer(),
      "a server needs at least one trusted peer pin; with none, every " &
      "handshake would be refused")
  result.server.identity = identity
  result.server.trusted = @trusted
  result.server.policy = policy
  result.server.peers = initTable[string, PeerLink]()
  result.server.idleSeconds = idleSeconds
  try:
    result.server.sock = bfx.openDacListener(a)
    result.server.open = true
    result.ok = true
  except CatchableError as exc:
    result = (false, GeistServer(), exc.msg)

proc pinFor(S: GeistServer, subject: string): int {.role: parser,
    tag: "ame|server".} =
  ## S/subject: index of the trusted peer with this subject, or -1.
  ##
  ## Selecting by NAME is not a trust decision -- the handshake still
  ## compares the actual public keys, and a mismatch is refused. This only
  ## decides which pin to compare against.
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

proc beginPeer(S: var GeistServer, payload: openArray[uint8],
    remote: bfx.DacAddress, key: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## S: server accepting a new conversation.
  ## payload/remote/key: the frame, its source and the peer table key.
  ##
  ## Answers a client hello and remembers the half-finished handshake. The
  ## reply goes back to the SAME address it came from, which is also the
  ## address the session will be keyed by -- the client keeps one socket
  ## for the handshake and everything after it.
  var
    hello: bfx.AmeClientHello
    at: int = -1
    answered: tuple[ok: bool, state: bfx.AmeServerHandshake,
      peerTrust: bfx.AmePeerTrustResult, err: string]
    link: PeerLink
  try:
    hello = bfx.decodeAmeClientHello(payload)
  except CatchableError as exc:
    return (false, "not a client hello from " & key & ": " & exc.msg)
  at = S.pinFor(hello.certificate.subject)
  if at < 0:
    S.refused = S.refused + 1
    return (false, "no pin for subject '" & hello.certificate.subject &
      "' from " & key & "; add its .pin to the trusted list")
  answered = bfx.answerAmePinnedHandshake(hello,
    [supportedTierPath(S.policy)], S.trusted[at].pin, S.identity)
  if not answered.ok:
    S.refused = S.refused + 1
    return (false, "handshake refused for '" & hello.certificate.subject &
      "': " & answered.err)
  bfx.sendDacFrameBytes(S.sock, remote,
    bfx.encodeAmeServerHello(answered.state.serverHello))
  link.subject = hello.certificate.subject
  link.address = key
  link.phase = ppHandshaking
  link.pending = answered.state
  link.peerTrust = answered.peerTrust
  link.rights = S.trusted[at].rights
  link.lastSeenAt = getTime().toUnix()
  S.peers[key] = link
  result = (true, "")

proc finishPeer(S: var GeistServer, payload: openArray[uint8],
    key: string): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "ame|networkSurface|server".} =
  ## S/payload/key: the client's finish message, completing one handshake.
  var
    accepted: bfx.AmeHandshakeResult
    link: PeerLink
  link = S.peers[key]
  try:
    accepted = bfx.acceptAmeHandshake(link.pending,
      bfx.decodeAmeClientFinish(payload))
  except CatchableError as exc:
    S.peers.del(key)
    return (false, "malformed handshake finish from " & key & ": " & exc.msg)
  if not accepted.ok:
    S.peers.del(key)
    S.refused = S.refused + 1
    return (false, accepted.err)
  # The handshake's trust result must ride into the session: initAmeSession
  # requires trust, and dropping it here fails every request AFTER a
  # handshake that actually succeeded.
  link.session = bfx.initAmeSession(accepted.auth,
    supportedTierPath(S.policy), link.pending.clientHello.sessionId, 1'u32, 5'u32,
    bfx.dplCleanPath, bfx.amcUserdata, bfx.defaultAmeInboxCapacity, true,
    link.peerTrust)
  link.phase = ppOpen
  link.lastSeenAt = getTime().toUnix()
  S.peers[key] = link
  S.handshakes = S.handshakes + 1
  result = (true, "")

proc answerPeer(S: var GeistServer, payload: openArray[uint8],
    remote: bfx.DacAddress, key: string,
    handler: ServedHandler): tuple[ok: bool, served: bool, err: string] {.
    role: orchestrator, tag: "ame|networkSurface|server".} =
  ## S/payload/remote/key/handler: one frame on an established session.
  ##
  ## `served` distinguishes a completed request from a chunk of one that is
  ## still arriving: a caller counting requests must not count the pieces.
  var
    link: PeerLink
    opened: bfx.AmeOpenResult
    ctx: PeerContext
    reply: Reply
    q: Query
    parsed: tuple[ok: bool, a: GeistAddress, err: string]
    fed: tuple[ok: bool, done: bool, payload: ByteSeq, err: string]
    sent: tuple[ok: bool, frames: int, err: string]
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
  q = decodeQuery(fed.payload)
  # Delegation is applied HERE, not in the handler, so no daemon can
  # forget to do it: a handler always receives rights that have already
  # been intersected with whatever the address claimed. A malformed
  # address carries no claim, so the connecting peer's own rights stand.
  parsed = parseAddress(q.collection)
  if parsed.ok:
    ctx = S.delegatedContext(ctx, parsed.a)
  reply = handler(q, ctx)
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
  var
    got: bfx.DacFrameBytesResult
    key: string = ""
    step: tuple[ok: bool, err: string]
    answered: tuple[ok: bool, served: bool, err: string]
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
  if S.peers.hasKey(key) and S.peers[key].phase == ppOpen:
    answered = S.answerPeer(got.payload, got.remote, key, handler)
    if answered.ok:
      return (true, answered.served, "")
    # An open session that will not open a frame may be a peer that
    # restarted and is saying hello again from the same port. Try that
    # reading before giving up on it.
    if S.beginPeer(got.payload, got.remote, key).ok:
      return (true, false, "")
    return (false, false, answered.err)
  if S.peers.hasKey(key) and S.peers[key].phase == ppHandshaking:
    step = S.finishPeer(got.payload, key)
    return (step.ok, false, step.err)
  step = S.beginPeer(got.payload, got.remote, key)
  result = (step.ok, false, step.err)

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

