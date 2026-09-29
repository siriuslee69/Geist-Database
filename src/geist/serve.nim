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
##   hello   (key material only)     ------->    challengePeer / beginPeer
##   finish  (our identity SEALED)   ------->    finishPeer: which pin?
##   Query                           ------->    answerPeer -> bytecheck
##                                   <-------      -> handler -> Reply

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./masks
import ./address
import ./bytecheck
import ./payload
import ./transport
import ./identity

proc handshakeParams(): bfx.AmeRuntimeParams {.role: configurator, inline,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## The tunables the responder imposes on the first epoch. Both halves of
  ## Geist name them in one place so a client and a server built from this
  ## file never disagree about the tag length.
  result = bfx.AmeRuntimeParams(authTagLen: bfx.aatl32)

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


## ---------------------------- who may dial in -----------------------

proc grant(P: var seq[TrustedPeer], pin: bfx.AmePinnedPeerIdentity,
    rights: set[PeerRight]) {.role: truthBuilder, tag: "cryptoBoundary|server".} =
  ## P/pin/rights: the pin added with these rights -- or, when it is listed
  ## already, given these rights as well. A pin listed as a reader AND a
  ## writer gets both: the operator clearly meant the wider one.
  for p in P.mitems:
    if p.pin.subject == pin.subject:
      p.rights = p.rights + rights
      return
  P.add TrustedPeer(pin: pin, rights: rights)

proc trustListFrom*(readers, writers: openArray[string]): tuple[ok: bool,
    peers: seq[TrustedPeer], err: string] {.role: dataFetcher,
    tag: "cryptoBoundary|read|server".} =
  ## readers: pin files of peers that may read (`--trust`).
  ## writers: pin files of peers that may read AND write (`--allow-write`).
  ##
  ## The FLAG grants the right, not the peer. Every daemon builds its trust
  ## list here, so they cannot come to disagree about what a flag means.
  ## A pin that will not load is FATAL rather than skipped: starting with a
  ## shorter list than the operator wrote would quietly refuse peers they
  ## believe are allowed.
  var
    loaded: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string] =
      (false, default(bfx.AmePinnedPeerIdentity), "")
  for path in readers:
    loaded = loadPin(path)
    if not loaded.ok:
      return (false, @[], path & ": " & loaded.err)
    result.peers.grant(loaded.pin, {prRead})
  for path in writers:
    loaded = loadPin(path)
    if not loaded.ok:
      return (false, @[], path & ": " & loaded.err)
    result.peers.grant(loaded.pin, {prRead, prWrite})
  result.ok = true
