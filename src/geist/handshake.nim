## ---------------------------------------------------------------------
## Handshake <- a stranger becomes a peer: hello, cookie, sealed finish
## ---------------------------------------------------------------------
##
##   client (transport)                          server (this file)
##   ------------------                          ------------------
##   hello   (key material only)     ------->    beginPeer
##                                   <-------      cookie challenge, or
##                                                 the server's half
##   finish  (our identity SEALED)   ------->    finishPeer: which pin?
##                                                 -> PeerLink is ppOpen
##
## Only the answering side lives here. ./serve reads a frame, sees it is a
## handshake record, and hands it to `beginPeer` or `finishPeer`. What a
## peer may do once it is in is ./peers (rights) and ./serve (answers).

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./masks
import ./peers
import ./authentication
import ./network_events

type
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

proc handshakeParams(): bfx.AmeRuntimeParams {.role: configurator, inline,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## The tunables the responder imposes on the first epoch. Both halves of
  ## Geist name them in one place so a client and a server built from this
  ## file never disagree about the tag length.
  result = bfx.AmeRuntimeParams(authTagLen: bfx.aatl32)

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
  bfx.sendAmeHandshakeDac(S.sock, remote, bfx.encodeAmeHelloRetryFrame(retry))
  reportNetwork(S.observer, "handshake.cookie", key, "",
    S.shared.authenticationName(), S.policy.startTier, hello.sessionId)
  result = (true, "")

proc allowsHelloMask(S: GeistServer, hello: bfx.AmeClientHello): bool {.
    role: sanitizer.} =
  ## S/hello: only Geist's exact layout and configured-or-stronger tier masks.
  var
    candidate: GeistTier = S.policy.startTier
  if not bfx.layoutsEquivalent(hello.layout, geistLayout()): return false
  while true:
    if (candidate == S.policy.startTier or S.policy.rows[candidate].kind != tkDisabled) and
        bfx.tiersEquivalent(hello.initialTier, tierOf(hello.layout, candidate)):
      return true
    if candidate == gtRecovery: break
    candidate = succ(candidate)

proc beginPeer*(S: var GeistServer, frame: bfx.AmeHandshakeFrame,
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
  if not S.allowsHelloMask(hello):
    S.refused = S.refused + 1
    reportNetwork(S.observer, "handshake.refused", key, "",
      S.shared.authenticationName(), S.policy.startTier, hello.sessionId,
      error = "client mask is below the configured tier or differs from Geist masks")
    return (false, "client mask is below the configured tier or differs from Geist masks")
  # `initAmePinnedAuthentication` needs one pin, and answering needs only
  # the MODE it carries -- AM1S adds nothing to the key schedule, and the
  # expected peer is read at the finish, not here. The first pin therefore
  # stands in for "we speak pinned-key"; every pin is tried in `finishPeer`.
  answered = bfx.answerAmeHandshake(hello, [supportedTierPath(S.policy)],
    S.shared.authenticationFor(S.trusted[0].pin), S.descriptor,
    S.identity, handshakeParams())
  if not answered.ok:
    S.refused = S.refused + 1
    reportNetwork(S.observer, "handshake.refused", key, "",
      S.shared.authenticationName(), S.policy.startTier, hello.sessionId,
      error = answered.err)
    return (false, "handshake refused from " & key & ": " & answered.err)
  link.answer = bfx.encodeAmeServerHelloFrame(hello.sessionId,
    answered.state.serverHello)
  bfx.sendAmeHandshakeDac(S.sock, remote, link.answer)
  link.address = key
  link.phase = ppHandshaking
  link.pending = answered.state
  link.lastSeenAt = now
  S.peers[key] = link
  reportNetwork(S.observer, "handshake.answer", key, "",
    S.shared.authenticationName(), S.policy.startTier, hello.sessionId,
    bytes = link.answer.len)
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
    attempt.authentication = S.shared.authenticationFor(S.trusted[i].pin)
    result.accepted = bfx.acceptAmeHandshake(attempt, finish, now)
    if result.accepted.ok:
      return (true, i, result.accepted)
    i = i + 1
  bfx.clearAmeServerHandshake(link.pending)

proc finishPeer*(S: var GeistServer, frame: bfx.AmeHandshakeFrame,
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
    reportNetwork(S.observer, "handshake.refused", key, "",
      S.shared.authenticationName(), S.policy.startTier,
      error = judged.accepted.err)
    return (false, "no pinned peer matched the identity sent from " & key &
      "; add its .pin to the trusted list (last reason: " &
      judged.accepted.err & ")")
  link.subject = S.trusted[judged.at].pin.subject
  link.rights = S.trusted[judged.at].rights
  link.peerTrust = judged.accepted.peerTrust
  sessionId = link.pending.clientHello.sessionId
  link.sessionId = sessionId
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
  reportNetwork(S.observer, "handshake.accepted", key, link.subject,
    S.shared.authenticationName(), S.policy.startTier, sessionId)
  result = (true, "")

