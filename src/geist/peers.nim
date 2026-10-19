## ---------------------------------------------------------------------
## Peers <- who may dial in, and what a server knows about each caller
## ---------------------------------------------------------------------
##
##   trustListFrom(readers, writers) -> seq[TrustedPeer]   from .pin files
##   initGeistServer(address, identity, trusted)          the bound socket
##   rightsFor / delegatedContext                         what a caller may do
##   dropIdlePeers / peerCount / closeServer              housekeeping
##
## The handshake and the answering are ./serve, which re-exports this.

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./masks
import ./address
import ./payload
import ./transport
import ./identity

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

  PeerPhase* = enum
    ppHandshaking, ppOpen

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
    sessionId*: uint64
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
    shared*: GeistSharedKey
    observer*: GeistNetworkObserver
    handshakePackages*: bfx.AmeHandshakePackages

const
  defaultPeerIdleSeconds* = 900'i64
    ## A session with nothing to say for this long is dropped. DAC is
    ## connectionless, so a peer that vanishes never says so -- without an
    ## idle sweep the table would only ever grow.

proc initGeistServer*(a: bfx.DacAddress, identity: bfx.AmeIdentityKey,
    trusted: openArray[TrustedPeer], policy: TriggerPolicy,
    idleSeconds: int64 = defaultPeerIdleSeconds,
    requireCookie: bool = true, shared: GeistSharedKey = nil,
    observer: GeistNetworkObserver = nil): tuple[ok: bool,
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
  result.server.shared = shared
  result.server.observer = observer
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
