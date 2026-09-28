## ---------------------------------------------------------------------
## Agent <- keep one store in step with its peers, as server, client or both
## ---------------------------------------------------------------------
##
## Two halves of a background sync, each one call per turn of a loop:
##
##   serveStore(S, cursors, server)    ANSWER: one request from any trusted
##                                     peer, against this store
##   tick(S, agent)                    ASK: when the plan is due, pull from
##                                     and/or push to every planned peer
##
##   a program's loop                        what happens
##   --------------------------------------  -----------------------------
##   while running:
##     discard serveStore(db, cur, server)   peers read and write here
##     for r in db.tick(agent): log(r)       every N s: this node reads and
##                                           writes there
##     ...the program's own work...
##
## `geistd` is exactly this loop with command-line options around it. A
## game server, a mail server or a password vault that wants to be its own
## sync node runs the same two calls in its own loop instead.
##
## Def. 1: a PLAN is the list of peers and how often to visit them.
## Def. 2: a PEER is where (`dac://host:port`), who (its pin -- public
## keys), and which way: pull (its rows come here), push (this node's rows
## go there) or both.
##
## Positions are filed per peer NAME (see `needLocal`/`offerLocal`), so a
## peer that moves to another address keeps its place.
##
## Links are kept open between ticks. A handshake is the expensive part of
## a conversation, and a plan that runs every 30 seconds would otherwise
## pay it every 30 seconds. A link that fails is dropped and redialled
## once, in the same tick.

import std/[os, sequtils, strutils, tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./masks
import ./address
import ./session
import ./transport
import ./serve
import ./answer
import ./need
import ./offer
import ./identity

type
  SyncWay* {.role: configurator, tag: "networkSurface|sync|types".} = enum
    ## Which way rows move between this node and one peer.
    swPull,   ## the peer's rows come here
    swPush,   ## this node's rows go there
    swBoth    ## pull, then push

  SyncPeer* {.role: configurator, tag: "networkSurface|sync|types".} = object
    ## One peer in a plan (Def. 2).
    ## name: what this peer's positions are filed under. Stable across
    ##   address changes; pick it once.
    ## endpoint: `dac://host:port`.
    ## pin: the peer's public keys, from its `.pin` file (`loadPin`).
    name*: string
    endpoint*: string
    pin*: bfx.AmePinnedPeerIdentity
    way*: SyncWay

  SyncPlan* {.role: configurator, tag: "networkSurface|sync|types".} = object
    ## Every peer, and how often to visit them (Def. 1).
    ## everySeconds: 0 means "every tick".
    ## limit: rows per request.
    peers*: seq[SyncPeer]
    everySeconds*: int
    limit*: uint32

  SyncSpec* {.role: truthState, tag: "config|networkSurface|sync|types".} = tuple
    ## One peer as written in a config (see `parseSyncSpec`).
    ok: bool
    name: string
    pinPath: string
    endpoint: string
    err: string

  SyncReport* {.role: truthState, tag: "networkSurface|status|sync|types".} = object
    ## What one visit to one peer did.
    peer*: string
    ok*: bool
    pulled*: int
    pushed*: int
    err*: string

  SyncAgent* {.role: truthState, tag: "networkSurface|sync|types",
      expectedCount: [0, 64], lifeCycle: lcForever.} = object
    ## The asking side of a node: who it is, its plan, when it last ran,
    ## and the links it keeps open between runs.
    identity*: bfx.AmeIdentityKey
    policy*: TriggerPolicy
    plan*: SyncPlan
    timeoutMs*: int
    lastRunAt*: int64
    links*: Table[string, GeistLink]
    nextSession*: uint64

const
  defaultSyncLimit* = 256'u32

proc initSyncAgent*(identity: bfx.AmeIdentityKey, plan: SyncPlan,
    policy: TriggerPolicy = defaultTriggerPolicy(),
    timeoutMs: int = 4000): SyncAgent {.role: configurator,
    tag: "appApi|networkSurface|sync".} =
  ## identity: who this node is -- the peers must hold its pin.
  ## plan: which peers, which way, how often.
  ## policy/timeoutMs: link strength and how long one request may take.
  result.identity = identity
  result.plan = plan
  if result.plan.limit == 0'u32:
    result.plan.limit = defaultSyncLimit
  result.policy = policy
  result.timeoutMs = timeoutMs
  result.links = initTable[string, GeistLink]()
  result.nextSession = 1'u64

proc syncDue*(A: SyncAgent, now: int64 = getTime().toUnix()): bool {.
    role: parser, tag: "appApi|sync".} =
  ## A/now: has the plan's interval passed since the last run? The first
  ## call always is.
  result = A.lastRunAt == 0'i64 or
    now - A.lastRunAt >= int64(A.plan.everySeconds)

proc dial(A: var SyncAgent, p: SyncPeer): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "networkSurface|sync".} =
  ## A/p: an open link to p in `A.links`, reused when one is there.
  var
    address: tuple[ok: bool, a: bfx.DacAddress] = bfx.parseDacAddress(
      p.endpoint)
    got: tuple[ok: bool, link: GeistLink, err: string] =
      (false, GeistLink(), "")
  if A.links.hasKey(p.name) and A.links[p.name].open:
    return (true, "")
  if not address.ok:
    return (false, "endpoint must be dac://host:port, got '" & p.endpoint &
      "'")
  got = connectGeist(address.a, A.identity, p.pin, A.policy, A.nextSession,
    A.timeoutMs)
  A.nextSession = A.nextSession + 1'u64
  if not got.ok:
    return (false, "cannot reach " & p.endpoint & ": " & got.err)
  A.links[p.name] = got.link
  result = (true, "")

proc drop(A: var SyncAgent, name: string) {.role: actor,
    tag: "networkSurface|sync".} =
  ## A/name: close and forget one peer's link.
  if A.links.hasKey(name):
    A.links[name].close()
    A.links.del(name)

proc exchange(S: var Session, link: var GeistLink, p: SyncPeer,
    limit: uint32): SyncReport {.role: orchestrator,
    tag: "networkSurface|sync|write".} =
  ## S/link/p/limit: pull, push or both over one open link.
  var
    pulled: NeedOutcome = default(NeedOutcome)
    pushed: OfferOutcome = default(OfferOutcome)
  result.peer = p.name
  if p.way in {swPull, swBoth}:
    pulled = needRemote(S, link, p.name, limit)
    result.pulled = pulled.applied
    if not pulled.ok:
      return SyncReport(peer: p.name, err: "pull: " & pulled.err)
  if p.way in {swPush, swBoth}:
    pushed = offerRemote(S, link, p.name, int(limit))
    result.pushed = pushed.sent
    if not pushed.ok:
      return SyncReport(peer: p.name, pulled: result.pulled,
        err: "push: " & pushed.err)
  result.ok = true

proc visit(S: var Session, A: var SyncAgent, p: SyncPeer): SyncReport {.
    role: orchestrator, tag: "networkSurface|sync|write".} =
  ## S/A/p: one peer, one attempt: dial (or reuse), exchange.
  var
    dialled: tuple[ok: bool, err: string] = A.dial(p)
  if not dialled.ok:
    return SyncReport(peer: p.name, err: dialled.err)
  result = exchange(S, A.links[p.name], p, A.plan.limit)
  if not result.ok:
    A.drop(p.name)

proc syncOnce*(S: var Session, A: var SyncAgent,
    now: int64 = getTime().toUnix()): seq[SyncReport] {.role: metaOrchestrator,
    tag: "appApi|networkSurface|sync|write".} =
  ## S: this node's store -- open for writing when any peer is pulled from.
  ## A: the agent; its plan says who and which way.
  ## now: the clock, recorded as the time of this run.
  ##
  ## Visits every peer in the plan now, whether or not it is due. A peer
  ## whose kept link has gone stale -- the other side restarted, or dropped
  ## an idle session -- is redialled once before it counts as failed; a
  ## fresh link that fails is not, since dialling again would only repeat
  ## the same refusal at the cost of another handshake. One
  ## peer failing does not stop the others.
  var
    r: SyncReport = SyncReport()
    reused: bool = false
  for p in A.plan.peers:
    reused = A.links.hasKey(p.name)
    r = visit(S, A, p)
    if not r.ok and reused:
      r = visit(S, A, p)
    result.add r
  A.lastRunAt = now

proc tick*(S: var Session, A: var SyncAgent,
    now: int64 = getTime().toUnix()): seq[SyncReport] {.role: metaOrchestrator,
    tag: "appApi|networkSurface|sync|write".} =
  ## S/A/now: `syncOnce` when the plan is due, nothing otherwise. The call
  ## a program's loop makes every turn.
  if A.syncDue(now):
    result = syncOnce(S, A, now)

proc closeAgent*(A: var SyncAgent) {.role: actor,
    tag: "appApi|networkSurface|sync".} =
  ## A: close every kept link.
  for name in toSeq(A.links.keys):
    A.drop(name)

proc serveStore*(S: var Session, cursors: var SyncCursors,
    server: var GeistServer, timeoutMs: int = 1000): tuple[ok: bool,
    served: bool, err: string] {.role: metaOrchestrator,
    tag: "appApi|networkSurface|server|sync".} =
  ## S: the store peers read from and, with `prWrite`, write into.
  ## cursors: subscription positions; keep one table for the store's life.
  ## server: from `initGeistServer`, listing who may do what.
  ## timeoutMs: how long to wait for a frame. An idle wait is ok = true
  ##   with served = false.
  ##
  ## One step of the answering side: at most one frame, which may be a
  ## handshake or a whole request. Call it in a loop.
  var
    store: ptr Session = addr S
    kept: ptr SyncCursors = addr cursors
  result = serveOnce(server,
    proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
      {.cast(gcsafe).}:
        result = answerQuery(store[], kept[], q, p),
    timeoutMs)

## ---------------------------- plans from text -----------------------
##
## A daemon is configured with text, not objects. One peer is one string:
##
##   peers/desk.pin@dac://10.0.0.2:47655
##   \____ pin ___/ \______ endpoint _____/
##
## and its NAME is the pin file's name without folder or extension --
## "desk" -- so the positions it is filed under stay put when the peer
## moves to another address, as long as its pin keeps its name.

proc parseSyncSpec*(spec: string): SyncSpec {.role: parser,
    tag: "config|networkSurface|parsing|sync".} =
  ## spec: `<pin file>@dac://host:port`. Split at the LAST `@`, since a
  ## folder may contain one and an endpoint never does.
  var
    at: int = spec.rfind('@')
  if at <= 0 or at == spec.high:
    return (false, "", "", "", "a sync peer is written <pin file>@dac://" &
      "host:port, got '" & spec & "'")
  result.pinPath = spec[0 ..< at]
  result.endpoint = spec[at + 1 .. ^1]
  if not result.endpoint.startsWith("dac://"):
    return (false, "", "", "", "'" & result.endpoint & "' in '" & spec &
      "' is not a dac://host:port endpoint")
  result.name = splitFile(result.pinPath).name
  result.ok = true

proc syncPeerFrom*(spec: string, way: SyncWay): tuple[ok: bool,
    peer: SyncPeer, err: string] {.role: dataFetcher,
    tag: "config|networkSurface|read|sync".} =
  ## spec/way: one peer from its text, its pin read from disk.
  var
    parsed: SyncSpec = parseSyncSpec(spec)
    pin: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string] =
      (false, default(bfx.AmePinnedPeerIdentity), "")
  if not parsed.ok:
    return (false, SyncPeer(), parsed.err)
  pin = loadPin(parsed.pinPath)
  if not pin.ok:
    return (false, SyncPeer(), parsed.pinPath & ": " & pin.err)
  result = (true, SyncPeer(name: parsed.name, endpoint: parsed.endpoint,
    pin: pin.pin, way: way), "")

proc addPeers(P: var SyncPlan, specs: openArray[string],
    way: SyncWay): string {.role: dataFetcher,
    tag: "config|networkSurface|read|sync".} =
  ## P/specs/way: every spec added to the plan in that direction; the
  ## first complaint, or "".
  var
    got: tuple[ok: bool, peer: SyncPeer, err: string] =
      (false, SyncPeer(), "")
  for spec in specs:
    got = syncPeerFrom(spec, way)
    if not got.ok:
      return got.err
    P.peers.add got.peer
  result = ""

proc syncPlanFrom*(pull, push, both: openArray[string],
    everySeconds: int): tuple[ok: bool, plan: SyncPlan, err: string] {.
    role: dataFetcher, tag: "config|networkSurface|read|sync".} =
  ## pull/push/both: peer specs, one list per direction.
  ## everySeconds: how often the plan runs.
  var
    complaint: string = ""
  result.plan.everySeconds = everySeconds
  complaint = result.plan.addPeers(pull, swPull)
  if complaint.len == 0:
    complaint = result.plan.addPeers(push, swPush)
  if complaint.len == 0:
    complaint = result.plan.addPeers(both, swBoth)
  if complaint.len > 0:
    return (false, SyncPlan(), complaint)
  result.ok = true
