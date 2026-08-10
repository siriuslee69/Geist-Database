## ---------------------------------------------------------------------
## Link <- one call that finds a hop, connects, asks, and fails over
## ---------------------------------------------------------------------
##
##   ask(client, query)
##      |
##      +-- parse the address out of q.collection      address.nim
##      +-- choose a hop for it                        route.nim
##      +-- reuse an open link, or connect             transport.nim
##      +-- send; on a TRANSPORT failure, note it and try the next hop
##      +-- on an APPLICATION refusal, return it and touch no health
##
## Every program that talks to a Geist daemon needs the same six steps,
## and before this module every one of them wrote them again: Eris in its
## `connection.nim`, Fjord in its transport bridge, Avalon in its sync
## path. Three copies of a retry loop is three different ideas about what
## counts as a failure.
##
## THE DISTINCTION THIS MODULE EXISTS TO ENFORCE:
##
##   the link did not work        -> noteFailure, try the next hop
##   the far end said no          -> return it, health untouched
##
## A daemon that answers `no such collection` is a working daemon. Failing
## over to a fallback because of it would move the traffic to a machine
## that will say exactly the same thing, and would demote the only host
## that has the data.
##
##   client                 gateway              d1        d2
##   ------                 -------              --        --
##   ask(geist://eris/notes)
##            ---------------->  chooseHop -> d1
##                               connect ------->  X  (refused)
##                               noteFailure(d1)
##                               chooseHop -> d2
##                               connect -------------------> ok
##            <----------------  reply
##
## LINKS ARE CACHED PER ENDPOINT. A handshake is expensive and a client
## that redid one per request would spend more time in post-quantum key
## exchange than in the request. A link that fails is dropped, so the next
## attempt reconnects rather than reusing a broken socket.
##
## THE CLOCK IS INJECTED. `nowSeconds` is a field, so a test drives
## takeover and recovery by assignment rather than by sleeping.

import std/[tables, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import ../analysis_pragmas
import ./types
import ./address
import ./identity
import ./masks
import ./route
import ./transport

const
  defaultAskTimeoutMs* = 4000
    ## How long one attempt at one hop may take. The whole `ask` may take
    ## this many milliseconds times the number of hops it tries, which is
    ## why a route with a long fallback list needs a short timeout rather
    ## than a long one.
  defaultMaxAttempts* = 3
    ## Hops tried before giving up, however many the route lists. A client
    ## walking eight dead daemons before answering is indistinguishable
    ## from one that hung.

type
  LinkSlot* {.role: truthState, metaTags: {tagNetworkSurface, tagTypes}.} =
      object
    ## One cached connection, and the pin it was made against.
    link*: GeistLink
    openedAt*: int64

  GeistClient* {.role: truthState, metaTags: {tagAppApi, tagNetworkSurface,
      tagTypes}.} = object
    ## Everything needed to reach whatever a request names.
    ##
    ## `identity` is this program's signing key; `pins` maps a hop's pin
    ## FILE to the loaded pin, so a table that names the same peer twice
    ## loads it once. `nowSeconds` is the clock -- see the module note.
    identity*: bfx.AmeIdentityKey
    policy*: TriggerPolicy
    routes*: RouteView
    links*: Table[string, LinkSlot]
    pins*: Table[string, bfx.AmePinnedPeerIdentity]
    timeoutMs*: int
    maxAttempts*: int
    sessionId*: uint64
    nowSeconds*: int64

  AskResult* {.role: truthState, metaTags: {tagAppApi, tagNetworkSurface,
      tagStatus, tagTypes}.} = object
    ## What came back, and how much work it took.
    ##
    ## `served` names the hop that answered, so a caller can log which
    ## machine is actually doing the work -- the whole point of a fallback
    ## is that this is not always the one you configured first.
    ##
    ## `ok` means the exchange happened. The far end's own answer is in
    ## `reply.ok`, and the two are different questions: a reply that says
    ## no is a successful exchange.
    ok*: bool
    reply*: Reply
    served*: string
    attempts*: int
    tried*: seq[string]
    err*: string

proc initGeistClient*(identity: bfx.AmeIdentityKey, t: RouteTable,
    policy: TriggerPolicy = defaultTriggerPolicy()): tuple[ok: bool,
    client: GeistClient, err: string] {.role: configurator,
    metaTags: {tagAppApi, tagNetworkSurface}.} =
  ## identity: this program's signing key.
  ## t: the route table, validated here so a bad one fails at startup
  ##   rather than on the first request that needed the broken route.
  ## policy: tier policy; the defaults are Geist's own.
  var
    v: tuple[ok: bool, err: string]
  v = t.validate()
  if not v.ok:
    return (false, GeistClient(), v.err)
  result.client.identity = identity
  result.client.policy = policy
  result.client.routes = initRouteView(t)
  result.client.links = initTable[string, LinkSlot]()
  result.client.pins = initTable[string, bfx.AmePinnedPeerIdentity]()
  result.client.timeoutMs = defaultAskTimeoutMs
  result.client.maxAttempts = defaultMaxAttempts
  result.client.sessionId = 1'u64
  result.ok = true

proc clockOf(c: GeistClient): int64 {.role: helper, inline,
    metaTags: {tagNetworkSurface}.} =
  ## c: the injected clock, or the real one when nothing set it.
  result = if c.nowSeconds != 0: c.nowSeconds else: getTime().toUnix()

proc pinFor(S: var GeistClient, path: string): tuple[ok: bool,
    pin: bfx.AmePinnedPeerIdentity, err: string] {.role: dataFetcher,
    metaTags: {tagNetworkSurface, tagPeerDirectory}.} =
  ## S/path: the pin file, loaded once and remembered.
  ##
  ## A pin that will not load is NOT a transport failure and must not
  ## demote the hop: the daemon at the other end may be perfectly healthy
  ## and the file on this machine merely missing.
  var
    t: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string]
  if S.pins.hasKey(path):
    return (true, S.pins[path], "")
  t = loadPin(path)
  if not t.ok:
    return (false, t.pin, "pin " & path & ": " & t.err)
  S.pins[path] = t.pin
  result = (true, t.pin, "")

proc dropLink*(S: var GeistClient, endpoint: string) {.role: stateController,
    metaTags: {tagNetworkSurface}.} =
  ## S/endpoint: forget a cached link, closing it if it is still open.
  ##
  ## Called after every transport failure. Reusing a socket that has
  ## already failed once turns one dead daemon into an unbounded series of
  ## instant failures, each of which looks like a fresh one.
  var
    slot: LinkSlot
  if not S.links.hasKey(endpoint):
    return
  slot = S.links[endpoint]
  if slot.link.open:
    slot.link.close()
  S.links.del(endpoint)

proc linkTo(S: var GeistClient, h: Hop): tuple[ok: bool, err: string] {.
    role: orchestrator, metaTags: {tagNetworkSurface, tagOrchestrator}.} =
  ## S/h: make sure there is an open link to this hop, reusing one if
  ## there already is.
  var
    remote: tuple[ok: bool, a: bfx.DacAddress]
    pin: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string]
    made: tuple[ok: bool, link: GeistLink, err: string]
    slot: LinkSlot
  if S.links.hasKey(h.endpoint) and S.links[h.endpoint].link.open:
    return (true, "")
  pin = S.pinFor(h.pin)
  if not pin.ok:
    return (false, pin.err)
  remote = bfx.parseDacAddress(h.endpoint)
  if not remote.ok:
    return (false, "endpoint " & h.endpoint & " is not dac://host:port")
  S.sessionId = S.sessionId + 1'u64
  made = connectGeist(remote.a, S.identity, pin.pin, S.policy, S.sessionId,
    S.timeoutMs)
  if not made.ok:
    return (false, made.err)
  slot.link = made.link
  slot.openedAt = S.clockOf()
  S.links[h.endpoint] = slot
  result = (true, "")

proc askHop(S: var GeistClient, h: Hop, q: Query): tuple[ok: bool,
    reply: Reply, err: string] {.role: orchestrator,
    metaTags: {tagNetworkSurface, tagOrchestrator}.} =
  ## S/h/q: one attempt against one hop.
  ##
  ## `ok` false means the LINK failed. A reply that arrived saying no is
  ## `ok` true with `reply.ok` false, and the caller must keep the two
  ## apart -- that is the whole distinction this module exists for.
  var
    made: tuple[ok: bool, err: string]
    sent: tuple[ok: bool, reply: Reply, err: string]
    slot: LinkSlot
  made = S.linkTo(h)
  if not made.ok:
    return (false, Reply(), made.err)
  slot = S.links[h.endpoint]
  sent = slot.link.send(q, S.timeoutMs)
  S.links[h.endpoint] = slot
  if not sent.ok:
    return (false, Reply(), sent.err)
  result = (true, sent.reply, "")

proc ask*(S: var GeistClient, q: Query): AskResult {.role: metaOrchestrator,
    metaTags: {tagAppApi, tagNetworkSurface, tagOrchestrator}.} =
  ## S: the client, whose health view this call updates.
  ## q: the request. `q.collection` carries the address; a bare collection
  ##   name is a legal one and routes on the `*` route, so a program that
  ##   knows nothing about federation still works.
  ##
  ## Tries hops in priority order until one answers or `maxAttempts` are
  ## spent. A hop that fails is noted, its link dropped, and the next one
  ## chosen from the updated health -- so the second attempt of a single
  ## `ask` already sees the first attempt's failure.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string]
    choice: HopChoice
    attempt: tuple[ok: bool, reply: Reply, err: string]
    forward: Query = q
    now: int64 = 0
    i: int = 0
  parsed = parseAddress(q.collection)
  if not parsed.ok:
    result.err = "address " & q.collection & ": " & parsed.err
    return
  while i < S.maxAttempts:
    now = S.clockOf()
    choice = S.routes.chooseHop(parsed.a, now)
    if not choice.ok:
      result.err = choice.err
      result.tried = choice.tried
      return
    result.attempts = result.attempts + 1
    result.tried.add choice.hop.name
    # The address travels WHOLE. A leaf resolves its own collection with
    # `forLeaf`, so stripping it here would work for one hop and break
    # the moment a router forwards to another router -- the second one
    # would receive a bare name, have no app to route on, and refuse.
    attempt = S.askHop(choice.hop, forward)
    if attempt.ok:
      S.routes.noteSuccess(choice.hop.keyOf(), now)
      result.ok = true
      result.reply = attempt.reply
      result.served = choice.hop.name
      return
    S.routes.noteFailure(choice.hop.keyOf(), now)
    S.dropLink(choice.hop.endpoint)
    result.err = choice.hop.name & ": " & attempt.err
    i = i + 1
  result.err = "no hop answered after " & $result.attempts & " attempt(s); " &
    "last error was " & result.err

proc closeClient*(S: var GeistClient) {.role: stateController,
    metaTags: {tagAppApi, tagLifecycle, tagNetworkSurface}.} =
  ## S: close every cached link.
  var
    endpoints: seq[string] = @[]
  for key in S.links.keys:
    endpoints.add key
  for key in endpoints:
    S.dropLink(key)

proc healthReport*(s: GeistClient): string {.role: helper,
    metaTags: {tagHealth, tagNetworkSurface, tagStatus}.} =
  ## s: the route table and what is currently known about each hop.
  result = s.routes.describe(s.clockOf())
