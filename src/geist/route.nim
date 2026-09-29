## ---------------------------------------------------------------------
## Route <- which endpoint serves an address, and who takes over
## ---------------------------------------------------------------------
##
##   GeistAddress --matchRoute--> Route --chooseHop--> one endpoint
##                                          ^
##                                          |  health, from what happened
##                                          |  last time this was tried
##
## A VPS running Eris, Fjord and Avalon has one public address and three
## apps behind it. `address.nim` says what a request names; this says
## where that goes, and what happens when the daemon it normally goes to
## has stopped answering.
##
##   route  eris.*    ->  vps-1  priority 0
##                        vps-2  priority 1        <- takes over
##   route  fjord.*   ->  vps-1  priority 0
##                        vps-3  priority 1        <- takes over
##   route  avalon.*  ->  vps-4  priority 0
##   route  *.*       ->  home-1 priority 0        <- catch-all
##
## THREE RULES, EACH FROM A SPECIFIC FAILURE.
##
##   TAKEOVER NEEDS CONTINUOUS FAILURE. A hop is down only after
##   `takeoverAfterSeconds` with no success at all. One request that timed
##   out during a garbage collection pause is not a dead daemon.
##
##   RECOVERY NEEDS CONSECUTIVE SUCCESSES. A daemon that is crash-looping
##   answers every third probe. Promoting it on the first one moves the
##   traffic back in time for the next crash, and the route oscillates.
##
##   PRIORITY IS STATIC AND TOTAL. No election, no quorum, no shared
##   state. Two hops in one route may not share a priority number --
##   `validate` refuses it -- so "who serves eris right now" is a pure
##   function of (table, health) and two routers with the same view always
##   agree. When their views DIFFER they disagree, and that is fine: two
##   daemons answering is a duplicate, not a corruption.
##
## AN APPLICATION ERROR IS NOT A TRANSPORT FAILURE. A hop that answers
## `ok = false` answered. Only `noteFailure` touches health, and it is
## called when the link did not work -- never when the far end merely said
## no. One malformed request must not demote a healthy daemon.
##
## THIS MODULE IS PURE. Endpoints are strings here and are parsed by
## whoever opens the socket, so a route table can be loaded, validated and
## exercised with no transport compiled at all -- which is what makes the
## failover tests deterministic instead of timing-dependent.

import std/[strutils, tables]

import runePragmas
import ./address

const
  anyPattern* = "*"
    ## What a route writes to match every app or every instance. An empty
    ## string means the same thing; `*` is what a person writes and the
    ## empty string is what a half-filled config file has.
  defaultTakeoverSeconds* = 30'u32
    ## How long a hop must fail without interruption before a lower
    ## priority takes over.
  defaultProbeSeconds* = 10'u32
    ## How often a hop that is down is tried again.
  defaultYieldSeconds* = 60'u32
    ## How long a link to a demoted hop is kept open after a higher
    ## priority comes back, so a long poll is not cut in half.
  defaultProbeSuccesses* = 2'u8
    ## Consecutive successes before a hop that was down is used again.
  defaultMaxHops* = 6'u8
    ## The ttl a router stamps on an address that arrived without one.

type
  Hop* {.role: configurator, tag: "config|networkSurface|peerDirectory|types".} = object
    ## One endpoint that can serve a route.
    ##
    ## `local` means this daemon answers it itself rather than forwarding.
    ## A router that serves one app and forwards the rest writes one local
    ## hop and the others as endpoints, and the same code path decides
    ## between them.
    ##
    ## `endpoint` and `pin` are TEXT here on purpose -- see the module
    ## note. Nothing in this file opens anything.
    name*: string
    endpoint*: string
    pin*: string
    priority*: uint8
    local*: bool

  Route* {.role: configurator, tag: "config|networkSurface|types".} = object
    ## A pattern and the hops that serve it. `*` in either field matches
    ## anything; the most specific matching route wins.
    app*: string
    instance*: string
    hops*: seq[Hop]

  RouteTable* {.role: configurator, tag: "config|networkSurface|types".} = object
    ## The whole table, as it appears in a config file.
    ##
    ## `node` is this daemon's own name and is what gets written into an
    ## address's `via` trail, so it must be unique among the daemons that
    ## can reach each other. A table with no node name cannot forward at
    ## all, because it could not detect a loop through itself.
    node*: string
    maxHops*: uint8
    takeoverAfterSeconds*: uint32
    probeEverySeconds*: uint32
    yieldAfterSeconds*: uint32
    probeSuccesses*: uint8
    route*: seq[Route]

  HopHealth* {.role: truthState, tag: "health|networkSurface|status|types".} = object
    ## What has happened to one endpoint, in local monotonic seconds.
    ##
    ## Peer timestamps are never used. Two machines whose clocks disagree
    ## by a minute would otherwise take over from each other forever.
    firstTry*: int64
    lastTry*: int64
    lastOk*: int64
    lastFail*: int64
    failures*: uint32
    successes*: uint32
    down*: bool

  RouteView* {.role: truthState, tag: "health|networkSurface|types".} = object
    ## The table plus what is currently known about each endpoint.
    ##
    ## Health is keyed by endpoint rather than by name so two routes that
    ## list the same daemon share one view of it: a failure seen while
    ## serving eris is the same failure when fjord asks a second later.
    table*: RouteTable
    health*: Table[string, HopHealth]

  HopChoice* {.role: truthState, tag: "networkSurface|status|types".} = object
    ## What `chooseHop` decided, and why.
    ##
    ## `probing` marks a hop that is still considered down and is being
    ## tried anyway because nothing better is available. A caller should
    ## log that differently from ordinary traffic: it is the difference
    ## between "working" and "the last thing left".
    ok*: bool
    hop*: Hop
    probing*: bool
    tried*: seq[string]
    err*: string

## ---------------------------- defaults ------------------------------

proc defaultRouteTable*(node: string = ""): RouteTable {.role: configurator,
    tag: "config|networkSurface".} =
  ## node: this daemon's name.
  ##
  ## Every timer at its documented value and no routes at all. A table
  ## with no routes forwards nothing, which is the right thing for a
  ## daemon nobody has configured as a router yet.
  result.node = node
  result.maxHops = defaultMaxHops
  result.takeoverAfterSeconds = defaultTakeoverSeconds
  result.probeEverySeconds = defaultProbeSeconds
  result.yieldAfterSeconds = defaultYieldSeconds
  result.probeSuccesses = defaultProbeSuccesses

proc initRouteView*(t: RouteTable): RouteView {.role: configurator,
    tag: "health|networkSurface".} =
  ## t: a validated table, with every endpoint's health unknown.
  result.table = t
  result.health = initTable[string, HopHealth]()

## ---------------------------- validation ----------------------------

proc isAny(s: string): bool {.role: parser, inline,
    tag: "config|networkSurface".} =
  ## s: does this pattern field match everything?
  result = s.len == 0 or s == anyPattern

proc hopsProblem(key: string, H: openArray[Hop]): string {.role: sanitizer,
    tag: "config|networkSurface".} =
  ## key/H: one route's hops -> the first thing wrong with them, or "".
  ## Every hop is named, is local or has an endpoint, and has a priority
  ## no other hop in the route shares.
  var
    seenPriority: Table[uint8, string] = initTable[uint8, string]()
  if H.len == 0:
    return "route " & key & " has no hops"
  for h in H:
    if h.name.len == 0:
      return "route " & key & " has an unnamed hop"
    if not h.local and h.endpoint.len == 0:
      return "hop " & h.name & " in route " & key &
        " is neither local nor has an endpoint"
    if seenPriority.hasKey(h.priority):
      return "hops " & seenPriority[h.priority] & " and " & h.name &
        " in route " & key & " share priority " & $h.priority
    seenPriority[h.priority] = h.name
  result = ""

proc validate*(t: RouteTable): tuple[ok: bool, err: string] {.
    role: sanitizer, tag: "config|networkSurface".} =
  ## t: the table as loaded, checked for the things that would make
  ## routing ambiguous rather than merely wrong.
  ##
  ## Two routes with the same pattern, or two hops in one route with the
  ## same priority, are refused. Both would leave "which one" to iteration
  ## order, and iteration order is not a routing policy.
  var
    i: int = 0
    key: string = ""
    seenRoute: Table[string, bool] = initTable[string, bool]()
  if t.node.len == 0:
    return (false, "routing.node is empty; a router that cannot name " &
      "itself cannot detect a loop through itself")
  if t.probeSuccesses == 0'u8:
    return (false, "routing.probeSuccesses is 0; a hop that is down " &
      "would never come back")
  while i < t.route.len:
    key = (if t.route[i].app.isAny(): anyPattern else: t.route[i].app) & "." &
      (if t.route[i].instance.isAny(): anyPattern else: t.route[i].instance)
    if seenRoute.hasKey(key):
      return (false, "two routes match " & key &
        "; priority would be decided by file order")
    seenRoute[key] = true
    key = hopsProblem(key, t.route[i].hops)
    if key.len > 0:
      return (false, key)
    i = i + 1
  result = (true, "")

## ---------------------------- matching ------------------------------

proc scoreRoute(r: Route, a: GeistAddress): int {.role: parser,
    tag: "networkSurface".} =
  ## r/a: how well this route matches, or -1 when it does not.
  ##
  ## An exact app is worth more than an exact instance, so `eris.*` beats
  ## `*.main` for `eris.main`. The app is the program; the instance is
  ## which copy of it, and serving the wrong program is the worse mistake.
  var
    t: int = 0
  if not r.app.isAny():
    if r.app != a.app:
      return -1
    t = t + 2
  if not r.instance.isAny():
    if r.instance != a.instance:
      return -1
    t = t + 1
  result = t

proc matchRoute*(t: RouteTable, a: GeistAddress): int {.role: parser,
    tag: "networkSurface".} =
  ## t/a: the index of the most specific matching route, or -1.
  var
    i: int = 0
    s: int = 0
    best: int = -1
    bestScore: int = -1
  while i < t.route.len:
    s = scoreRoute(t.route[i], a)
    if s > bestScore:
      bestScore = s
      best = i
    i = i + 1
  result = best

## ---------------------------- health --------------------------------

proc healthOf*(V: RouteView, endpoint: string): HopHealth {.role: parser,
    tag: "health|networkSurface".} =
  ## V/endpoint: what is known, or a blank record for one never tried.
  if V.health.hasKey(endpoint):
    return V.health[endpoint]
  result = HopHealth()

proc noteSuccess*(S: var RouteView, endpoint: string, now: int64) {.
    role: actor, tag: "health|networkSurface".} =
  ## S/endpoint/now: the link worked.
  ##
  ## A hop that is down needs `probeSuccesses` of these in a row before it
  ## carries traffic again; one is not enough, and the counter is reset by
  ## any failure in between.
  var
    h: HopHealth = S.healthOf(endpoint)
  if h.firstTry == 0:
    h.firstTry = now
  h.lastTry = now
  h.lastOk = now
  h.failures = 0'u32
  h.successes = h.successes + 1'u32
  if h.down and h.successes >= uint32(S.table.probeSuccesses):
    h.down = false
  S.health[endpoint] = h

proc noteFailure*(S: var RouteView, endpoint: string, now: int64) {.
    role: actor, tag: "health|networkSurface".} =
  ## S/endpoint/now: the link did not work.
  ##
  ## Call this for a refused connection, a timeout or a broken link --
  ## never for a reply that arrived saying no. See the module note.
  var
    h: HopHealth = S.healthOf(endpoint)
    since: int64 = 0
  if h.firstTry == 0:
    h.firstTry = now
  h.lastTry = now
  h.lastFail = now
  h.successes = 0'u32
  h.failures = h.failures + 1'u32
  since = if h.lastOk > 0: h.lastOk else: h.firstTry
  if now - since >= int64(S.table.takeoverAfterSeconds):
    h.down = true
  S.health[endpoint] = h

proc dueForProbe*(V: RouteView, endpoint: string, now: int64): bool {.
    role: parser, tag: "health|networkSurface".} =
  ## V/endpoint/now: may a hop that is down be tried again yet?
  var
    h: HopHealth = V.healthOf(endpoint)
  if not h.down:
    return true
  result = now - h.lastTry >= int64(V.table.probeEverySeconds)

## ---------------------------- choosing ------------------------------

proc byPriority(hops: seq[Hop]): seq[Hop] {.role: helper,
    tag: "networkSurface".} =
  ## hops: the same hops, lowest priority number first.
  ##
  ## An insertion sort: a route has a handful of hops, and this keeps the
  ## order of equal priorities stable -- which `validate` has already made
  ## impossible, but a table that failed validation still has to behave
  ## predictably in a log message.
  var
    i: int = 0
    j: int = 0
    t: Hop = default(Hop)
  result = hops
  i = 1
  while i < result.len:
    t = result[i]
    j = i - 1
    while j >= 0 and result[j].priority > t.priority:
      result[j + 1] = result[j]
      j = j - 1
    result[j + 1] = t
    i = i + 1

proc keyOf*(h: Hop): string {.role: helper, inline,
    tag: "networkSurface".} =
  ## h: what this hop's health is filed under. A local hop has no
  ## endpoint, so it is filed under its name.
  result = if h.local: "local:" & h.name else: h.endpoint

proc chooseHop*(V: RouteView, a: GeistAddress, now: int64): HopChoice {.
    role: actor, tag: "health|networkSurface".} =
  ## V: the table and what is known about each endpoint.
  ## a: where the request is going.
  ## now: local monotonic seconds.
  ##
  ## The lowest-priority-number hop that is not down. If every hop is
  ## down, the best one whose probe is due is returned with `probing` set
  ## -- traffic is a probe, and refusing to try anything at all would keep
  ## a route dead after the daemons behind it had recovered.
  ##
  ## An address that names a node (`@vps-1`) is pinned to that hop: the
  ## sender asked for a specific machine, and silently sending it
  ## elsewhere would answer a different question from the one asked.
  var
    i: int = 0
    n: int = -1
    hops: seq[Hop] = @[]
    fallback: int = -1
  n = V.table.matchRoute(a)
  if n < 0:
    result.err = "no route for " & (if a.app.len > 0: a.app else: "(no app)")
    return
  hops = byPriority(V.table.route[n].hops)
  while i < hops.len:
    if a.node.len > 0 and hops[i].name != a.node:
      i = i + 1
      continue
    result.tried.add hops[i].name
    if not V.healthOf(hops[i].keyOf()).down:
      result.ok = true
      result.hop = hops[i]
      return
    if fallback < 0 and V.dueForProbe(hops[i].keyOf(), now):
      fallback = i
    i = i + 1
  if result.tried.len == 0:
    result.err = "route matched but no hop is named " & a.node
    return
  if fallback < 0:
    result.err = "every hop is down and none is due for a probe: " &
      result.tried.join(", ")
    return
  result.ok = true
  result.probing = true
  result.hop = hops[fallback]

proc servesLocally*(V: RouteView, a: GeistAddress): bool {.role: parser,
    tag: "networkSurface".} =
  ## V/a: would this address be answered here rather than forwarded?
  ##
  ## Asked before a hop is chosen, because a request this daemon serves
  ## itself never needs an outgoing link, a loop check or a ttl.
  var
    n: int = V.table.matchRoute(a)
    i: int = 0
  if n < 0:
    return false
  while i < V.table.route[n].hops.len:
    if V.table.route[n].hops[i].local and
        V.table.route[n].hops[i].priority == 0'u8:
      return true
    i = i + 1
  result = false

proc hopLine(V: RouteView, hop: Hop, now: int64): string {.role: helper,
    tag: "health|networkSurface|status".} =
  ## V/hop/now: one hop as a status line -- priority, name, where, state.
  var
    h: HopHealth = V.healthOf(hop.keyOf())
    state: string = "unknown"
  if h.down:
    state = "DOWN for " & $(now - h.lastOk) & "s"
  elif h.lastOk > 0:
    state = "up"
  result = "  " & $hop.priority & "  " & hop.name & "  " &
    (if hop.local: "(local)" else: hop.endpoint) & "  " & state

proc describe*(V: RouteView, now: int64): string {.role: helper,
    tag: "health|networkSurface|status".} =
  ## V/now: the table and its health, one line per hop, for an operator.
  var
    L: seq[string] = @[]
    i: int = 0
    hops: seq[Hop] = @[]
  L.add "node " & V.table.node & ", takeover after " &
    $V.table.takeoverAfterSeconds & "s, probe every " &
    $V.table.probeEverySeconds & "s"
  while i < V.table.route.len:
    L.add "route " &
      (if V.table.route[i].app.isAny(): anyPattern else: V.table.route[i].app) &
      "." & (if V.table.route[i].instance.isAny(): anyPattern
             else: V.table.route[i].instance)
    hops = byPriority(V.table.route[i].hops)
    for hop in hops:
      L.add V.hopLine(hop, now)
    i = i + 1
  result = L.join("\n")
