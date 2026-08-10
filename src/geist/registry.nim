## ---------------------------------------------------------------------
## Registry <- many stores behind one daemon, chosen by address
## ---------------------------------------------------------------------
##
##   Query(collection: "geist://fjord/mail/alice/inbox")
##        |
##        +-- parseAddress                                   address.nim
##        +-- may this daemon serve that app?                 allow list
##        +-- storeFor(home, address) -> a path               layout.nim
##        +-- already open?  --yes-->  touch it
##        |                  --no -->  open it, maybe evict
##        +-- answerQuery(session, cursors, q, p)             answer.nim
##
## `geistd` serves ONE database, which is right for what it is: a
## general-purpose daemon pointed at a folder. But an application server is
## not that shape. Fjord holds a store per mailbox, Eris a store per game,
## Avalon a store per vault -- and every one of them was about to write the
## same forty lines: a table of open sessions, a lazy open, a bound on how
## many stay open, and a rule for which app's addresses it will answer at
## all.
##
## Three copies of that is three different answers to "what happens at the
## thirty-third mailbox".
##
## WHY THERE IS A BOUND. A server with ten thousand accounts cannot hold
## ten thousand open databases: each one costs a file handle, a write lease
## and its resident rows. So the registry keeps the most recently used and
## closes the rest. Reopening is cheap; running out of file handles halfway
## through a Tuesday is not.
##
##   limit = 3, all open, a fourth arrives
##
##   used: [ alice/inbox  bob/inbox  carol/inbox ]   <- oldest first
##   ask dave/inbox
##   used: [ bob/inbox  carol/inbox  dave/inbox ]    alice SAVED and closed
##
## EVICTION SAVES FIRST. A session is closed only after `save` succeeds; a
## save that fails leaves the store open and evicts the next candidate
## instead. Dropping unsaved rows to stay under a limit would trade a
## resource problem for a data-loss problem, which is not a trade.
##
## THE ALLOW LIST IS A BOUNDARY, NOT AN OPTIMISATION. A Fjord server that
## answered `geist://eris/...` would happily create `db/eris/` and serve
## whatever landed there, because the address is the path and the path is
## whatever it was told. Naming the apps a daemon serves is what stops one
## application's server from becoming a general file server for any address
## a peer can spell.
##
## HOW A STORE IS OPENED IS THE APPLICATION'S BUSINESS. Schema, password
## and read-only-ness differ per app and per target -- Fjord's `accounts`
## is not shaped like its `mail` -- so opening is a callback. The registry
## owns WHEN a store is open and WHICH one; the application owns WHAT it is.
##
## SLOTS ARE `ref` FOR A REASON. `Session` owns a move-only `Secret`, so it
## cannot be copied, and a `Table[string, Session]` cannot exist. A table
## of refs copies the pointer and never the session.

import std/[strutils, tables, times]

import ../analysis_pragmas
import ./types
import ./address
import ./answer
import ./layout
import ./session

const
  defaultOpenStores* = 32
    ## Stores kept open at once before the least recently used is closed.
    ## Chosen to sit well under the usual thousand-handle soft limit with
    ## room for the sockets, the journals and the sidecars a busy daemon
    ## also holds.

  minOpenStores* = 1
    ## A registry that could hold nothing would close each store as it
    ## opened the next, and every request would pay a full open.

type
  StoreSlot* {.role: truthState, metaTags: {tagDb, tagServer, tagTypes}.} =
      ref object
    ## One open database, and what the registry knows about it.
    ##
    ## `cursors` is per store on purpose: a subscription name means
    ## "where I am in THIS log", and two stores that both have a
    ## subscriber called `phone` are two positions, not one.
    ##
    ## `uses` and `openedAt` are not bookkeeping for its own sake -- they
    ## are what an operator reads when asking why a store is being
    ## reopened constantly, which is the symptom of a limit set too low.
    session*: Session
    cursors*: SyncCursors
    key*: string
    path*: string
    address*: GeistAddress
    writable*: bool
    openedAt*: int64
    usedAt*: int64
    uses*: uint64

  OpenStore* {.role: configurator, metaTags: {tagDb, tagServer, tagTypes}.} =
      proc (h: GeistHome, a: GeistAddress, path: string, S: var Session):
        tuple[ok: bool, writable: bool, err: string] {.closure.}
    ## How this application opens one of its own stores.
    ##
    ## NOT `gcsafe`, deliberately. `openSession` is not -- it reaches
    ## Tyr's hashing through the sidecar cache -- so a type that demanded
    ## it would be a promise no opener could keep. The cast belongs at the
    ## `serveOnce` boundary, where `geistd` already puts it, rather than
    ## here where it would be a cast per application.
    ##
    ## `S` is filled IN PLACE rather than returned, because a `Session`
    ## cannot be copied out of a tuple. `writable` reports whether the
    ## session took the write lease, which the registry needs in order to
    ## decide whether an eviction has anything to save.
    ##
    ## Returning `ok = false` refuses the address. An application says
    ## "there is no such mailbox" here, and the registry turns that into a
    ## refusal rather than an empty database -- opening a store for a name
    ## nobody has ever used is how a typo becomes a directory.

  RegistryReport* {.role: truthState, metaTags: {tagServer, tagStatus,
      tagTypes}.} = object
    ## What the registry has done since it was made. Counters rather than
    ## a log, because a daemon that logged every acquire would spend more
    ## on the log than on the work.
    opened*: uint64
    evicted*: uint64
    refused*: uint64
    hits*: uint64

  StoreRegistry* {.role: truthState, metaTags: {tagDb, tagServer,
      tagTypes}.} = object
    ## home: the one folder everything on this machine lives under.
    ## open: the application's opener.
    ## allow: app names this daemon answers for. EMPTY MEANS NONE, not
    ##   any -- a registry nobody configured should refuse rather than
    ##   serve the whole address space.
    ## limit: how many stores stay open.
    ## order: keys, least recently used first. A seq rather than a heap:
    ##   at these sizes a linear touch is faster than the bookkeeping a
    ##   heap would need, and it is obvious when read.
    ## nowSeconds: injected clock; zero means the real one.
    home*: GeistHome
    open*: OpenStore
    slots*: Table[string, StoreSlot]
    order*: seq[string]
    allow*: seq[string]
    limit*: int
    nowSeconds*: int64
    report*: RegistryReport

proc initRegistry*(home: GeistHome, open: OpenStore,
    allow: openArray[string], limit: int = defaultOpenStores): tuple[ok: bool,
    registry: StoreRegistry, err: string] {.role: configurator,
    metaTags: {tagConfig, tagDb, tagServer}.} =
  ## home: an opened `GeistHome`.
  ## open: how this application opens one store.
  ## allow: the app names this daemon serves.
  ## limit: open stores kept at once.
  ##
  ## Refuses an empty allow list at STARTUP rather than refusing every
  ## request at runtime. The difference matters: one is a message an
  ## operator reads while deploying, the other is a message a user reads
  ## instead of their mail.
  var
    i: int = 0
  if open == nil:
    return (false, StoreRegistry(), "a registry needs an opener")
  if allow.len == 0:
    return (false, StoreRegistry(),
      "a registry that serves no app would refuse every request; name " &
      "the app(s) this daemon answers for")
  if limit < minOpenStores:
    return (false, StoreRegistry(),
      "a registry must keep at least " & $minOpenStores & " store open")
  result.registry.home = home
  result.registry.open = open
  result.registry.limit = limit
  result.registry.slots = initTable[string, StoreSlot]()
  while i < allow.len:
    result.registry.allow.add allow[i].toLowerAscii()
    i = i + 1
  result.ok = true

proc clockOf(R: StoreRegistry): int64 {.role: helper, inline,
    metaTags: {tagServer}.} =
  ## R: the injected clock, or the real one when nothing set it.
  result = if R.nowSeconds != 0: R.nowSeconds else: getTime().toUnix()

proc slotKey*(a: GeistAddress): string {.role: parser, inline,
    metaTags: {tagDb, tagServer}.} =
  ## a: the address, reduced to what identifies a STORE.
  ##
  ## `destinationKey` and not a key of its own: two requests that reached
  ## this daemon by different routes must land on the same open session
  ## rather than opening the same folder twice, and a sync cursor filed
  ## against that store has to agree about which store it is.
  result = a.destinationKey()

proc serves*(R: StoreRegistry, app: string): bool {.role: parser,
    metaTags: {tagServer}.} =
  ## R/app: whether this daemon answers for an app at all.
  var
    i: int = 0
    t: string = app.toLowerAscii()
  while i < R.allow.len:
    if R.allow[i] == t:
      return true
    i = i + 1
  result = false

proc forget(S: var StoreRegistry, key: string) {.role: stateController,
    metaTags: {tagServer}.} =
  ## S/key: drop one key from the recency order, wherever it sits.
  var
    i: int = 0
  while i < S.order.len:
    if S.order[i] == key:
      S.order.delete(i)
      return
    i = i + 1

proc touch(S: var StoreRegistry, key: string) {.role: stateController,
    metaTags: {tagServer}.} =
  ## S/key: move this store to the most-recently-used end.
  S.forget(key)
  S.order.add key

proc closeSlot(S: var StoreRegistry, key: string): tuple[ok: bool,
    err: string] {.role: dataWriter, metaTags: {tagDb, tagServer,
    tagStorageIo, tagWrite}.} =
  ## S/key: save and close one store, and forget it.
  ##
  ## A writable session is SAVED FIRST and not closed if the save fails.
  ## The caller then tries a different candidate: staying over the limit
  ## for another moment is recoverable, and losing the rows is not.
  var
    slot: StoreSlot
    saved: tuple[ok: bool, err: string]
  if not S.slots.hasKey(key):
    return (true, "")
  slot = S.slots[key]
  if slot.writable:
    saved = slot.session.save()
    if not saved.ok:
      return (false, "store " & key & " was not closed: " & saved.err)
  slot.session.close()
  S.slots.del(key)
  S.forget(key)
  result = (true, "")

proc evictTo(S: var StoreRegistry, room: int): tuple[ok: bool, err: string] {.
    role: orchestrator, metaTags: {tagDb, tagLifecycle, tagServer}.} =
  ## S: the registry.
  ## room: how many stores may remain open.
  ##
  ## Walks from the least recently used. A store that refuses to close is
  ## SKIPPED rather than retried, so one unsaveable database cannot stop
  ## every eviction behind it -- otherwise a single full disk would stall
  ## the whole registry at its limit.
  var
    i: int = 0
    closed: tuple[ok: bool, err: string]
    stuck: string = ""
    candidates: seq[string] = @[]
  while S.slots.len > room and i < S.order.len:
    candidates = S.order
    if i >= candidates.len:
      break
    closed = S.closeSlot(candidates[i])
    if closed.ok:
      S.report.evicted = S.report.evicted + 1'u64
      i = 0
    else:
      # Leave it open and step past it.
      if stuck.len == 0:
        stuck = closed.err
      i = i + 1
  result = (true, stuck)

proc acquire*(S: var StoreRegistry, a: GeistAddress): tuple[ok: bool,
    slot: StoreSlot, err: string] {.role: metaOrchestrator,
    metaTags: {tagDb, tagOrchestrator, tagServer, tagStorageIo}.} =
  ## S: the registry, whose open set this call may change.
  ## a: the address being served.
  ##
  ## The returned slot is borrowed and stays valid until the next
  ## `acquire`, which is exactly the lifetime a single-threaded serve loop
  ## needs. A caller that wants to hold two at once must raise `limit` and
  ## must not assume the first survives -- which is why this returns a
  ## `ref` that eviction leaves intact rather than an index that eviction
  ## would invalidate.
  var
    key: string = ""
    path: tuple[ok: bool, path: string, err: string]
    slot: StoreSlot
    made: tuple[ok: bool, writable: bool, err: string]
    room: tuple[ok: bool, err: string]
  if S.open == nil:
    S.report.refused = S.report.refused + 1'u64
    return (false, nil, "this registry has no opener")
  if a.app.len == 0:
    S.report.refused = S.report.refused + 1'u64
    return (false, nil,
      "address " & a.target & " names no app, so no store can be chosen " &
      "for it")
  if not S.serves(a.app):
    S.report.refused = S.report.refused + 1'u64
    return (false, nil, "this daemon does not serve '" & a.app & "'")
  key = slotKey(a)
  if S.slots.hasKey(key):
    slot = S.slots[key]
    slot.usedAt = S.clockOf()
    slot.uses = slot.uses + 1'u64
    S.touch(key)
    S.report.hits = S.report.hits + 1'u64
    return (true, slot, "")
  path = S.home.storeFor(a)
  if not path.ok:
    S.report.refused = S.report.refused + 1'u64
    return (false, nil, path.err)
  # Make room BEFORE opening, not after: opening first would peak at
  # limit + 1 handles, which is precisely the moment a daemon at its
  # ceiling falls over.
  room = S.evictTo(max(S.limit - 1, 0))
  new(slot)
  made = S.open(S.home, a, path.path, slot.session)
  if not made.ok:
    S.report.refused = S.report.refused + 1'u64
    return (false, nil, made.err)
  slot.key = key
  slot.path = path.path
  slot.address = a
  slot.writable = made.writable
  slot.cursors = initSyncCursors()
  slot.openedAt = S.clockOf()
  slot.usedAt = slot.openedAt
  slot.uses = 1'u64
  S.slots[key] = slot
  S.touch(key)
  S.report.opened = S.report.opened + 1'u64
  result = (true, slot, room.err)

proc serveQuery*(S: var StoreRegistry, q: Query, p: PeerContext): Reply {.
    role: actor, metaTags: {tagAppApi, tagDb, tagNetworkSurface, tagServer}.} =
  ## S: the registry.
  ##
  ## NOT called `answer`: `answer.nim` is a module in this namespace, and
  ## a proc sharing its name resolves to the module the moment an
  ## application re-exports both -- which every application does, because
  ## it needs `answerQuery` too.
  ## q: the request, whose `collection` carries the address.
  ## p: who is asking, and what their pin permits.
  ##
  ## The handler an embedding server hands to `serveOnce`. Rights are not
  ## touched here: `answerQuery` enforces them against `p`, and a registry
  ## that also had an opinion would be a second place to get them wrong.
  ##
  ## An address this daemon does not serve comes back as a REFUSAL, not a
  ## transport failure, so a client's `ask` returns it instead of failing
  ## over to a fallback that would say exactly the same thing.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string]
    got: tuple[ok: bool, slot: StoreSlot, err: string]
    inner: Query = q
  parsed = parseAddress(q.collection)
  if not parsed.ok:
    return Reply(ok: false, err: "address " & q.collection & ": " & parsed.err)
  got = S.acquire(parsed.a)
  if not got.ok:
    return Reply(ok: false, err: got.err)
  # The store is chosen; what reaches the session is the leaf name, so
  # nothing below this line has to know an address exists.
  inner.collection = parsed.a.forLeaf()
  result = answerQuery(got.slot.session, got.slot.cursors, inner, p)

proc saveAll*(S: var StoreRegistry): tuple[ok: bool, saved: int,
    err: string] {.role: dataWriter, metaTags: {tagDb, tagServer,
    tagStorageIo, tagWrite}.} =
  ## S: every writable store, flushed.
  ##
  ## Reports the FIRST failure but keeps going, because a shutdown that
  ## stopped at the first unsaveable store would abandon the ones behind
  ## it -- and those may be perfectly saveable.
  var
    saved: tuple[ok: bool, err: string]
  result.ok = true
  for key, slot in S.slots.pairs:
    if not slot.writable:
      continue
    saved = slot.session.save()
    if saved.ok:
      result.saved = result.saved + 1
    else:
      result.ok = false
      if result.err.len == 0:
        result.err = "store " & key & ": " & saved.err

proc closeRegistry*(S: var StoreRegistry): tuple[ok: bool, err: string] {.
    role: dataWriter, metaTags: {tagDb, tagLifecycle, tagServer,
    tagStorageIo}.} =
  ## S: close everything, saving what is writable.
  ##
  ## Every store is attempted even when one fails: the alternative leaves
  ## write leases held by a process that is on its way out, and the next
  ## start would refuse to open them.
  var
    keys: seq[string] = @[]
    closed: tuple[ok: bool, err: string]
    i: int = 0
  for key in S.slots.keys:
    keys.add key
  result.ok = true
  while i < keys.len:
    closed = S.closeSlot(keys[i])
    if not closed.ok:
      result.ok = false
      if result.err.len == 0:
        result.err = closed.err
    i = i + 1

proc openCount*(S: StoreRegistry): int {.role: parser, inline,
    metaTags: {tagServer, tagStatus}.} =
  ## S: how many stores are open right now.
  result = S.slots.len

proc openKeys*(S: StoreRegistry): seq[string] {.role: parser,
    metaTags: {tagServer, tagStatus}.} =
  ## S: the open stores, least recently used FIRST.
  ##
  ## In recency order rather than sorted, because the question an operator
  ## asks of this list is "what is about to be evicted".
  result = S.order

proc describeRegistry*(S: StoreRegistry): string {.role: parser,
    metaTags: {tagDocs, tagServer, tagStatus}.} =
  ## S: one line for a status page or a log.
  result = $S.openCount() & "/" & $S.limit & " store(s) open, " &
    $S.report.opened & " opened, " & $S.report.evicted & " evicted, " &
    $S.report.hits & " hit(s), " & $S.report.refused & " refused"
