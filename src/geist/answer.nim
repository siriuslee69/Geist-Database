## ---------------------------------------------------------------------
## Answer <- one Query against one Session, with the asker's rights
## ---------------------------------------------------------------------
##
##   Query + Session + PeerContext  ->  Reply
##
## This is the whole server-side semantics of the protocol, and it lives in
## the LIBRARY rather than in the daemon: an application that wants to
## expose its own database over Bifrost should not have to reimplement what
## `qoSync` means, and a test should not have to import a program to find
## out.
##
##   geistd            -> answerQuery   (adds logging and a reload check)
##   an embedding app  -> answerQuery   (adds whatever it likes)
##
## RIGHTS ARE NOT NEGOTIABLE HERE. `p.rights` comes from the pin the
## handshake verified, which comes from the operator's trust list. A
## request cannot ask for more, and this module never widens the set -- it
## only refuses when a write is attempted without `prWrite`.
##
## CURSORS. A follower's position is a LOG POSITION, and the log only ever
## grows, so a position means the same thing tomorrow. `qoSync` lets the
## caller keep it; `qoSubscribe` and `qoPoll` keep it here, under a name.
## Either way `Reply.epoch` travels with the answer: if it changes, the log
## was rewritten and every position the follower holds is meaningless.

import std/tables

import runePragmas
import ./types
import ./config
import ./dynamic
import ./rowid
import ./session
import ./store
import ./transport

const
  replyRowBudget* = 28_000
    ## How many bytes of rows one answer carries before it stops and lets
    ## the follower ask again. Below the transport's whole-frame threshold,
    ## so an ordinary reply is one datagram and the package path stays a
    ## fallback for the case it cannot avoid: a single row bigger than a
    ## frame, which is answered whole regardless.

type
  SyncCursors* = Table[string, uint64]
    ## Named subscription -> log position. Kept by the CALLER, not the
    ## session: a daemon reloads its session when the file changes
    ## underneath, and a subscriber's position must outlive that.

proc initSyncCursors*(): SyncCursors {.role: configurator, stage: stDone,
    tag: "server|sync|types".} =
  ## An empty cursor table.
  result = initTable[string, uint64]()

proc localPeer*(): PeerContext {.role: configurator, stage: stDone,
    tag: "server|sync".} =
  ## Who is asking when the asker is THIS process: `needLocal` and
  ## `offerLocal` hand a Query straight to `answerQuery`, with no
  ## handshake to prove a name, and a program may always read and write
  ## the stores it opened itself.
  result = PeerContext(subject: "this process", address: "local",
    rights: {prRead, prWrite})

proc commitRemote(S: var Session): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "db|server|write".} =
  ## S: session whose accepted remote write is made durable.
  ##
  ## An acknowledgement that LEAVES THE MACHINE has to be true when it
  ## arrives. The write policy governs local writes, where the caller can
  ## see what it has not saved yet; a peer cannot, and it will not send the
  ## row again because it was told the row was stored. So a remote write
  ## saves, whatever `writeMode` would have done on its own.
  ##
  ## `wmVolatile` is the exception, and honestly so: a volatile database
  ## has said it never persists, and "stored" means stored in memory for as
  ## long as this process lives.
  if S.config.writeMode == wmVolatile or not S.dirty:
    return (true, "")
  result = S.save()

proc denied(schema: Schema, epoch: uint64, who, what: string): Reply {.
    role: helper, tag: "server|status".} =
  ## schema/epoch: context every reply carries.
  ## who/what: the peer and the right it lacks, named in the message --
  ## "denied" alone leaves an operator guessing which pin to change.
  result = Reply(ok: false, schema: schema, epoch: epoch,
    err: "'" & who & "' may read but not " & what &
      "; the operator grants that with --allow-write <pin>")

## ---------------------------- one routine per operation -------------
##
##   answerQuery --case q.op--> answerGet | answerFind | answerFetch
##                              answerSync | answerSubscribe | answerPoll
##                              answerPut | answerDelete
##
## Every answer carries the schema and the log epoch (`answered`), so a
## refusal is just `refused(S, why)`.

proc answered(S: Session): Reply {.role: truthBuilder, inline,
    tag: "db|networkSurface".} =
  ## S: an empty answer carrying the schema and the log epoch.
  result = Reply(schema: S.entries.schema, epoch: S.logEpoch)

proc refused(S: Session, why: string): Reply {.role: truthBuilder, inline,
    tag: "db|networkSurface".} =
  ## S/why: a refusal, with the schema and epoch every answer carries.
  result = S.answered()
  result.err = why

proc limitOf(q: Query): int {.role: parser, inline, tag: "networkSurface".} =
  ## q: its row limit; 0 means the default, 64.
  result = if q.limit == 0'u32: 64 else: int(q.limit)

proc answerGet(S: Session, q: Query): Reply {.role: actor,
    tag: "db|networkSurface|read".} =
  ## S/q: the visible row at position `q.cursor`.
  if uint32(q.cursor) >= S.entryCount():
    return S.refused("row " & $q.cursor & " is out of range (" &
      $S.entryCount() & " rows)")
  result = S.answered()
  result.rows.add S.entries.rowAt(S.livePosition(uint32(q.cursor)))
  result.matched = 1'u32
  result.ok = true

proc answerFind(S: Session, q: Query): Reply {.role: actor,
    tag: "db|networkSurface|read".} =
  ## S/q: visible rows matching `q.where[0]`, from position `q.cursor`.
  ##
  ## `cursor` is where to START, in visible-row positions, and the reply
  ## says where to resume. A search can stop early for two reasons -- the
  ## row limit, or the byte budget -- and without a resume point a caller
  ## could not tell a short answer from a complete one.
  var
    i: uint32 = uint32(min(q.cursor, uint64(S.entryCount())))
    r: Row = default(Row)
    used: int = 0
  result = S.answered()
  while i < S.entryCount() and result.rows.len < q.limitOf():
    if result.rows.len > 0 and used >= replyRowBudget:
      break
    r = S.entries.rowAt(S.livePosition(i))
    if q.where.len == 0 or matchesText(S.entries.schema, r.data,
        q.where[0].field, q.where[0].text):
      result.rows.add r
      used = used + r.data.len
      result.matched = result.matched + 1'u32
    i = i + 1'u32
  result.cursor = uint64(i)
  result.ok = true

proc answerFetch(S: Session, q: Query): Reply {.role: actor,
    tag: "db|networkSurface|read".} =
  ## S/q: one row BY NAME. `cursor` carries the id: it is the only u64 a
  ## Query has, and a fetch has nowhere else to put one.
  var
    id: RowId = RowId(q.cursor)
    at: int = -1
  if not S.hasIdentity():
    return S.refused("this database stores rows without identity, so " &
      "there is no id to fetch by")
  at = S.live.positionOf(id)
  if at < 0:
    return S.refused("no row with id " & $id)
  result = S.answered()
  result.rows.add S.entries.rowAt(uint32(at))
  result.matched = 1'u32
  result.ok = true

proc rowsFrom(S: Session, cursor: uint64, q: Query): Reply {.role: actor,
    tag: "db|networkSurface|read|sync".} =
  ## S/cursor/q: rows of the LOG from `cursor`, and where the next call
  ## resumes. Superseded versions and tombstones are included on purpose --
  ## they are what the follower missed, and replaying them in order
  ## reproduces this database exactly.
  result = S.answered()
  result.rows = S.rowsSince(cursor, q.limitOf(), replyRowBudget)
  result.cursor = min(cursor, uint64(S.logCount())) +
    uint64(result.rows.len)
  result.matched = S.logCount()
  result.ok = true

proc answerSubscribe(S: Session, cursors: var SyncCursors,
    q: Query): Reply {.role: actor, tag: "db|networkSurface|sync".} =
  ## S/cursors/q: a name for a cursor, so a follower need not keep one.
  ##
  ## `cursor` is where to start, and it means the same thing it means
  ## everywhere else: how many rows the follower already has. Zero is
  ## therefore "send me everything", NOT "start from now" -- a subscriber
  ## that wants only what happens next says so by passing the row count it
  ## was just told, which every reply carries in `matched`.
  if q.subscriptionId.len == 0:
    return S.refused("a subscription needs a name")
  cursors[q.subscriptionId] = q.cursor
  result = S.answered()
  result.cursor = q.cursor
  result.matched = S.logCount()
  result.ok = true

proc answerPoll(S: Session, cursors: var SyncCursors, q: Query): Reply {.
    role: actor, tag: "db|networkSurface|read|sync".} =
  ## S/cursors/q: what changed since this subscription last asked -- WITH
  ## the rows. A count alone left a remote subscriber no option but to
  ## re-read the whole database.
  if not cursors.hasKey(q.subscriptionId):
    return S.refused("no subscription '" & q.subscriptionId &
      "'; subscribe first")
  result = S.rowsFrom(cursors[q.subscriptionId], q)
  cursors[q.subscriptionId] = result.cursor

proc writeRefused(S: Session, p: PeerContext, what: string): tuple[
    no: bool, reply: Reply] {.role: sanitizer, tag: "db|networkSurface".} =
  ## S/p/what: why this peer may not write here now, if it may not -- no
  ## right to, or this node holds no write lease.
  if not (prWrite in p.rights):
    return (true, denied(S.entries.schema, S.logEpoch, p.subject, what))
  if S.readOnly:
    return (true, S.refused("this node holds no write lease: " &
      S.writeRefusal()))
  result = (false, Reply())

proc applyIncoming(S: var Session, r: var Row): tuple[ok: bool,
    applied: int, err: string] {.role: dataWriter,
    tag: "db|networkSurface|sync|write".} =
  ## S/r: one row a peer sent, stored.
  ##
  ## A row with NO identity is a client adding one, not a peer replicating:
  ## it has no database of its own to allocate from, so this side names the
  ## row. A peer's rows always arrive with their own ids and keep them.
  ## Each row is named as it is applied, because `nextIdFor` only moves
  ## once a row carrying that id is stored.
  var
    stamped: tuple[ok: bool, data: ByteSeq, err: string] =
      (true, r.data, "")
  if S.hasIdentity() and S.entries.schema.rowIdOf(r.data) == 0'u64:
    stamped = restampRow(S.entries.schema, r.data, S.nextIdFor(), 0'u64,
      S.sidecarStore)
  if not stamped.ok:
    return (false, 0, stamped.err)
  r.data = stamped.data
  result = S.applyRows([r])

proc answerPut(S: var Session, q: Query, p: PeerContext): Reply {.
    role: actor, tag: "db|networkSurface|sync|write".} =
  ## S/q/p: rows FROM a peer, exactly as that peer stored them. Applying
  ## one reproduces its operation: a new id adds, a known id supersedes, a
  ## tombstone removes. `matched` counts the rows that changed something.
  var
    gate: tuple[no: bool, reply: Reply] = S.writeRefused(p, "write")
    o: int = 0
    incoming: seq[Row] = @[]
    applied: tuple[ok: bool, applied: int, err: string] = (false, 0, "")
    committed: tuple[ok: bool, err: string] = (false, "")
    i: int = 0
  if gate.no:
    return gate.reply
  incoming = decodeRows(q.payload, o)
  if incoming.len == 0:
    return S.refused("a put carried no rows")
  result = S.answered()
  while i < incoming.len:
    applied = S.applyIncoming(incoming[i])
    if not applied.ok:
      return S.refused(applied.err)
    result.matched = result.matched + uint32(applied.applied)
    i = i + 1
  committed = commitRemote(S)
  if not committed.ok:
    return S.refused("rows applied but not saved: " & committed.err)
  result.cursor = uint64(S.logCount())
  result.ok = true

proc answerDelete(S: var Session, q: Query, p: PeerContext): Reply {.
    role: actor, tag: "db|networkSurface|write".} =
  ## S/q/p: remove the row whose id is `q.cursor`.
  var
    gate: tuple[no: bool, reply: Reply] = S.writeRefused(p, "delete")
    id: RowId = RowId(q.cursor)
    committed: tuple[ok: bool, err: string] = (false, "")
  if gate.no:
    return gate.reply
  if not S.hasIdentity():
    return S.refused("this database stores rows without identity, so " &
      "there is no id to delete by")
  if not S.delete(id):
    return S.refused("no row with id " & $id & " (or it is already deleted)")
  committed = commitRemote(S)
  if not committed.ok:
    return S.refused("row removed but not saved: " & committed.err)
  result = S.answered()
  result.matched = 1'u32
  result.cursor = uint64(S.logCount())
  result.ok = true

proc answerQuery*(S: var Session, cursors: var SyncCursors, q: Query,
    p: PeerContext): Reply {.role: actor,
    tag: "appApi|db|networkSurface|read|server|sync".} =
  ## S: the open database.
  ## cursors: named subscription positions, updated in place.
  ## q: the request.
  ## p: who is asking, and what their pin permits.
  ##
  ## Rows are self-contained: each carries its own values and its own
  ## identity rather than pointing into shared state, so nothing has to be
  ## projected out before a reply goes on the wire -- and nothing has to be
  ## reconstructed on arrival.
  case q.op
  of qoGet: result = S.answerGet(q)
  of qoFind: result = S.answerFind(q)
  of qoFetch: result = S.answerFetch(q)
  of qoSync: result = S.rowsFrom(q.cursor, q)
  of qoSubscribe: result = S.answerSubscribe(cursors, q)
  of qoPoll: result = S.answerPoll(cursors, q)
  of qoPut: result = S.answerPut(q, p)
  of qoDelete: result = S.answerDelete(q, p)
