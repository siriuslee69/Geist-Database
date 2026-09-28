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

proc answerQuery*(S: var Session, cursors: var SyncCursors, q: Query,
    p: PeerContext): Reply {.role: actor, tag: "appApi|db|networkSurface|read|server|sync".} =
  ## S: the open database.
  ## cursors: named subscription positions, updated in place.
  ## q: the request.
  ## p: who is asking, and what their pin permits.
  ##
  ## Rows are self-contained: each carries its own values and its own
  ## identity rather than pointing into shared state, so nothing has to be
  ## projected out before a reply goes on the wire -- and nothing has to be
  ## reconstructed on arrival.
  var
    i: uint32 = 0'u32
    limit: int = 0
    r: Row = default(Row)
    incoming: seq[Row] = @[]
    o: int = 0
    applied: tuple[ok: bool, applied: int, err: string] = (false, 0, "")
    id: RowId = 0'u64
    cursor: uint64 = 0'u64
    at: int = -1
    used: int = 0
    stamped: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
    committed: tuple[ok: bool, err: string] = (false, "")
  result.schema = S.entries.schema
  result.epoch = S.logEpoch
  limit = if q.limit == 0'u32: 64 else: int(q.limit)
  case q.op
  of qoGet:
    if uint32(q.cursor) >= S.entryCount():
      return Reply(ok: false, err: "row " & $q.cursor & " is out of range (" &
        $S.entryCount() & " rows)", schema: result.schema, epoch: result.epoch)
    result.rows.add S.entries.rowAt(S.livePosition(uint32(q.cursor)))
    result.matched = 1'u32
    result.ok = true
  of qoFind:
    # `cursor` is where to START, in visible-row positions, and the reply
    # says where to resume. A search can stop early for two reasons -- the
    # row limit, or the byte budget -- and without a resume point a caller
    # could not tell a short answer from a complete one.
    i = uint32(min(q.cursor, uint64(S.entryCount())))
    while i < S.entryCount() and result.rows.len < limit:
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
  of qoFetch:
    # One row BY NAME. `cursor` carries the id: it is the only u64 a Query
    # has, and a fetch has nowhere else to put one.
    id = RowId(q.cursor)
    if not S.hasIdentity():
      return Reply(ok: false, schema: result.schema, epoch: result.epoch,
        err: "this database stores rows without identity, so there is no " &
          "id to fetch by")
    at = S.live.positionOf(id)
    if at < 0:
      return Reply(ok: false, err: "no row with id " & $id,
        schema: result.schema, epoch: result.epoch)
    result.rows.add S.entries.rowAt(uint32(at))
    result.matched = 1'u32
    result.ok = true
  of qoSync:
    # The catch-up call: rows of the LOG from where the follower left off.
    # Superseded versions and tombstones are included on purpose -- they
    # are what it missed, and replaying them in order reproduces this
    # database exactly.
    result.rows = S.rowsSince(q.cursor, limit, replyRowBudget)
    result.cursor = min(q.cursor, uint64(S.logCount())) +
      uint64(result.rows.len)
    result.matched = S.logCount()
    result.ok = true
  of qoSubscribe:
    # A name for a cursor, so a follower need not keep one.
    #
    # `cursor` is where to start, and it means the same thing it means
    # everywhere else: how many rows the follower already has. Zero is
    # therefore "send me everything", NOT "start from now" -- a subscriber
    # that wants only what happens next says so by passing the row count it
    # was just told, which every reply carries in `matched`.
    if q.subscriptionId.len == 0:
      return Reply(ok: false, err: "a subscription needs a name",
        schema: result.schema, epoch: result.epoch)
    cursor = q.cursor
    cursors[q.subscriptionId] = cursor
    result.cursor = cursor
    result.matched = S.logCount()
    result.ok = true
  of qoPoll:
    # What changed since this subscription last asked -- WITH the rows.
    # Answering with a count alone left a remote subscriber no option but
    # to re-read the whole database.
    if not cursors.hasKey(q.subscriptionId):
      return Reply(ok: false, err: "no subscription '" & q.subscriptionId &
        "'; subscribe first", schema: result.schema, epoch: result.epoch)
    cursor = cursors[q.subscriptionId]
    result.rows = S.rowsSince(cursor, limit, replyRowBudget)
    result.cursor = min(cursor, uint64(S.logCount())) +
      uint64(result.rows.len)
    result.matched = S.logCount()
    cursors[q.subscriptionId] = result.cursor
    result.ok = true
  of qoPut:
    # Rows FROM a peer, exactly as that peer stored them. Applying one
    # reproduces its operation: a new id adds, a known id supersedes, a
    # tombstone removes.
    if not (prWrite in p.rights):
      return denied(result.schema, result.epoch, p.subject, "write")
    if S.readOnly:
      return Reply(ok: false, schema: result.schema, epoch: result.epoch,
        err: "this node holds no write lease: " & S.writeRefusal())
    o = 0
    incoming = decodeRows(q.payload, o)
    if incoming.len == 0:
      return Reply(ok: false, err: "a put carried no rows",
        schema: result.schema, epoch: result.epoch)
    # A row with NO identity is a client adding one, not a peer
    # replicating: it has no database of its own to allocate from, so this
    # side names the row. A peer's rows always arrive with their own ids
    # and keep them.
    #
    # Each row is applied as it is named, because `nextIdFor` only moves
    # once a row carrying that id is stored -- naming two rows before
    # storing either would give them the same one.
    i = 0
    while int(i) < incoming.len:
      if S.hasIdentity() and
          S.entries.schema.rowIdOf(incoming[int(i)].data) == 0'u64:
        stamped = restampRow(S.entries.schema, incoming[int(i)].data,
          S.nextIdFor(), 0'u64, S.sidecarStore)
        if not stamped.ok:
          return Reply(ok: false, err: stamped.err, schema: result.schema,
            epoch: result.epoch)
        incoming[int(i)].data = stamped.data
      applied = S.applyRows([incoming[int(i)]])
      if not applied.ok:
        return Reply(ok: false, err: applied.err, schema: result.schema,
          epoch: result.epoch)
      result.matched = result.matched + uint32(applied.applied)
      i = i + 1'u32
    committed = commitRemote(S)
    if not committed.ok:
      return Reply(ok: false, err: "rows applied but not saved: " &
        committed.err, schema: result.schema, epoch: result.epoch)
    result.cursor = uint64(S.logCount())
    result.ok = true
  of qoDelete:
    if not (prWrite in p.rights):
      return denied(result.schema, result.epoch, p.subject, "delete")
    if S.readOnly:
      return Reply(ok: false, schema: result.schema, epoch: result.epoch,
        err: "this node holds no write lease: " & S.writeRefusal())
    id = RowId(q.cursor)
    if not S.hasIdentity():
      return Reply(ok: false, schema: result.schema, epoch: result.epoch,
        err: "this database stores rows without identity, so there is no " &
          "id to delete by")
    if not S.delete(id):
      return Reply(ok: false, schema: result.schema, epoch: result.epoch,
        err: "no row with id " & $id & " (or it is already deleted)")
    committed = commitRemote(S)
    if not committed.ok:
      return Reply(ok: false, err: "row removed but not saved: " &
        committed.err, schema: result.schema, epoch: result.epoch)
    result.matched = 1'u32
    result.cursor = uint64(S.logCount())
    result.ok = true
