## ---------------------------------------------------------------------
## Replicate <- a store's log handed to a peer, and a peer's rows applied
## ---------------------------------------------------------------------
##
## rowsSince / applyRows are the two halves of every sync; subscribe /
## poll follow changes by name. Rows carry their own identity, so
## applying one reproduces the sender's operation exactly.
##
## Part of the Session; see ./session for how the parts fit.

import std/[times]

import runePragmas
import ./types
import ./rowid
import ./row
import ./store
import ./sessioncore

## --------------------------- replication ----------------------------
##
## What one desktop sends another is ROWS OF THE LOG, and the cursor is a
## log position. That works because the log only ever grows and because a
## row carries its own identity:
##
##   follower has 12 rows  ->  "give me from 12"  ->  rows 12..N
##   each row says which id it is and whether it is a tombstone, so
##   applying it is the same operation whatever it turns out to be
##
## No separate change protocol, no per-event encoding, and a follower that
## was offline for a week catches up with the same call it uses when it was
## offline for a second.
##
## The one thing a position cannot survive is the log being REWRITTEN.
## `logEpoch` is what says that happened; a follower whose epoch differs
## has to take the whole thing again.

proc rowsSince*(s: Session, cursor: uint64, limit: int = 256,
    byteBudget: int = 0): seq[Row] {.role: parser,
    tag: "appApi|db|read|sync".} =
  ## s: session being read from.
  ## cursor: the follower's log position -- how many rows it already has.
  ## limit: maximum rows per call.
  ## byteBudget: stop once the rows total this many bytes, so an answer
  ##   stays inside one datagram and the expensive package path is not
  ##   needed for the ordinary case. Zero means no budget.
  ##
  ## The FIRST row is always included, however large it is. A budget that
  ## could return nothing would stall a follower on a single big row for
  ## ever, and the transport can package one oversized answer.
  ##
  ## Includes superseded versions and tombstones on purpose: they are what
  ## the follower missed, and replaying them in order reproduces exactly
  ## the state this session is in.
  var
    i: uint32 = 0'u32
    used: int = 0
  i = uint32(min(cursor, uint64(s.entries.rowCount)))
  while i < s.entries.rowCount and result.len < limit:
    if byteBudget > 0 and result.len > 0 and used >= byteBudget:
      break
    result.add s.entries.rowAt(i)
    used = used + result[^1].data.len
    i = i + 1'u32

proc changeOf(S: Session, ident: tuple[id: RowId, flags: uint64],
    data: openArray[uint8]): tuple[same: bool, kind: ChangeKind] {.
    role: parser, tag: "db|sync".} =
  ## S/ident/data: what storing this row from a peer would be.
  ##
  ##   no id at all                       ckAdded
  ##   id unknown, not a tombstone        ckAdded
  ##   id unknown, a tombstone            ckDeleted
  ##   id known, these exact bytes        same -- nothing to do
  ##   id known, a tombstone              ckDeleted
  ##   id known, other bytes              ckUpdated
  var
    at: int = (if ident.id == 0'u64: -1 else: S.live.positionOf(ident.id))
  if at >= 0 and S.entries.rowBytesAt(uint32(at)) == @data:
    return (true, ckAdded)
  if ident.id != 0'u64 and ident.flags.isTombstone():
    return (false, ckDeleted)
  result = (false, (if at >= 0: ckUpdated else: ckAdded))

proc applyRow*(S: var Session, r: Row): tuple[ok: bool, id: RowId,
    err: string] {.role: dataWriter, tag: "appApi|db|sync|write".} =
  ## S: session receiving one row FROM A PEER.
  ## r: the row exactly as the peer stored it, identity included.
  ##
  ## Appending it reproduces the peer's own operation: a new id adds, a
  ## known id supersedes, a tombstone removes. That is the whole apply
  ## logic, and it is the same three lines for all three cases -- which is
  ## the payoff for keeping identity inside the row.
  ##
  ## A row already present at the same version is skipped, so replaying an
  ## overlapping range is harmless. Peers retry; an apply that was not
  ## idempotent would turn a retry into a duplicate.
  var
    shaped: tuple[ok: bool, err: string] = (false, "")
    ident: tuple[id: RowId, flags: uint64] = (default(RowId), 0'u64)
    change: tuple[same: bool, kind: ChangeKind] = (false, ckAdded)
  if S.readOnly:
    return (false, 0'u64, S.writeRefusal())
  shaped = validateRow(S.entries.schema, r.data)
  if not shaped.ok:
    return (false, 0'u64, "row from peer does not fit the schema: " &
      shaped.err)
  ident = S.entries.schema.identityOf(r.data)
  if S.hasIdentity() and ident.id == 0'u64:
    return (false, 0'u64, "row from peer carries no identity")
  change = S.changeOf(ident, r.data)
  if change.same:
    # Already have exactly this version.
    return (true, ident.id, "")
  discard S.appendPacked(r.data, ident.id, ident.flags, change.kind)
  result = (true, ident.id, "")

proc applyRows*(S: var Session, R: openArray[Row]): tuple[ok: bool,
    applied: int, err: string] {.role: orchestrator,
    tag: "appApi|db|sync|write".} =
  ## S/R: a batch from a peer, applied IN ORDER and flushed once.
  ##
  ## Order matters and is the sender's: two versions of one row must not
  ## swap places on the way in, or the older one would win.
  var
    i: int = 0
    one: tuple[ok: bool, id: RowId, err: string] = (false, default(RowId), "")
    written: tuple[ok: bool, err: string] = (false, "")
    before: uint32 = 0'u32
  while i < R.len:
    before = S.logCount()
    one = S.applyRow(R[i])
    if not one.ok:
      return (false, result.applied, one.err)
    # Counted only when the log grew: a row this store already held (an
    # echo of its own push, a retried batch) is skipped and is not news.
    if S.logCount() > before:
      result.applied = result.applied + 1
    i = i + 1
  written = S.maybeFlush()
  if not written.ok:
    return (false, result.applied, written.err)
  result.ok = true

## --------------------------- change following -----------------------

proc subscribe*(S: var Session, id: string, replay: bool = false,
    fromOrdinal: uint64 = 0'u64): Subscription {.role: actor,
    tag: "appApi|db|sync|write", discardable.} =
  ## S: session whose changefeed gains a cursor.
  ## id: stable subscription name, reused across reconnects.
  ## replay: true rewinds to `fromOrdinal`; the default starts at the
  ##   current head, so a new subscriber sees what happens next rather
  ##   than being flooded with everything that already happened.
  ## fromOrdinal: explicit rewind point, only consulted when replaying.
  var
    i: int = 0
  result.id = id
  result.cursor = if replay: fromOrdinal else: S.changeOrdinal
  result.createdAt = uint64(getTime().toUnix())
  while i < S.subscriptions.len:
    if S.subscriptions[i].id == id:
      S.subscriptions[i] = result
      return
    i = i + 1
  S.subscriptions.add result

proc subscriptionAt(S: Session, id: string): int {.role: parser,
    tag: "db|read|sync".} =
  ## S/id: the position of that subscription, or -1.
  var
    i: int = 0
  while i < S.subscriptions.len:
    if S.subscriptions[i].id == id:
      return i
    i = i + 1
  result = -1

proc changesAfter(S: Session, cursor: uint64,
    limit: int): seq[ChangeEvent] {.role: parser, tag: "db|read|sync".} =
  ## S/cursor/limit: at most `limit` changes newer than `cursor`, oldest
  ## first.
  var
    j: int = 0
  while j < S.changes.len and result.len < limit:
    if S.changes[j].ordinal > cursor:
      result.add S.changes[j]
    j = j + 1

proc poll*(S: var Session, id: string,
    limit: int = 64): seq[ChangeEvent] {.role: parser,
    tag: "appApi|db|read|sync".} =
  ## S: session to drain.
  ## id: subscription whose cursor advances past the returned events.
  ## limit: maximum events per call.
  var
    at: int = S.subscriptionAt(id)
  if at < 0:
    raise newException(ValueError, "no such subscription: " & id)
  result = S.changesAfter(S.subscriptions[at].cursor, limit)
  if result.len > 0:
    S.subscriptions[at].cursor = result[^1].ordinal

proc unsubscribe*(S: var Session, id: string) {.role: actor,
    tag: "appApi|db|sync|write".} =
  ## S/id: session and subscription removed.
  var
    at: int = S.subscriptionAt(id)
  if at >= 0:
    S.subscriptions.delete(at)

