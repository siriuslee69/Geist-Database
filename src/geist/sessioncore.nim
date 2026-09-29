## ---------------------------------------------------------------------
## Session core <- put / set / delete, read the live view, save, close
## ---------------------------------------------------------------------
##
## Opening, and the Session type itself, are ./sessionopen, re-exported
## here. See ./session for how all the parts fit.

import std/[os, strutils, times]


import runePragmas
import ./types
import ./format
import ./lease
import ./rowid
import ./row
import ./store
import ./config
import ./backup
import ./keys
import ./crypto/batch
import ./crypto/column
import ./transpose
import ./sessionopen

export sessionopen

proc save*(S: var Session): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "appApi|db|orchestrator|storageIo|write".}
  ## Forward-declared: the write policy below has to be reachable from
  ## `put`, and it decides by calling this.

proc flushDue*(s: Session): bool {.role: parser,
    tag: "appApi|db|status".} =
  ## s: session asked whether its configuration wants a flush right now.
  ## Pure, so a caller driving `wmInterval` from its own event loop can ask
  ## without writing anything.
  case s.config.writeMode
  of wmManual, wmVolatile:
    result = false
  of wmOnChange:
    result = s.dirty
  of wmInterval:
    result = s.dirty and
      uint64(getTime().toUnix()) - s.lastSaveAt >=
        uint64(s.config.writeIntervalSeconds)

proc maybeFlush*(S: var Session): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|db|storageIo|write".} =
  ## S: session flushed if and only if `writeMode` says so.
  ##
  ## Called after every mutation, and safe to call from a timer as well:
  ## nothing here runs in the background, so an idle `wmInterval` database
  ## flushes on its next write rather than on the second it came due. A
  ## caller that needs the wall-clock guarantee calls this on a tick.
  if not S.flushDue():
    return (true, "")
  result = S.save()

proc writeRefusal*(s: Session): string {.role: helper,
    tag: "appApi|db|status".} =
  ## s: read-only session explaining ITSELF, because "read-only" alone does
  ## not tell an operator whether to close another window or fix their code.
  if s.leaseHolder.len > 0:
    result = "session is read-only: " & s.leaseHolder
  else:
    result = "session is read-only"

proc appendPacked*(S: var Session, A: openArray[uint8], id: RowId,
    flags: uint64, kind: ChangeKind): uint32 {.role: dataWriter,
    tag: "db|store|write".} =
  ## S: session receiving one already-packed row.
  ## A: the row bytes.
  ## id/flags: its identity, for the live view and the changefeed.
  ## kind: what this append MEANS to a follower.
  ##
  ## Every write in the session funnels through here -- typed, dynamic,
  ## update, delete and rows arriving from a peer -- so the log, the live
  ## view and the changefeed can never be updated by three paths that
  ## disagree.
  if S.readOnly:
    raise newException(IOError, S.writeRefusal())
  result = S.entries.addRowBytes(A)
  if id != 0'u64:
    S.live.noteAppend(S.entries, id, flags, result)
  S.dirty = true
  S.backupState.noteWrite()
  S.noteChange(crEntry, result, kind, id)

proc packFor[T: object](S: var Session, x: T, id: RowId,
    flags: uint64): ByteSeq {.role: encryptor,
    tag: "db|store|write".} =
  ## S/x/id/flags: one object packed against the entry schema, with its
  ## identity columns filled in. Raises on a column policy violation, which
  ## is the caller's data being wrong rather than a defect here.
  var
    built: BuiltRow = default(BuiltRow)
    i: int = 0
  built = toRowBytes(x, S.entries.schema, S.sidecarStore, id, flags)
  if built.err.len > 0:
    raise newException(ValueError, built.err)
  S.entries.truncated = S.entries.truncated + built.truncated
  S.entries.externalised = S.entries.externalised + built.externalised
  while i < built.truncatedIn.len:
    if not (built.truncatedIn[i] in S.entries.truncatedIn):
      S.entries.truncatedIn.add built.truncatedIn[i]
    i = i + 1
  result = built.data

proc nextRowId(S: var Session): RowId {.role: actor,
    tag: "db|write".} =
  ## S: session allocating the next never-used identity. Zero when the
  ## database stores no identity, which is what tells the writers to skip
  ## the live view entirely.
  if not S.hasIdentity():
    return 0'u64
  result = S.live.freshRowId()

proc put*[T: object](S: var Session, x: T): RowId {.role: orchestrator,
    tag: "appApi|db|orchestrator|store|write",
    discardable.} =
  ## S: open session.
  ## x: object appended, then flushed if `writeMode` calls for it. A failed
  ##   automatic flush raises: the row is in memory either way, but a caller
  ##   who asked for durability per write must not be told it succeeded.
  ##
  ## Returns the row's ID, not its position. A position stops meaning the
  ## same row as soon as anything is replaced or removed; an id does not,
  ## which is what makes it the thing worth handing back.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  result = S.nextRowId()
  discard S.appendPacked(S.packFor(x, result, 0'u64), result, 0'u64, ckAdded)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc put*[T: object](S: var Session, A: openArray[T]): seq[RowId] {.
    role: orchestrator, tag: "appApi|db|orchestrator|store|write", discardable.} =
  ## S: open session.
  ## A: objects appended in order, then flushed ONCE. Under `wmOnChange`
  ##   that is the difference between one whole-file rewrite and `A.len` of
  ##   them; the batch is still atomic from a reader's point of view,
  ##   because a reader only ever sees a committed generation.
  var
    i: int = 0
    id: RowId = 0'u64
    written: tuple[ok: bool, err: string] = (false, "")
  while i < A.len:
    id = S.nextRowId()
    discard S.appendPacked(S.packFor(A[i], id, 0'u64), id, 0'u64, ckAdded)
    result.add id
    i = i + 1
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc set*[T: object](S: var Session, id: RowId, x: T): bool {.
    role: orchestrator, tag: "appApi|db|orchestrator|store|write", discardable.} =
  ## S: open session.
  ## id: the row being replaced.
  ## x: its new contents.
  ##
  ## Appends a NEW version rather than editing the stored one. Returns
  ## false for an id that was never allocated -- a typo must not silently
  ## create a row, because the caller believes it is editing one.
  ##
  ## Replacing a deleted row revives it: the tombstone is just the previous
  ## version, and a later version supersedes it like any other.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  S.requireIdentity()
  if S.live.positionOf(id) < 0:
    return false
  discard S.appendPacked(S.packFor(x, id, 0'u64), id, 0'u64, ckUpdated)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)
  result = true

proc delete*(S: var Session, id: RowId): bool {.role: orchestrator,
    tag: "appApi|db|orchestrator|store|write",
    discardable.} =
  ## S: open session.
  ## id: the row being removed.
  ##
  ## Appends a TOMBSTONE: an empty row carrying the id and the removal bit.
  ## The rows before it stay in the log, so a follower that is behind can
  ## still be told what happened, and `compact` is what actually reclaims
  ## the space.
  ##
  ## Returns false for an unknown id, and for one already deleted -- both
  ## mean "there was nothing here to remove", and appending a second
  ## tombstone would only grow the log.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    at: int = -1
  S.requireIdentity()
  at = S.live.positionOf(id)
  if at < 0:
    return false
  if S.entries.schema.rowFlagsOf(S.entries.rowBytesAt(uint32(at))).isTombstone():
    return false
  discard S.appendPacked(
    tombstoneRow(S.entries.schema, id, S.sidecarStore), id,
    tombstoneFlag, ckDeleted)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)
  result = true

proc putRow*(S: var Session, r: Row): RowId {.role: dataWriter,
    tag: "appApi|db|store|write", discardable.} =
  ## S: open session.
  ## r: a row already built against `S.entries.schema` -- the path a
  ## schema-driven tool uses when it has no compile-time object type, and
  ## the path a row arriving from a peer takes.
  ##
  ## The row's OWN identity columns are honoured: a peer sending version 3
  ## of row 12 stores it as version 3 of row 12, not as a new row. A row
  ## whose id is zero on a database that has identity is given the next
  ## free one, which is what a dynamic `geist put` produces.
  ##
  ## Dense and varying schemas are both accepted: a row is self-contained,
  ## so the only thing it must agree with is the schema it was packed
  ## against. `buildRow` in dynamic.nim produces exactly that.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    ident: tuple[id: RowId, flags: uint64] = (default(RowId), 0'u64)
    shaped: tuple[ok: bool, err: string] = (false, "")
    kind: ChangeKind = ckAdded
  if S.readOnly:
    raise newException(IOError, S.writeRefusal())
  # Check the SHAPE before reading anything out of it. This is the boundary
  # a hand-built row and a row from a peer both cross.
  shaped = validateRow(S.entries.schema, r.data)
  if not shaped.ok:
    raise newException(ValueError,
      "this row does not fit the schema: " & shaped.err)
  ident = S.entries.schema.identityOf(r.data)
  if S.hasIdentity() and ident.id == 0'u64:
    raise newException(ValueError,
      "this database gives every row an identity, but the row offered " &
      "carries id 0. Build it with buildRow(schema, values, store, id) " &
      "using the id from nextIdFor, or use put[T].")
  if ident.id != 0'u64 and S.live.positionOf(ident.id) >= 0:
    kind = if ident.flags.isTombstone(): ckDeleted else: ckUpdated
  elif ident.flags.isTombstone():
    kind = ckDeleted
  result = ident.id
  discard S.appendPacked(r.data, ident.id, ident.flags, kind)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc nextIdFor*(S: var Session): RowId {.role: actor,
    tag: "appApi|db|write".} =
  ## S: session handing out the id a schema-driven caller should stamp into
  ## the row it is about to build. Not consumed until that row is stored,
  ## so asking twice without storing gives the same answer.
  result = S.nextRowId()

proc compact*(S: var Session): tuple[ok: bool, removed: uint32,
    err: string] {.role: orchestrator, tag: "appApi|db|orchestrator|storageIo|write".} =
  ## S: session whose log is rewritten to hold only what is visible.
  ##
  ##   before  id1 v1 | id2 v1 | id1 v2 | id3 v1 | id3 tombstone
  ##   after   id2 v1 | id1 v2
  ##
  ## Ids and their contents survive; superseded versions and tombstones do
  ## not. That is the trade: the space comes back, and a follower that had
  ## not caught up can no longer be told what it missed row by row -- it
  ## has to take the whole cluster again.
  ##
  ## The allocator does NOT go backwards, even though the largest stored id
  ## may just have been removed. See the watermark note above.
  var
    fresh: ClusterBuild = default(ClusterBuild)
    i: int = 0
    keep: RowId = 0'u64
    before: uint32 = 0'u32
  if S.readOnly:
    return (false, 0'u32, S.writeRefusal())
  if not S.hasIdentity():
    return (false, 0'u32,
      "compaction needs row identity: without it every row is live and " &
      "there is nothing superseded to reclaim")
  before = S.entries.rowCount
  keep = S.live.nextCounter
  fresh = initClusterBuild(crEntry, cmAppend, S.entries.schema,
    S.sidecarStore, S.entries.schemaId, S.config.chainHash,
    S.config.treeHash)
  while i < S.live.live.len:
    fresh.addRowBytes(S.entries.rowBytesAt(S.live.live[i]))
    i = i + 1
  S.entries = fresh
  S.indexLive()
  if S.live.nextCounter < keep:
    S.live.nextCounter = keep
  # Positions now mean different rows. Anyone following by position has to
  # be told, and this is the only thing that tells them.
  S.logEpoch = S.logEpoch + 1'u64
  S.dirty = true
  result.removed = before - S.entries.rowCount
  result.ok = true

proc storageStats*(s: Session): StorageStats {.role: parser,
    tag: "appApi|db|read|status".} =
  ## s: session reporting what its column policy cost.
  ##
  ## Read this after a bulk load. A non-zero `truncated` means values were
  ## cut to fit a `colFixed` column carrying `opTruncate` -- legal, asked
  ## for, and invisible in the stored rows, so this is where it surfaces.
  ## `truncatedIn` names the columns responsible.
  result.rows = s.entries.rowCount
  result.truncated = s.entries.truncated + s.meta.truncated +
    s.journal.truncated
  result.externalised = s.entries.externalised + s.meta.externalised +
    s.journal.externalised
  result.truncatedIn = s.entries.truncatedIn

## ------------------------- reading the live view --------------------
##
## Two numbers, and they answer different questions:
##
##   entryCount   how many rows a CALLER has        <- the live view
##   logCount     how many rows are STORED          <- the append log
##
## They are equal until the first update or delete. After that the log
## keeps the superseded versions -- which is what a follower catching up
## needs -- and `compact` is what makes them equal again.

proc entryCount*(s: Session): uint32 {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## s: session whose VISIBLE row count is returned: current versions,
  ## tombstones excluded.
  if not s.hasIdentity():
    return s.entries.rowCount
  result = s.live.liveCount()

proc logCount*(s: Session): uint32 {.role: parser, inline,
    tag: "appApi|db|read|status".} =
  ## s: session whose STORED row count is returned, superseded versions
  ## and tombstones included. The number `compact` reduces.
  result = s.entries.rowCount

proc livePosition*(s: Session, i: uint32): uint32 {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: the i-th visible row resolved to its position in the log.
  ## Identity-free databases pass positions straight through, because there
  ## the log IS the view.
  if not s.hasIdentity():
    return i
  if int(i) >= s.live.live.len:
    raise newException(IndexDefect,
      "row " & $i & " is out of range for " & $s.live.live.len & " rows")
  result = s.live.live[int(i)]

proc rowIds*(s: Session): seq[RowId] {.role: parser,
    tag: "appApi|db|read".} =
  ## s: the ids of every visible row, in view order -- what a caller
  ## iterates when it intends to `set` or `delete` afterwards.
  var
    i: int = 0
  if not s.hasIdentity():
    return @[]
  while i < s.live.order.len:
    if s.live.positionOf(s.live.order[i]) >= 0 and
        not s.entries.schema.rowFlagsOf(
          s.entries.rowBytesAt(uint32(s.live.positionOf(s.live.order[i])))
        ).isTombstone():
      result.add s.live.order[i]
    i = i + 1

proc get*[T: object](s: Session, i: uint32): T {.role: parser,
    tag: "appApi|db|read".} =
  ## s: session to read from.
  ## i: index into the VISIBLE rows, not into the log. Superseded versions
  ##   and tombstones are not addressable this way -- `get(0)` is the first
  ##   row a caller would say it has.
  result = objectAt[T](s.entries, s.livePosition(i))

proc rawRowAt*(s: Session, i: uint32): Row {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: one row of the LOG, by log position, exactly as stored. For
  ## replication and inspection: `get` is what an application wants.
  result = s.entries.rowAt(i)

proc byId*[T: object](s: Session, id: RowId): tuple[found: bool, value: T] {.
    role: parser, tag: "appApi|db|read".} =
  ## s/id: the newest version of one row.
  ## `found` is false for an id that never existed AND for one that was
  ## deleted: both mean the caller has nothing to show.
  var
    at: int = -1
  if not s.hasIdentity():
    return (false, default(T))
  at = s.live.positionOf(id)
  if at < 0:
    return (false, default(T))
  if s.entries.schema.rowFlagsOf(
      s.entries.rowBytesAt(uint32(at))).isTombstone():
    return (false, default(T))
  result = (true, objectAt[T](s.entries, uint32(at)))

proc idAt*(s: Session, i: uint32): RowId {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: the id of the i-th visible row, so a caller that found something
  ## by reading can name it when changing it.
  if not s.hasIdentity():
    return 0'u64
  result = s.entries.schema.rowIdOf(
    s.entries.rowBytesAt(s.livePosition(i)))

proc find*[T: object](s: Session, field, value: string): seq[T] {.
    role: parser, tag: "appApi|db|read".} =
  ## s: session to search.
  ## field: object field name.
  ## value: exact text match.
  ##
  ## Visible rows only: a search that returned superseded versions would
  ## hand back text the caller already replaced.
  var
    slot: int = -1
    i: uint32 = 0'u32
    at: uint32 = 0'u32
    n: uint32 = 0'u32
    raw: ByteSeq = @[]
  slot = s.entries.schema.slotIndex(field)
  if slot < 0:
    raise newException(ValueError, "no such field in schema: " & field)
  # Compare the field in place: resolving offsets and reading one column
  # avoids materialising an object per candidate row.
  n = s.entryCount()
  while i < n:
    at = s.livePosition(i)
    raw = s.entries.rowBytesAt(at)
    if s.entries.schema.textAt(raw, fieldOffsets(s.entries.schema, raw), slot,
        s.sidecarStore) == value:
      result.add objectAt[T](s.entries, at)
    i = i + 1

proc findIds*(s: Session, field, value: string): seq[RowId] {.role: parser,
    tag: "appApi|db|read".} =
  ## s/field/value: the same search, returning IDS instead of objects --
  ## the call to make when the next step is `set` or `delete`.
  var
    slot: int = -1
    i: uint32 = 0'u32
    at: uint32 = 0'u32
    n: uint32 = 0'u32
    raw: ByteSeq = @[]
  s.requireIdentity()
  slot = s.entries.schema.slotIndex(field)
  if slot < 0:
    raise newException(ValueError, "no such field in schema: " & field)
  n = s.entryCount()
  while i < n:
    at = s.livePosition(i)
    raw = s.entries.rowBytesAt(at)
    if s.entries.schema.textAt(raw, fieldOffsets(s.entries.schema, raw), slot,
        s.sidecarStore) == value:
      result.add s.entries.schema.rowIdOf(raw)
    i = i + 1

proc publishGeneration(S: var Session, next: uint64,
    staged: tuple[ok: bool, err: string]): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "db|keyLifecycle|orchestrator|storageIo|write".} =
  ## S: session whose live generation is being replaced.
  ## next: the generation already written to disk under its own name.
  ## staged: how the writing went. A failure is passed straight through
  ##   here rather than checked by every caller, so the cleanup of a
  ##   half-written generation lives in ONE place.
  ##
  ## The second half of every publish, whatever produced the bytes -- a
  ## save, or a restore from a backup slot:
  ##
  ##   verify -> commit the manifest -> retire N-1 -> become N+1
  ##
  ## Nothing before the commit is visible to a reader, so any failure up to
  ## that point throws the staged generation away and leaves the live one
  ## exactly as it was.
  var
    step: tuple[ok: bool, err: string] = (false, "")
  if not staged.ok:
    discard retireGeneration(S.baseDir, S.baseName, next)
    return staged
  # Verify BEFORE publishing. A generation that cannot be read back is
  # thrown away here, while the live one is still whatever it was.
  step = verifyGeneration(S.baseDir, S.baseName, next, S.encrypted)
  if step.ok:
    step = commitManifest(S.baseDir, next)
  if not step.ok:
    discard retireGeneration(S.baseDir, S.baseName, next)
    return step
  # Published. From here the session IS generation N+1, and N-1 is no
  # longer anyone's fallback -- N is.
  discard retireGeneration(S.baseDir, S.baseName, S.generation - 1'u64)
  S.generation = next
  # Publishing is proof of life: a writer that saves regularly can never
  # look abandoned to a process wondering whether to break the lease.
  S.writeLease.refreshLease()
  result = (true, "")

proc transposeDue(S: Session): bool {.role: parser,
    tag: "db|status".} =
  ## S: whether this save should rebuild the column copy.
  ##
  ## `tmInterval` measures from the copy's own modification time rather
  ## than from a counter on the session. A counter would restart every
  ## time the process did, and the file already knows when it was written.
  var
    found: tuple[path: string, generation: uint64] = ("", 0'u64)
    age: int64 = 0
  case S.config.transpose
  of tmNone, tmManual:
    return false
  of tmOnSave:
    return true
  of tmInterval:
    found = existingTransposed(S.baseDir, S.baseName)
    if found.path.len == 0:
      return true
    try:
      age = getTime().toUnix() -
        getLastModificationTime(found.path).toUnix()
    except CatchableError:
      return true
    result = age >= int64(S.config.transposeEverySeconds)

proc writeTransposedNow*(S: Session,
    generation: uint64): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "db|storageIo|write".} =
  ## S/generation: build the column copy for one generation and drop the
  ## copies of every other. Old ones are not kept: nobody reads a stale
  ## column file, because a reader asks whether it is current first.
  result = writeTransposed(transposedPath(S.baseDir, S.baseName, generation),
    S.entries, generation)
  if result.ok:
    retireTransposed(S.baseDir, S.baseName, generation)
proc save*(S: var Session): tuple[ok: bool, err: string] =
  ## S: session published as a NEW generation, then rotated if the backup
  ## policy triggers. Backup takes the whole artifact set.
  ##
  ## An EXPLICIT save always writes, whatever `writeMode` says -- including
  ## `wmVolatile`. The mode governs what happens on its own; a caller who
  ## asks in so many words is answered.
  ##
  ##   write .gN+1  ->  fsync  ->  verify  ->  rename current  ->  drop .gN-1
  ##   ^^^^^^^^^^^                             ^^^^^^^^^^^^^^
  ##   invisible to readers, so a crash                the ONLY step that
  ##   here loses nothing but the new rows             changes what a
  ##                                                   reader sees
  ##
  ## Nothing is ever written over the live file. A reader that opened
  ## generation N keeps reading a complete N while N+1 is being built, and a
  ## crash at any point leaves N exactly as it was.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    br: BackupResult = default(BackupResult)
    onDisk: ClusterBuild = default(ClusterBuild)
    metaDisk: ClusterBuild = default(ClusterBuild)
    journalDisk: ClusterBuild = default(ClusterBuild)
    keyRef: KeyId = 0'u64
    next: uint64 = 0'u64
    staging: Generation = default(Generation)
  if S.readOnly:
    return (false, S.writeRefusal())
  next = S.generation + 1'u64
  staging = generationPaths(S.baseDir, S.baseName, next)
  # The allocator's position travels with the data, so a reopened database
  # never hands out an id that a peer has already seen retired.
  S.stampMetaCounters()
  # Seal COPIES: the live session keeps plaintext rows so a caller can
  # keep reading after save() without a decrypt round trip.
  onDisk = S.entries
  metaDisk = S.meta
  journalDisk = S.journal
  if S.encrypted:
    keyRef = if S.keySet.records.len > 0: S.keySet.records[0].keyId else: 1'u64
    if onDisk.varyingRows():
      # Variable rows have no column-range geometry, so the whole row is
      # the unit. See crypto/column.nim.
      sealPacked(S.keySet.master, S.ledger, onDisk.rows, onDisk.rowOffsets,
        onDisk.rowCount, S.baseName, geistFormatVersion, S.config.cipher,
        S.config.mac, keyRef, S.config.treeHash)
    elif S.ledger.groups.len > 0:
      sealCluster(S.keySet.master, S.ledger, onDisk.schema, onDisk.rows,
        onDisk.rowCount, S.baseName, geistFormatVersion,
        S.config.cipher, S.config.mac, keyRef, S.config.treeHash)
    # Meta and journal carry `Record`, whose text and payload columns make
    # its rows vary -- so they take the packed path, exactly like an entry
    # cluster with a text column. A column group is only a byte range when
    # every row has the same shape.
    if S.config.sealMeta and S.metaLedger.groups.len > 0:
      sealPacked(S.keySet.master, S.metaLedger, metaDisk.rows,
        metaDisk.rowOffsets, metaDisk.rowCount, S.metaLedger.databaseId,
        geistFormatVersion, S.config.cipher, S.config.mac, keyRef,
        S.config.treeHash)
    if S.config.sealJournal and S.journalLedger.groups.len > 0:
      sealPacked(S.keySet.master, S.journalLedger, journalDisk.rows,
        journalDisk.rowOffsets, journalDisk.rowCount,
        S.journalLedger.databaseId, geistFormatVersion, S.config.cipher,
        S.config.mac, keyRef, S.config.treeHash)
  written = writeGeistFile(staging.dataPath,
    @[metaDisk, journalDisk, onDisk], next)
  if written.ok and S.encrypted:
    written = writeKeyFile(staging.keyPath, S.password, S.keySet)
    if written.ok:
      written = writeLedgerFile(staging.ledgerPath,
        @[S.ledger, S.metaLedger, S.journalLedger])
  written = S.publishGeneration(next, written)
  if not written.ok:
    return written
  br = runBackup(S.artifactSet(), S.backupStems(), S.backupPolicy,
    S.backupState)
  if br.err.len > 0:
    return (false, br.err)
  S.dirty = false
  S.lastSaveAt = uint64(getTime().toUnix())
  # The column copy is written AFTER the generation is published, and its
  # failure does not fail the save: the rows are on disk either way, and a
  # save reported as failed would send a caller looking for lost data
  # rather than for a full disk. A copy that did not get written is stale,
  # which is a state the freshness check already has a name for.
  if S.transposeDue():
    discard S.writeTransposedNow(S.generation)
  result = (true, "")

proc checkpoint*(S: var Session, message: string = "checkpoint"): uint32 {.
    role: actor, tag: "appApi|db|stateController|sync|write", discardable.} =
  ## S: session whose journal receives a hash-chained checkpoint row.
  ## message: human-readable reason.
  var
    r: Record = default(Record)
    written: tuple[ok: bool, err: string] = (false, "")
  if not S.config.keepHistory:
    raise newException(ValueError,
      S.config.name & " configuration disables history")
  r.kind = rkCheckpoint
  r.at = uint64(getTime().toUnix())
  r.label = message
  r.parentHash = S.journal.chainHash
  result = S.journal.addRow(r)
  S.dirty = true
  S.noteChange(crJournal, result)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc close*(S: var Session) {.role: actor,
    tag: "appApi|db|lifecycle|stateController|storageIo".} =
  ## S: session persisted if dirty, then cleared from memory.
  ##
  ## `wmVolatile` DISCARDS instead. That is the whole meaning of the mode:
  ## a database that exists only while the process does. A caller who wants
  ## the rows kept calls `save` before closing, and gets them.
  ##
  ## The write lease is released LAST and unconditionally: a save that fails
  ## must still let the next process in, or one bad write locks the database
  ## until somebody deletes a file by hand.
  var
    written: tuple[ok: bool, err: string] = (true, "")
  try:
    if S.dirty and not S.readOnly and S.config.writeMode != wmVolatile:
      written = S.save()
    if not written.ok:
      raise newException(IOError, written.err)
  finally:
    S.writeLease.releaseLease()
  S.entries = ClusterBuild()
  S.meta = ClusterBuild()
  S.journal = ClusterBuild()
  S.keySet = KeySet()

proc restoreSlot*(S: var Session, slot: int): tuple[ok: bool,
    err: string] {.role: orchestrator, tag: "appApi|backup|db|orchestrator|storageIo|write".} =
  ## S: session whose database is replaced by one of its backup slots.
  ## slot: 1 is the most recent copy.
  ##
  ## A restore publishes the backed-up bytes as a NEW generation, through
  ## exactly the protocol a save uses: write, verify, then rename the
  ## manifest. So a restore that fails half way leaves the current database
  ## untouched, and a reader mid-read keeps reading a complete file.
  ##
  ##   .b2 (the bytes)  ->  .gN+1  ->  verify  ->  manifest  ->  live
  ##
  ## The session must be REOPENED afterwards: the rows in memory are the
  ## ones just replaced.
  var
    stems: seq[string] = @[]
    src: seq[string] = @[]
    next: uint64 = 0'u64
    staging: Generation = default(Generation)
    dst: seq[string] = @[]
    i: int = 0
    step: tuple[ok: bool, err: string] = (false, "")
  if S.readOnly:
    return (false, S.writeRefusal())
  stems = S.backupStems()
  src = restorePaths(stems, slot)
  while i < src.len:
    if not fileExists(src[i]):
      return (false, "cannot restore: missing " & src[i])
    i = i + 1
  next = S.generation + 1'u64
  staging = generationPaths(S.baseDir, S.baseName, next)
  dst = @[staging.dataPath]
  if S.encrypted:
    dst.add staging.keyPath
    dst.add staging.ledgerPath
  if dst.len != src.len:
    return (false, "backup slot " & $slot & " has " & $src.len &
      " artifacts but this database needs " & $dst.len)
  try:
    i = 0
    while i < src.len:
      copyFile(src[i], dst[i])
      i = i + 1
    # The copied file still declares the generation it was written under.
    step = stampGeneration(staging.dataPath, next)
  except CatchableError as exc:
    step = (false, exc.msg)
  step = S.publishGeneration(next, step)
  if not step.ok:
    return step
  S.dirty = false
  result = (true, "")

