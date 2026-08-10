## ---------------------------------------------------------------------
## RowId <- stable identity, so a row can be changed and removed
## ---------------------------------------------------------------------
##
## A position is not an identity. `row 7` means "the eighth row currently
## stored", which is a different row after anything is inserted, replaced
## or removed. Every operation beyond appending needs a name for a row that
## does not move, and every peer that wants to say "I changed this one"
## needs to say WHICH one in words the other side also understands.
##
## So each row carries two extra columns, ahead of the caller's own:
##
##   +---------+---------+---------------------------------------------+
##   | __rowId | __flags | the object's own columns, unchanged          |
##   |  8 B    |  8 B    |                                             |
##   +---------+---------+---------------------------------------------+
##
## They are ORDINARY columns. Not a side table, not a hidden header: the
## sealing covers them, a seek addresses them, the wire carries them, and a
## backup cannot lose them separately from the row they belong to.
##
## THE LOG AND THE LIVE VIEW
##
## The entry cluster stays append-only. An update appends a NEW version of
## the same id; a delete appends a version with the tombstone bit and no
## payload worth reading. Nothing is ever overwritten in place.
##
##   stored log                      live view
##   ----------                      ---------
##   id=1 v1  "draft"          ->
##   id=2 v1  "notes"          ->    id=2  "notes"
##   id=1 v2  "final"          ->    id=1  "final"     (v1 superseded)
##   id=3 v1  "temp"           ->
##   id=3 tombstone            ->                      (gone)
##
## `LiveIndex` is that right-hand column: the newest version of each id, in
## the order the ids first appeared. It is rebuilt by one pass over the
## rows when the database opens, which is the same pass that already loads
## them, and maintained incrementally afterwards.
##
## Why the log rather than editing in place: an append is atomic with
## respect to readers, it keeps the hash chain meaningful, and it is what
## lets a peer catch up by asking for "everything after ordinal N" instead
## of re-reading the database. `compact` reclaims the superseded versions
## when their space matters more than their history.

import std/tables

import ../analysis_pragmas
import ./types
import ./mapper
import ./row
import ./sidecar
import ./store

## `rowIdColumn`, `rowFlagsColumn`, `identityColumnCount` and
## `tombstoneFlag` are defined in types.nim, where the codec and the
## configuration can also see them.

type
  LiveIndex* {.role: truthState, metaTags: {tagDb, tagIndex, tagRead,
      tagTypes}.} = object
    ## The newest version of every id, and the order to present them in.
    ##
    ## newest: id -> row position in the log. Present for tombstoned ids
    ##   too, because "this id was deleted" is an answer a peer needs and
    ##   "no such id" is a different one.
    ## order:  ids in first-appearance order, which is the order a caller
    ##   who has never deleted anything expects to iterate.
    ## live:   positions of the non-tombstoned newest versions, in `order`.
    ##   Materialised because every read walks it and recomputing it per
    ##   call would make a scan quadratic.
    ## nodeTag: this database's own 24 bits (see below). Only ids carrying
    ##   it advance the counter -- another node's ids are not ours to
    ##   allocate from.
    ## nextCounter: allocator, one past the largest counter WE ever issued.
    newest*: Table[RowId, uint32]
    order*: seq[RowId]
    live*: seq[uint32]
    nodeTag*: uint64
    nextCounter*: uint64
    tombstones*: uint32
    superseded*: uint32

## ------------------------ ids across machines -----------------------
##
## A counter is unique within one database and useless between two. Both
## desktops would call their first row 1, and a push would then land one
## on top of the other -- silently, because from the receiver's side an
## id it already knows is an UPDATE by definition.
##
## So an id is two fields in one 64-bit word:
##
##    63          40 39                                        0
##   +--------------+------------------------------------------+
##   | node tag     | counter                                  |
##   |  24 bits     |  40 bits                                 |
##   +--------------+------------------------------------------+
##    random, per     sequential, per database
##    database
##
## The tag is minted once when a database is created and never changes, so
## every id it ever issues is distinguishable from every id any other
## database issues. 40 bits is a trillion rows; 24 bits of tag puts two
## specific desktops colliding at about one in sixteen million, and ten of
## them at about one in four hundred thousand.
##
## The alternative -- fully random ids -- needs no tag but gives up the
## ordering that makes a log readable and a counter recoverable. This keeps
## both: the low bits still count up, so the rows a database issued are in
## the order it issued them.

const
  rowIdCounterBits* = 40
  rowIdCounterMask* = (1'u64 shl rowIdCounterBits) - 1'u64
  rowIdNodeMask* = 0xFFFFFF'u64
    ## 24 bits. A tag of zero is legal but only produced by a database made
    ## before tags existed, where every id is its own counter.

proc composeRowId*(nodeTag, counter: uint64): RowId {.role: helper, inline,
    metaTags: {tagAppApi, tagDb, tagSync}.} =
  ## nodeTag/counter: the two halves joined into the id that is stored.
  result = ((nodeTag and rowIdNodeMask) shl rowIdCounterBits) or
    (counter and rowIdCounterMask)

proc nodeTagOf*(id: RowId): uint64 {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagSync}.} =
  ## id: which database issued this row.
  result = (id shr rowIdCounterBits) and rowIdNodeMask

proc counterOf*(id: RowId): uint64 {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagSync}.} =
  ## id: the issuing database's own sequence number for it.
  result = id and rowIdCounterMask

proc hasIdentity*(s: Schema): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s: schema asked whether its rows carry identity. The test itself is
  ## `hasIdentityColumns` in types.nim; this is the name the rest of the
  ## identity layer reads better with.
  result = s.hasIdentityColumns()

proc withIdentity*(s: Schema): Schema {.role: truthBuilder,
    metaTags: {tagAppApi, tagDb, tagTypes}.} =
  ## s: schema gaining the two reserved columns, if it does not have them.
  ##
  ## They go FIRST and they are `colFixed`, so their offsets are constant
  ## and reading an id costs no offset walk. A schema that already carries
  ## them is returned unchanged, which makes this safe to apply to a schema
  ## read back from a file.
  var
    i: int = 0
  if s.hasIdentity():
    return s
  result.typeName = s.typeName
  result.autoCollapse = s.autoCollapse
  result.aliases = s.aliases
  result.slots.add defaultSlot(result.intern(rowIdColumn), skInt)
  result.slots.add defaultSlot(result.intern(rowFlagsColumn), skInt)
  while i < s.slots.len:
    result.slots.add Slot(nameId: result.intern(s.nameOf(s.slots[i].nameId)),
      kind: s.slots[i].kind, column: s.slots[i].column,
      width: s.slots[i].width, onOverflow: s.slots[i].onOverflow)
    i = i + 1

proc withoutIdentity*(s: Schema): Schema {.role: truthBuilder,
    metaTags: {tagAppApi, tagDb, tagTypes}.} =
  ## s: schema with the reserved columns removed, for showing a caller the
  ## fields THEY declared. Used by `geist schema` and by anything comparing
  ## a stored schema against `schemaFor[T]()`.
  var
    i: int = 0
  if not s.hasIdentity():
    return s
  result.typeName = s.typeName
  result.autoCollapse = s.autoCollapse
  result.aliases = s.aliases
  i = identityColumnCount
  while i < s.slots.len:
    result.slots.add Slot(nameId: result.intern(s.nameOf(s.slots[i].nameId)),
      kind: s.slots[i].kind, column: s.slots[i].column,
      width: s.slots[i].width, onOverflow: s.slots[i].onOverflow)
    i = i + 1

## ------------------------- reading identity -------------------------

proc identityOf*(s: Schema, A: openArray[uint8]): tuple[id: RowId,
    flags: uint64] {.role: parser, metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s/A: schema and one stored row, read in ONE offset pass.
  ##
  ## Both halves together, always: resolving the offsets is the whole cost
  ## of the read, and doing it twice to answer two questions about the same
  ## row is what the index build would have paid on every row.
  ##
  ## Zero and zero when the schema has no identity -- which is also the id
  ## no row is ever given, since allocation starts at one.
  var
    offsets: seq[int] = @[]
  if not s.hasIdentity():
    return (0'u64, 0'u64)
  offsets = fieldOffsets(s, A)
  result.id = s.u64At(A, offsets, 0)
  result.flags = s.u64At(A, offsets, 1)

proc rowIdOf*(s: Schema, A: openArray[uint8]): RowId {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s/A: just the id, for a caller that has no use for the flags.
  result = s.identityOf(A).id

proc rowFlagsOf*(s: Schema, A: openArray[uint8]): uint64 {.role: parser,
    inline, metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s/A: just the flags. `isTombstone` is what usually follows.
  result = s.identityOf(A).flags

proc isTombstone*(flags: uint64): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## flags: the `__flags` word. Only bit 0 is consulted.
  result = (flags and tombstoneFlag) != 0'u64

proc tombstoneRow*(s: Schema, id: RowId,
    store: SidecarStore = SidecarStore()): ByteSeq {.role: truthBuilder,
    metaTags: {tagAppApi, tagDb, tagWrite}.} =
  ## s: schema the tombstone is packed against.
  ## id: the row being removed.
  ## store: sidecar; never used, since a tombstone writes no values.
  ##
  ## A removal is an ordinary row: the id, the flag, and every other column
  ## empty. That is what lets it travel, seal, seek and replicate exactly
  ## like the versions it supersedes -- there is no second record type and
  ## no reader that has to know about one.
  var
    W: RowWriter
    i: int = 0
  W = initRowWriter(s, store)
  W.writeU64(id)
  W.writeU64(tombstoneFlag)
  i = identityColumnCount
  while i < s.slots.len:
    W.writeColumn(@[])
    i = i + 1
  result = W.finish()

proc restampRow*(s: Schema, A: openArray[uint8], id: RowId,
    flags: uint64 = 0'u64,
    store: SidecarStore = SidecarStore()): tuple[ok: bool, data: ByteSeq,
    err: string] {.role: truthBuilder,
    metaTags: {tagAppApi, tagDb, tagSync, tagWrite}.} =
  ## s: schema the row is packed against.
  ## A: a complete row whose identity is being replaced.
  ## id/flags: what to put there instead.
  ##
  ## For the one case where a row arrives WITHOUT an identity: a client
  ## adding a row through a daemon has no database of its own and no id
  ## space to allocate from, so the receiver names the row.
  ##
  ## The row is rebuilt rather than patched. Patching would work only while
  ## the two identity columns sit at a constant offset, and with collapsing
  ## on an id of zero is omitted entirely -- so writing a real id would
  ## have to move a bitmap bit and every byte after it.
  ##
  ## A column that took the sidecar escape is REFUSED: its stored bytes are
  ## a reference, and rebuilding would store that reference as if it were a
  ## value. Such a row came from a database that has its own sidecar, which
  ## means it also has its own id, which means it should not be here.
  var
    W: RowWriter
    offsets: seq[int] = @[]
    i: int = 0
  offsets = fieldOffsets(s, A)
  while i < s.slots.len:
    if s.isExternal(A, i):
      return (false, @[], "column '" & s.nameOf(s.slots[i].nameId) &
        "' holds a sidecar reference, so this row cannot be re-identified; " &
        "send it with the id its own database gave it")
    i = i + 1
  W = initRowWriter(s, store)
  W.writeU64(id)
  W.writeU64(flags)
  i = identityColumnCount
  while i < s.slots.len:
    W.writeColumn(s.rawAt(A, offsets, i))
    if W.err.len > 0:
      return (false, @[], W.err)
    i = i + 1
  result = (true, W.finish(), "")

## --------------------------- the live view --------------------------

proc initLiveIndex*(nodeTag: uint64 = 0'u64): LiveIndex {.role: configurator,
    metaTags: {tagDb, tagTypes}.} =
  ## nodeTag: this database's 24 bits, so the index knows which ids are its
  ## own to count from.
  ## The counter starts at one, so a composed id is never zero and zero
  ## stays available as "no row".
  result.newest = initTable[RowId, uint32]()
  result.nodeTag = nodeTag and rowIdNodeMask
  result.nextCounter = 1'u64

proc freshRowId*(S: LiveIndex): RowId {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagWrite}.} =
  ## S: index whose next unused id is composed. Not consumed until a row
  ## carrying it is stored, so asking twice without storing gives the same
  ## answer.
  result = composeRowId(S.nodeTag, S.nextCounter)

proc noteRow*(S: var LiveIndex, id: RowId, flags: uint64, at: uint32) {.
    role: stateController, metaTags: {tagDb, tagWrite}.} =
  ## S: index updated for ONE appended row.
  ## id/flags/at: its identity and its position in the log.
  ##
  ## Incremental, so appending stays O(1) and the index never has to be
  ## rebuilt while a session is open.
  var
    known: bool = false
  if id == 0'u64:
    return
  known = S.newest.hasKey(id)
  if not known:
    S.order.add id
  else:
    S.superseded = S.superseded + 1'u32
  S.newest[id] = at
  # Only OUR ids move OUR allocator. A row that arrived from a peer carries
  # that peer's tag, and counting from it would waste our own space and
  # prove nothing about what we have issued.
  if id.nodeTagOf() == S.nodeTag and id.counterOf() >= S.nextCounter:
    S.nextCounter = id.counterOf() + 1'u64
  if flags.isTombstone():
    S.tombstones = S.tombstones + 1'u32


proc rebuildLive*(S: var LiveIndex, C: ClusterBuild) {.role: truthBuilder,
    metaTags: {tagDb, tagRead}.} =
  ## S: index whose `live` positions are recomputed from `newest`.
  ## C: the cluster those positions address.
  ##
  ## Separated from `noteRow` because the live LIST changes shape whenever
  ## a row is superseded or removed, while the map does not -- an append of
  ## a brand new id only adds to the end.
  var
    i: int = 0
    at: uint32 = 0'u32
  S.live = @[]
  while i < S.order.len:
    at = S.newest.getOrDefault(S.order[i], 0'u32)
    if not C.schema.rowFlagsOf(C.rowBytesAt(at)).isTombstone():
      S.live.add at
    i = i + 1

proc noteAppend*(S: var LiveIndex, C: ClusterBuild, id: RowId, flags: uint64,
    at: uint32) {.role: stateController, metaTags: {tagDb, tagWrite}.} =
  ## S: index updated for ONE row just appended to `C` at position `at`.
  ## C: the cluster it landed in, read only when a rebuild is unavoidable.
  ## id/flags/at: the row's identity and where it went.
  ##
  ## The whole live-view update for an append, in one place, because the
  ## cheap case and the expensive case are easy to confuse:
  ##
  ##   a brand new id      -> it is the newest version of an id nothing has
  ##                          seen, and `order` puts it last, so it belongs
  ##                          at the END of `live`. O(1).
  ##   a known id          -> some existing entry now points at the wrong
  ##                          position, or has to disappear. Rebuild.
  ##   a fresh tombstone   -> recorded, but never visible, so `live` does
  ##                          not change at all.
  ##
  ## Rebuilding unconditionally made storing N rows cost O(N^2), and not by
  ## a constant factor: 10k rows took 8 s and 50k took 210 s, because every
  ## append walked every id decoding its flags. Appends are the common case
  ## in an append-only log, so they are the one that has to be cheap.
  if id == 0'u64:
    return
  var
    fresh: bool = not S.newest.hasKey(id)
  S.noteRow(id, flags, at)
  if fresh:
    if not flags.isTombstone():
      S.live.add at
  else:
    S.rebuildLive(C)

proc liveCount*(s: LiveIndex): uint32 {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s: index whose visible row count is returned.
  result = uint32(s.live.len)

proc positionOf*(s: LiveIndex, id: RowId): int {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## s/id: log position of an id's newest version, or -1 when unknown.
  if not s.newest.hasKey(id):
    return -1
  result = int(s.newest[id])
