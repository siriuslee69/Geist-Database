## ---------------------------------------------------------------------
## Row <- ONE row format. Storage policy is per column, not per table.
## ---------------------------------------------------------------------
##
##   +------------+------------+--------------------------------------+
##   | null bmp   | capped bmp | columns, in declaration order        |
##   | if collapse| if capped  |   colFixed    -> width bytes         |
##   |            |            |   colCapped   -> width bytes, inline |
##   |            |            |                  or a 23 B reference |
##   |            |            |   colVariable -> u32 len | payload   |
##   +------------+------------+--------------------------------------+
##
## Both bitmaps are conditional on the SCHEMA, so a table pays for a
## feature only if it declares one: no collapsing, no null bitmap; no
## capped column, no capped bitmap.
##
## WHY THIS REPLACED THE TWO PROFILES
##
## `CellLayout` made storage a property of the TABLE -- every column got
## the same treatment, and a schema with one big text field and four
## counters had to choose which of them to serve badly. Moving the choice
## to the column removes the compromise and makes the old layouts fall out
## as special cases:
##
##   clInline   = every column colFixed, no collapse   -> still dense
##   clTruncate = colFixed with onOverflow = opTruncate
##   clPacked   = every column colVariable + collapse
##   clRegion   = the pointer-slot layout in mapper.nim, kept for files
##                already written in that format
##
## ADDRESSING
##
## A schema of only `colFixed` columns with collapsing off is DENSE: row i
## sits at `i * rowBytes`, no indirection, memory-mappable. Anything else
## makes rows vary and the cluster carries a `rowCount+1` offset table.
## `Schema.isDense` is the single place that decides, and `rowBytes` of 0
## is how a reader is told.
##
## The bitmap and a zero length prefix are mildly redundant on a
## `colVariable` column -- both can say "empty". Kept anyway: making the
## bitmap mean different things for different column kinds would cost more
## in reasoning than the bit costs in bytes.

import ../analysis_pragmas
import ./types
import ./format
import ./sidecar

const
  varLengthBytes* = 4
    ## u32 length prefix on a `colVariable` value.
  cappedLengthBytes* = 2
    ## u16 length prefix on an INLINE `colCapped` value. Two bytes because
    ## the value is bounded by the column width, which is a u32 but in
    ## practice far below 64 KiB; a capped column wider than that should
    ## be `colVariable` instead.

## ------------------------------ bitmaps -----------------------------

proc bitSet(A: var ByteSeq, base, slot: int) {.role: helper, inline,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## A/base/slot: buffer, bitmap start and column index.
  A[base + (slot shr 3)] = A[base + (slot shr 3)] or
    (1'u8 shl uint8(slot and 7))

proc bitGet(A: openArray[uint8], base, slot: int): bool {.role: parser,
    inline, metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## A/base/slot: buffer, bitmap start and column index.
  result = (A[base + (slot shr 3)] and (1'u8 shl uint8(slot and 7))) != 0'u8

proc nullBase*(s: Schema): int {.role: helper, inline,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s: schema whose null bitmap starts at byte zero when present.
  result = 0

proc cappedBase*(s: Schema): int {.role: helper, inline,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s: schema whose capped bitmap follows the null bitmap when present.
  if s.autoCollapse:
    result = nullBitmapBytes(s.slots.len)

proc isOmitted*(s: Schema, A: openArray[uint8], slot: int): bool {.
    role: parser, inline, metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/slot: schema, row and column. False when the schema does not
  ## collapse, because then nothing is ever omitted.
  if not s.autoCollapse:
    return false
  result = bitGet(A, s.nullBase(), slot)

proc isExternal*(s: Schema, A: openArray[uint8], slot: int): bool {.
    role: parser, inline, metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/slot: schema, row and column. True when a capped column took the
  ## sidecar escape and holds a reference rather than a value.
  if not s.hasCapped():
    return false
  result = bitGet(A, s.cappedBase(), slot)

## ------------------------------ writing -----------------------------

type
  RowWriter* {.role: truthState, metaTags: {tagCodecBoundary, tagDb,
      tagTypes}.} = object
    ## Accumulates one row. The bitmaps are only final once every column
    ## has declared itself, so the body is staged separately and joined at
    ## the end.
    schema*: Schema
    head*: ByteSeq
    body*: ByteSeq
    cursor*: int
    omitted*: uint32
    externalised*: uint32
    truncated*: uint32
    ## truncatedIn: the columns that were cut, by name. A count alone says
    ## data was lost without saying where, and truncation leaves no trace
    ## in the stored row -- so if the name is not reported here it cannot
    ## be recovered afterwards. Only appended to when a cut happens, so the
    ## ordinary path allocates nothing.
    truncatedIn*: seq[FieldName]
    store*: SidecarStore
    err*: string

proc initRowWriter*(s: Schema,
    store: SidecarStore = SidecarStore()): RowWriter {.role: configurator,
    metaTags: {tagCodecBoundary, tagDb}.} =
  ## s: schema being written.
  ## store: sidecar store, required only if the schema has capped columns.
  result.schema = s
  result.head = newSeq[uint8](s.headerBytesOf())
  result.store = store

proc padTo(W: var RowWriter, n: int) {.role: helper, inline,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## W/n: writer and the byte count this column must occupy.
  var
    i: int = 0
  while i < n:
    W.body.add 0'u8
    i = i + 1

proc writeColumn*(W: var RowWriter, A: openArray[uint8]) {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagDb, tagSidecar, tagWrite}.} =
  ## W: writer positioned at its next column.
  ## A: the value's bytes, already encoded for its `SlotKind`.
  ##
  ## Every storage decision for the column happens here, once, so the
  ## object mappers above never branch on policy.
  var
    sl: Slot
    n: int = 0
    payload: ByteSeq = @[]
    r: Ref
    encoded: ByteSeq = @[]
    i: int = 0
    allEmpty: bool = false
  if W.cursor >= W.schema.slots.len:
    W.err = "more values than columns in " & W.schema.typeName
    return
  sl = W.schema.slots[W.cursor]
  n = A.len

  # Collapse first: an omitted column occupies no bytes at all, whatever
  # its kind. Zero and empty are the same thing in Nim, so this is
  # lossless rather than a policy decision.
  if W.schema.autoCollapse:
    allEmpty = true
    i = 0
    while i < n:
      if A[i] != 0'u8:
        allEmpty = false
        break
      i = i + 1
    if n == 0 or allEmpty:
      W.head.bitSet(W.schema.nullBase(), W.cursor)
      W.omitted = W.omitted + 1'u32
      W.cursor = W.cursor + 1
      return

  case sl.column
  of colVariable:
    W.body.addU32(uint32(n))
    W.body.addBytes(A)
  of colFixed:
    if uint32(n) > sl.width:
      case sl.onOverflow
      of opError:
        W.err = "column '" & W.schema.nameOf(sl.nameId) & "' is " &
          $sl.width & " B and cannot hold " & $n & " B; widen it, make " &
          "it colCapped or colVariable, or set onOverflow = opTruncate"
        return
      of opTruncate:
        W.body.addBytes(A.toOpenArray(0, int(sl.width) - 1))
        W.truncated = W.truncated + 1'u32
        W.truncatedIn.add W.schema.nameOf(sl.nameId)
        W.cursor = W.cursor + 1
        return
    W.body.addBytes(A)
    W.padTo(int(sl.width) - n)
  of colCapped:
    if uint32(n) + uint32(cappedLengthBytes) <= sl.width:
      W.body.addU16(uint16(n))
      W.body.addBytes(A)
      W.padTo(int(sl.width) - cappedLengthBytes - n)
    else:
      # Too wide to sit inline: the value moves to the sidecar and its
      # reference occupies the same column. The bit is what tells a reader
      # which of the two it is looking at.
      payload = @A
      r = W.store.putSidecar(payload)
      encoded = encodeRef(r)
      if uint32(encoded.len) > sl.width:
        W.err = "column '" & W.schema.nameOf(sl.nameId) & "' is " &
          $sl.width & " B, too narrow for a " & $encoded.len &
          " B reference; a colCapped column needs at least " &
          $minCappedWidth & " B"
        return
      W.head.bitSet(W.schema.cappedBase(), W.cursor)
      W.externalised = W.externalised + 1'u32
      W.body.addBytes(encoded)
      W.padTo(int(sl.width) - encoded.len)
  W.cursor = W.cursor + 1

proc writeU64*(W: var RowWriter, v: uint64) {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## W/v: writer and one integer-shaped value, encoded little-endian to
  ## the column's declared width.
  var
    sl: Slot
    buf: ByteSeq = @[]
    i: int = 0
    w: int = 0
  if W.cursor >= W.schema.slots.len:
    W.err = "more values than columns in " & W.schema.typeName
    return
  sl = W.schema.slots[W.cursor]
  w = if sl.column == colVariable: 8 else: int(sl.width)
  if w > 8:
    w = 8
  buf = newSeq[uint8](w)
  while i < w:
    buf[i] = uint8((v shr (i * 8)) and 0xFF'u64)
    i = i + 1
  W.writeColumn(buf)

proc writeText*(W: var RowWriter, s: string) {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## W/s: writer and one text value.
  var
    t: ByteSeq = @[]
    i: int = 0
  t = newSeq[uint8](s.len)
  while i < s.len:
    t[i] = uint8(s[i])
    i = i + 1
  W.writeColumn(t)

proc finish*(W: RowWriter): ByteSeq {.role: truthBuilder,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## W: writer whose bitmaps and body are joined into the stored row.
  result = W.head
  result.addBytes(W.body)

## ------------------------------ reading -----------------------------

proc fieldOffsets*(s: Schema, A: openArray[uint8]): seq[int] {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A: schema and one stored row.
  ## Returns each column's byte offset, or -1 when it was omitted. One
  ## pass answers every later field access, so a random read does not walk
  ## the row per field.
  var
    o: int = 0
    i: int = 0
    n: int = 0
  result = newSeq[int](s.slots.len)
  o = s.headerBytesOf()
  while i < s.slots.len:
    if s.isOmitted(A, i):
      result[i] = -1
    else:
      result[i] = o
      case s.slots[i].column
      of colVariable:
        n = int(A.getU32(o))
        o = o + varLengthBytes + n
      of colFixed, colCapped:
        o = o + int(s.slots[i].width)
    i = i + 1

proc validateRow*(s: Schema, A: openArray[uint8]): tuple[ok: bool,
    err: string] {.role: sanitizer,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A: schema and a row from somewhere UNTRUSTED -- a command line, a
  ## file, a peer.
  ##
  ## Walks the row exactly as `fieldOffsets` does, but checks every step
  ## against the buffer's length instead of assuming it fits. Without this,
  ## a length prefix claiming four gigabytes turns a bad packet into an
  ## IndexDefect somewhere far away from the code that accepted it.
  ##
  ## Trailing bytes are an error too. A row that decodes and then has
  ## leftovers is not the row the sender meant, whatever it decodes to.
  var
    o: int = 0
    i: int = 0
    n: int = 0
  o = s.headerBytesOf()
  if A.len < o:
    return (false, "row is " & $A.len & " B, shorter than the " & $o &
      " B of bitmaps this schema declares")
  while i < s.slots.len:
    if not s.isOmitted(A, i):
      case s.slots[i].column
      of colVariable:
        if o + varLengthBytes > A.len:
          return (false, "column '" & s.nameOf(s.slots[i].nameId) &
            "' has no room for its length prefix")
        n = int(A.getU32(o))
        o = o + varLengthBytes + n
      of colFixed, colCapped:
        o = o + int(s.slots[i].width)
      if o > A.len:
        return (false, "column '" & s.nameOf(s.slots[i].nameId) &
          "' claims " & $(o - A.len) & " B past the end of a " & $A.len &
          " B row")
    i = i + 1
  if o != A.len:
    return (false, "row has " & $(A.len - o) &
      " trailing bytes that no column accounts for")
  result = (true, "")

proc rawAt*(s: Schema, A: openArray[uint8], offsets: seq[int],
    slot: int): ByteSeq {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/offsets/slot: the column's bytes AS STORED. A capped column that
  ## externalised yields its reference, not the payload -- follow it with
  ## `resolve`.
  var
    o: int = 0
    n: int = 0
    i: int = 0
  if offsets[slot] < 0:
    return @[]
  o = offsets[slot]
  case s.slots[slot].column
  of colVariable:
    n = int(A.getU32(o))
    o = o + varLengthBytes
  of colFixed:
    n = int(s.slots[slot].width)
  of colCapped:
    if s.isExternal(A, slot):
      n = int(s.slots[slot].width)
    else:
      n = int(A.getU16(o))
      o = o + cappedLengthBytes
  result = newSeq[uint8](n)
  while i < n:
    result[i] = A[o + i]
    i = i + 1

proc resolve*(s: Schema, A: openArray[uint8], offsets: seq[int], slot: int,
    store: SidecarStore): ByteSeq {.role: dataFetcher,
    metaTags: {tagCodecBoundary, tagDb, tagRead, tagSidecar}.} =
  ## s/A/offsets/slot/store: the column's VALUE, following the sidecar
  ## when the capped bit is set. Raises when a payload is missing or fails
  ## verification, because returning short data would corrupt the caller.
  var
    fetched: tuple[ok: bool, data: ByteSeq, err: string]
  result = s.rawAt(A, offsets, slot)
  if not s.isExternal(A, slot):
    return
  fetched = store.getSidecar(decodeRef(result))
  if not fetched.ok:
    raise newException(IOError, fetched.err)
  result = fetched.data

proc u64At*(s: Schema, A: openArray[uint8], offsets: seq[int],
    slot: int): uint64 {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/offsets/slot: an integer-shaped column, widened from whatever
  ## width it declared. An omitted column reads back as zero, which is its
  ## Nim value anyway.
  var
    raw: ByteSeq = @[]
    i: int = 0
  if offsets[slot] < 0:
    return 0'u64
  raw = s.rawAt(A, offsets, slot)
  while i < raw.len and i < 8:
    result = result or (uint64(raw[i]) shl (i * 8))
    i = i + 1

proc textAt*(s: Schema, A: openArray[uint8], offsets: seq[int], slot: int,
    store: SidecarStore = SidecarStore()): string {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/offsets/slot/store: a text column, sidecar followed if needed.
  var
    raw: ByteSeq = @[]
    i: int = 0
  raw = s.resolve(A, offsets, slot, store)
  result = newString(raw.len)
  while i < raw.len:
    result[i] = char(raw[i])
    i = i + 1

## --------------------------- object mapping -------------------------
##
## fieldPairs unrolls lexically, so a nested level cannot reuse the outer
## loop's identifiers. The `...B` twins alternate identifier sets so
## recursion works at any depth. Same constraint as mapper.nim.

proc packB[T: object](x: T, W: var RowWriter)

proc pack*[T: object](x: T, W: var RowWriter) {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## x: object written in declaration order.
  ## W: writer holding the schema and its storage policy.
  for fa, va in fieldPairs(x):
    when va is Ref:
      W.writeColumn(encodeRef(va))
    elif va is seq[uint8]:
      W.writeColumn(va)
    elif va is string:
      W.writeText(va)
    elif va is enum:
      W.writeU64(uint64(ord(va)))
    elif va is SomeFloat:
      W.writeU64(cast[uint64](float64(va)))
    elif va is bool:
      W.writeU64(uint64(ord(va)))
    elif va is SomeSignedInt:
      W.writeU64(cast[uint64](int64(va)))
    elif va is object:
      packB(va, W)
    else:
      W.writeU64(uint64(va))

proc packB[T: object](x: T, W: var RowWriter) {.role: dataWriter,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## Alternating twin of `pack`; see the note above.
  for fb, vb in fieldPairs(x):
    when vb is Ref:
      W.writeColumn(encodeRef(vb))
    elif vb is seq[uint8]:
      W.writeColumn(vb)
    elif vb is string:
      W.writeText(vb)
    elif vb is enum:
      W.writeU64(uint64(ord(vb)))
    elif vb is SomeFloat:
      W.writeU64(cast[uint64](float64(vb)))
    elif vb is bool:
      W.writeU64(uint64(ord(vb)))
    elif vb is SomeSignedInt:
      W.writeU64(cast[uint64](int64(vb)))
    elif vb is object:
      pack(vb, W)
    else:
      W.writeU64(uint64(vb))

type
  RowReader* {.role: truthState, metaTags: {tagCodecBoundary, tagDb,
      tagTypes}.} = object
    ## The read-side counterpart of `RowWriter`: everything an unpack pass
    ## needs, so the twins below take one parameter instead of five.
    schema*: Schema
    data*: ByteSeq
    offsets*: seq[int]
    store*: SidecarStore

proc initRowReader*(s: Schema, A: openArray[uint8],
    store: SidecarStore = SidecarStore()): RowReader {.role: configurator,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s/A/store: schema, stored row and the sidecar it may reference.
  result.schema = s
  result.data = @A
  result.offsets = fieldOffsets(s, A)
  result.store = store

proc unpackB[T: object](x: var T, R: RowReader, i: var int)

proc unpack*[T: object](x: var T, R: RowReader, i: var int) {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## x: object reconstructed in declaration order.
  ## R: reader over one row.
  ## i: column cursor shared across nesting levels.
  for fa, va in fieldPairs(x):
    when va is Ref:
      va = decodeRef(R.schema.rawAt(R.data, R.offsets, i)); i = i + 1
    elif va is seq[uint8]:
      va = R.schema.resolve(R.data, R.offsets, i, R.store); i = i + 1
    elif va is string:
      va = R.schema.textAt(R.data, R.offsets, i, R.store); i = i + 1
    elif va is enum:
      va = type(va)(R.schema.u64At(R.data, R.offsets, i)); i = i + 1
    elif va is SomeFloat:
      va = type(va)(cast[float64](R.schema.u64At(R.data, R.offsets, i)))
      i = i + 1
    elif va is bool:
      va = R.schema.u64At(R.data, R.offsets, i) != 0'u64; i = i + 1
    elif va is SomeSignedInt:
      va = type(va)(cast[int64](R.schema.u64At(R.data, R.offsets, i)))
      i = i + 1
    elif va is object:
      unpackB(va, R, i)
    else:
      va = type(va)(R.schema.u64At(R.data, R.offsets, i)); i = i + 1

proc unpackB[T: object](x: var T, R: RowReader, i: var int) {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## Alternating twin of `unpack`; see the note above.
  for fb, vb in fieldPairs(x):
    when vb is Ref:
      vb = decodeRef(R.schema.rawAt(R.data, R.offsets, i)); i = i + 1
    elif vb is seq[uint8]:
      vb = R.schema.resolve(R.data, R.offsets, i, R.store); i = i + 1
    elif vb is string:
      vb = R.schema.textAt(R.data, R.offsets, i, R.store); i = i + 1
    elif vb is enum:
      vb = type(vb)(R.schema.u64At(R.data, R.offsets, i)); i = i + 1
    elif vb is SomeFloat:
      vb = type(vb)(cast[float64](R.schema.u64At(R.data, R.offsets, i)))
      i = i + 1
    elif vb is bool:
      vb = R.schema.u64At(R.data, R.offsets, i) != 0'u64; i = i + 1
    elif vb is SomeSignedInt:
      vb = type(vb)(cast[int64](R.schema.u64At(R.data, R.offsets, i)))
      i = i + 1
    elif vb is object:
      unpack(vb, R, i)
    else:
      vb = type(vb)(R.schema.u64At(R.data, R.offsets, i)); i = i + 1

proc reservedColumns*(s: Schema): int {.role: parser, inline,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## s: schema whose leading columns belong to Geist rather than to the
  ## caller's object -- the index at which T's own first field sits.
  ## Two when the schema carries row identity, zero otherwise.
  result = if s.hasIdentityColumns(): identityColumnCount else: 0

proc toRowBytes*[T: object](x: T, s: Schema,
    store: SidecarStore = SidecarStore(), id: uint64 = 0'u64,
    flags: uint64 = 0'u64): tuple[data: ByteSeq,
    truncated: uint32, externalised: uint32, omitted: uint32,
    truncatedIn: seq[FieldName], err: string] {.role: orchestrator,
    metaTags: {tagAppApi, tagCodecBoundary, tagDb, tagWrite}.} =
  ## x: object to store.
  ## s: schema carrying the per-column storage policy.
  ## store: sidecar, needed only when a capped column overflows.
  ## id/flags: the reserved identity columns, written ahead of the object's
  ##   own fields when the schema carries them and ignored when it does
  ##   not. Passing them here rather than patching the row afterwards is
  ##   deliberate: with collapsing on, a zero written after the fact would
  ##   have to move a bitmap bit and every following byte.
  ##
  ## An error is RETURNED rather than raised, because `opError` is an
  ## ordinary outcome of a caller's data and not a defect.
  ##
  ## The counters are returned for the same reason. `opTruncate` is opt-in,
  ## so cutting a value is not an error -- but a cut that nothing reports
  ## is indistinguishable from data that was always short, and the stored
  ## row keeps no evidence either way. Callers accumulate these; see
  ## `ClusterBuild.truncated` and `Session.storageStats`.
  var
    W: RowWriter
  W = initRowWriter(s, store)
  if s.reservedColumns() == 2:
    W.writeU64(id)
    W.writeU64(flags)
  pack(x, W)
  if W.err.len > 0:
    return (@[], 0'u32, 0'u32, 0'u32, @[], W.err)
  result.data = W.finish()
  result.truncated = W.truncated
  result.externalised = W.externalised
  result.omitted = W.omitted
  result.truncatedIn = W.truncatedIn

proc fromRowBytes*[T: object](A: openArray[uint8], s: Schema,
    store: SidecarStore = SidecarStore()): T {.role: orchestrator,
    metaTags: {tagAppApi, tagCodecBoundary, tagDb, tagRead}.} =
  ## A/s/store: one stored row, its schema and the sidecar it may follow.
  ##
  ## The cursor starts past the reserved columns, so T sees exactly the
  ## fields it declared and identity stays invisible to the object model.
  var
    R: RowReader
    i: int = 0
  R = initRowReader(s, A, store)
  i = s.reservedColumns()
  unpack(result, R, i)

## ---------------------------- statistics ----------------------------

proc rowStats*(s: Schema, A: openArray[uint8]): tuple[present: int,
    omitted: int, external: int, bytes: int] {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead, tagStatus}.} =
  ## s/A: schema and row. What the bitmaps saved and what escaped to the
  ## sidecar -- the two numbers that say whether a schema's column policy
  ## suits the data it is actually holding.
  var
    i: int = 0
  while i < s.slots.len:
    if s.isOmitted(A, i):
      result.omitted = result.omitted + 1
    else:
      result.present = result.present + 1
      if s.isExternal(A, i):
        result.external = result.external + 1
    i = i + 1
  result.bytes = A.len
