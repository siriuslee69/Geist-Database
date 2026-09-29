## ---------------------------------------------------------------------
## Transposed <- reading the column-first copy (see ./transpose)
## ---------------------------------------------------------------------
##
##   openTransposed(path) -> directory      one read, a few hundred bytes
##   transposedColumn(t, slot)              one column, every row
##   transposedValue / transposedRow        one cell, one whole row
##   transposedFind(t, field, value)        exact match over one column
##
## The file's layout, and why the copy exists at all, are described in
## ./transpose, which writes it. This half only reads, and trusts nothing
## in the file: every offset and length is checked against what is there.

import std/[os, strutils, tables]

import runePragmas
import ./types
import ./format
import ./row
import ./store
import ./keys
import ./dynamic
import ./bytecheck

const
  transposedMagic* = "GETR1"
  transposedVersion* = 1'u16
  transposedSuffix* = ".getr"
  directoryEntryBytes* = 21
    ## at u64 | len u64 | dense u8 | width u32

type
  ColumnRegion* {.role: truthState, tag: "db|storageIo|types".} = object
    ## Where one column lives in the file, and how to address inside it.
    ## `dense` means arithmetic: value i starts at `at + i * width`.
    at*: uint64
    len*: uint64
    dense*: bool
    width*: uint32

  TransposedFile* {.role: truthState, tag: "db|storageIo|types".} = object
    ## The directory of a transposed file -- everything except the data.
    ## Opening one reads this and nothing more, so asking a question about
    ## a 500 MB column store costs a few hundred bytes.
    path*: string
    generation*: uint64
    rowCount*: uint32
    headerBytes*: uint32
    schema*: Schema
    header*: ColumnRegion
    columns*: seq[ColumnRegion]

  TransposeState* {.role: truthState, tag: "db|status|types".} = enum
    ## What the two artifacts have to say about each other.
    ##
    ##   tsAbsent   no transposed file; the store is row-major only
    ##   tsCurrent  built from the generation that is live now
    ##   tsStale    built from an older generation; rows have moved since
    ##   tsOrphan   built from a generation NEWER than the manifest names,
    ##              which means a save was rolled back under it
    tsAbsent, tsCurrent, tsStale, tsOrphan

  TransposeStatus* {.role: truthState, tag: "db|status|types".} = tuple
    ## Where the column copy stands against the live generation.
    ##   state  one of the four above
    ##   live   the generation the manifest names now
    ##   built  the generation the copy was built from (0 = none)
    ##   path   the copy's file
    state: TransposeState
    live: uint64
    built: uint64
    path: string

## ------------------------------- paths ------------------------------

proc transposedPath*(baseDir, baseName: string, n: uint64): string {.
    role: parser, tag: "db|storageIo".} =
  ## baseDir/baseName/n: the transposed artifact of one generation.
  result = baseDir / (baseName & transposedSuffix & generationSuffix(n))

proc liveTransposedPath*(baseDir: string,
    baseName: string = "main"): string {.role: parser,
    tag: "db|read|storageIo".} =
  ## baseDir/baseName: the transposed file matching the live generation.
  ## It may not exist -- that is `tsAbsent`, not an error.
  result = transposedPath(baseDir, baseName, liveGeneration(baseDir))

proc existingTransposed*(baseDir: string,
    baseName: string = "main"): tuple[path: string, generation: uint64] {.
    role: parser, tag: "db|read|storageIo".} =
  ## baseDir/baseName: the newest transposed file actually on disk, at any
  ## generation, or an empty path.
  ##
  ## Needed because the interesting question is usually "is the one I have
  ## still current?", and that cannot be asked of a path that assumes the
  ## answer is yes.
  var
    stem: string = baseName & transposedSuffix & ".g"
    n: uint64 = 0'u64
  if not dirExists(baseDir):
    return ("", 0'u64)
  for kind, path in walkDir(baseDir):
    if kind != pcFile:
      continue
    var name = path.extractFilename()
    if not name.startsWith(stem):
      continue
    try:
      n = parseBiggestUInt(name[stem.len .. ^1]).uint64
    except ValueError:
      continue
    if n >= result.generation:
      result = (path, n)


proc columnSpan*(s: Schema, A: openArray[uint8], offsets: seq[int],
    slot: int): tuple[at, len: int] {.role: parser,
    tag: "codecBoundary|db|read".} =
  ## s/A/offsets/slot: where one column's bytes sit inside one row.
  ##
  ## Derived from the offsets `fieldOffsets` already produced rather than
  ## walked again: the length of a column is a property of its kind and
  ## its own length prefix, so a second walk would be a second chance to
  ## disagree with the first.
  if offsets[slot] < 0:
    return (0, 0)
  if s.slots[slot].column == colVariable:
    return (offsets[slot], varLengthBytes + int(A.getU32(offsets[slot])))
  result = (offsets[slot], int(s.slots[slot].width))

proc isDenseColumn*(s: Schema, slot: int): bool {.role: parser, inline,
    tag: "db|storageIo".} =
  ## s/slot: whether every row spends the same bytes on this column.
  ##
  ## A collapsing schema omits zero values, so even a fixed column stops
  ## being arithmetic there -- the bitmap decides per row whether the
  ## bytes are present at all.
  if s.autoCollapse:
    return false
  result = s.slots[slot].column != colVariable

## ----------------------------- reading ------------------------------

proc readTransposed(path: string): tuple[ok: bool, t: TransposedFile,
    err: string] {.role: parser,
    tag: "db|read|storageIo".} =
  ## path: a transposed file whose DIRECTORY is read -- not its data.
  ## May raise IOError; `openTransposed` turns that into an answer.
  ##
  ## Every length is checked against the file that is actually there. This
  ## is a derived artifact that may have been truncated by a full disk, and
  ## a directory claiming a four-gigabyte column must produce an error
  ## rather than an allocation.
  var
    head: ByteSeq = @[]
    o: int = 0
    schemaLen: int = 0
    n: int = 0
    j: int = 0
    size: int64 = 0
    e: ColumnRegion = default(ColumnRegion)
    so: int = 0
  if not fileExists(path):
    return (false, TransposedFile(), "no transposed file at " & path)
  try:
    size = getFileSize(path)
  except CatchableError as exc:
    return (false, TransposedFile(), exc.msg)
  if size < 31:
    return (false, TransposedFile(), path & " is too short to be a " &
      "transposed file")
  head = readAt(path, 0'u64, 31)
  while o < transposedMagic.len:
    if head[o] != uint8(transposedMagic[o]):
      return (false, TransposedFile(), path & " is not a transposed file")
    o = o + 1
  o = 5
  if head.getU16(o) != transposedVersion:
    return (false, TransposedFile(),
      path & " is a transposed file of version " & $head.getU16(o) &
      "; this build writes version " & $transposedVersion)
  o = o + 2
  result.t.path = path
  result.t.generation = head.getU64(o); o = o + 8
  result.t.rowCount = head.getU32(o); o = o + 4
  result.t.headerBytes = head.getU32(o); o = o + 4
  n = int(head.getU32(o)); o = o + 4
  if n <= 0 or n > 4096:
    return (false, TransposedFile(),
      path & " declares " & $n & " columns, which cannot be right")
  head = readAt(path, uint64(o), 4)
  schemaLen = int(head.getU32(0))
  if schemaLen <= 0 or int64(o) + 4 + int64(schemaLen) > size:
    return (false, TransposedFile(), path & " has a truncated schema")
  head = readAt(path, uint64(o + 4), schemaLen)
  result.t.schema = schemaFrom(head, so, path)
  o = o + 4 + schemaLen
  head = readAt(path, uint64(o), (n + 1) * directoryEntryBytes)
  if head.len < (n + 1) * directoryEntryBytes:
    return (false, TransposedFile(), path & " has a truncated directory")
  so = 0
  while j <= n:
    e = ColumnRegion()
    e.at = head.getU64(so); so = so + 8
    e.len = head.getU64(so); so = so + 8
    e.dense = head[so] != 0'u8; so = so + 1
    e.width = head.getU32(so); so = so + 4
    if e.at + e.len > uint64(size):
      return (false, TransposedFile(),
        path & " points past its own end; rebuild it")
    if j == 0:
      result.t.header = e
    else:
      result.t.columns.add e
    j = j + 1
  if result.t.schema.slots.len != n:
    return (false, TransposedFile(),
      path & " has " & $n & " columns and a schema of " &
      $result.t.schema.slots.len)
  result.ok = true

proc openTransposed*(path: string): tuple[ok: bool, t: TransposedFile,
    err: string] {.role: parser, tag: "db|read|storageIo".} =
  ## path: a transposed file whose DIRECTORY is read -- not its data.
  ##
  ## Every length is checked against the file that is actually there. This
  ## is a derived artifact that may have been truncated by a full disk, so
  ## a short or damaged file is an answer (ok = false, and why), never a
  ## crash: `readAt` and `schemaFrom` raise IOError on what does not fit,
  ## and it is caught here.
  try:
    result = readTransposed(path)
  except IOError as exc:
    result = (false, TransposedFile(), exc.msg)

proc valueSpan*(t: TransposedFile, slot: int,
    i: uint32): tuple[at: uint64, len: int] {.role: parser,
    tag: "db|read".} =
  ## t/slot/i: where one value of one column lives, absolutely.
  ##
  ## A dense column is arithmetic. A varying one costs one extra read of
  ## eight bytes -- its two neighbouring offsets -- rather than the whole
  ## offset table, because gathering one row must not pay for every row.
  var
    e: ColumnRegion = default(ColumnRegion)
    pair: ByteSeq = @[]
    base: uint64 = 0'u64
  if slot < 0 or slot >= t.columns.len or i >= t.rowCount:
    return (0'u64, 0)
  e = t.columns[slot]
  if e.dense:
    return (e.at + uint64(i) * uint64(e.width), int(e.width))
  base = e.at + uint64(t.rowCount + 1'u32) * 4'u64
  pair = readAt(t.path, e.at + uint64(i) * 4'u64, 8)
  if pair.len < 8:
    return (0'u64, 0)
  result.at = base + uint64(pair.getU32(0))
  result.len = int(pair.getU32(4)) - int(pair.getU32(0))

proc transposedValue*(t: TransposedFile, slot: int,
    i: uint32): ByteSeq {.role: dataFetcher,
    tag: "db|read|storageIo".} =
  ## t/slot/i: one column's bytes for one row, exactly as they were stored.
  var
    span: tuple[at: uint64, len: int] = t.valueSpan(slot, i)
  if span.len <= 0:
    return @[]
  result = readAt(t.path, span.at, span.len)

proc denseValues(blob: ByteSeq, rowCount: uint32,
    width: int): seq[ByteSeq] {.role: parser, tag: "db|read".} =
  ## blob/rowCount/width: a dense region -> one value per row, each
  ## `width` bytes. Stops early rather than reading past a short region.
  var
    i: int = 0
  while i < int(rowCount) and (i + 1) * width <= blob.len:
    result.add blob[i * width ..< (i + 1) * width]
    i = i + 1

proc offsetTable(blob: ByteSeq, rowCount: uint32): seq[uint32] {.
    role: parser, tag: "db|read".} =
  ## blob/rowCount: the `rowCount + 1` offsets in front of a varying
  ## region, or fewer when the region is cut short.
  var
    i: int = 0
  while i <= int(rowCount) and i * 4 + 4 <= blob.len:
    result.add blob.getU32(i * 4)
    i = i + 1

proc varyingValues(blob: ByteSeq, rowCount: uint32): seq[ByteSeq] {.
    role: parser, tag: "db|read".} =
  ## blob/rowCount: a varying region -> one value per row, cut where its
  ## offsets say. Stops at the first value that would run past the region.
  ##
  ##   | off 0 | off 1 | ... | off n | values ... |
  ##   \____ (rowCount + 1) x u32 ___/ ^ base
  var
    offsets: seq[uint32] = offsetTable(blob, rowCount)
    base: int = int(rowCount + 1'u32) * 4
    i: int = 0
  if offsets.len < int(rowCount) + 1:
    return @[]
  while i < int(rowCount) and base + int(offsets[i + 1]) <= blob.len:
    result.add blob[base + int(offsets[i]) ..< base + int(offsets[i + 1])]
    i = i + 1

proc transposedColumn*(t: TransposedFile, slot: int): seq[ByteSeq] {.
    role: dataFetcher, tag: "db|read|storageIo".} =
  ## t/slot: every value of one column, in row order, in ONE read.
  ##
  ## This is what the whole file is for. A scan reads this region and no
  ## other, so the bytes it touches are proportional to the column rather
  ## than to the table.
  var
    e: ColumnRegion = default(ColumnRegion)
  if slot < 0 or slot >= t.columns.len:
    return @[]
  e = t.columns[slot]
  if e.dense:
    result = denseValues(readAt(t.path, e.at, int(e.len)), t.rowCount,
      int(e.width))
  else:
    result = varyingValues(readAt(t.path, e.at, int(e.len)), t.rowCount)

proc transposedRow*(t: TransposedFile, i: uint32): Row {.role: dataFetcher,
    tag: "db|read|storageIo".} =
  ## t/i: one row, rebuilt byte for byte as the row-major file holds it.
  ##
  ## A row is the header prefix followed by each column in schema order,
  ## and that is exactly what was taken apart, so putting it back needs no
  ## knowledge of any column's meaning. The result decodes with the
  ## ordinary `fromRow[T]`: a transposed store still hands back objects.
  ##
  ## This is the expensive direction, and honestly so -- one read per
  ## column instead of one read per row. It is why the row-major file
  ## stays the store and this one stays an index.
  var
    j: int = 0
  if i >= t.rowCount:
    return Row()
  if t.headerBytes > 0:
    result.data.addBytes readAt(t.path,
      t.header.at + uint64(i) * uint64(t.headerBytes), int(t.headerBytes))
  while j < t.columns.len:
    result.data.addBytes t.transposedValue(j, i)
    j = j + 1

proc scanBytes*(t: TransposedFile, slot: int): uint64 {.role: parser, inline,
    tag: "db|read|status".} =
  ## t/slot: how many bytes a scan of this column will read.
  ##
  ## The number worth quoting when someone asks whether the second copy
  ## paid for itself: compare it with the size of the row-major file.
  if slot < 0 or slot >= t.columns.len:
    return 0'u64
  result = t.columns[slot].len

proc wantedBytes(t: TransposedFile, field, value: string,
    slot: int): tuple[ok: bool, want: ByteSeq, err: string] {.role: parser,
    tag: "db|read".} =
  ## t/field/value/slot: the exact bytes `value` has in that column --
  ## built as a one-field row and cut out again, so text and numbers are
  ## encoded exactly the way the stored rows encoded them.
  var
    pairs: Table[string, string] = {field: value}.toTable
    probe: tuple[ok: bool, data: ByteSeq, err: string] =
      buildRow(t.schema, pairs)
    span: tuple[at, len: int] = (0, 0)
  if not probe.ok:
    return (false, @[], probe.err)
  span = columnSpan(t.schema, probe.data,
    fieldOffsets(t.schema, probe.data), slot)
  result = (true, probe.data[span.at ..< span.at + span.len], "")

proc transposedFind*(t: TransposedFile, field, value: string,
    limit: int = 0): tuple[ok: bool, rows: seq[uint32], read: uint64,
    err: string] {.role: parser,
    tag: "appApi|db|read|storageIo".} =
  ## t/field/value: the rows whose column renders exactly `value`.
  ## limit: stop after this many, 0 for all.
  ##
  ## The probe is encoded by the REAL encoder -- `buildRow` on this
  ## schema -- and then compared as bytes. Re-implementing "what does this
  ## value look like once stored" here would be a second encoder, and the
  ## day the two disagreed the search would quietly answer nothing.
  ##
  ## `read` is what it cost, so a caller can prove the saving rather than
  ## assume it.
  var
    slot: int = t.schema.slotIndex(field)
    wanted: tuple[ok: bool, want: ByteSeq, err: string] = (false, @[], "")
    values: seq[ByteSeq] = @[]
    i: int = 0
  if slot < 0:
    return (false, @[], 0'u64, "no column '" & field & "' in this database")
  wanted = t.wantedBytes(field, value, slot)
  if not wanted.ok:
    return (false, @[], 0'u64, wanted.err)
  values = t.transposedColumn(slot)
  result.read = t.scanBytes(slot)
  while i < values.len and (limit <= 0 or result.rows.len < limit):
    if values[i] == wanted.want:
      result.rows.add uint32(i)
    i = i + 1
  result.ok = true
