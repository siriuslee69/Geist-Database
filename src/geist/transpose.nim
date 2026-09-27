## ---------------------------------------------------------------------
## Transpose <- the same rows, written column first
## ---------------------------------------------------------------------
##
##   name.ge1st.gN     rows, one after another          THE STORE
##   name.getr.gN      columns, one after another       a derived copy
##
## A row-major file answers "give me row 4" with one read and "which rows
## have title = x" by walking every byte of every row, most of which
## belong to columns nobody asked about. Turning the table on its side
## swaps those costs: a scan of one column reads that column and nothing
## else.
##
##   row-major                        transposed
##   ---------                        ----------
##   [id|flags|noteId|title|body]     [id id id ...]
##   [id|flags|noteId|title|body]     [flags flags flags ...]
##   [id|flags|noteId|title|body]     [noteId noteId noteId ...]
##                                    [title title title ...]
##                                    [body body body ...]
##
##   find over title:                 find over title:
##     reads every row                  reads the title region
##
## THIS FILE IS DERIVED, NEVER THE TRUTH. The row-major generation holds
## the metadata, the journal, the key ledger and the id allocator; those
## are excluded from transposition on purpose -- a column store of a
## hash-chained journal would be a chain nobody can walk. So this artifact
## carries the ENTRY rows only, it is rebuilt rather than repaired, and it
## is not part of `artifactSet()`: losing it costs a rebuild, not data.
##
## WHICH ONE IS NEWER is not tracked in a side file. The transposed header
## records the generation it was built from, and the manifest records the
## generation that is live; comparing them is the answer. A tracker file
## would be a second copy of a fact already on disk, and the two would
## eventually disagree.
##
## Layout:
##
##   magic "GETR1" | version | generation | rowCount | headerBytes
##   columnCount | schema
##   directory: (columnCount + 1) x (at, len, dense, width)
##     entry 0        the per-row bitmap prefix, or empty
##     entry 1..n     one per column, in schema order
##   regions
##
## A column is DENSE when every row spends the same number of bytes on it
## (fixed and capped columns of a schema that does not collapse), and its
## region is then `rowCount * width` with no addressing overhead at all.
## Anything else gets `rowCount + 1` offsets in front of its values, the
## same shape the row-major file uses for varying rows.

import std/[os, strutils, tables]

import runePragmas
import ./types
import ./format
import ./row
import ./store
import ./keys
import ./dynamic

const
  transposedMagic* = "GETR1"
  transposedVersion* = 1'u16
  transposedSuffix* = ".getr"
  directoryEntryBytes = 21
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

## ----------------------------- writing ------------------------------

proc columnSpan(s: Schema, A: openArray[uint8], offsets: seq[int],
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

proc writeTransposed*(path: string, C: ClusterBuild,
    generation: uint64): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "db|storageIo|write".} =
  ## path: where the transposed copy is written.
  ## C: the ENTRY cluster, the only one that is ever transposed.
  ## generation: the row-major generation this mirrors, stored in the
  ##   header so staleness is a comparison rather than a guess.
  ##
  ## Written whole and renamed into place by the caller's discipline: this
  ## is a derived file, so a half-written one is rebuilt rather than
  ## recovered. That is the one way it is allowed to be simpler than the
  ## store it mirrors.
  var
    s: Schema = C.schema
    n: int = C.schema.slots.len
    headerBytes: int = C.schema.headerBytesOf()
    regions: seq[ByteSeq] = @[]
    offsetTables: seq[seq[uint32]] = @[]
    dense: seq[bool] = @[]
    headerRegion: ByteSeq = @[]
    body: ByteSeq = @[]
    blob: ByteSeq = @[]
    schemaBytes: ByteSeq = @[]
    at: uint64 = 0'u64
    i: uint32 = 0'u32
    j: int = 0
    rowData: ByteSeq = @[]
    offsets: seq[int] = @[]
    span: tuple[at, len: int] = (0, 0)
  if n == 0:
    return (false, "a transposed file needs a schema")
  for j in 0 ..< n:
    regions.add @[]
    offsetTables.add @[]
    dense.add isDenseColumn(s, j)
    if not dense[j]:
      offsetTables[j].add 0'u32
  while i < C.rowCount:
    rowData = C.rowBytesAt(i)
    if headerBytes > 0:
      headerRegion.addBytes rowData[0 ..< headerBytes]
    offsets = fieldOffsets(s, rowData)
    j = 0
    while j < n:
      span = columnSpan(s, rowData, offsets, j)
      if span.len > 0:
        regions[j].addBytes rowData[span.at ..< span.at + span.len]
      if not dense[j]:
        offsetTables[j].add uint32(regions[j].len)
      j = j + 1
    i = i + 1'u32
  # Header, then the directory, then the regions. The directory can only
  # be written once every region's length is known, so the regions are
  # built first and their offsets computed against a fixed prologue.
  schemaBytes = encodeSchema(s)
  for c in transposedMagic:
    blob.add uint8(c)
  blob.addU16 transposedVersion
  blob.addU64 generation
  blob.addU32 C.rowCount
  blob.addU32 uint32(headerBytes)
  blob.addU32 uint32(n)
  blob.addU32 uint32(schemaBytes.len)
  blob.addBytes schemaBytes
  at = uint64(blob.len + (n + 1) * directoryEntryBytes)
  # Entry 0 is the per-row bitmap prefix; entries 1..n are the columns.
  blob.addU64 at
  blob.addU64 uint64(headerRegion.len)
  blob.add 1'u8
  blob.addU32 uint32(headerBytes)
  at = at + uint64(headerRegion.len)
  j = 0
  while j < n:
    body = @[]
    if not dense[j]:
      for o in offsetTables[j]:
        body.addU32 o
    body.addBytes regions[j]
    blob.addU64 at
    blob.addU64 uint64(body.len)
    blob.add (if dense[j]: 1'u8 else: 0'u8)
    blob.addU32 s.slots[j].width
    at = at + uint64(body.len)
    j = j + 1
  blob.addBytes headerRegion
  j = 0
  while j < n:
    if not dense[j]:
      for o in offsetTables[j]:
        blob.addU32 o
    blob.addBytes regions[j]
    j = j + 1
  try:
    if path.parentDir().len > 0:
      createDir(path.parentDir())
    writeFile(path, blob)
    result = (true, "")
  except CatchableError as exc:
    result = (false, "could not write " & path & ": " & exc.msg)

## ----------------------------- reading ------------------------------

proc openTransposed*(path: string): tuple[ok: bool, t: TransposedFile,
    err: string] {.role: parser,
    tag: "db|read|storageIo".} =
  ## path: a transposed file whose DIRECTORY is read -- not its data.
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
  if not fileExists(path):
    return (false, TransposedFile(), "no transposed file at " & path)
  try:
    size = getFileSize(path)
  except CatchableError as exc:
    return (false, TransposedFile(), exc.msg)
  head = readAt(path, 0'u64, 31)
  if head.len < 31:
    return (false, TransposedFile(), path & " is too short to be a " &
      "transposed file")
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
  var so: int = 0
  result.t.schema = decodeSchema(head, so)
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

proc transposedColumn*(t: TransposedFile, slot: int): seq[ByteSeq] {.
    role: dataFetcher, tag: "db|read|storageIo".} =
  ## t/slot: every value of one column, in row order, in ONE read.
  ##
  ## This is what the whole file is for. A scan reads this region and no
  ## other, so the bytes it touches are proportional to the column rather
  ## than to the table.
  var
    e: ColumnRegion = default(ColumnRegion)
    blob: ByteSeq = @[]
    offsets: seq[uint32] = @[]
    i: uint32 = 0'u32
    base: int = 0
  if slot < 0 or slot >= t.columns.len:
    return @[]
  e = t.columns[slot]
  blob = readAt(t.path, e.at, int(e.len))
  if e.dense:
    while i < t.rowCount:
      base = int(i) * int(e.width)
      if base + int(e.width) > blob.len:
        break
      result.add blob[base ..< base + int(e.width)]
      i = i + 1'u32
    return
  base = int(t.rowCount + 1'u32) * 4
  while i <= t.rowCount:
    if int(i) * 4 + 4 > blob.len:
      return
    offsets.add blob.getU32(int(i) * 4)
    i = i + 1'u32
  i = 0'u32
  while i < t.rowCount:
    if base + int(offsets[int(i) + 1]) > blob.len:
      return
    result.add blob[base + int(offsets[int(i)]) ..<
      base + int(offsets[int(i) + 1])]
    i = i + 1'u32

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
    slot: int = -1
    probe: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
    offsets: seq[int] = @[]
    span: tuple[at, len: int] = (0, 0)
    want: ByteSeq = @[]
    values: seq[ByteSeq] = @[]
    i: int = 0
    pairs = initTable[string, string]()
  slot = t.schema.slotIndex(field)
  if slot < 0:
    return (false, @[], 0'u64,
      "no column '" & field & "' in this database")
  pairs[field] = value
  probe = buildRow(t.schema, pairs)
  if not probe.ok:
    return (false, @[], 0'u64, probe.err)
  offsets = fieldOffsets(t.schema, probe.data)
  span = columnSpan(t.schema, probe.data, offsets, slot)
  if span.len > 0:
    want = probe.data[span.at ..< span.at + span.len]
  values = t.transposedColumn(slot)
  result.read = t.scanBytes(slot)
  while i < values.len:
    if values[i] == want:
      result.rows.add uint32(i)
      if limit > 0 and result.rows.len >= limit:
        break
    i = i + 1
  result.ok = true

## ---------------------------- freshness -----------------------------

proc transposeState*(baseDir: string,
    baseName: string = "main"): TransposeStatus {.role: parser,
    tag: "db|read|status".} =
  ## baseDir/baseName: which of the two artifacts is ahead, and by how far.
  ##
  ## Both numbers come off disk: `live` from the manifest, `built` from
  ## the transposed file's own header. Nothing is remembered between calls,
  ## so there is no third place for the answer to be wrong.
  var
    found: tuple[path: string, generation: uint64] = existingTransposed(
      baseDir, baseName)
  result.live = liveGeneration(baseDir)
  result.path = found.path
  result.built = found.generation
  if found.path.len == 0:
    return (tsAbsent, result.live, 0'u64, "")
  if found.generation == result.live:
    result.state = tsCurrent
  elif found.generation < result.live:
    result.state = tsStale
  else:
    result.state = tsOrphan

proc describeTransposeState*(s: TransposeState, live, built: uint64): string {.
    role: helper, tag: "db|status".} =
  ## s/live/built: one line an operator can act on.
  case s
  of tsAbsent:
    result = "absent (row-major only; `geist transpose` builds it)"
  of tsCurrent:
    result = "current (built from generation " & $built & ")"
  of tsStale:
    result = "STALE: built from generation " & $built & ", live is " &
      $live & " -- searches fall back to the row scan until rebuilt"
  of tsOrphan:
    result = "orphaned: built from generation " & $built &
      ", which is newer than the live " & $live & " -- a save was rolled " &
      "back under it; rebuild"

proc retireTransposed*(baseDir, baseName: string, keep: uint64) {.
    role: actor, tag: "db|lifecycle|storageIo".} =
  ## baseDir/baseName/keep: delete every transposed file except one.
  ##
  ## Generations of the store are retired one at a time because a reader
  ## may still hold the previous one. Nobody reads an old transposed file:
  ## it is derived, and a reader that wants one asks whether it is current
  ## before it reads a byte.
  if not dirExists(baseDir):
    return
  var
    stem: string = baseName & transposedSuffix & ".g"
    keepName: string = baseName & transposedSuffix & generationSuffix(keep)
  for kind, path in walkDir(baseDir):
    if kind != pcFile:
      continue
    var name = path.extractFilename()
    if not name.startsWith(stem) or name == keepName:
      continue
    try:
      removeFile(path)
    except CatchableError:
      discard
