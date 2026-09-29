## ---------------------------------------------------------------------
## Seek <- reading part of a database without loading the whole cluster
## ---------------------------------------------------------------------
##
##   seekRow(path, i)          one row      -> 1 index read + 1 row read
##   seekColumn(path, slot)    one column   -> 1 index read + N row reads
##   seekRange(path, a, b)     a row window -> 1 index read + 1 bulk read
##
## Rows are fixed width, so row `i` lives at `at + schemaBytes + i*rowBytes`
## and reaching it is arithmetic, not a scan. That addressability is the
## entire reason variable-length bytes were moved out of the row.
##
## `Session` deliberately does NOT use these: it loads clusters whole,
## because an open session is a working set. These are for the other cases
## -- a tool inspecting a database it does not own, a daemon answering one
## question, a process whose database does not fit in RAM.
##
## Every proc here opens the file, reads, and closes. Nothing is cached and
## nothing is locked, so a seek is safe against a file another process is
## appending to: the worst case is reading an index one generation old.

import std/[os, strutils]

import runePragmas
import ./types
import ./format
import ./row
import ./store
import ./sidecar

type
  SeekHandle* {.role: truthState, tag: "appApi|db|storageIo|types".} = object
    ## A resolved cluster: enough to address any row without re-reading the
    ## index. Hold one across several seeks to pay the index cost once.
    path*: string
    entry*: IndexEntry
    schema*: Schema
    schemaBytes*: int
    generation*: uint64

proc openSeek*(path: string,
    role: ClusterRole = crEntry): tuple[ok: bool, h: SeekHandle,
    err: string] {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## path: a Geist data file.
  ## role: which cluster to address; crEntry is the application's rows.
  ## Cost is the index (32 B + 80 B per cluster) plus the schema block,
  ## regardless of how many rows the file holds.
  var
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    at: int = -1
    sch: tuple[s: Schema, schemaBytes: int] = (default(Schema), 0)
  idx = readIndex(path)
  if not idx.ok:
    return (false, SeekHandle(), idx.err)
  at = idx.f.findIndex(role)
  if at < 0:
    return (false, SeekHandle(), "no " & $role & " cluster in " & path)
  try:
    sch = readSchemaOf(path, idx.f.index[at])
  except IOError as exc:
    # A damaged schema block is an answer, like a missing cluster is.
    return (false, SeekHandle(), exc.msg)
  result.h.path = path
  result.h.entry = idx.f.index[at]
  result.h.schema = sch.s
  result.h.schemaBytes = sch.schemaBytes
  result.h.generation = idx.f.header.generation
  result.ok = true

proc rowCount*(h: SeekHandle): uint32 {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## h: handle whose cluster row count is returned.
  result = h.entry.rowCount

proc looksSealed*(h: SeekHandle): bool {.role: parser,
    tag: "appApi|cryptoBoundary|db|read".} =
  ## h: handle whose database is checked for a ledger artifact.
  ##
  ## A seek returns bytes AS STORED, so a sealed cluster yields ciphertext
  ## and every proc in this module will hand back convincing nonsense.
  ## Nothing in the data file itself records that: sealing is described by
  ## the ledger, which is a separate artifact precisely so that losing it
  ## makes the data unrecoverable. So this answers the question it can
  ## actually answer -- "is there a ledger beside this file" -- and is
  ## named to say so. A caller needing certainty must open a session.
  var
    stem: string = ""
    dir: string = ""
    name: string = ""
    i: int = 0
  dir = parentDir(h.path)
  name = extractFilename(h.path)
  i = name.find(".ge1st")
  if i < 0:
    return false
  stem = name[0 ..< i]
  for f in walkFiles(dir / stem & ".ledger*"):
    return true
  result = false

proc isDenseHandle*(h: SeekHandle): bool {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## h: handle whose cluster has uniform rows, so a column is a byte range
  ## at a constant offset and can be strided without parsing anything.
  result = h.schema.isDense()

proc rowOffsetTable*(h: SeekHandle): seq[uint32] {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## h: handle whose offset table is read from the auxiliary region.
  ## Empty for a dense cluster, which needs none.
  if h.isDenseHandle():
    return @[]
  result = decodeOffsets(readAux(h.path, h.entry))

proc seekRow*(h: SeekHandle, i: uint32): Row {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## h/i: handle and row index.
  ## Dense: one seek of `rowBytes`. Varying: the offset table is read
  ## first, so the row itself is still one seek but the table costs one
  ## more -- hold the handle and use `seekRange` when reading many.
  var
    offs: seq[uint32] = @[]
  if i >= h.entry.rowCount:
    raise newException(IndexDefect,
      "row " & $i & " is out of range for a cluster of " &
      $h.entry.rowCount)
  if h.isDenseHandle():
    return readRowAt(h.path, h.entry, h.schemaBytes, i)
  offs = h.rowOffsetTable()
  if int(i) + 1 >= offs.len:
    raise newException(IndexDefect,
      "row " & $i & " has no entry in the offset table")
  result.schemaId = h.entry.schemaId
  result.data = readAt(h.path,
    h.entry.at + uint64(h.schemaBytes) + uint64(offs[int(i)]),
    int(offs[int(i) + 1]) - int(offs[int(i)]))

proc seekRange*(h: SeekHandle, first, count: uint32): seq[Row] {.
    role: dataFetcher, tag: "appApi|db|storageIo|read".} =
  ## h: handle.
  ## first/count: row window read as ONE contiguous block rather than
  ##   `count` separate seeks, which is what makes a range scan cheap.
  var
    n: uint32 = count
    raw: ByteSeq = @[]
    offs: seq[uint32] = @[]
    i: uint32 = 0'u32
    w: int = 0
    base: int = 0
    r: Row = default(Row)
  if first >= h.entry.rowCount:
    return @[]
  if first + n > h.entry.rowCount:
    n = h.entry.rowCount - first
  if n == 0'u32:
    return @[]
  if h.isDenseHandle():
    w = int(h.entry.rowBytes)
    raw = readAt(h.path, h.entry.at + uint64(h.schemaBytes) +
      uint64(first) * uint64(h.entry.rowBytes), int(n) * w)
    while i < n:
      r.schemaId = h.entry.schemaId
      r.data = raw[int(i) * w ..< (int(i) + 1) * w]
      result.add r
      i = i + 1'u32
    return
  # Varying rows: the window is still ONE read, bounded by the first and
  # last offsets, then sliced in memory. That is what keeps a range scan
  # cheaper than `count` separate seeks even without uniform widths.
  offs = h.rowOffsetTable()
  if int(first) + int(n) >= offs.len:
    n = uint32(offs.len - 1 - int(first))
  if n == 0'u32:
    return @[]
  base = int(offs[int(first)])
  raw = readAt(h.path, h.entry.at + uint64(h.schemaBytes) + uint64(base),
    int(offs[int(first) + int(n)]) - base)
  while i < n:
    r.schemaId = h.entry.schemaId
    r.data = raw[int(offs[int(first) + int(i)]) - base ..<
      int(offs[int(first) + int(i) + 1]) - base]
    result.add r
    i = i + 1'u32

proc seekFixedColumn*(h: SeekHandle, slot: int): seq[uint64] {.
    role: dataFetcher, tag: "appApi|db|storageIo|read".} =
  ## h/slot: handle and an integer-shaped column.
  ##
  ## A DENSE cluster is read once and strided at `rowBytes`, touching only
  ## the column's own bytes -- the cheap path, and the reason dense schemas
  ## exist. A varying cluster has to resolve each row's field offsets, so
  ## it costs a pass over the rows; still one bulk read, not one per row.
  var
    raw: ByteSeq = @[]
    offs: seq[uint32] = @[]
    row: ByteSeq = @[]
    i: uint32 = 0'u32
    w: int = 0
  if slot < 0 or slot >= h.schema.slots.len:
    raise newException(IndexDefect, "no slot " & $slot & " in this schema")
  if h.entry.rowCount == 0'u32:
    return @[]
  raw = readAt(h.path, h.entry.at + uint64(h.schemaBytes),
    int(h.entry.len) - h.schemaBytes)
  if h.isDenseHandle():
    w = int(h.entry.rowBytes)
    while i < h.entry.rowCount:
      result.add raw.getU64(int(i) * w + int(h.schema.slotAt(slot)))
      i = i + 1'u32
    return
  offs = h.rowOffsetTable()
  while i < h.entry.rowCount and int(i) + 1 < offs.len:
    row = raw[int(offs[int(i)]) ..< int(offs[int(i) + 1])]
    result.add h.schema.u64At(row, fieldOffsets(h.schema, row), slot)
    i = i + 1'u32

proc seekColumnBytes*(h: SeekHandle, slot: int,
    store: SidecarStore = SidecarStore()): seq[ByteSeq] {.
    role: dataFetcher, tag: "appApi|db|storageIo|read".} =
  ## h/slot/store: handle, column, and the sidecar a capped column may
  ## reference. Returns each row's value in order, as stored.
  var
    raw: ByteSeq = @[]
    offs: seq[uint32] = @[]
    row: ByteSeq = @[]
    i: uint32 = 0'u32
    w: int = 0
  if slot < 0 or slot >= h.schema.slots.len:
    raise newException(IndexDefect, "no slot " & $slot & " in this schema")
  if h.entry.rowCount == 0'u32:
    return @[]
  raw = readAt(h.path, h.entry.at + uint64(h.schemaBytes),
    int(h.entry.len) - h.schemaBytes)
  if h.isDenseHandle():
    w = int(h.entry.rowBytes)
    while i < h.entry.rowCount:
      row = raw[int(i) * w ..< (int(i) + 1) * w]
      result.add h.schema.resolve(row, fieldOffsets(h.schema, row), slot,
        store)
      i = i + 1'u32
    return
  offs = h.rowOffsetTable()
  while i < h.entry.rowCount and int(i) + 1 < offs.len:
    row = raw[int(offs[int(i)]) ..< int(offs[int(i) + 1])]
    result.add h.schema.resolve(row, fieldOffsets(h.schema, row), slot, store)
    i = i + 1'u32

proc seekObject*[T: object](h: SeekHandle, i: uint32,
    store: SidecarStore = SidecarStore()): T {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## h/i: handle and row index unpacked into T.
  ## store: sidecar store, needed only if a capped column externalised.
  ## The row now carries its own values, so this reads the row and nothing
  ## else -- no second region to fetch.
  result = fromRowBytes[T](h.seekRow(i).data, h.schema, store)

proc seekText*(h: SeekHandle, i: uint32, slot: int,
    store: SidecarStore = SidecarStore()): string {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## h/i/slot/store: one text column of one row.
  ## Reads the row and resolves one column out of it, so a wide row with
  ## several large fields still costs one read.
  var
    row: ByteSeq = @[]
  row = h.seekRow(i).data
  result = h.schema.textAt(row, fieldOffsets(h.schema, row), slot, store)

proc seekMatching*(h: SeekHandle, slot: int, value: uint64,
    limit: int = 0): seq[uint32] {.role: dataFetcher,
    tag: "appApi|db|storageIo|read".} =
  ## h/slot/value: fixed-column equality scan returning row INDICES.
  ## limit: stop after this many hits; 0 means all.
  ## Returning indices rather than rows lets a caller decide what to fetch,
  ## which matters when the match is narrow and the rows are wide.
  var
    col: seq[uint64] = @[]
    i: int = 0
  col = h.seekFixedColumn(slot)
  while i < col.len and (limit <= 0 or result.len < limit):
    if col[i] == value:
      result.add uint32(i)
    i = i + 1

proc indexCostBytes*(path: string): int {.role: parser,
    tag: "appApi|db|read".} =
  ## path: file whose index size is reported, for callers deciding whether
  ## to hold a handle open. Independent of row count by construction.
  var
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  idx = readIndex(path)
  if not idx.ok:
    return 0
  result = idx.f.indexBytes

proc fileGeneration*(path: string): uint64 {.role: parser,
    tag: "appApi|db|read".} =
  ## path: file whose generation is read from the header alone. A cheap way
  ## for a holder of a `SeekHandle` to notice its handle went stale.
  var
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  idx = readIndex(path)
  if idx.ok:
    result = idx.f.header.generation

proc isStale*(h: SeekHandle): bool {.role: parser,
    tag: "appApi|db|read".} =
  ## h: handle checked against the file it came from. A handle caches the
  ## index, so a writer that appended rows since `openSeek` would otherwise
  ## be invisible -- this is the cheap check that says to reopen.
  if not fileExists(h.path):
    return true
  result = fileGeneration(h.path) != h.generation or
    readIndex(h.path).f.index.len == 0
