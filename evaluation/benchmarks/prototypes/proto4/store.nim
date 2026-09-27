## ------------------------------------------------------------------
## Writer/reader <- builds the file, and reads pieces of it in isolation
## ------------------------------------------------------------------

import runePragmas
import std/[streams]
import ./format

type
  Overflow* = object
    data*: ByteSeq

  ClusterBuild* = object
    role*: ClusterRole
    mode*: ClusterMode
    schema*: Schema
    rows*: ByteSeq          ## rowCount * rowBytes, contiguous
    rowCount*: uint32

proc push*(o: var Overflow, A: openArray[uint8]): (uint32, uint32) {.
    role: truthBuilder.} =
  ## Returns (start, len). Dedups identical runs cheaply for short values.
  result = (uint32(o.data.len), uint32(A.len))
  for b in A: o.data.add b

proc pull*(o: Overflow, start, n: uint32): ByteSeq {.role: parser.} =
  result = newSeq[uint8](int(n))
  for i in 0'u32 ..< n: result[int(i)] = o.data[int(start + i)]

proc beginRow*(c: var ClusterBuild) {.role: truthBuilder.} =
  var n = int(c.schema.rowBytes())
  for i in 0 ..< n: c.rows.add 0'u8
  c.rowCount.inc

proc rowBase*(c: ClusterBuild, i: uint32): int {.role: math.} =
  int(i * c.schema.rowBytes())

proc setInt*(c: var ClusterBuild, row: uint32, slot: int, v: uint64) {.
    role: truthBuilder.} =
  c.rows.putU64(c.rowBase(row) + int(slotAt(slot)), v)

proc setVar*(c: var ClusterBuild, o: var Overflow, row: uint32, slot: int,
    A: openArray[uint8]) {.role: truthBuilder.} =
  var (s, n) = o.push(A)
  var b = c.rowBase(row) + int(slotAt(slot))
  c.rows.putU32(b, s)
  c.rows.putU32(b + 4, n)

# ------------------------- file writing -------------------------

proc encodeSchema(s: Schema): ByteSeq {.role: truthBuilder.} =
  result.addU32(uint32(s.typeName.len))
  for ch in s.typeName: result.add uint8(ch)
  result.addU32(uint32(s.names.len))
  for nm in s.names:
    result.addU32(uint32(nm.len))
    for ch in nm: result.add uint8(ch)
  result.addU32(uint32(s.slots.len))
  for sl in s.slots:
    result.addU32(uint32(sl.nameId))
    result.add uint8(ord(sl.kind))

proc writeFile*(path: string, C: seq[ClusterBuild], o: Overflow) {.
    role: dataWriter.} =
  var
    body: ByteSeq = @[]
    idx: seq[ClusterIndexEntry] = @[]
    headerLen = magic.len + 8 + 8 + 4
    indexLen = C.len * (1 + 1 + 2 + 4 + 8 + 8)
    base = uint64(headerLen + indexLen)
  for c in C:
    var blob = encodeSchema(c.schema)
    for b in c.rows: blob.add b
    idx.add ClusterIndexEntry(role: c.role, mode: c.mode, schemaId: 0'u16,
      rowCount: c.rowCount, at: base + uint64(body.len),
      len: uint64(blob.len))
    for b in blob: body.add b

  var buf: ByteSeq = @[]
  for ch in magic: buf.add uint8(ch)
  buf.addU64(base + uint64(body.len))          # overflowAt
  buf.addU64(uint64(o.data.len))               # overflowLen
  buf.addU32(uint32(C.len))                    # clusterCount
  for e in idx:
    buf.add uint8(ord(e.role)); buf.add uint8(ord(e.mode))
    buf.add uint8(e.schemaId and 0xFF); buf.add uint8(e.schemaId shr 8)
    buf.addU32(e.rowCount); buf.addU64(e.at); buf.addU64(e.len)
  for b in body: buf.add b
  for b in o.data: buf.add b

  var fs = newFileStream(path, fmWrite)
  for b in buf: fs.write(b)
  fs.close()

# ------------------------- partial reading -------------------------

proc readAt(path: string, at: uint64, n: int): ByteSeq {.role: dataFetcher.} =
  var fs = newFileStream(path, fmRead)
  fs.setPosition(int(at))
  result = newSeq[uint8](n)
  if n > 0: discard fs.readData(result[0].addr, n)
  fs.close()

proc readIndex*(path: string): (seq[ClusterIndexEntry], uint64, uint64, int) {.
    role: dataFetcher.} =
  ## Reads ONLY the header + cluster index. This is all geistd needs
  ## to answer "what changed" without touching a single row.
  var
    headerLen = magic.len + 8 + 8 + 4
    h = readAt(path, 0, headerLen)
    overflowAt = h.getU64(magic.len)
    overflowLen = h.getU64(magic.len + 8)
    count = int(h.getU32(magic.len + 16))
    rowLen = 1 + 1 + 2 + 4 + 8 + 8
    raw = readAt(path, uint64(headerLen), count * rowLen)
    idx: seq[ClusterIndexEntry] = @[]
  for i in 0 ..< count:
    var o = i * rowLen
    idx.add ClusterIndexEntry(
      role: ClusterRole(raw[o]), mode: ClusterMode(raw[o + 1]),
      schemaId: uint16(raw[o + 2]) or (uint16(raw[o + 3]) shl 8),
      rowCount: raw.getU32(o + 4), at: raw.getU64(o + 8),
      len: raw.getU64(o + 16))
  result = (idx, overflowAt, overflowLen, headerLen + count * rowLen)

proc readOneRow*(path: string, e: ClusterIndexEntry, schemaBytes: uint64,
    rowW: uint32, i: uint32): ByteSeq {.role: dataFetcher.} =
  ## Seeks straight to row i. No cluster load, no scan.
  readAt(path, e.at + schemaBytes + uint64(i * rowW), int(rowW))

proc readOverflowSlice*(path: string, overflowAt: uint64, start,
    n: uint32): ByteSeq {.role: dataFetcher.} =
  readAt(path, overflowAt + uint64(start), int(n))
