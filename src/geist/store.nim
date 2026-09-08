## ---------------------------------------------------------------------
## Store <- clusters on disk, and reading pieces of them in isolation
## ---------------------------------------------------------------------
##
##   build clusters -> writeGeistFile
##   readIndex(path)          <- header + index only, a few hundred bytes
##   readRowAt(path, e, i)    <- one row, direct seek, no cluster load
##
## A cluster is `schema block | rows | aux`. Whether row i can be found by
## arithmetic follows from the schema: a dense one puts it at
## `at + schemaBytes + i*rowBytes`, and anything else carries a row offset
## table in the aux region. Rows are self-contained either way -- no value
## lives outside the row except in the sidecar, which is a separate file.

import std/[os, streams]

import geistPragmas
import ./types
import ./durable
import ./format
import ./sidecar
import ./row
import ./crypto/hashing

type
  ClusterBuild* {.role: truthState, metaTags: {tagDb, tagStorageIo,
      tagTypes}.} = object
    role*: ClusterRole
    mode*: ClusterMode
    schema*: Schema
    schemaId*: uint16
    rows*: ByteSeq
    rowCount*: uint32
    store*: SidecarStore
    chainHash*: ByteSeq
    chainHashKind*: HashKind
    indexHashKind*: HashKind
    ## rowOffsets: varying schemas only. `rowCount + 1` entries, so row i is
    ## `[rowOffsets[i], rowOffsets[i+1])`. A dense schema leaves it empty
    ## and addresses by `i * rowBytes` instead.
    rowOffsets*: seq[uint32]
    ## What the column policy cost while filling this cluster. `truncated`
    ## especially: `opTruncate` cuts silently by design, and the row keeps
    ## no evidence, so this counter is the only record that it happened.
    truncated*: uint32
    externalised*: uint32
    truncatedIn*: seq[FieldName]

  GeistFile* {.role: truthState, metaTags: {tagDb, tagStorageIo,
      tagTypes}.} = object
    ## The parsed shape of a file. `index` alone answers "what changed".
    header*: FileHeader
    index*: seq[IndexEntry]
    indexBytes*: int

proc initClusterBuild*(role: ClusterRole, mode: ClusterMode, s: Schema,
    store: SidecarStore = SidecarStore(), schemaId: uint16 = 0'u16,
    chainHashKind: HashKind = hkBlake3,
    indexHashKind: HashKind = hkBlake3): ClusterBuild {.
    role: configurator, metaTags: {tagDb, tagStorageIo}.} =
  ## role/mode: cluster classification and append semantics.
  ## s: schema for every row in this cluster, carrying its column policy.
  ## store: sidecar a capped column escapes to; a zero-value store means
  ##   there is nowhere to escape to, which is correct for a schema with no
  ##   capped columns.
  ## chainHashKind: family linking cmChained rows.
  ## indexHashKind: family producing the index entry's change detector.
  result.role = role
  result.mode = mode
  result.schema = s
  result.schemaId = schemaId
  result.store = store
  result.chainHashKind = chainHashKind
  result.indexHashKind = indexHashKind

proc chainStep(prev: ByteSeq, A: openArray[uint8],
    h: HashKind): ByteSeq {.role: helper,
    metaTags: {tagCryptoBoundary, tagDb, tagLedger}.} =
  ## prev: running chain hash.
  ## A: newly appended row bytes folded into the chain.
  ## h: chain hash family. Always full width -- a chain link that only
  ##   resisted preimages could be forked by a birthday collision.
  var
    buf: ByteSeq = @[]
  buf.addBytes(prev)
  buf.addBytes(A)
  result = geistHash(h, buf, fullDigestBytes)

proc varyingRows*(C: ClusterBuild): bool {.role: parser, inline,
    metaTags: {tagDb, tagRead}.} =
  ## C: cluster whose rows vary in length, so addressing goes through the
  ## offset table rather than arithmetic.
  ##
  ## This is now DERIVED from the schema's column policy rather than
  ## chosen as a table-level layout: a schema of only `colFixed` columns
  ## with collapsing off stays dense, and anything else does not. The
  ## caller never picks it, so it can never disagree with the columns.
  result = not C.schema.isDense()

proc addRow*[T: object](C: var ClusterBuild, x: T): uint32 {.
    role: dataWriter, metaTags: {tagAppApi, tagDb, tagStorageIo, tagWrite},
    discardable.} =
  ## C: cluster receiving one row.
  ## x: object whose declaration order must match `C.schema`.
  ## Each column decides its own storage inside `toRowBytes`; the cluster
  ## only decides whether it must remember where the row ended.
  var
    built: tuple[data: ByteSeq, truncated: uint32, externalised: uint32,
      omitted: uint32, truncatedIn: seq[FieldName], err: string]
    i: int = 0
  built = toRowBytes(x, C.schema, C.store)
  if built.err.len > 0:
    raise newException(ValueError, built.err)
  # What the policy cost, kept per cluster. A truncating write is legal but
  # lossy, and nothing in the row records it, so it is recorded here.
  C.truncated = C.truncated + built.truncated
  C.externalised = C.externalised + built.externalised
  i = 0
  while i < built.truncatedIn.len:
    if not (built.truncatedIn[i] in C.truncatedIn):
      C.truncatedIn.add built.truncatedIn[i]
    i = i + 1
  # The offset table exists only when rows vary. A dense schema keeps its
  # arithmetic addressing and pays nothing for it.
  if C.varyingRows() and C.rowOffsets.len == 0:
    C.rowOffsets.add 0'u32
  i = 0
  while i < built.data.len:
    C.rows.add built.data[i]
    i = i + 1
  if C.varyingRows():
    C.rowOffsets.add uint32(C.rows.len)
  result = C.rowCount
  C.rowCount = C.rowCount + 1'u32
  if C.mode == cmChained:
    C.chainHash = chainStep(C.chainHash, built.data, C.chainHashKind)

proc addRowBytes*(C: var ClusterBuild, A: openArray[uint8]): uint32 {.
    role: dataWriter, metaTags: {tagAppApi, tagDb, tagStorageIo, tagWrite},
    discardable.} =
  ## C: cluster receiving one row.
  ## A: a COMPLETE row, already packed against `C.schema` -- by `toRowBytes`
  ##   for a typed caller, by `buildRow` for a schema-driven one, or by a
  ##   peer that sent it over the wire.
  ##
  ## This is `addRow` without the object: identical bookkeeping, no mapper.
  ## Everything that ingests rows funnels through one of the two, so the
  ## offset table and the hash chain cannot be updated in two ways that
  ## disagree.
  ##
  ##   dense schema   -> the row must be exactly rowBytes wide
  ##   varying schema -> any width; the offset table records where it ended
  var
    i: int = 0
  if not C.varyingRows() and A.len != int(C.schema.rowBytes()):
    raise newException(ValueError,
      "row is " & $A.len & " B but this dense schema needs " &
      $C.schema.rowBytes() & " B")
  if C.varyingRows() and C.rowOffsets.len == 0:
    C.rowOffsets.add 0'u32
  while i < A.len:
    C.rows.add A[i]
    i = i + 1
  if C.varyingRows():
    C.rowOffsets.add uint32(C.rows.len)
  result = C.rowCount
  C.rowCount = C.rowCount + 1'u32
  if C.mode == cmChained:
    C.chainHash = chainStep(C.chainHash, A, C.chainHashKind)

proc rowSpan*(C: ClusterBuild, i: uint32): tuple[at: int, len: int] {.
    role: parser, metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: cluster and row index resolved to a byte range.
  ## Dense schemas compute it; varying ones read two offsets. Both O(1),
  ## which is the point of keeping the table rather than walking lengths.
  var
    w: int = 0
  if C.varyingRows():
    if int(i) + 1 >= C.rowOffsets.len:
      raise newException(IndexDefect,
        "row " & $i & " is out of range for a cluster of " & $C.rowCount)
    result.at = int(C.rowOffsets[int(i)])
    result.len = int(C.rowOffsets[int(i) + 1]) - result.at
    return
  w = int(C.schema.rowBytes())
  if i >= C.rowCount:
    raise newException(IndexDefect,
      "row " & $i & " is out of range for a cluster of " & $C.rowCount)
  result.at = int(i) * w
  result.len = w

proc rowBytesAt*(C: ClusterBuild, i: uint32): ByteSeq {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: one stored row's bytes, whichever addressing applies.
  var
    span: tuple[at: int, len: int]
    j: int = 0
  span = C.rowSpan(i)
  result = newSeq[uint8](span.len)
  while j < span.len:
    result[j] = C.rows[span.at + j]
    j = j + 1

proc rowAt*(C: ClusterBuild, i: uint32): Row {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: one row wrapped for callers that still take a `Row`.
  result.schemaId = C.schemaId
  result.data = C.rowBytesAt(i)

proc objectAt*[T: object](C: ClusterBuild, i: uint32): T {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: cluster and row index unpacked back into T.
  result = fromRowBytes[T](C.rowBytesAt(i), C.schema, C.store)

proc encodeOffsets*(O: seq[uint32]): ByteSeq {.role: encryptor,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## O: the packed cluster's row offset table.
  var
    i: int = 0
  result.addU32(uint32(O.len))
  while i < O.len:
    result.addU32(O[i])
    i = i + 1

proc decodeOffsets*(A: openArray[uint8]): seq[uint32] {.role: parser,
    metaTags: {tagCodecBoundary, tagDb, tagRead}.} =
  ## A: bytes produced by `encodeOffsets`.
  var
    n: int = 0
    i: int = 0
  if A.len < 4:
    return @[]
  n = int(A.getU32(0))
  while i < n and 4 + i * 4 + 4 <= A.len:
    result.add A.getU32(4 + i * 4)
    i = i + 1

proc encodeCluster(C: ClusterBuild): tuple[body: ByteSeq, schemaBytes: int] {.
    role: encryptor, metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## C: cluster serialised as `schema block | rows`.
  ## When the schema is not dense the rows vary in length and their offset
  ## table travels in the auxiliary region (see `IndexEntry.auxAt`).
  var
    sch: ByteSeq = @[]
  sch = encodeSchema(C.schema)
  result.schemaBytes = sch.len
  result.body = sch
  result.body.addBytes(C.rows)

proc auxRegion(C: ClusterBuild): ByteSeq {.role: helper,
    metaTags: {tagCodecBoundary, tagDb, tagWrite}.} =
  ## C: cluster whose auxiliary region is returned.
  ##
  ## The region holds the row offset table and nothing else. It used to
  ## double as the overflow region for cells that did not fit their row;
  ## no cell is stored outside its row any more, so a dense cluster now
  ## writes no auxiliary region at all.
  if not C.varyingRows():
    return @[]
  # An empty cluster needs no table either. Writing the bare u32 count
  # would cost 4 bytes per empty cluster, and every database has two of
  # them (meta and journal) before a single row is stored.
  if C.rowOffsets.len == 0:
    return @[]
  result = encodeOffsets(C.rowOffsets)

proc writeGeistFile*(path: string, C: openArray[ClusterBuild],
    generation: uint64 = 1'u64): tuple[ok: bool, err: string] {.
    role: dataWriter, metaTags: {tagDb, tagStorageIo, tagWrite}.} =
  ## path: destination file.
  ## C: clusters written in order; index order is file order.
  ## generation: bumped by the key lifecycle on every rekey.
  var
    header: FileHeader
    index: seq[IndexEntry] = @[]
    bodies: seq[ByteSeq] = @[]
    auxes: seq[ByteSeq] = @[]
    aux: ByteSeq = @[]
    e: IndexEntry
    enc: tuple[body: ByteSeq, schemaBytes: int]
    base: uint64 = 0'u64
    cursor: uint64 = 0'u64
    buf: ByteSeq = @[]
    fs: FileStream = nil
    i: int = 0
  header.version = geistFormatVersion
  header.clusterCount = uint32(C.len)
  header.generation = generation
  base = uint64(headerBytes + C.len * indexEntryBytes)
  cursor = base
  while i < C.len:
    enc = encodeCluster(C[i])
    bodies.add enc.body
    e = IndexEntry()
    e.role = C[i].role
    e.mode = C[i].mode
    e.schemaId = C[i].schemaId
    e.rowCount = C[i].rowCount
    # rowBytes = 0 declares "rows are variable length, consult the offset
    # table". A dense schema writes its real width, so a reader can tell
    # the two apart from the index alone without loading anything.
    e.rowBytes = C[i].schema.rowBytes()
    e.at = cursor
    e.len = uint64(enc.body.len)
    cursor = cursor + uint64(enc.body.len)
    e.auxAt = cursor
    aux = auxRegion(C[i])
    auxes.add aux
    e.auxLen = uint64(aux.len)
    cursor = cursor + e.auxLen
    # Index hash: a change detector for observers, and the value
    # `changedClusters` compares. Full width because a collision here would
    # let a modified cluster pass as unchanged.
    e.hash = geistHash(C[i].indexHashKind, enc.body, fullDigestBytes)
    index.add e
    i = i + 1
  buf = encodeHeader(header)
  i = 0
  while i < index.len:
    buf.addBytes(encodeIndexEntry(index[i]))
    i = i + 1
  i = 0
  while i < bodies.len:
    buf.addBytes(bodies[i])
    buf.addBytes(auxes[i])
    i = i + 1
  # Durable, not merely written: this file is one third of a generation and
  # the manifest is about to promise all three are on disk. See durable.nim.
  result = writeDurable(path, buf)

proc stampGeneration*(path: string, n: uint64): tuple[ok: bool,
    err: string] {.role: dataWriter,
    metaTags: {tagDb, tagStorageIo, tagWrite}.} =
  ## path: an existing Geist file whose header generation is rewritten.
  ## n: the generation it is being published AS.
  ##
  ## Restoring a backup takes bytes written under an older generation and
  ## publishes them as a new one. Without this the file would carry a
  ## number the manifest contradicts, and `verifyGeneration` would refuse
  ## the very generation it was just told to trust -- correctly, because a
  ## file whose header disagrees with the manifest is exactly the corrupt
  ## case that check exists for.
  var
    raw: ByteSeq = @[]
    head: ByteSeq = @[]
  if not fileExists(path):
    return (false, "no such Geist file: " & path)
  try:
    raw = cast[ByteSeq](readFile(path))
    if raw.len < headerBytes:
      return (false, "file is shorter than a Geist header: " & path)
    head = raw
    head.putU64(14, n)
    result = writeDurable(path, head)
  except CatchableError as exc:
    result = (false, exc.msg)

proc readAt*(path: string, at: uint64, n: int): ByteSeq {.role: dataFetcher,
    metaTags: {tagDb, tagStorageIo, tagRead}.} =
  ## path/at/n: file, absolute offset and byte count read in isolation.
  var
    fs: FileStream = nil
  result = newSeq[uint8](n)
  if n == 0:
    return
  fs = newFileStream(path, fmRead)
  if fs == nil:
    raise newException(IOError, "cannot open for reading: " & path)
  try:
    fs.setPosition(int(at))
    discard fs.readData(addr result[0], n)
  finally:
    fs.close()

proc readIndex*(path: string): tuple[ok: bool, f: GeistFile, err: string] {.
    role: dataFetcher, metaTags: {tagAppApi, tagDb, tagStorageIo, tagRead}.} =
  ## path: file whose header and cluster index are read WITHOUT touching
  ## a single row. This is the daemon's observation path: cost is
  ## `headerBytes + indexEntryBytes * clusterCount` regardless of file size.
  var
    head: ByteSeq = @[]
    decoded: tuple[ok: bool, h: FileHeader, err: string]
    raw: ByteSeq = @[]
    i: int = 0
  if not fileExists(path):
    return (false, GeistFile(), "no such Geist file: " & path)
  head = readAt(path, 0'u64, headerBytes)
  decoded = decodeHeader(head)
  if not decoded.ok:
    return (false, GeistFile(), decoded.err)
  result.f.header = decoded.h
  result.f.indexBytes = headerBytes +
    int(decoded.h.clusterCount) * indexEntryBytes
  raw = readAt(path, uint64(headerBytes),
    int(decoded.h.clusterCount) * indexEntryBytes)
  while i < int(decoded.h.clusterCount):
    result.f.index.add decodeIndexEntry(raw, i * indexEntryBytes)
    i = i + 1
  result.ok = true

const
  schemaProbeBytes = 64 * 1024
    ## Upper bound on a schema block when its exact size cannot be computed.
    ## A fixed cluster gives it away as `len - rowCount*rowBytes`; a packed
    ## one cannot, because rows vary. `decodeSchema` reports where it
    ## stopped, so reading a bounded prefix is enough -- and bounded, so a
    ## multi-gigabyte cluster is not pulled in to find its header.

proc readSchemaOf*(path: string, e: IndexEntry): tuple[s: Schema,
    schemaBytes: int] {.role: dataFetcher,
    metaTags: {tagDb, tagStorageIo, tagRead}.} =
  ## path/e: file and index entry whose schema block is read alone.
  var
    raw: ByteSeq = @[]
    o: int = 0
    n: int = 0
  if e.rowBytes == 0'u32:
    n = min(int(e.len), schemaProbeBytes)
  else:
    n = int(e.len) - int(e.rowCount * e.rowBytes)
  raw = readAt(path, e.at, n)
  result.s = decodeSchema(raw, o)
  result.schemaBytes = o

proc readRowAt*(path: string, e: IndexEntry, schemaBytes: int,
    i: uint32): Row {.role: dataFetcher,
    metaTags: {tagAppApi, tagDb, tagStorageIo, tagRead}.} =
  ## path/e: file and the row's cluster.
  ## schemaBytes: size of the cluster's schema block, from `readSchemaOf`.
  ## i: row index; seeks straight to it with no cluster load and no scan.
  result.schemaId = e.schemaId
  result.data = readAt(path, e.at + uint64(schemaBytes) +
    uint64(i * e.rowBytes), int(e.rowBytes))

proc readAux*(path: string, e: IndexEntry): ByteSeq {.role: dataFetcher,
    metaTags: {tagDb, tagStorageIo, tagRead}.} =
  ## path/e: file and cluster whose auxiliary region is read whole. That is
  ## the row offset table, and it is empty for a dense cluster.
  result = readAt(path, e.auxAt, int(e.auxLen))

proc readCluster*(path: string, e: IndexEntry,
    store: SidecarStore = SidecarStore(),
    chainHashKind: HashKind = hkBlake3,
    indexHashKind: HashKind = hkBlake3): ClusterBuild {.role: dataFetcher,
    metaTags: {tagAppApi, tagDb, tagStorageIo, tagRead}.} =
  ## path/e: file and index entry loaded fully back into memory.
  ## store: sidecar store used when rows resolve externalised values.
  ## chainHashKind/indexHashKind: carried in from the configuration. They
  ##   are NOT stored per cluster, so a caller that reopens with a
  ##   different configuration than it wrote with would rehash differently
  ##   and see spurious "changed" clusters -- pass what the config says.
  var
    raw: ByteSeq = @[]
    o: int = 0
  raw = readAt(path, e.at, int(e.len))
  result.role = e.role
  result.mode = e.mode
  result.schemaId = e.schemaId
  result.schema = decodeSchema(raw, o)
  result.rowCount = e.rowCount
  result.rows = raw[o .. ^1]
  result.store = store
  result.chainHashKind = chainHashKind
  result.indexHashKind = indexHashKind
  # Whether there IS a table is decided by the schema just decoded, not by
  # a stored byte -- see `auxRegion`. Deriving it means a file can never
  # claim an addressing scheme its columns contradict.
  if result.varyingRows():
    result.rowOffsets = decodeOffsets(readAux(path, e))

proc findIndex*(f: GeistFile, role: ClusterRole,
    typeHint: uint16 = 0'u16): int {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## f: parsed file shape.
  ## role: cluster role to locate.
  ## typeHint: schema id when several clusters share a role.
  var
    i: int = 0
  result = -1
  while i < f.index.len:
    if f.index[i].role == role and
        (typeHint == 0'u16 or f.index[i].schemaId == typeHint):
      return i
    i = i + 1

proc changedClusters*(before, after: GeistFile): seq[int] {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead, tagStatus}.} =
  ## before/after: two index reads of the same file.
  ## Returns the indices whose content hash or row count moved, so a daemon
  ## can follow a file it does not own without loading any rows.
  var
    i: int = 0
    j: int = 0
    differs: bool = false
  while i < after.index.len:
    if i >= before.index.len:
      result.add i
      i = i + 1
      continue
    differs = before.index[i].rowCount != after.index[i].rowCount
    j = 0
    while j < after.index[i].hash.len and not differs:
      if before.index[i].hash[j] != after.index[i].hash[j]:
        differs = true
      j = j + 1
    if differs:
      result.add i
    i = i + 1
