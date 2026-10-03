## ---------------------------------------------------------------------
## Column crypto <- applying batches to a cluster's rows
## ---------------------------------------------------------------------
##
##   for each column group g, for each batch b of N rows:
##       plaintext = concat over rows r in b, over slots s in g of
##                     row r's byte range for column s
##
## A column group is a set of byte RANGES, which only exists when every row
## has the same shape. That restricts group sealing to dense schemas, and
## `sealCluster` enforces it; a varying schema seals whole rows instead
## through `sealPacked` below.
##
## Values no longer live outside their row, so there is no second region
## to navigate and no clear-text pointer to leak a length. What a group
## seals is exactly the columns named in it, in place.
##
## See docs/DESIGN_RATIONALE.md section 10.

import runePragmas
import ../types
import ./batch

type
  Piece* {.role: truthState, tag: "batch|cryptoBoundary|types".} = object
    ## One contiguous run of bytes belonging to a batch, as an offset into
    ## the cluster's row region. There is no second region to point at.
    at*: int
    len*: int

proc piecesFor*(s: Schema, rows: ByteSeq, rowIndex: uint32,
    slots: seq[int]): seq[Piece] {.role: truthBuilder,
    tag: "batch|cryptoBoundary|read".} =
  ## s: cluster schema; MUST be dense.
  ## rows: the cluster's contiguous row region.
  ## rowIndex/slots: the row and the group's column indices.
  ##
  ## A column group is a byte range only when every row has the same
  ## shape. `sealCluster` enforces that; a varying schema goes through
  ## `sealPacked`, which seals whole rows instead.
  var
    base: int = 0
    i: int = 0
  base = int(rowIndex) * int(s.rowBytes())
  while i < slots.len:
    result.add Piece(at: base + int(s.slotAt(slots[i])),
      len: int(s.slots[slots[i]].width))
    i = i + 1

proc gather(rows: ByteSeq, P: seq[Piece]): ByteSeq {.role: helper,
    tag: "batch|cryptoBoundary|read".} =
  ## rows: the cluster's row region.
  ## P: pieces copied out in order to form one contiguous batch buffer.
  var
    i: int = 0
    j: int = 0
  while i < P.len:
    j = 0
    while j < P[i].len:
      result.add rows[P[i].at + j]
      j = j + 1
    i = i + 1

proc scatter(rows: var ByteSeq, P: seq[Piece], A: ByteSeq) {.
    role: dataWriter, tag: "batch|cryptoBoundary|write".} =
  ## rows: row region written back in place.
  ## P/A: the same piece list and the transformed bytes.
  var
    i: int = 0
    j: int = 0
    k: int = 0
  while i < P.len:
    j = 0
    while j < P[i].len:
      rows[P[i].at + j] = A[k]
      j = j + 1
      k = k + 1
    i = i + 1

proc batchPieces(s: Schema, rows: ByteSeq, first, last: uint32,
    slots: seq[int]): tuple[pieces: seq[Piece], rowLens: seq[int]] {.
    role: truthBuilder, tag: "batch|cryptoBoundary".} =
  ## s/rows: schema and fixed-row region.
  ## first/last: inclusive row range of this batch.
  ## slots: the column group.
  var
    r: uint32 = first
    p: seq[Piece] = @[]
    total: int = 0
    i: int = 0
  while r <= last:
    p = piecesFor(s, rows, r, slots)
    total = 0
    i = 0
    while i < p.len:
      result.pieces.add p[i]
      total = total + p[i].len
      i = i + 1
    result.rowLens.add total
    r = r + 1'u32

proc lastRowOf(L: Ledger, b: uint32, rowCount: uint32): uint32 {.role: math,
    inline, tag: "batch".} =
  ## L/b/rowCount: the last row of batch b; the final batch may be short.
  result = min(b * L.batchRows + L.batchRows - 1'u32, rowCount - 1'u32)

proc slotOf(L: Ledger, g: int, b: uint32): int {.role: math, inline,
    tag: "batch".} =
  ## L/g/b: where group g's entry for batch b sits in the ledger:
  ##
  ##   entries = | b0 g0 | b0 g1 | ... | b1 g0 | b1 g1 | ...
  result = int(b) * max(1, L.groups.len) + int(L.groups[g].groupId)

proc entryFor(L: var Ledger, g: int, b: uint32, cipher: CipherKind,
    treeHash: HashKind, keyRef: KeyId): LedgerEntry {.
    role: truthBuilder, tag: "batch|cryptoBoundary".} =
  ## L/g/b: the entry batch b of group g is sealed under -- the one on
  ## file, grown into when new, with its coordinates filled in.
  ## cipher/treeHash: what this seal uses.
  ## keyRef: the key to use when the entry names none yet. An entry that
  ## already names one keeps it: re-sealing a batch must not move it to
  ## another key behind the ledger's back.
  L.ensureCapacity(b)
  result = L.entries[L.slotOf(g, b)]
  result.groupId = L.groups[g].groupId
  result.batchIndex = b
  result.cipher = cipher
  result.treeHash = treeHash
  if result.keyRef == 0'u64:
    result.keyRef = keyRef

proc storedEntry(L: Ledger, g: int, b: uint32): LedgerEntry {.role: parser,
    tag: "batch|cryptoBoundary".} =
  ## L/g/b: the entry batch b of group g was sealed under; ValueError when
  ## the ledger does not have it.
  if L.slotOf(g, b) >= L.entries.len:
    raise newException(ValueError,
      "ledger is missing batch " & $b & " for column group " &
      $L.groups[g].groupId & ": the database cannot be decrypted " &
      "without its ledger")
  result = L.entries[L.slotOf(g, b)]

proc rowSlicesOf(plain: ByteSeq, lens: seq[int]): seq[ByteSeq] {.
    role: parser, tag: "batch".} =
  ## plain/lens: one batch's gathered bytes cut back into its rows.
  var
    o: int = 0
  for n in lens:
    result.add plain[o ..< o + n]
    o = o + n

proc sealCluster*(master: Secret, L: var Ledger, s: Schema,
    rows: var ByteSeq, rowCount: uint32,
    databaseId: string, schemaVersion: uint16,
    cipher: CipherKind, keyRef: KeyId,
    treeHash: HashKind = hkBlake3) {.role: encryptor,
    tag: "appApi|batch|cryptoBoundary|write".} =
  ## master/L: key material and the ledger receiving one entry per batch.
  ## s/rows/rowCount: the cluster being sealed in place.
  ## databaseId/schemaVersion: AAD components binding each batch's position.
  ## cipher/keyRef/treeHash: policy from the configuration. Each is
  ##   recorded in the ledger entry so the data stays readable if the
  ##   configuration later changes.
  var
    g: int = 0
    b: uint32 = 0'u32
    built: tuple[pieces: seq[Piece], rowLens: seq[int]] = (@[], @[])
    plain: ByteSeq = @[]
    sealedBytes: ByteSeq = @[]
    e: LedgerEntry = default(LedgerEntry)
  if L.batchRows == 0'u32 or rowCount == 0'u32:
    return
  if not s.isDense():
    raise newException(ValueError,
      "sealCluster needs a dense schema: a column group is only a byte " &
      "range when every row has the same shape. Use sealPacked.")
  while g < L.groups.len:
    b = 0'u32
    while b * L.batchRows < rowCount:
      e = L.entryFor(g, b, cipher, treeHash, keyRef)
      built = batchPieces(s, rows, b * L.batchRows,
        L.lastRowOf(b, rowCount), L.groups[g].slots)
      plain = gather(rows, built.pieces)
      sealedBytes = sealBatch(master, e, databaseId, schemaVersion, plain,
        rowSlicesOf(plain, built.rowLens), clusterBinding(s, rowCount))
      L.entries[L.slotOf(g, b)] = e
      scatter(rows, built.pieces, sealedBytes)
      b = b + 1'u32
    g = g + 1

proc openCluster*(master: Secret, L: Ledger, s: Schema,
    rows: var ByteSeq, rowCount: uint32,
    databaseId: string, schemaVersion: uint16) {.role: decryptor,
    tag: "appApi|batch|cryptoBoundary|read".} =
  ## master/L: key material and the ledger holding each batch's coordinates.
  ## s/rows/rowCount: the cluster decrypted in place.
  ## databaseId/schemaVersion: the same AAD components used when sealing.
  var
    g: int = 0
    b: uint32 = 0'u32
    built: tuple[pieces: seq[Piece], rowLens: seq[int]] = (@[], @[])
    cipherBytes: ByteSeq = @[]
    plain: ByteSeq = @[]
  if L.batchRows == 0'u32 or rowCount == 0'u32:
    return
  while g < L.groups.len:
    b = 0'u32
    while b * L.batchRows < rowCount:
      built = batchPieces(s, rows, b * L.batchRows,
        L.lastRowOf(b, rowCount), L.groups[g].slots)
      cipherBytes = gather(rows, built.pieces)
      plain = openBatch(master, L.storedEntry(g, b), databaseId,
        schemaVersion, cipherBytes, built.rowLens, clusterBinding(s, rowCount))
      scatter(rows, built.pieces, plain)
      b = b + 1'u32
    g = g + 1

proc lensOf(offsets: seq[uint32], first, last: uint32): seq[int] {.role: parser,
    tag: "batch|read".} =
  ## offsets/first/last: each row's length in one packed batch (call after
  ## `spanOf`, which has already checked the table covers these rows). A
  ## stored table running backwards is damage: ValueError, not a crash.
  var
    r: uint32 = first
  while r <= last:
    result.add int(offsets[int(r) + 1]) - int(offsets[int(r)])
    if result[^1] < 0:
      raise newException(ValueError, "damaged data: row-offset table runs backwards at row " & $r)
    r = r + 1'u32

proc spanOf(offsets: seq[uint32], first, last: uint32, n: int): tuple[a, z: int] {.
    role: sanitizer, tag: "batch|read".} =
  ## offsets: a stored (so possibly damaged) row-offset table. first/last:
  ## the batch's rows. n: bytes in the row region. Where the batch starts
  ## and ends; ValueError ("damaged") instead of a crash when the table
  ## points outside the rows or backwards.
  if int(last) + 1 >= offsets.len:
    raise newException(ValueError, "damaged data: row-offset table is too short")
  result = (int(offsets[int(first)]), int(offsets[int(last) + 1]))
  if result.a > result.z or result.z > n:
    raise newException(ValueError, "damaged data: row offsets " & $result.a & ".." &
      $result.z & " lie outside the " & $n & " stored bytes")

## ------------------------- packed (P1) -------------------------------
##
## A packed row is variable length, so a column group is NOT a byte range:
## you cannot locate group G in row i without parsing rows 0..i-1 of that
## row first. Column-group sealing therefore does not apply, and the unit
## becomes the whole row.
##
## That costs nothing this profile wanted. P1 rewrites the entire file on
## save (STORAGE_PLAN 4), so per-column seek was never available to it --
## and sealing whole rows means the null bitmap is covered too, which
## column sealing would have left in clear.

proc sealPacked*(master: Secret, L: var Ledger, s: Schema, rows: var ByteSeq,
    offsets: seq[uint32], rowCount: uint32, databaseId: string,
    schemaVersion: uint16, cipher: CipherKind, keyRef: KeyId,
    treeHash: HashKind = hkBlake3) {.role: encryptor,
    tag: "appApi|batch|cryptoBoundary|write".} =
  ## master/L: key material and the ledger receiving one entry per batch.
  ## s: the cluster's schema, bound into each batch's checks.
  ## rows/offsets/rowCount: the varying cluster, sealed in place.
  ## The offset table stays in CLEAR: encrypting it would make the rows
  ## region un-navigable -- you could not find the row to decrypt without
  ## first decrypting something to learn where it starts. It leaks row
  ## LENGTH, not row content.
  var
    b: uint32 = 0'u32
    first: uint32 = 0'u32
    last: uint32 = 0'u32
    a: int = 0
    z: int = 0
    plain: ByteSeq = @[]
    sealedBytes: ByteSeq = @[]
    rowSlices: seq[ByteSeq] = @[]
    e: LedgerEntry = default(LedgerEntry)
    slot: int = 0
    r: uint32 = 0'u32
    i: int = 0
  if L.batchRows == 0'u32 or rowCount == 0'u32 or offsets.len == 0:
    return
  while b * L.batchRows < rowCount:
    first = b * L.batchRows
    last = min(first + L.batchRows - 1'u32, rowCount - 1'u32)
    a = int(offsets[int(first)])
    z = int(offsets[int(last) + 1])
    plain = rows[a ..< z]
    rowSlices = @[]
    r = first
    while r <= last:
      rowSlices.add rows[int(offsets[int(r)]) ..< int(offsets[int(r) + 1])]
      r = r + 1'u32
    L.ensureCapacity(b)
    slot = int(b) * max(1, L.groups.len)
    e = L.entries[slot]
    e.cipher = cipher
    e.treeHash = treeHash
    e.groupId = 0'u16
    e.batchIndex = b
    if e.keyRef == 0'u64:
      e.keyRef = keyRef
    sealedBytes = sealBatch(master, e, databaseId, schemaVersion, plain,
      rowSlices, clusterBinding(s, rowCount))
    L.entries[slot] = e
    i = 0
    while i < sealedBytes.len:
      rows[a + i] = sealedBytes[i]
      i = i + 1
    b = b + 1'u32

proc openPacked*(master: Secret, L: Ledger, s: Schema, rows: var ByteSeq,
    offsets: seq[uint32], rowCount: uint32, databaseId: string,
    schemaVersion: uint16) {.role: decryptor,
    tag: "appApi|batch|cryptoBoundary|read".} =
  ## master/L/s/rows/offsets/rowCount: the inverse of `sealPacked`.
  var
    b: uint32 = 0'u32
    first: uint32 = 0'u32
    last: uint32 = 0'u32
    a: int = 0
    z: int = 0
    plain: ByteSeq = @[]
    e: LedgerEntry = default(LedgerEntry)
    slot: int = 0
    i: int = 0
  if L.batchRows == 0'u32 or rowCount == 0'u32 or offsets.len == 0:
    return
  while b * L.batchRows < rowCount:
    first = b * L.batchRows
    last = min(first + L.batchRows - 1'u32, rowCount - 1'u32)
    (a, z) = spanOf(offsets, first, last, rows.len)
    slot = int(b) * max(1, L.groups.len)
    if slot >= L.entries.len:
      raise newException(ValueError,
        "ledger is missing batch " & $b & ": the database cannot be " &
        "decrypted without its ledger")
    e = L.entries[slot]
    plain = openBatch(master, e, databaseId, schemaVersion, rows[a ..< z],
      lensOf(offsets, first, last), clusterBinding(s, rowCount))
    i = 0
    while i < plain.len:
      rows[a + i] = plain[i]
      i = i + 1
    b = b + 1'u32

## ------------------------- sealed batches ----------------------------
##
## Where each batch's SEALED bytes sit, worked out from public data only:
## the ledger, the clear offset table (packed rows) and the schema (dense
## rows). This is what lets `checkBatch` run without a key.

proc packedBatch(L: Ledger, rows: ByteSeq, offsets: seq[uint32], b, last: uint32):
    tuple[e: LedgerEntry, sealed: ByteSeq, lens: seq[int]] {.role: parser, inline,
    tag: "batch|cryptoBoundary|read".} =
  ## L/rows/offsets: a packed cluster. b/last: the batch and its last row.
  var
    s: tuple[a, z: int] = spanOf(offsets, b * L.batchRows, last, rows.len)
  if int(b) * max(1, L.groups.len) >= L.entries.len:
    raise newException(ValueError, "ledger is missing batch " & $b)
  result = (L.entries[int(b) * max(1, L.groups.len)], rows[s.a ..< s.z],
    lensOf(offsets, b * L.batchRows, last))

proc denseBatches(L: Ledger, s: Schema, rows: ByteSeq, b, last: uint32):
    seq[tuple[e: LedgerEntry, sealed: ByteSeq, lens: seq[int]]] {.role: parser, inline,
    tag: "batch|cryptoBoundary|read".} =
  ## L/s/rows: a dense cluster. b/last: the batch and its last row; one
  ## result per column group.
  var
    g: int = 0
    built: tuple[pieces: seq[Piece], rowLens: seq[int]] = (@[], @[])
  while g < L.groups.len:
    built = batchPieces(s, rows, b * L.batchRows, last, L.groups[g].slots)
    result.add (L.storedEntry(g, b), gather(rows, built.pieces), built.rowLens)
    g = g + 1

proc sealedBatches*(L: Ledger, s: Schema, rows: ByteSeq, offsets: seq[uint32],
    rowCount: uint32, varying: bool): seq[tuple[e: LedgerEntry, sealed: ByteSeq, lens: seq[int]]] {.
    role: parser, tag: "appApi|batch|cryptoBoundary|read".} =
  ## L: the cluster's ledger. s/rows/offsets/rowCount: the cluster as stored.
  ## varying: packed (whole rows per batch) or dense (column groups).
  ## ValueError when the ledger lacks an entry the rows need.
  var
    b: uint32 = 0'u32
  if L.batchRows == 0'u32 or rowCount == 0'u32 or L.entries.len == 0:
    return
  while b * L.batchRows < rowCount:
    if varying:
      result.add packedBatch(L, rows, offsets, b, L.lastRowOf(b, rowCount))
    else:
      result.add denseBatches(L, s, rows, b, L.lastRowOf(b, rowCount))
    b = b + 1'u32
