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

import geistPragmas
import ../types
import ./batch

type
  Piece* {.role: truthState, metaTags: {tagBatch, tagCryptoBoundary,
      tagTypes}.} = object
    ## One contiguous run of bytes belonging to a batch, as an offset into
    ## the cluster's row region. There is no second region to point at.
    at*: int
    len*: int

proc piecesFor*(s: Schema, rows: ByteSeq, rowIndex: uint32,
    slots: seq[int]): seq[Piece] {.role: truthBuilder,
    metaTags: {tagBatch, tagCryptoBoundary, tagRead}.} =
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
    metaTags: {tagBatch, tagCryptoBoundary, tagRead}.} =
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
    role: dataWriter, metaTags: {tagBatch, tagCryptoBoundary, tagWrite}.} =
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
    role: truthBuilder, metaTags: {tagBatch, tagCryptoBoundary}.} =
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

proc sealCluster*(master: Secret, L: var Ledger, s: Schema,
    rows: var ByteSeq, rowCount: uint32,
    databaseId: string, schemaVersion: uint16,
    cipher: CipherKind, mac: MacKind, keyRef: KeyId,
    treeHash: HashKind = hkBlake3) {.role: encryptor,
    metaTags: {tagAppApi, tagBatch, tagCryptoBoundary, tagWrite}.} =
  ## master/L: key material and the ledger receiving one entry per batch.
  ## s/rows/rowCount: the cluster being sealed in place.
  ## databaseId/schemaVersion: AAD components binding each batch's position.
  ## cipher/mac/keyRef/treeHash: policy from the configuration. Each is
  ##   recorded in the ledger entry so the data stays readable if the
  ##   configuration later changes.
  var
    g: int = 0
    b: uint32 = 0'u32
    first: uint32 = 0'u32
    last: uint32 = 0'u32
    built: tuple[pieces: seq[Piece], rowLens: seq[int]]
    plain: ByteSeq = @[]
    sealedBytes: ByteSeq = @[]
    rowSlices: seq[ByteSeq] = @[]
    e: LedgerEntry
    slot: int = 0
    o: int = 0
    i: int = 0
  if L.batchRows == 0'u32 or rowCount == 0'u32:
    return
  if not s.isDense():
    raise newException(ValueError,
      "sealCluster needs a dense schema: a column group is only a byte " &
      "range when every row has the same shape. Use sealPacked.")
  while g < L.groups.len:
    b = 0'u32
    while b * L.batchRows < rowCount:
      first = b * L.batchRows
      last = min(first + L.batchRows - 1'u32, rowCount - 1'u32)
      built = batchPieces(s, rows, first, last, L.groups[g].slots)
      plain = gather(rows, built.pieces)
      rowSlices = @[]
      o = 0
      i = 0
      while i < built.rowLens.len:
        rowSlices.add plain[o ..< o + built.rowLens[i]]
        o = o + built.rowLens[i]
        i = i + 1
      L.ensureCapacity(b)
      slot = int(b) * max(1, L.groups.len) + int(L.groups[g].groupId)
      e = L.entries[slot]
      e.cipher = cipher
      e.mac = mac
      e.treeHash = treeHash
      e.groupId = L.groups[g].groupId
      e.batchIndex = b
      if e.keyRef == 0'u64:
        e.keyRef = keyRef
      sealedBytes = sealBatch(master, e, databaseId, schemaVersion, plain,
        rowSlices)
      L.entries[slot] = e
      scatter(rows, built.pieces, sealedBytes)
      b = b + 1'u32
    g = g + 1

proc openCluster*(master: Secret, L: Ledger, s: Schema,
    rows: var ByteSeq, rowCount: uint32,
    databaseId: string, schemaVersion: uint16) {.role: decryptor,
    metaTags: {tagAppApi, tagBatch, tagCryptoBoundary, tagRead}.} =
  ## master/L: key material and the ledger holding each batch's coordinates.
  ## s/rows/rowCount: the cluster decrypted in place.
  ## databaseId/schemaVersion: the same AAD components used when sealing.
  var
    g: int = 0
    b: uint32 = 0'u32
    first: uint32 = 0'u32
    last: uint32 = 0'u32
    built: tuple[pieces: seq[Piece], rowLens: seq[int]]
    cipherBytes: ByteSeq = @[]
    plain: ByteSeq = @[]
    e: LedgerEntry
    slot: int = 0
  if L.batchRows == 0'u32 or rowCount == 0'u32:
    return
  while g < L.groups.len:
    b = 0'u32
    while b * L.batchRows < rowCount:
      first = b * L.batchRows
      last = min(first + L.batchRows - 1'u32, rowCount - 1'u32)
      built = batchPieces(s, rows, first, last, L.groups[g].slots)
      cipherBytes = gather(rows, built.pieces)
      slot = int(b) * max(1, L.groups.len) + int(L.groups[g].groupId)
      if slot >= L.entries.len:
        raise newException(ValueError,
          "ledger is missing batch " & $b & " for column group " &
          $L.groups[g].groupId & ": the database cannot be decrypted " &
          "without its ledger")
      e = L.entries[slot]
      plain = openBatch(master, e, databaseId, schemaVersion, cipherBytes)
      scatter(rows, built.pieces, plain)
      b = b + 1'u32
    g = g + 1

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

proc sealPacked*(master: Secret, L: var Ledger, rows: var ByteSeq,
    offsets: seq[uint32], rowCount: uint32, databaseId: string,
    schemaVersion: uint16, cipher: CipherKind, mac: MacKind, keyRef: KeyId,
    treeHash: HashKind = hkBlake3) {.role: encryptor,
    metaTags: {tagAppApi, tagBatch, tagCryptoBoundary, tagWrite}.} =
  ## master/L: key material and the ledger receiving one entry per batch.
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
    e: LedgerEntry
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
    e.mac = mac
    e.treeHash = treeHash
    e.groupId = 0'u16
    e.batchIndex = b
    if e.keyRef == 0'u64:
      e.keyRef = keyRef
    sealedBytes = sealBatch(master, e, databaseId, schemaVersion, plain,
      rowSlices)
    L.entries[slot] = e
    i = 0
    while i < sealedBytes.len:
      rows[a + i] = sealedBytes[i]
      i = i + 1
    b = b + 1'u32

proc openPacked*(master: Secret, L: Ledger, rows: var ByteSeq,
    offsets: seq[uint32], rowCount: uint32, databaseId: string,
    schemaVersion: uint16) {.role: decryptor,
    metaTags: {tagAppApi, tagBatch, tagCryptoBoundary, tagRead}.} =
  ## master/L/rows/offsets/rowCount: the inverse of `sealPacked`.
  var
    b: uint32 = 0'u32
    first: uint32 = 0'u32
    last: uint32 = 0'u32
    a: int = 0
    z: int = 0
    plain: ByteSeq = @[]
    e: LedgerEntry
    slot: int = 0
    i: int = 0
  if L.batchRows == 0'u32 or rowCount == 0'u32 or offsets.len == 0:
    return
  while b * L.batchRows < rowCount:
    first = b * L.batchRows
    last = min(first + L.batchRows - 1'u32, rowCount - 1'u32)
    a = int(offsets[int(first)])
    z = int(offsets[int(last) + 1])
    slot = int(b) * max(1, L.groups.len)
    if slot >= L.entries.len:
      raise newException(ValueError,
        "ledger is missing batch " & $b & ": the database cannot be " &
        "decrypted without its ledger")
    e = L.entries[slot]
    plain = openBatch(master, e, databaseId, schemaVersion, rows[a ..< z])
    i = 0
    while i < plain.len:
      rows[a + i] = plain[i]
      i = i + 1
    b = b + 1'u32
