## ---------------------------------------------------------------------
## Batch <- two-dimensional encryption units and the keyref ledger
## ---------------------------------------------------------------------
##
##   A batch is (row range x column group).
##
##        columns ->     [group 0]      [group 1]
##   rows  0..N-1        ledger[0][0]   ledger[0][1]
##         N..2N-1       ledger[1][0]   ledger[1][1]
##
##        ledgerRow = floor(rowIndex / batchRows)
##
##   Row 33 with batchRows = 10  ->  ledger row 3.  A column group of one
##   is the degenerate case, so this generalises per-column encryption
##   rather than replacing it.
##
## The nonce is NEVER stored. It derives from
##   (keyRef, groupId, batchIndex, epoch)
## and `epoch` increments on every rewrite of that batch, so re-encrypting
## after an edit cannot reuse a (key, nonce) pair. That failure mode is
## catastrophic for stream ciphers and is the single easiest mistake to
## make with a stored nonce, so the format removes the opportunity.
##
## The AAD binds position. Without it a batch can be moved to a different
## ledger row -- or a different column group under the same key -- and it
## will decrypt cleanly and authenticate. See DESIGN_RATIONALE section 9.

import tyr

import runePragmas
import ../types
import ../format
import ./cipher
import ./mac

type
  ColumnGroup* {.role: configurator, tag: "batch|config|cryptoBoundary|types".} = object
    ## groupId: stable identifier bound into the nonce and the AAD.
    ## slots: slot indices encrypted together.
    groupId*: uint16
    slots*: seq[int]

  LedgerEntry* {.role: truthState, tag: "batch|cryptoBoundary|ledger|types".} = object
    ## One (batch, column group) tuple. No nonce -- it derives.
    ## `treeHash` is stored per entry for the same reason `cipher` and
    ## `mac` are: a database written under one configuration must stay
    ## readable after the configuration changes, so the algorithm travels
    ## with the data rather than with the caller.
    cipher*: CipherKind
    mac*: MacKind
    treeHash*: HashKind
    keyRef*: KeyId
    groupId*: uint16
    batchIndex*: uint32
    epoch*: uint64
    root*: ByteSeq

  Ledger* {.role: truthState, tag: "batch|ledger|types".} = object
    ## Rows are batches, columns are groups. Lookup is O(1) division;
    ## no scan, because the mapping is arithmetic.
    databaseId*: string
    batchRows*: uint32
    groups*: seq[ColumnGroup]
    entries*: seq[LedgerEntry]

proc ledgerRowOf*(rowIndex: uint32, batchRows: uint32): uint32 {.role: math,
    inline, tag: "batch|read".} =
  ## rowIndex: data row.
  ## batchRows: N. Row 33 with N=10 lands in ledger row 3.
  if batchRows == 0'u32:
    return 0'u32
  result = rowIndex div batchRows

proc entrySlot(L: Ledger, batchIndex: uint32, groupId: uint16): int {.
    role: parser, tag: "batch|ledger|read".} =
  ## L/batchIndex/groupId: ledger coordinates resolved to a storage index.
  result = int(batchIndex) * max(1, L.groups.len) + int(groupId)

proc ensureCapacity*(L: var Ledger, batchIndex: uint32) {.
    role: actor, tag: "batch|ledger|write".} =
  ## L: ledger grown so `batchIndex` is addressable for every group.
  var
    need: int = 0
  need = (int(batchIndex) + 1) * max(1, L.groups.len)
  while L.entries.len < need:
    L.entries.add LedgerEntry()

proc entryAt*(L: Ledger, batchIndex: uint32,
    groupId: uint16): LedgerEntry {.role: parser,
    tag: "appApi|batch|ledger|read".} =
  ## L/batchIndex/groupId: direct arithmetic lookup, no search.
  var
    i: int = 0
  i = L.entrySlot(batchIndex, groupId)
  if i >= 0 and i < L.entries.len:
    result = L.entries[i]

proc buildAad*(databaseId: string, groupId: uint16, batchIndex: uint32,
    epoch: uint64, schemaVersion: uint16): ByteSeq {.role: truthBuilder,
    tag: "batch|cryptoBoundary".} =
  ## databaseId/groupId/batchIndex/epoch/schemaVersion: the full position
  ## of this batch. Authenticating it is what stops a batch being relocated.
  result = @[]
  result.addText(databaseId)
  result.addU16(groupId)
  result.addU32(batchIndex)
  result.addU64(epoch)
  result.addU16(schemaVersion)

proc deriveBatchKey*(master: Secret, keyRef: KeyId, groupId: uint16,
    batchIndex: uint32, epoch: uint64): Secret {.role: encryptor,
    tag: "batch|cryptoBoundary|keyLifecycle".} =
  ## master: long-lived key material from the key file.
  ## keyRef/groupId/batchIndex/epoch: full batch coordinates. A new keyRef
  ##   is a fresh nonce space, which is what makes per-batch rekey safe.
  var
    info: ByteSeq = @[]
  info = @(cast[ByteSeq]("geist-batch-key-v1"))
  info.addU64(keyRef)
  info.addU16(groupId)
  info.addU32(batchIndex)
  info.addU64(epoch)
  result = initSecret(blake3TyrKeyedHash(master.use(), info, 32))

proc sealBatch*(master: Secret, e: var LedgerEntry, databaseId: string,
    schemaVersion: uint16, A: openArray[uint8],
    R: seq[ByteSeq]): ByteSeq {.role: encryptor,
    tag: "appApi|batch|cryptoBoundary|write".} =
  ## master: key material.
  ## e: ledger entry; its epoch is incremented here, never reused.
  ## databaseId/schemaVersion: AAD components binding the batch in place.
  ## A: concatenated plaintext for this (batch, group).
  ## R: per-row byte slices, used to build the Merkle leaves.
  var
    key: Secret = default(Secret)
    keys: StreamKeys = default(StreamKeys)
    aad: ByteSeq = @[]
    leaves: seq[ByteSeq] = @[]
    i: int = 0
  e.epoch = e.epoch + 1'u64
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  aad = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  keys = deriveStreamKeys(key, aad)
  result = applyKeystream(e.cipher, keys, 0'u64, A)
  while i < R.len:
    leaves.add leafHash(key, uint32(i), R[i], e.treeHash)
    i = i + 1
  e.root = merkleRoot(leaves, e.treeHash)

proc openBatch*(master: Secret, e: LedgerEntry, databaseId: string,
    schemaVersion: uint16, A: openArray[uint8]): ByteSeq {.role: decryptor,
    tag: "appApi|batch|cryptoBoundary|read".} =
  ## master/e/databaseId/schemaVersion: as for `sealBatch`.
  ## A: the whole ciphertext for this (batch, group).
  var
    key: Secret = default(Secret)
    keys: StreamKeys = default(StreamKeys)
    aad: ByteSeq = @[]
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  aad = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  keys = deriveStreamKeys(key, aad)
  result = applyKeystream(e.cipher, keys, 0'u64, A)

proc openRow*(master: Secret, e: LedgerEntry, databaseId: string,
    schemaVersion: uint16, byteOffset: uint64,
    A: openArray[uint8]): ByteSeq {.role: decryptor,
    tag: "appApi|batch|cryptoBoundary|read".} =
  ## Decrypt ONE row out of a batch without touching the others.
  ## byteOffset: that row's offset inside the batch payload.
  ## Only valid for a seekable cipher; callers must check `isSeekable`
  ## and fall back to `openBatch` otherwise.
  var
    key: Secret = default(Secret)
    keys: StreamKeys = default(StreamKeys)
    aad: ByteSeq = @[]
  if not isSeekable(e.cipher):
    raise newException(ValueError,
      "cipher " & $e.cipher & " cannot decrypt a single row; use openBatch")
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  aad = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  keys = deriveStreamKeys(key, aad)
  result = applyKeystream(e.cipher, keys, byteOffset, A)

proc verifyRow*(master: Secret, e: LedgerEntry, rowIndex: uint32,
    rowPlain: openArray[uint8], proof: seq[ByteSeq]): bool {.
    role: sanitizer, tag: "appApi|batch|cryptoBoundary|read".} =
  ## Verify one row against the batch root with a log2(N) sibling path
  ## instead of re-hashing every row in the batch.
  var
    key: Secret = default(Secret)
    leaf: ByteSeq = @[]
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  leaf = leafHash(key, rowIndex, rowPlain, e.treeHash)
  result = verifyMerkle(leaf, int(rowIndex), proof, e.root, e.treeHash)

proc encodeLedgerEntry*(e: LedgerEntry): ByteSeq {.role: encryptor,
    tag: "codecBoundary|ledger|write".} =
  ## e: ledger tuple serialised as algo | keyRef | epoch | root.
  result = @[]
  result.add uint8(ord(e.cipher))
  result.add uint8(ord(e.mac))
  result.add uint8(ord(e.treeHash))
  result.addU64(e.keyRef)
  result.addU16(e.groupId)
  result.addU32(e.batchIndex)
  result.addU64(e.epoch)
  result.addU32(uint32(e.root.len))
  result.addBytes(e.root)

proc decodeLedgerEntry*(A: openArray[uint8], o: var int): LedgerEntry {.
    role: parser, tag: "codecBoundary|ledger|read".} =
  ## A/o: buffer and cursor advanced past one encoded ledger tuple.
  var
    n: int = 0
    i: int = 0
  result.cipher = CipherKind(A[o])
  result.mac = MacKind(A[o + 1])
  result.treeHash = HashKind(A[o + 2])
  result.keyRef = A.getU64(o + 3)
  result.groupId = A.getU16(o + 11)
  result.batchIndex = A.getU32(o + 13)
  result.epoch = A.getU64(o + 17)
  n = int(A.getU32(o + 25))
  o = o + 29
  result.root = newSeq[uint8](n)
  while i < n:
    result.root[i] = A[o + i]
    i = i + 1
  o = o + n

proc needsRekey*(e: LedgerEntry, highWater: uint64 = defaultRekeyAtEpoch): bool {.
    role: parser, inline, tag: "batch|keyLifecycle|read".} =
  ## e: ledger entry whose epoch is checked against the rekey high-water
  ##   mark. Rekeying ONE batch is enough: a fresh keyRef is a fresh nonce
  ##   space, so an epoch approaching wrap never forces a global rekey.
  result = e.epoch >= highWater
