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
##
## Every sealed batch carries TWO checks in its ledger entry, both over the
## SEALED bytes and the batch's public position (encrypt-then-check):
##
##   check    made with        key?   answers                          on failure
##   -------  ---------------  -----  -------------------------------  ----------
##   digest   Gimli (unkeyed)  no     "are these the bytes written?"   damaged
##   tag      BLAKE3 (keyed)   yes    "did a key holder write them?"   tampered
##
## The digest lets anyone (a backup tool, a relay, `geist verify`) find a
## damaged batch without the password. Anyone can also RECOMPUTE it, so it
## proves nothing about intent; the tag does, and opening a batch checks
## both before a single byte is decrypted.
##
##   position (public)  = databaseId | groupId | batchIndex | epoch | schema version
##   layout   (public)  = cluster binding | rows in batch | each row's length
##   cluster binding    = BLAKE3(encoded schema | cluster's total row count)
##   bound              = position | layout
##   digest = Gimli-XOF("geist-batch-digest-v1" | len | bound | sealed)
##   tag    = BLAKE3-keyed(macKey, len | bound | sealed)
##
## The layout is what stops a re-split: the row offsets and the schema are
## stored in clear, so without it a reader could be handed the same sealed
## bytes cut at other row boundaries, or read under other field types. The
## total row count is in it too: lowering the count in the index would
## otherwise drop whole trailing batches while every remaining one checks.
##   macKey = BLAKE3-keyed(batchKey, "geist-batch-mac-v1")   -- never the cipher key

import tyr

import runePragmas
import ../types
import ../format
import ./cipher
import ./mac

const
  batchCheckBytes* = 32
    ## Width of both per-batch checks (digest and tag): full strength, fixed.

type
  ColumnGroup* {.role: configurator, tag: "batch|config|cryptoBoundary|types".} = object
    ## groupId: stable identifier bound into the nonce and the AAD.
    ## slots: slot indices encrypted together.
    groupId*: uint16
    slots*: seq[int]

  LedgerEntry* {.role: truthState, tag: "batch|cryptoBoundary|ledger|types".} = object
    ## One (batch, column group) tuple. No nonce -- it derives.
    ## `treeHash` is stored per entry for the same reason `cipher` is: a
    ## database written under one configuration must stay readable after
    ## the configuration changes, so the algorithm travels with the data.
    ## digest/tag: the two checks over the sealed bytes (module notes).
    cipher*: CipherKind
    treeHash*: HashKind
    keyRef*: KeyId
    groupId*: uint16
    batchIndex*: uint32
    epoch*: uint64
    root*: ByteSeq
    digest*: ByteSeq
    tag*: ByteSeq

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

proc clusterBinding*(s: Schema, rowCount: uint32): ByteSeq {.role: encryptor,
    tag: "batch|cryptoBoundary".} =
  ## s/rowCount: a cluster's schema and total row count -> BLAKE3 of the
  ## schema's stored encoding and the count, bound into every batch check
  ## of that cluster (module notes).
  var
    t: ByteSeq = encodeSchema(s)
  t.addU32(rowCount)
  result = geistHash(hkBlake3, t, 32)

proc boundOf*(databaseId: string, e: LedgerEntry, schemaVersion: uint16,
    lens: openArray[int], binding: openArray[uint8]): ByteSeq {.
    role: truthBuilder, tag: "batch|cryptoBoundary".} =
  ## The public data a batch's two checks are bound to (module notes).
  ## lens: each row's length in this batch. binding: see `clusterBinding`.
  result = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  result.addBytes(binding)
  result.addU32(uint32(lens.len))
  for n in lens:
    result.addU32(uint32(n))

proc framed(aad, A: openArray[uint8]): ByteSeq {.role: helper,
    tag: "batch|cryptoBoundary".} =
  ## aad/A: position and sealed bytes, joined with the position's length in
  ## front so no (position, bytes) pair can be re-split into another.
  result.addU32(uint32(aad.len))
  result.addBytes(aad)
  result.addBytes(A)

proc batchDigest*(aad, A: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "batch|cryptoBoundary".} =
  ## aad/A: position and sealed bytes -> the unkeyed Gimli integrity digest.
  ## Public on purpose: anyone may compute it (see `checkBatch`).
  result = geistHash(hkGimli, @(cast[ByteSeq]("geist-batch-digest-v1")) & framed(aad, A),
    batchCheckBytes)

proc batchTag(batchKey: Secret, aad, A: openArray[uint8]): ByteSeq {.
    role: encryptor, tag: "batch|cryptoBoundary".} =
  ## batchKey/aad/A: the keyed BLAKE3 tag. Its key is derived under its own
  ## label, so the MAC never shares a key with either cipher leg.
  var
    macKey: Secret = initSecret(blake3TyrKeyedHash(batchKey.use(),
      cast[ByteSeq]("geist-batch-mac-v1"), 32))
  result = geistKeyedHash(hkBlake3, macKey, framed(aad, A), batchCheckBytes)

proc sealBatch*(master: Secret, e: var LedgerEntry, databaseId: string,
    schemaVersion: uint16, A: openArray[uint8],
    R: seq[ByteSeq], binding: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "appApi|batch|cryptoBoundary|write".} =
  ## master: key material.
  ## binding: the cluster's `clusterBinding`, bound into both checks.
  ## e: ledger entry; its epoch is incremented here, never reused.
  ## databaseId/schemaVersion: AAD components binding the batch in place.
  ## A: concatenated plaintext for this (batch, group).
  ## R: per-row byte slices, used to build the Merkle leaves.
  var
    key: Secret = default(Secret)
    keys: StreamKeys = default(StreamKeys)
    aad: ByteSeq = @[]
    leaves: seq[ByteSeq] = @[]
    lens: seq[int] = @[]
    bound: ByteSeq = @[]
    i: int = 0
  e.epoch = e.epoch + 1'u64
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  aad = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  keys = deriveStreamKeys(key, aad)
  result = applyKeystream(e.cipher, keys, 0'u64, A)
  while i < R.len:
    leaves.add leafHash(key, uint32(i), R[i], e.treeHash)
    lens.add R[i].len
    i = i + 1
  e.root = merkleRoot(leaves, e.treeHash)
  bound = boundOf(databaseId, e, schemaVersion, lens, binding)
  e.digest = batchDigest(bound, result)
  e.tag = batchTag(key, bound, result)

proc checkBatch*(e: LedgerEntry, databaseId: string, schemaVersion: uint16,
    A: openArray[uint8], lens: openArray[int], binding: openArray[uint8]): bool {.
    role: sanitizer, tag: "appApi|batch|cryptoBoundary|read".} =
  ## e/databaseId/schemaVersion: the batch and its public position.
  ## A: its sealed bytes; lens: its row lengths; binding: its cluster's.
  ## Needs NO key: true when they are the bytes, cut and typed as the ledger
  ## says they were written. Proves no intent -- see `openBatch`.
  result = e.digest.len == batchCheckBytes and constantTimeEq(
    batchDigest(boundOf(databaseId, e, schemaVersion, lens, binding), A), e.digest)

proc openBatch*(master: Secret, e: LedgerEntry, databaseId: string,
    schemaVersion: uint16, A: openArray[uint8], lens: openArray[int],
    binding: openArray[uint8]): ByteSeq {.role: decryptor,
    tag: "appApi|batch|cryptoBoundary|read".} =
  ## master/e/databaseId/schemaVersion/binding: as for `sealBatch`.
  ## A: the whole ciphertext for this (batch, group); lens: its row lengths.
  ## Both checks come first; nothing is decrypted from bytes that fail one:
  ##   digest wrong -> IOError "damaged"     (no key needed to see it)
  ##   tag wrong    -> IOError "tampered"    (digest recomputed, or a wrong key)
  var
    key: Secret = default(Secret)
    keys: StreamKeys = default(StreamKeys)
    aad: ByteSeq = @[]
    at: string = " (batch " & $e.batchIndex & ", column group " & $e.groupId & ")"
  key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
  aad = buildAad(databaseId, e.groupId, e.batchIndex, e.epoch, schemaVersion)
  if not checkBatch(e, databaseId, schemaVersion, A, lens, binding):
    raise newException(IOError, "sealed data is damaged" & at &
      ": its bytes do not match the integrity digest in the ledger")
  if e.tag.len != batchCheckBytes or not constantTimeEq(
      batchTag(key, boundOf(databaseId, e, schemaVersion, lens, binding), A), e.tag):
    raise newException(IOError, "sealed data failed authentication" & at &
      ": it was changed after sealing, or this is the wrong key")
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
  ## e: ledger tuple serialised as
  ##   cipher(1) treeHash(1) keyRef(8) groupId(2) batchIndex(4) epoch(8)
  ##   rootLen(4) root  digestLen(4) digest  tagLen(4) tag
  result = @[]
  result.add uint8(ord(e.cipher))
  result.add uint8(ord(e.treeHash))
  result.addU64(e.keyRef)
  result.addU16(e.groupId)
  result.addU32(e.batchIndex)
  result.addU64(e.epoch)
  result.addU32(uint32(e.root.len))
  result.addBytes(e.root)
  result.addU32(uint32(e.digest.len))
  result.addBytes(e.digest)
  result.addU32(uint32(e.tag.len))
  result.addBytes(e.tag)

proc readBlob(A: openArray[uint8], o: var int): ByteSeq {.role: parser,
    tag: "codecBoundary|ledger|read".} =
  ## A/o: a u32 length then that many bytes; o moves past both.
  var
    n: int = int(A.getU32(o))
  if n < 0 or o + 4 + n > A.len:
    raise newException(ValueError, "ledger entry is truncated")
  result = @(A[o + 4 ..< o + 4 + n])
  o = o + 4 + n

proc decodeLedgerEntry*(A: openArray[uint8], o: var int): LedgerEntry {.
    role: parser, tag: "codecBoundary|ledger|read".} =
  ## A/o: buffer and cursor advanced past one encoded ledger tuple.
  result.cipher = enumAt[CipherKind](A[o], "cipher")
  result.treeHash = enumAt[HashKind](A[o + 1], "tree hash")
  result.keyRef = A.getU64(o + 2)
  result.groupId = A.getU16(o + 10)
  result.batchIndex = A.getU32(o + 12)
  result.epoch = A.getU64(o + 16)
  o = o + 24
  result.root = readBlob(A, o)
  result.digest = readBlob(A, o)
  result.tag = readBlob(A, o)

proc needsRekey*(e: LedgerEntry, highWater: uint64 = defaultRekeyAtEpoch): bool {.
    role: parser, inline, tag: "batch|keyLifecycle|read".} =
  ## e: ledger entry whose epoch is checked against the rekey high-water
  ##   mark. Rekeying ONE batch is enough: a fresh keyRef is a fresh nonce
  ##   space, so an epoch approaching wrap never forces a global rekey.
  result = e.epoch >= highWater
