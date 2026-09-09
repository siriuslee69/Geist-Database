## ---------------------------------------------------------------------
## Keys <- key file, generation manifest, and graceful rekey
## ---------------------------------------------------------------------
##
##   <name>.keys     master key material, sealed under an Argon2id key
##   <name>.ledger   algo | keyRef | epoch | root   (public, integrity only)
##   current         one line naming the live generation
##
## The manifest exists because THREE files must swap together. Renaming
## them one at a time leaves a window where the data is generation N+1 and
## the ledger is still N, which is unrecoverable. Only `current` is
## renamed, and rename() is atomic on POSIX and via MoveFileEx on Windows.
##
##   1. take write lock          readers continue on generation N
##   2. write generation N+1     .ge1st.gN / .keys.gN / .ledger.gN
##   3. fsync, verify
##   4. rename current -> N+1    <- the ONLY atomic step
##   5. retain N until N+1 survives one clean cycle
##
## Rekey is PER BATCH first. A fresh keyRef is a fresh nonce space, so an
## epoch approaching its high-water mark never forces a global rewrite.
## Global rekey is reserved for key compromise and policy rotation.
##
## 2-of-2: an encrypted database without BOTH the key file and the ledger
## is unrecoverable, because the ledger holds the epochs the nonces derive
## from. That is intentional -- and a footgun. Back up all three together.

import std/[os, strutils]

import tyr

import runePragmas
import ./types
import ./durable
import ./format
import ./crypto/cipher
import ./crypto/mac
import ./crypto/batch

const
  manifestName* = "current"
  keySuffix* = ".keys"
  ledgerSuffix* = ".ledger"
  argonPasses* = 3
  argonMemoryKiB* = 65536
  argonLanes* = 4
  keyFileMagic* = "GEKEY\x02"

type
  KeySet* {.role: truthState, tag: "cryptoBoundary|keyLifecycle|types".} = object
    ## master: the root secret every batch key derives from.
    ## records: the public key ledger rows.
    ## nextKeyRef: monotonic allocator for per-batch key references.
    master*: Secret
    records*: seq[KeyRecord]
    nextKeyRef*: KeyId

  Generation* {.role: truthState, tag: "keyLifecycle|storageIo|types".} = object
    ## The manifest contents: which generation is live, and since when.
    number*: uint64
    dataPath*: string
    keyPath*: string
    ledgerPath*: string
    updatedAt*: uint64

proc generationSuffix*(n: uint64): string {.role: helper,
    tag: "keyLifecycle|storageIo".} =
  ## n: generation number rendered as the `.gN` filename suffix.
  result = ".g" & $n

proc generationPaths*(baseDir, baseName: string, n: uint64): Generation {.
    role: configurator, tag: "keyLifecycle|storageIo".} =
  ## baseDir/baseName: store root and database stem.
  ## n: generation whose three artifact paths are produced as a set.
  var
    sfx: string = ""
  sfx = generationSuffix(n)
  result.number = n
  result.dataPath = baseDir / (baseName & ".ge1st" & sfx)
  result.keyPath = baseDir / (baseName & keySuffix & sfx)
  result.ledgerPath = baseDir / (baseName & ledgerSuffix & sfx)

proc manifestPath*(baseDir: string): string {.role: helper,
    tag: "keyLifecycle|storageIo".} =
  ## baseDir: store root holding the single atomic swap point.
  result = baseDir / manifestName

proc readManifest*(baseDir: string): tuple[ok: bool, n: uint64, err: string] {.
    role: dataFetcher, tag: "keyLifecycle|read|storageIo".} =
  ## baseDir: store root whose live generation number is read.
  var
    p: string = ""
    raw: string = ""
  p = manifestPath(baseDir)
  if not fileExists(p):
    return (false, 0'u64, "no generation manifest at " & p)
  raw = readFile(p).strip()
  try:
    result = (true, parseBiggestUInt(raw).uint64, "")
  except ValueError:
    result = (false, 0'u64, "malformed generation manifest: " & raw)

proc commitManifest*(baseDir: string, n: uint64): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "keyLifecycle|storageIo|write".} =
  ## baseDir: store root.
  ## n: generation to publish. Written to a temporary file, fsynced and
  ## renamed over, so a reader never observes a half-written manifest and a
  ## power cut never leaves one behind. THE atomic step of a save.
  var
    p: string = ""
  p = manifestPath(baseDir)
  result = replaceDurable(p, $n & "\n")

proc generationArtifacts*(baseDir, baseName: string, n: uint64,
    encrypted: bool): seq[string] {.role: helper,
    tag: "backup|keyLifecycle|storageIo".} =
  ## baseDir/baseName: store root and database stem.
  ## n: generation whose files are named as a SET.
  ## encrypted: false leaves out the key and ledger, which do not exist for
  ##   a plaintext database.
  var
    g: Generation
  g = generationPaths(baseDir, baseName, n)
  result = @[g.dataPath]
  if encrypted:
    result.add g.keyPath
    result.add g.ledgerPath

proc retireGeneration*(baseDir, baseName: string, n: uint64): int {.
    role: dataWriter, tag: "keyLifecycle|storageIo|write",
    discardable.} =
  ## baseDir/baseName: store root and stem.
  ## n: generation removed, whatever it consists of. Returns how many files
  ##   went, so a caller can log a retirement that found nothing.
  ##
  ## Called for generation N-1 AFTER N+1 is committed, which is the
  ## "retain N until N+1 survives one clean cycle" rule: at any instant the
  ## disk holds the live generation and the one before it, so a manifest
  ## that fails to load still has a complete set to fall back to.
  var
    A: seq[string] = @[]
    i: int = 0
  if n == 0'u64:
    return 0
  A = generationArtifacts(baseDir, baseName, n, true)
  while i < A.len:
    if fileExists(A[i]):
      try:
        removeFile(A[i])
        result = result + 1
      except CatchableError:
        discard
    i = i + 1

proc sweepUncommitted*(baseDir, baseName: string, live: uint64): int {.
    role: dataWriter, tag: "keyLifecycle|storageIo|write",
    discardable.} =
  ## baseDir/baseName: store root and stem.
  ## live: the committed generation. Anything ABOVE it was being written
  ##   when a process died: it was never published, so nobody has ever read
  ##   it and nobody ever will.
  ##
  ## Call ONLY while holding the write lease. Without it, a generation above
  ## the live one is not debris -- it is another process's save in progress.
  ##
  ## Stops at the first gap, so a single surviving high-numbered file cannot
  ## make this walk forever.
  var
    n: uint64 = 0'u64
    removed: int = 0
  n = live + 1'u64
  while fileExists(generationPaths(baseDir, baseName, n).dataPath):
    removed = retireGeneration(baseDir, baseName, n)
    result = result + removed
    n = n + 1'u64

proc liveGeneration*(baseDir: string): uint64 {.role: parser,
    tag: "keyLifecycle|read|storageIo".} =
  ## baseDir: store root whose committed generation number is returned.
  ## One before any file was ever committed, so a fresh directory and a
  ## first-generation database name the same paths.
  var
    m: tuple[ok: bool, n: uint64, err: string]
  m = readManifest(baseDir)
  result = if m.ok: m.n else: 1'u64

proc liveDataPath*(baseDir: string, baseName: string = "main"): string {.
    role: parser, tag: "appApi|keyLifecycle|read|storageIo".} =
  ## baseDir/baseName: store root and stem.
  ##
  ## The path an OBSERVER should read. A save publishes a new generation, so
  ## the file name changes underneath anyone holding a fixed one -- resolve
  ## it through the manifest each time rather than remembering it.
  result = generationPaths(baseDir, baseName, liveGeneration(baseDir)).dataPath

## ---------------------------- key file ------------------------------

proc deriveFileKey(password: string, salt: openArray[uint8]): Secret {.
    role: encryptor, tag: "cryptoBoundary|keyLifecycle".} =
  ## password: operator credential.
  ## salt: per-file random salt stored in clear beside the ciphertext.
  result = initSecret(argon2idTyrHash(cast[seq[byte]](password), salt,
    argonPasses, argonMemoryKiB, argonLanes, 32))

proc newKeySet*(): KeySet {.role: configurator,
    tag: "cryptoBoundary|keyLifecycle".} =
  ## Allocate a fresh master secret and an empty key ledger.
  result.master = initSecret(cryptoRandomBytes(32))
  result.nextKeyRef = 1'u64

proc allocKeyRef*(K: var KeySet, label: string): KeyId {.role: actor,
    tag: "cryptoBoundary|keyLifecycle|ledger|write".} =
  ## K: key set whose allocator advances.
  ## label: human-readable purpose recorded in the ledger.
  var
    r: KeyRecord
  result = K.nextKeyRef
  K.nextKeyRef = K.nextKeyRef + 1'u64
  r.keyId = result
  r.label = label
  r.createdAt = 0'u64
  K.records.add r

proc writeKeyFile*(path, password: string, K: KeySet): tuple[ok: bool,
    err: string] {.role: dataWriter, tag: "cryptoBoundary|keyLifecycle|storageIo|write".} =
  ## path: `<name>.keys` destination.
  ## password: credential whose Argon2id output seals the master secret.
  ## K: key set being persisted.
  var
    salt: ByteSeq = @[]
    fileKey: Secret
    keys: StreamKeys
    body: ByteSeq = @[]
    sealedMaster: ByteSeq = @[]
    tag: ByteSeq = @[]
    buf: ByteSeq = @[]
    i: int = 0
  salt = @(cryptoRandomBytes(16))
  fileKey = deriveFileKey(password, salt)
  keys = deriveStreamKeys(fileKey, salt)
  sealedMaster = applyKeystream(ckCascade, keys, 0'u64, K.master.use())
  body.addU64(K.nextKeyRef)
  body.addU32(uint32(K.records.len))
  while i < K.records.len:
    body.addU64(K.records[i].keyId)
    body.addText(K.records[i].label)
    body.addU16(K.records[i].purpose)
    body.addU64(K.records[i].createdAt)
    body.addU64(K.records[i].retiredAt)
    i = i + 1
  tag = authTag(mkCombined, fileKey, sealedMaster & body, salt)
  buf = @(cast[ByteSeq](keyFileMagic))
  buf.addU32(uint32(salt.len));        buf.addBytes(salt)
  buf.addU32(uint32(sealedMaster.len));buf.addBytes(sealedMaster)
  buf.addU32(uint32(tag.len));         buf.addBytes(tag)
  buf.addU32(uint32(body.len));        buf.addBytes(body)
  result = writeDurable(path, buf)

proc readKeyFile*(path, password: string): tuple[ok: bool, keys: KeySet,
    err: string] {.role: dataFetcher, tag: "cryptoBoundary|keyLifecycle|read|storageIo".} =
  ## path: `<name>.keys` source.
  ## password: credential; a wrong one fails the tag check, not the parse.
  var
    raw: ByteSeq = @[]
    o: int = 0
    salt: ByteSeq = @[]
    sealedMaster: ByteSeq = @[]
    tag: ByteSeq = @[]
    body: ByteSeq = @[]
    fileKey: Secret
    strm: StreamKeys
    n: int = 0
    i: int = 0
    bo: int = 0
    r: KeyRecord
  if not fileExists(path):
    return (false, KeySet(), "no key file at " & path)
  raw = cast[ByteSeq](readFile(path))
  if raw.len < keyFileMagic.len:
    return (false, KeySet(), "key file is truncated")
  while i < keyFileMagic.len:
    if raw[i] != uint8(keyFileMagic[i]):
      return (false, KeySet(), "not a Geist key file")
    i = i + 1
  o = keyFileMagic.len
  n = int(raw.getU32(o)); o = o + 4
  salt = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  sealedMaster = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  tag = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  body = raw[o ..< o + n]
  fileKey = deriveFileKey(password, salt)
  if not verifyTag(mkCombined, fileKey, sealedMaster & body, salt, tag):
    return (false, KeySet(), "key file rejected: wrong password or tampering")
  strm = deriveStreamKeys(fileKey, salt)
  result.keys.master = initSecret(applyKeystream(ckCascade, strm, 0'u64,
    sealedMaster))
  result.keys.nextKeyRef = body.getU64(0)
  n = int(body.getU32(8))
  bo = 12
  i = 0
  while i < n:
    r = KeyRecord()
    r.keyId = body.getU64(bo); bo = bo + 8
    r.label = body.readText(bo)
    r.purpose = body.getU16(bo); bo = bo + 2
    r.createdAt = body.getU64(bo); bo = bo + 8
    r.retiredAt = body.getU64(bo); bo = bo + 8
    result.keys.records.add r
    i = i + 1
  result.ok = true

## ----------------------------- ledger -------------------------------

proc encodeLedger(L: Ledger): ByteSeq {.role: encryptor,
    tag: "codecBoundary|ledger|write".} =
  ## L: one ledger serialised as groups followed by batch entries.
  var
    i: int = 0
    j: int = 0
  result = @[]
  result.addText(L.databaseId)
  result.addU32(L.batchRows)
  result.addU32(uint32(L.groups.len))
  while i < L.groups.len:
    result.addU16(L.groups[i].groupId)
    result.addU32(uint32(L.groups[i].slots.len))
    j = 0
    while j < L.groups[i].slots.len:
      result.addU32(uint32(L.groups[i].slots[j]))
      j = j + 1
    i = i + 1
  i = 0
  result.addU32(uint32(L.entries.len))
  while i < L.entries.len:
    result.addBytes(encodeLedgerEntry(L.entries[i]))
    i = i + 1

proc decodeLedger(A: openArray[uint8], o: var int): Ledger {.role: parser,
    tag: "codecBoundary|ledger|read".} =
  ## A/o: buffer and cursor advanced past one encoded ledger.
  var
    n: int = 0
    i: int = 0
    j: int = 0
    g: ColumnGroup
  result.databaseId = A.readText(o)
  result.batchRows = A.getU32(o); o = o + 4
  n = int(A.getU32(o)); o = o + 4
  while i < n:
    g = ColumnGroup()
    g.groupId = A.getU16(o); o = o + 2
    j = int(A.getU32(o)); o = o + 4
    while g.slots.len < j:
      g.slots.add int(A.getU32(o))
      o = o + 4
    result.groups.add g
    i = i + 1
  n = int(A.getU32(o)); o = o + 4
  i = 0
  while i < n:
    result.entries.add decodeLedgerEntry(A, o)
    i = i + 1

proc writeLedgerFile*(path: string, L: openArray[Ledger]): tuple[ok: bool,
    err: string] {.role: dataWriter,
    tag: "ledger|storageIo|write".} =
  ## path: `<name>.ledger` destination.
  ## L: one ledger per sealed cluster, in cluster order. Public material:
  ## it needs integrity, NOT confidentiality. Only the key file is secret.
  ## Getting this backwards is a common error.
  var
    buf: ByteSeq = @[]
    i: int = 0
  buf.addU32(uint32(L.len))
  while i < L.len:
    buf.addBytes(encodeLedger(L[i]))
    i = i + 1
  buf.addBytes(blake3TyrHash(buf, 32))
  result = writeDurable(path, buf)

proc readLedgerFile*(path: string): tuple[ok: bool, ledgers: seq[Ledger],
    err: string] {.role: dataFetcher,
    tag: "ledger|read|storageIo".} =
  ## path: `<name>.ledger` source; the trailing hash is checked first.
  var
    raw: ByteSeq = @[]
    o: int = 0
    n: int = 0
    i: int = 0
    check: ByteSeq = @[]
  if not fileExists(path):
    return (false, @[], "no ledger file at " & path)
  raw = cast[ByteSeq](readFile(path))
  if raw.len < 36:
    return (false, @[], "ledger file is truncated")
  check = @(blake3TyrHash(raw[0 ..< raw.len - 32], 32))
  while i < 32:
    if check[i] != raw[raw.len - 32 + i]:
      return (false, @[], "ledger file failed integrity check")
    i = i + 1
  n = int(raw.getU32(o)); o = o + 4
  i = 0
  while i < n:
    result.ledgers.add decodeLedger(raw, o)
    i = i + 1
  result.ok = true

## ----------------------------- rekey --------------------------------

proc rekeyBatch*(K: var KeySet, L: var Ledger, batchIndex: uint32,
    groupId: uint16): KeyId {.role: actor,
    tag: "batch|cryptoBoundary|keyLifecycle|write".} =
  ## K/L: key set and ledger.
  ## batchIndex/groupId: the ONE batch being re-keyed.
  ## A new keyRef is a fresh nonce space, so an epoch nearing its
  ## high-water mark is handled here without a global rewrite. The caller
  ## must re-seal that batch's payload with the returned reference.
  var
    i: int = 0
    previous: KeyId = 0'u64
  i = int(batchIndex) * max(1, L.groups.len) + int(groupId)
  L.ensureCapacity(batchIndex)
  if i < L.entries.len:
    previous = L.entries[i].keyRef
  # A ledger loaded from disk can reference a keyRef the allocator has not
  # caught up to. Handing back the same reference would reset the epoch on
  # an UNCHANGED key, which is exactly the (key, nonce) reuse this design
  # exists to prevent -- so advance past it rather than trusting the counter.
  if K.nextKeyRef <= previous:
    K.nextKeyRef = previous + 1'u64
  result = K.allocKeyRef("rekey-b" & $batchIndex & "-g" & $groupId)
  if i < L.entries.len:
    L.entries[i].keyRef = result
    L.entries[i].epoch = 0'u64

proc batchesNeedingRekey*(L: Ledger,
    highWater: uint64 = defaultRekeyAtEpoch): seq[tuple[batchIndex: uint32,
    groupId: uint16]] {.role: parser,
    tag: "batch|keyLifecycle|read|status".} =
  ## L: ledger scanned for batches approaching epoch wrap.
  ## highWater: threshold; the default is far below any u64 wrap so the
  ## rekey happens long before it could ever be needed.
  var
    i: int = 0
  while i < L.entries.len:
    if L.entries[i].needsRekey(highWater):
      result.add (batchIndex: L.entries[i].batchIndex,
        groupId: L.entries[i].groupId)
    i = i + 1
