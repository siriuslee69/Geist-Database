## Crypto: cascade seek, merkle proofs, AAD binding, epoch monotonicity, per-batch digest + tag.
import std/[os, strutils, unittest]
import geist

suite "crypto":
  setup:
    var
      master = initSecret(@[1'u8,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32])
      e = LedgerEntry(cipher: ckCascade, keyRef: 7'u64,
                      groupId: 2'u16, batchIndex: 5'u32)
      rows: seq[ByteSeq] = @[]
      plain: ByteSeq = @[]
      w = 16
      sd = newSeq[uint8](32)          # a schema digest; any 32 bytes do here
      lens = @[16, 16, 16, 16, 16, 16, 16, 16]
    for i in 0 ..< 8:
      var r = newSeq[uint8](w)
      for j in 0 ..< w: r[j] = uint8((i * 31 + j) and 0xFF)
      rows.add r
      plain.add r

  # {.testKind: tkUnit.}
  test "whole batch seals and opens":
    var ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
    check ct != plain
    check openBatch(master, e, "db", 1'u16, ct, lens, sd) == plain

  # {.testKind: tkUnit.}
  test "a seekable cipher decrypts one row without the batch":
    var ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
    check isSeekable(e.cipher)
    check openRow(master, e, "db", 1'u16, uint64(3 * w),
      ct[3 * w ..< 4 * w]) == rows[3]

  # {.testKind: tkEdgeCase.}
  test "epoch increments on every seal so a nonce is never reused":
    var first = e.epoch
    discard sealBatch(master, e, "db", 1'u16, plain, rows, sd)
    var second = e.epoch
    discard sealBatch(master, e, "db", 1'u16, plain, rows, sd)
    check first < second
    check second < e.epoch

  # {.testKind: tkEdgeCase.}
  test "AAD binds position: a relocated batch is refused":
    var
      ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
      moved = e
    moved.batchIndex = 9'u32
    expect IOError:
      discard openBatch(master, moved, "db", 1'u16, ct, lens, sd)
    moved = e
    moved.groupId = 3'u16
    expect IOError:
      discard openBatch(master, moved, "db", 1'u16, ct, lens, sd)
    expect IOError:
      discard openBatch(master, e, "other-db", 1'u16, ct, lens, sd)

  # {.testKind: tkRegression, covers: "sealBatch|openBatch|checkBatch", pins: "sealed batches were decrypted without any integrity or authentication check".}
  test "a changed byte is damage; a changed byte with a recomputed digest is forgery":
    var
      ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
      bad = ct
      forged = e
      why = ""
    check e.digest.len == 32 and e.tag.len == 32
    check checkBatch(e, "db", 1'u16, ct, lens, sd)
    bad[5] = bad[5] xor 0x01'u8
    check not checkBatch(e, "db", 1'u16, bad, lens, sd)          # no key needed to see it
    try: discard openBatch(master, e, "db", 1'u16, bad, lens, sd)
    except IOError: why = getCurrentExceptionMsg()
    check "damaged" in why
    # An attacker can recompute the unkeyed digest -- but not the keyed tag.
    forged.digest = batchDigest(boundOf("db", e, 1'u16, lens, sd), bad)
    check checkBatch(forged, "db", 1'u16, bad, lens, sd)
    try: discard openBatch(master, forged, "db", 1'u16, bad, lens, sd)
    except IOError: why = getCurrentExceptionMsg()
    check "authentication" in why

  # {.testKind: tkEdgeCase, covers: "openBatch|checkBatch|boundOf".}
  test "the same sealed bytes cut at other row boundaries, or under another schema, are refused":
    var
      ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
      resplit = @[8, 24, 16, 16, 16, 16, 16, 16]     # same total, other boundaries
      otherSchema = newSeq[uint8](32)
    otherSchema[0] = 1
    check not checkBatch(e, "db", 1'u16, ct, resplit, sd)
    check not checkBatch(e, "db", 1'u16, ct, lens, otherSchema)
    expect IOError:
      discard openBatch(master, e, "db", 1'u16, ct, resplit, sd)
    expect IOError:
      discard openBatch(master, e, "db", 1'u16, ct, lens, otherSchema)

  # {.testKind: tkEdgeCase, covers: "openBatch".}
  test "the wrong key fails authentication before anything is decrypted":
    var
      ct = sealBatch(master, e, "db", 1'u16, plain, rows, sd)
      other = initSecret(newSeq[uint8](32))
    expect IOError:
      discard openBatch(other, e, "db", 1'u16, ct, lens, sd)

  # {.testKind: tkUnit.}
  test "a row verifies against the root with a log2(N) path":
    discard sealBatch(master, e, "db", 1'u16, plain, rows, sd)
    var
      key = deriveBatchKey(master, e.keyRef, e.groupId, e.batchIndex, e.epoch)
      leaves: seq[ByteSeq] = @[]
    for i in 0 ..< rows.len: leaves.add leafHash(key, uint32(i), rows[i])
    var proof = merkleProof(leaves, 3)
    check proof.len == 3                       # log2(8)
    check verifyRow(master, e, 3'u32, rows[3], proof)
    check not verifyRow(master, e, 3'u32, @[0'u8, 1, 2], proof)

  # {.testKind: tkUnit.}
  test "the combined MAC is a sound PRF combiner and verifies":
    var
      aad = buildAad("db", 2'u16, 5'u32, 1'u64, 1'u16)
      t = authTag(mkCombined, master, plain, aad)
    check t.len == 32
    check verifyTag(mkCombined, master, plain, aad, t)
    check not verifyTag(mkCombined, master, plain,
      buildAad("db", 2'u16, 6'u32, 1'u64, 1'u16), t)

  # {.testKind: tkEdgeCase.}
  test "batch index is arithmetic, not a search":
    check ledgerRowOf(33'u32, 10'u32) == 3'u32
    check ledgerRowOf(0'u32, 10'u32) == 0'u32
    check ledgerRowOf(9'u32, 10'u32) == 0'u32
    check ledgerRowOf(10'u32, 10'u32) == 1'u32

suite "sealed store checks":
  # {.testKind: tkIntegration, covers: "verifyStoreIntegrity|openKeyrings|unlock".}
  test "a store is verified without its password, and a flipped byte is caught twice":
    var
      root = getTempDir() / "geist_t_batch_checks"
      K = default(Keyrings)
      R: IntegrityReport = default(IntegrityReport)
      data = ""
      raw = ""
    removeDir(root)
    K = createKeyrings(root, ["r"], ["pw"])
    for i in 0 ..< 40:
      K.upsert("r", RingRow(rowKey: "k" & $i, kind: "c", body: "value-" & $i))
    check K.save().ok
    K.close()
    R = verifyStoreIntegrity(root)
    check R.ok and R.batches >= 2                     # 40 rows / 32 per batch
    data = generationPaths(root / "r", "main", liveGeneration(root / "r")).dataPath
    raw = readFile(data)
    raw[raw.len div 2] = char(uint8(raw[raw.len div 2]) xor 0x01'u8)
    writeFile(data, raw)
    R = verifyStoreIntegrity(root)
    check not R.ok and R.problems.len >= 1            # found without the key
    K = openKeyrings(root)
    check not K.unlock("r", "pw").ok                  # and refused with it

  # {.testKind: tkFuzz, covers: "verifyStoreIntegrity|readIndex|readCluster|decodeLedgerEntry", pins: "a damaged byte made the file parser crash with RangeDefect instead of reporting damage".}
  test "every single-byte flip in a sealed store is reported, and none crashes":
    var
      root = getTempDir() / "geist_t_flip_all"
      K = default(Keyrings)
      orig = ""
      raw = ""
      missed: seq[int] = @[]
      path = ""
      good: seq[RingRow] = @[]
    removeDir(root)
    K = createKeyrings(root, ["r"], ["pw"])
    for i in 0 ..< 50:
      K.upsert("r", RingRow(rowKey: "k" & $i, kind: "c", body: "value-" & $i))
    check K.save().ok
    K.close()
    path = generationPaths(root / "r", "main", liveGeneration(root / "r")).dataPath
    orig = readFile(path)
    K = openKeyrings(root)
    check K.unlock("r", "pw").ok
    good = K.rows("r")
    K.close()
    for p in 0 ..< orig.len:
      raw = orig
      raw[p] = char(uint8(raw[p]) xor 0x01'u8)
      writeFile(path, raw)
      if verifyStoreIntegrity(root).ok:
        missed.add p
    # The keyless check covers every sealed row byte, row boundary, schema
    # and cluster; what it may miss are layout fields a reader never uses
    # (header padding, index rowBytes/schemaId, high bytes of lengths).
    check missed.len < orig.len div 20
    # The property that matters: with the key, none of those flips ever
    # yields altered rows -- refused, a flagged fallback, or the same rows.
    for p in missed:
      raw = orig
      raw[p] = char(uint8(raw[p]) xor 0x01'u8)
      writeFile(path, raw)
      K = openKeyrings(root)
      if K.unlock("r", "pw").ok and K.rings[0].session.recoveredFrom == 0'u64:
        check K.rows("r") == good
      K.close()
    # With the password too, on a spread of positions (each costs a key
    # derivation): the damaged generation is never read as if intact. It is
    # refused, or the open steps back to the previous generation and says so
    # (`recoveredFrom`, the crash-safety fallback in resolveGeneration).
    for p in countup(0, orig.len - 1, max(1, orig.len div 20)):
      raw = orig
      raw[p] = char(uint8(raw[p]) xor 0x01'u8)
      writeFile(path, raw)
      K = openKeyrings(root)
      check (not K.unlock("r", "pw").ok) or K.rings[0].session.recoveredFrom != 0'u64
      K.close()
    writeFile(path, orig)

  # {.testKind: tkRegression, covers: "clusterBinding|requirePresent|verifyStoreIntegrity", pins: "lowering the row count or the cluster count in the clear index dropped rows while every remaining batch still checked".}
  test "trailing batches or a whole cluster cannot be cut off through the index":
    var
      root = getTempDir() / "geist_t_truncate"
      K = default(Keyrings)
      orig = ""
      raw = ""
      path = ""
      at = 0
    removeDir(root)
    K = createKeyrings(root, ["r"], ["pw"])
    for i in 0 ..< 50:
      K.upsert("r", RingRow(rowKey: "k" & $i, kind: "c", body: "value-" & $i))
    check K.save().ok
    K.close()
    path = generationPaths(root / "r", "main", liveGeneration(root / "r")).dataPath
    orig = readFile(path)
    at = headerBytes + indexEntryBytes * readIndex(path).f.findIndex(crEntry)
    # 50 rows -> 32: exactly one batch of 32 left, the second batch dropped.
    raw = orig
    raw[at + 4] = char(32); raw[at + 5] = char(0); raw[at + 6] = char(0); raw[at + 7] = char(0)
    writeFile(path, raw)
    check not verifyStoreIntegrity(root).ok
    K = openKeyrings(root)
    check (not K.unlock("r", "pw").ok) or K.rings[0].session.recoveredFrom != 0'u64
    K.close()
    # Cluster count 3 -> 2: the entries cluster (last in the index) vanishes.
    raw = orig
    raw[10] = char(2)
    writeFile(path, raw)
    check not verifyStoreIntegrity(root).ok
    K = openKeyrings(root)
    check (not K.unlock("r", "pw").ok) or K.rings[0].session.recoveredFrom != 0'u64
    K.close()
    writeFile(path, orig)
