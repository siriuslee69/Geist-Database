## Crypto: cascade seek, merkle proofs, AAD binding, epoch monotonicity.
import std/unittest
import geist

suite "crypto":
  setup:
    var
      master = initSecret(@[1'u8,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32])
      e = LedgerEntry(cipher: ckCascade, mac: mkCombined, keyRef: 7'u64,
                      groupId: 2'u16, batchIndex: 5'u32)
      rows: seq[ByteSeq] = @[]
      plain: ByteSeq = @[]
      w = 16
    for i in 0 ..< 8:
      var r = newSeq[uint8](w)
      for j in 0 ..< w: r[j] = uint8((i * 31 + j) and 0xFF)
      rows.add r
      plain.add r

  # {.testKind: tkUnit.}
  test "whole batch seals and opens":
    var ct = sealBatch(master, e, "db", 1'u16, plain, rows)
    check ct != plain
    check openBatch(master, e, "db", 1'u16, ct) == plain

  # {.testKind: tkUnit.}
  test "a seekable cipher decrypts one row without the batch":
    var ct = sealBatch(master, e, "db", 1'u16, plain, rows)
    check isSeekable(e.cipher)
    check openRow(master, e, "db", 1'u16, uint64(3 * w),
      ct[3 * w ..< 4 * w]) == rows[3]

  # {.testKind: tkEdgeCase.}
  test "epoch increments on every seal so a nonce is never reused":
    var first = e.epoch
    discard sealBatch(master, e, "db", 1'u16, plain, rows)
    var second = e.epoch
    discard sealBatch(master, e, "db", 1'u16, plain, rows)
    check first < second
    check second < e.epoch

  # {.testKind: tkEdgeCase.}
  test "AAD binds position: a relocated batch does not open":
    var
      ct = sealBatch(master, e, "db", 1'u16, plain, rows)
      moved = e
    moved.batchIndex = 9'u32
    check openBatch(master, moved, "db", 1'u16, ct) != plain
    moved = e
    moved.groupId = 3'u16
    check openBatch(master, moved, "db", 1'u16, ct) != plain
    check openBatch(master, e, "other-db", 1'u16, ct) != plain

  # {.testKind: tkUnit.}
  test "a row verifies against the root with a log2(N) path":
    discard sealBatch(master, e, "db", 1'u16, plain, rows)
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
