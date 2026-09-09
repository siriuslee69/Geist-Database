## ---------------------------------------------------------------------
## MAC <- BLAKE3 (+) Gimli authenticator and the per-batch Merkle tree
## ---------------------------------------------------------------------
##
##   batchTag  = BLAKE3-HMAC XOR Gimli-HMAC        (PRF combiner: sound)
##   merkleRoot= BLAKE3 tree over per-row leaves   (collision resistance)
##
##          root
##         /    \
##      h01      h23          proof for row 2 = [h3, h01]
##      / \      / \          verify cost 32 * log2(N), not N rows
##    h0  h1   h2  h3
##
## Two different combiners, deliberately:
##
##   * For the batch TAG the property needed is unforgeability (a PRF
##     property), and XOR is a sound PRF combiner -- if either primitive
##     is a secure PRF, the XOR is.
##
##   * For the MERKLE TREE the property needed is collision resistance,
##     and XOR is NOT a sound combiner for that: a collision in the XOR
##     need not be a collision in either input. The tree therefore uses
##     BLAKE3 alone. Do not "unify" these two by XOR-ing the tree hash.
##
## See docs/DESIGN_RATIONALE.md section 8.

import runePragmas
import ../types
import ./hashing

export hashing

const
  tagBytes* = fullDigestBytes
    ## Default tag width. `authTag` takes an explicit width so a config can
    ## narrow it; this is only the fallback for callers that do not care.
  leafDomain = "geist-merkle-leaf-v1"
  nodeDomain = "geist-merkle-node-v1"

proc authTag*(m: MacKind, key: Secret, msg, aad: openArray[uint8],
    outLen: int = tagBytes): ByteSeq {.role: encryptor,
    tag: "cryptoBoundary|batch".} =
  ## m: authenticator selection.
  ## key: batch key material.
  ## msg: ciphertext being authenticated.
  ## aad: position binding; without it a batch can be relocated to another
  ##   ledger row or column and still verify.
  ## outLen: tag width from the configuration.
  var
    buf: ByteSeq = @[]
    i: int = 0
  buf = @aad
  buf.add uint8(0xFF)
  while i < msg.len:
    buf.add msg[i]
    i = i + 1
  result = geistMacOf(m, key, buf, outLen)

proc verifyTag*(m: MacKind, key: Secret, msg, aad,
    expected: openArray[uint8]): bool {.role: sanitizer,
    tag: "cryptoBoundary|batch|read".} =
  ## m/key/msg/aad: as for `authTag`.
  ## expected: stored tag. Its length selects the width to recompute at,
  ## so a narrowed config verifies without a second parameter, and the
  ## comparison is constant time.
  var
    got: ByteSeq = @[]
  if expected.len == 0:
    return false
  got = authTag(m, key, msg, aad, expected.len)
  result = constantTimeEq(got, expected)

## ------------------------------ merkle ------------------------------

proc leafHash*(key: Secret, i: uint32, A: openArray[uint8],
    h: HashKind = hkBlake3): ByteSeq {.role: helper,
    tag: "cryptoBoundary|batch".} =
  ## key: batch key, so leaves are unpredictable to an observer.
  ## i: row index inside the batch, bound in to prevent leaf reordering.
  ## A: row bytes.
  ## h: tree hash family from the configuration.
  ## Always full width: a Merkle tree needs collision resistance, which a
  ## 16-byte digest would put at 2^64.
  var
    buf: ByteSeq = @[]
    j: int = 0
  buf = @(cast[ByteSeq](leafDomain))
  while j < 4:
    buf.add uint8((i shr (j * 8)) and 0xFF'u32)
    j = j + 1
  j = 0
  while j < A.len:
    buf.add A[j]
    j = j + 1
  result = geistKeyedHash(h, key, buf, fullDigestBytes)

proc nodeHash*(l, r: openArray[uint8],
    h: HashKind = hkBlake3): ByteSeq {.role: helper,
    tag: "cryptoBoundary|batch".} =
  ## l/r: child hashes combined into their parent.
  ## h: tree hash family.
  var
    buf: ByteSeq = @[]
  buf = @(cast[ByteSeq](nodeDomain))
  buf.add @l
  buf.add @r
  result = geistHash(h, buf, fullDigestBytes)

proc emptyLeaf*(h: HashKind = hkBlake3): ByteSeq {.role: helper,
    tag: "cryptoBoundary|batch".} =
  ## Domain-separated padding leaf. Distinct from any keyed real leaf, so
  ## padding can never be confused with data.
  result = geistHash(h, cast[ByteSeq](nodeDomain & "-empty"), fullDigestBytes)

proc padToPowerOfTwo(L: seq[ByteSeq],
    h: HashKind = hkBlake3): seq[ByteSeq] {.role: helper,
    tag: "cryptoBoundary|batch".} =
  ## L: leaves padded up to the next power of two.
  ## Promoting an odd level instead would make some levels contribute no
  ## proof element, and a verifier replaying the path has no way to know
  ## which levels were skipped. Padding keeps every level even, so the
  ## proof length is exactly log2(n) and replay is unambiguous.
  var
    n: int = 1
    pad: ByteSeq = @[]
  result = L
  if L.len <= 1:
    return
  while n < L.len:
    n = n * 2
  pad = emptyLeaf(h)
  while result.len < n:
    result.add pad

proc merkleRoot*(L: seq[ByteSeq], h: HashKind = hkBlake3): ByteSeq {.
    role: truthBuilder, tag: "cryptoBoundary|batch".} =
  ## L: leaf hashes in row order.
  ## h: tree hash family.
  var
    level: seq[ByteSeq] = @[]
    nxt: seq[ByteSeq] = @[]
    i: int = 0
  if L.len == 0:
    return newSeq[uint8](fullDigestBytes)
  level = padToPowerOfTwo(L, h)
  while level.len > 1:
    nxt = @[]
    i = 0
    while i + 1 < level.len:
      nxt.add nodeHash(level[i], level[i + 1], h)
      i = i + 2
    level = nxt
  result = level[0]

proc merkleProof*(L: seq[ByteSeq], index: int,
    h: HashKind = hkBlake3): seq[ByteSeq] {.role: truthBuilder,
    tag: "cryptoBoundary|batch|read".} =
  ## L: leaf hashes in row order.
  ## index: row whose sibling path is returned. Verification cost is
  ## 32 bytes per level instead of re-hashing every row in the batch.
  ## h: tree hash family.
  var
    level: seq[ByteSeq] = @[]
    nxt: seq[ByteSeq] = @[]
    idx: int = index
    i: int = 0
  if L.len == 0 or index < 0 or index >= L.len:
    return @[]
  level = padToPowerOfTwo(L, h)
  while level.len > 1:
    result.add level[idx xor 1]
    nxt = @[]
    i = 0
    while i + 1 < level.len:
      nxt.add nodeHash(level[i], level[i + 1], h)
      i = i + 2
    level = nxt
    idx = idx div 2

proc verifyMerkle*(leaf: ByteSeq, index: int, proof: seq[ByteSeq],
    root: openArray[uint8], h: HashKind = hkBlake3): bool {.role: sanitizer,
    tag: "cryptoBoundary|batch|read".} =
  ## leaf: hash of the row being checked.
  ## index/proof: position and sibling path from `merkleProof`.
  ## root: value stored in the ledger row.
  ## h: tree hash family, which must match the one that built the root.
  var
    acc: ByteSeq = @[]
    idx: int = index
    i: int = 0
  acc = leaf
  while i < proof.len:
    if (idx and 1) == 0:
      acc = nodeHash(acc, proof[i], h)
    else:
      acc = nodeHash(proof[i], acc, h)
    idx = idx div 2
    i = i + 1
  result = constantTimeEq(acc, root)
