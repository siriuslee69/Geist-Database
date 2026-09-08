## ---------------------------------------------------------------------
## Hashing <- one selectable hash family, three call sites, two widths
## ---------------------------------------------------------------------
##
##   contentHash -> sidecar / reference verification   (16 or 32 B)
##   treeHash    -> Merkle leaves and nodes            (32 B)
##   chainHash   -> cmChained journal links            (32 B)
##
## Every hardcoded `blake3TyrHash` call used to pick the algorithm AND the
## width at the call site. Routing all three through here is what makes
## `HashKind` a configuration rather than an edit.
##
## WHY THERE IS NO XOR-COMBINED HASH
##
## `MacKind` offers mkCombined (BLAKE3 XOR Gimli) because XOR is a sound
## PRF combiner: the tag is unforgeable if EITHER primitive is. Collision
## resistance does not combine that way -- there is no collision-resistance
## combiner shorter than concatenation -- so `blake3(x) xor gimli(x)` has
## no collision proof and must never address content, build a Merkle leaf,
## or link a journal row. `HashKind` therefore offers single families only.
##
## See docs/DESIGN_RATIONALE.md section 8 and docs/STORAGE_PLAN.md 6.7.

import tyr

import geistPragmas
import ../types

export hashwidths

proc sha3Width(outLen: int): int {.role: helper, inline,
    metaTags: {tagCryptoBoundary}.} =
  ## outLen: requested width mapped up to the nearest SHA3 variant.
  ## SHA3 is NOT an extendable-output function -- it is a fixed family of
  ## 224/256/384/512-bit digests, and Tyr rejects anything else. BLAKE3 and
  ## the Gimli sponge genuinely are extendable, so only this family needs
  ## the mapping.
  if outLen <= 28: result = 28
  elif outLen <= 32: result = 32
  elif outLen <= 48: result = 48
  else: result = 64

proc truncated(A: ByteSeq, outLen: int): ByteSeq {.role: helper, inline,
    metaTags: {tagCryptoBoundary}.} =
  ## A/outLen: digest cut to the requested width.
  ## Truncating a hash preserves preimage and second-preimage resistance at
  ## the truncated length, which is exactly what the packed tier needs. It
  ## does NOT preserve collision resistance beyond the new width, which is
  ## why `validateGeistConfig` refuses a truncated tree hash.
  if A.len <= outLen:
    result = A
  else:
    result = A[0 ..< outLen]

proc geistHash*(k: HashKind, A: openArray[uint8],
    outLen: int = fullDigestBytes): ByteSeq {.role: encryptor,
    metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## k: hash family.
  ## A: message.
  ## outLen: digest width. BLAKE3 and Gimli take it natively; SHA3 is
  ##   computed at its nearest standard variant and truncated.
  case k
  of hkBlake3:
    result = @(blake3TyrHash(A, outLen))
  of hkSha3:
    result = truncated(@(sha3TyrHash(A, sha3Width(outLen))), outLen)
  of hkGimli:
    result = @(gimliTyrXof(@[], @[], A, outLen))

proc geistKeyedHash*(k: HashKind, key: Secret, A: openArray[uint8],
    outLen: int = fullDigestBytes): ByteSeq {.role: encryptor,
    metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## k/key/A/outLen: keyed variant, used for Merkle leaves so an observer
  ## cannot recompute them without the batch key.
  case k
  of hkBlake3:
    result = @(blake3TyrKeyedHash(key.use(), A, outLen))
  of hkSha3:
    result = truncated(@(sha3CustomHmac(key.use(), A, sha3Width(outLen))),
      outLen)
  of hkGimli:
    result = @(gimliCustomHmac(key.use(), A, outLen))

proc geistMacOf*(m: MacKind, key: Secret, A: openArray[uint8],
    outLen: int = fullDigestBytes): ByteSeq {.role: encryptor,
    metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## m: authenticator selection, including the XOR combiner.
  ## key/A/outLen: key material, message and tag width.
  ## Unlike `geistHash` this MAY combine, because unforgeability is a PRF
  ## property and XOR is a sound PRF combiner.
  var
    other: ByteSeq = @[]
    i: int = 0
  case m
  of mkBlake3:
    result = @(blake3CustomHmac(key.use(), A, outLen))
  of mkGimli:
    result = @(gimliCustomHmac(key.use(), A, outLen))
  of mkCombined:
    result = @(blake3CustomHmac(key.use(), A, outLen))
    other = @(gimliCustomHmac(key.use(), A, outLen))
    while i < result.len and i < other.len:
      result[i] = result[i] xor other[i]
      i = i + 1
