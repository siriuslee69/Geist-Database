## ---------------------------------------------------------------------
## Cipher <- seekable keystreams and the ChaCha20 (+) AES-CTR cascade
## ---------------------------------------------------------------------
##
##   ckChaCha20 : ChaCha20 keystream                     seekable
##   ckAesCtr   : AES-256-CTR keystream                  seekable
##   ckCascade  : ChaCha20 XOR AES-CTR, independent keys seekable
##
##        offset o  ->  block floor(o/64)  ->  generate only what is needed
##
## Why a cascade: XOR of two independent keystreams is a sound combiner --
## the result is at least as strong as the stronger of the two, so a break
## in one primitive does not break the database. Keys are derived with
## distinct KDF labels so the two streams are independent.
##
## Why seekable matters: reading one row out of a batch of N would
## otherwise cost N rows of decryption. With a block counter it costs the
## row. Gimli is deliberately NOT offered as a cipher here: its sponge
## squeeze is sequential and cannot skip blocks. It remains available on
## the authentication side, where that property is irrelevant.
##
## Threading: splitting a two-stream XOR across cores only pays once the
## payload is large. Below `parallelThresholdBytes` the thread setup costs
## more than the keystream. See docs/DESIGN_RATIONALE.md section 7.

import tyr

import runePragmas
import ../types

const
  chachaBlockBytes* = 64
  aesBlockBytes* = 16
  cipherKeyBytes* = 32
  chachaNonceBytes* = 12
  aesNonceBytes* = 16
  parallelThresholdBytes* = 8 * 1024 * 1024
    ## Below this, the cascade runs both keystreams inline. Spawning two
    ## threads to encrypt a few hundred bytes is pure overhead; this only
    ## triggers for multi-gigabyte bulk encrypt/decrypt passes.

type
  StreamKeys* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## Two independent keys and nonces, one per cascade leg.
    chachaKey*: ByteSeq
    chachaNonce*: ByteSeq
    aesKey*: ByteSeq
    aesNonce*: ByteSeq

proc deriveStreamKeys*(base: Secret, aad: openArray[uint8]): StreamKeys {.
    role: encryptor, tag: "cryptoBoundary|batch".} =
  ## base: batch key material.
  ## aad: position binding (database, column group, batch index, epoch).
  ## Distinct labels keep the two cascade legs independent, which is what
  ## makes the XOR combiner sound.
  var
    seedA: ByteSeq = @[]
    seedB: ByteSeq = @[]
  seedA = @(blake3TyrKeyedHash(base.use(),
    @(cast[ByteSeq]("geist-cascade-chacha-v1")) & @aad, 44))
  seedB = @(blake3TyrKeyedHash(base.use(),
    @(cast[ByteSeq]("geist-cascade-aesctr-v1")) & @aad, 48))
  result.chachaKey = seedA[0 ..< cipherKeyBytes]
  result.chachaNonce = seedA[cipherKeyBytes ..< cipherKeyBytes + chachaNonceBytes]
  result.aesKey = seedB[0 ..< cipherKeyBytes]
  result.aesNonce = seedB[cipherKeyBytes ..< cipherKeyBytes + aesNonceBytes]

proc advanceCounter(n: openArray[uint8], blocks: uint64): ByteSeq {.
    role: math, tag: "cryptoBoundary".} =
  ## n: 16-byte AES-CTR counter block.
  ## blocks: number of blocks to skip. Tyr exposes no seek for AES-CTR, so
  ## the counter is advanced here as a big-endian 128-bit add.
  var
    carry: uint64 = blocks
    i: int = 0
    sum: uint64 = 0'u64
  result = @n
  i = result.len - 1
  while i >= 0 and carry > 0'u64:
    sum = uint64(result[i]) + (carry and 0xFF'u64)
    result[i] = uint8(sum and 0xFF'u64)
    carry = (carry shr 8) + (sum shr 8)
    i = i - 1

proc chachaKeystream(k: StreamKeys, startBlock: uint64, n: int): ByteSeq {.
    role: encryptor, tag: "cryptoBoundary".} =
  ## k/startBlock/n: keys, first 64-byte block index, and byte count.
  result = @(chacha20TyrStream(k.chachaKey, k.chachaNonce, n,
    uint32(startBlock)))

proc aesKeystream(k: StreamKeys, startBlock: uint64, n: int): ByteSeq {.
    role: encryptor, tag: "cryptoBoundary".} =
  ## k/startBlock/n: keys, first 16-byte block index, and byte count.
  var
    zeros: ByteSeq = @[]
    ctr: ByteSeq = @[]
  zeros = newSeq[uint8](n)
  ctr = advanceCounter(k.aesNonce, startBlock)
  result = @(aesCtrTyrXor(k.aesKey, ctr, zeros))

when compileOption("threads"):
  type
    KsJob = object
      keys: ptr StreamKeys
      startBlock: uint64
      n: int
      dst: ptr UncheckedArray[uint8]

  proc chachaWorker(j: KsJob) {.thread, nimcall.} =
    ## j: keystream job filling a caller-owned destination buffer.
    var
      ks: ByteSeq = @[]
      i: int = 0
    ks = chachaKeystream(j.keys[], j.startBlock, j.n)
    while i < j.n:
      j.dst[i] = ks[i]
      i = i + 1

proc cascadeKeystreamParallel(k: StreamKeys, chachaStart, aesStart: uint64,
    n: int): ByteSeq {.role: encryptor, tag: "cryptoBoundary".} =
  ## k/chachaStart/aesStart/n: keys, per-leg first block, byte count.
  ## Only reached above `parallelThresholdBytes`.
  result = newSeq[uint8](n)
  when compileOption("threads"):
    var
      a: ByteSeq = newSeq[uint8](n)
      b: ByteSeq = newSeq[uint8](n)
      keys: StreamKeys = k
      tA: Thread[KsJob] = default(Thread[KsJob])
      tB: Thread[KsJob] = default(Thread[KsJob])
      i: int = 0
    createThread(tA, chachaWorker, KsJob(keys: addr keys,
      startBlock: chachaStart, n: n,
      dst: cast[ptr UncheckedArray[uint8]](addr a[0])))
    b = aesKeystream(keys, aesStart, n)
    joinThread(tA)
    joinThread(tB)
    while i < n:
      result[i] = a[i] xor b[i]
      i = i + 1
  else:
    var
      a: ByteSeq = @[]
      b: ByteSeq = @[]
      i: int = 0
    a = chachaKeystream(k, chachaStart, n)
    b = aesKeystream(k, aesStart, n)
    while i < n:
      result[i] = a[i] xor b[i]
      i = i + 1

proc keystream*(c: CipherKind, k: StreamKeys, byteOffset: uint64,
    n: int): ByteSeq {.role: encryptor, tag: "cryptoBoundary".} =
  ## c: cipher selection.
  ## k: derived stream keys.
  ## byteOffset: absolute offset inside the batch payload; the whole point
  ##   of a seekable cipher is that this need not be zero.
  ## n: number of keystream bytes required.
  ## Generation is aligned down to a 64-byte block and sliced, so both legs
  ## stay on their natural block boundaries.
  var
    alignedStart: uint64 = 0'u64
    skew: int = 0
    span: int = 0
    raw: ByteSeq = @[]
    a: ByteSeq = @[]
    b: ByteSeq = @[]
    i: int = 0
  if n <= 0:
    return @[]
  alignedStart = (byteOffset div uint64(chachaBlockBytes)) *
    uint64(chachaBlockBytes)
  skew = int(byteOffset - alignedStart)
  span = skew + n
  case c
  of ckNone:
    result = newSeq[uint8](n)
    return
  of ckChaCha20:
    raw = chachaKeystream(k, alignedStart div uint64(chachaBlockBytes), span)
  of ckAesCtr:
    raw = aesKeystream(k, alignedStart div uint64(aesBlockBytes), span)
  of ckCascade:
    if span >= parallelThresholdBytes:
      raw = cascadeKeystreamParallel(k,
        alignedStart div uint64(chachaBlockBytes),
        alignedStart div uint64(aesBlockBytes), span)
    else:
      a = chachaKeystream(k, alignedStart div uint64(chachaBlockBytes), span)
      b = aesKeystream(k, alignedStart div uint64(aesBlockBytes), span)
      raw = newSeq[uint8](span)
      while i < span:
        raw[i] = a[i] xor b[i]
        i = i + 1
  result = raw[skew ..< span]

proc applyKeystream*(c: CipherKind, k: StreamKeys, byteOffset: uint64,
    A: openArray[uint8]): ByteSeq {.role: encryptor,
    tag: "cryptoBoundary".} =
  ## c/k/byteOffset: cipher, keys and absolute offset of `A` in the batch.
  ## A: plaintext or ciphertext; the operation is its own inverse.
  var
    ks: ByteSeq = @[]
    i: int = 0
  ks = keystream(c, k, byteOffset, A.len)
  result = newSeq[uint8](A.len)
  while i < A.len:
    result[i] = A[i] xor ks[i]
    i = i + 1

proc isSeekable*(c: CipherKind): bool {.role: parser, inline,
    tag: "cryptoBoundary|read".} =
  ## c: cipher whose single-row decrypt capability is reported.
  result = c in {ckChaCha20, ckAesCtr, ckCascade}
