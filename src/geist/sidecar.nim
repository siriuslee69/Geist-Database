## ---------------------------------------------------------------------
## Sidecar <- content-addressed store for values too large to inline
## ---------------------------------------------------------------------
##
##   value >= sidecarThreshold  ->  <root>/ab/cd/abcdef...  ->  Ref in the row
##                                                     `-> hash verified on read
##
## This replaces what the Koerper folder used to be. A value at or above
## the threshold (1 KiB by default) never enters the cluster's overflow
## region; the row stores a `Ref` instead, so the overflow region stays
## small enough to keep clusters cheap to rewrite and compact.
##
## Naming is content-addressed with two levels of fan-out, so a directory
## never accumulates more than 256 children at either level and identical
## payloads deduplicate for free.

import std/os

import geistPragmas
import ./types
import ./crypto/hashing

type
  SidecarStore* {.role: truthState, metaTags: {tagSidecar, tagStorageIo,
      tagTypes}.} = object
    ## root: directory holding the fan-out tree; empty disables the store.
    ## threshold: byte size at or above which a value moves out of the row.
    ## hash: content-hash family; the own-file tier addresses BY this hash.
    ## writes/reused: counters surfaced through database metadata.
    root*: string
    threshold*: uint32
    hash*: HashKind
    writes*: uint32
    reused*: uint32
    bytesWritten*: uint64

proc initSidecarStore*(root: string,
    threshold: uint32 = defaultSidecarThreshold,
    hash: HashKind = hkBlake3): SidecarStore {.
    role: configurator, metaTags: {tagSidecar, tagStorageIo}.} =
  ## root: sidecar directory; created lazily on first write.
  ## threshold: size at or above which values are externalised.
  ## hash: content-hash family. Always applied at full width here, because
  ##   in this tier the digest is the path: truncating it would turn a
  ##   chosen-payload collision into a 2^64 search.
  result.root = root
  result.threshold = if threshold == 0'u32: defaultSidecarThreshold
    else: threshold
  result.hash = hash

proc hexOf(A: openArray[uint8]): string {.role: helper,
    metaTags: {tagFormatting, tagSidecar}.} =
  ## A: hash bytes rendered as lowercase hex.
  const
    H = "0123456789abcdef"
  var
    i: int = 0
  result = newString(A.len * 2)
  while i < A.len:
    result[i * 2] = H[int(A[i] shr 4)]
    result[i * 2 + 1] = H[int(A[i] and 0x0F'u8)]
    i = i + 1

proc sidecarLocator*(A: openArray[uint8]): string {.role: helper,
    metaTags: {tagSidecar, tagStorageIo}.} =
  ## A: content hash whose two-level fan-out path is returned.
  var
    h: string = ""
  h = hexOf(A)
  result = h[0 .. 1] & "/" & h[2 .. 3] & "/" & h

proc sidecarPath*(s: SidecarStore, locator: string): string {.role: helper,
    metaTags: {tagSidecar, tagStorageIo}.} =
  ## s: sidecar store whose root is joined with the locator.
  ## locator: fan-out relative path produced by `sidecarLocator`.
  result = s.root / locator

proc shouldExternalise*(s: SidecarStore, n: int): bool {.role: parser, inline,
    metaTags: {tagSidecar, tagRead}.} =
  ## s: sidecar store carrying the threshold.
  ## n: candidate value length in bytes.
  result = s.root.len > 0 and uint32(n) >= s.threshold

proc describeRef*(r: Ref): string {.role: helper,
    metaTags: {tagFormatting, tagSidecar}.} =
  ## r: reference rendered for a CLI listing. A size is deliberately not
  ## shown: it is no longer stored, and reading the payload just to print
  ## its length would defeat the point of a cheap listing.
  case r.target
  of rtSidecar:
    result = "<sidecar " & hexOf(r.hash)[0 .. 15] & "...>"
  of rtPacked:
    result = "<packed " & $r.fileId & ":" & $r.slot & ">"
  of rtEntry:
    result = "<entry " & $r.entryId & ">"
  of rtExternal:
    result = "<external " & r.databaseId & ">"

proc refLocator*(r: Ref): string {.role: helper,
    metaTags: {tagSidecar, tagStorageIo}.} =
  ## r: own-file reference whose path is DERIVED, never stored. This is the
  ## whole reason the cell is 33 bytes instead of 118.
  result = sidecarLocator(r.hash)

proc putSidecar*(S: var SidecarStore, A: openArray[uint8]): Ref {.
    role: dataWriter, metaTags: {tagSidecar, tagStorageIo, tagWrite}.} =
  ## S: sidecar store updated with write counters.
  ## A: payload written under its own content hash.
  var
    hash: ByteSeq = @[]
    locator: string = ""
    full: string = ""
    dir: string = ""
  hash = geistHash(S.hash, A, fullDigestBytes)
  locator = sidecarLocator(hash)
  full = S.sidecarPath(locator)
  dir = parentDir(full)
  result.target = rtSidecar
  result.hash = hash
  if fileExists(full):
    S.reused = S.reused + 1'u32
    return
  if not dirExists(dir):
    createDir(dir)
  writeFile(full, cast[string](@A))
  S.writes = S.writes + 1'u32
  S.bytesWritten = S.bytesWritten + uint64(A.len)

proc getSidecar*(s: SidecarStore, r: Ref): tuple[ok: bool, data: ByteSeq,
    err: string] {.role: dataFetcher,
    metaTags: {tagSidecar, tagStorageIo, tagRead}.} =
  ## s: sidecar store to read from.
  ## r: reference produced by `putSidecar`; its hash is re-verified.
  var
    full: string = ""
    raw: string = ""
    check: ByteSeq = @[]
    locator: string = ""
  if not validRef(r):
    return (false, @[],
      "sidecar reference has no full-width hash, so it addresses nothing")
  locator = r.refLocator()
  full = s.sidecarPath(locator)
  if not fileExists(full):
    return (false, @[], "sidecar payload is missing: " & locator)
  raw = readFile(full)
  result.data = cast[ByteSeq](raw)
  # Re-hashing is the integrity check, not overhead: the path only says
  # WHERE the bytes are, and the row's committed hash is what says they
  # are the right bytes. That hash is inside a Merkle leaf, so a tampered
  # payload cannot be made to verify without forging the root.
  check = geistHash(s.hash, result.data, r.hash.len)
  if not constantTimeEq(check, r.hash):
    return (false, @[], "sidecar payload failed hash verification: " & locator)
  result.ok = true

proc encodeRef*(r: Ref): ByteSeq {.role: encryptor,
    metaTags: {tagCodecBoundary, tagSidecar, tagWrite}.} =
  ## r: reference serialised into a cluster overflow region.
  ##
  ##   rtSidecar  tag | hash32                     33 B
  ##   rtPacked   tag | hash16 | fileId | slot      23 B
  ##
  ## The previous encoding was 118 B, of which 66 were a hex rendering of
  ## the 32-byte hash stored immediately after it. Neither the locator nor
  ## the size is written now: the locator is `hex(hash)` (a pure function
  ## of a field already present) and the size is known by the file or the
  ## slot row. See docs/STORAGE_PLAN.md 6.1.
  var
    i: int = 0
  result = @[]
  result.add uint8(ord(r.target))
  case r.target
  of rtSidecar, rtExternal:
    while i < r.hash.len:
      result.add r.hash[i]
      i = i + 1
  of rtPacked:
    while i < r.hash.len:
      result.add r.hash[i]
      i = i + 1
    result.add uint8(r.fileId and 0xFF'u16)
    result.add uint8((r.fileId shr 8) and 0xFF'u16)
    i = 0
    while i < 4:
      result.add uint8((r.slot shr (i * 8)) and 0xFF'u32)
      i = i + 1
  of rtEntry:
    i = 0
    while i < 8:
      result.add uint8((r.entryId shr (i * 8)) and 0xFF'u64)
      i = i + 1

proc decodeRef*(A: openArray[uint8]): Ref {.role: parser,
    metaTags: {tagCodecBoundary, tagSidecar, tagRead}.} =
  ## A: bytes produced by `encodeRef`, POSSIBLY PADDED.
  ##
  ## Each target implies its own length, so a reference is self-delimiting
  ## and decodes correctly out of a `colCapped` column wider than it is.
  ## Deriving the hash width from `A.len` instead would read the column's
  ## zero padding as part of the digest and fail verification.
  var
    i: int = 0
    n: int = 0
  if A.len < refTagBytes + 1:
    return
  result.target = RefTarget(A[0])
  case result.target
  of rtSidecar, rtExternal:
    n = min(fullDigestBytes, A.len - refTagBytes)
    result.hash = newSeq[uint8](n)
    while i < n:
      result.hash[i] = A[refTagBytes + i]
      i = i + 1
  of rtPacked:
    n = shortDigestBytes
    if A.len < refTagBytes + n + 6:
      return
    result.hash = newSeq[uint8](n)
    while i < n:
      result.hash[i] = A[refTagBytes + i]
      i = i + 1
    result.fileId = uint16(A[refTagBytes + n]) or
      (uint16(A[refTagBytes + n + 1]) shl 8)
    i = 0
    while i < 4:
      result.slot = result.slot or
        (uint32(A[refTagBytes + n + 2 + i]) shl (i * 8))
      i = i + 1
  of rtEntry:
    i = 0
    while i < 8 and refTagBytes + i < A.len:
      result.entryId = result.entryId or
        (uint64(A[refTagBytes + i]) shl (i * 8))
      i = i + 1
