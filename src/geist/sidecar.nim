## ---------------------------------------------------------------------
## Sidecar <- content-addressed store for values too large to inline
## ---------------------------------------------------------------------
##
##   capped column, value too wide for it  ->  <root>/ab/cd/abcdef...  ->  Ref in the row
##                                                              `-> hash verified on read
##
## <root> is the store folder's `.geist-sidecar` (sidecarFolderName). This
## replaces what the Koerper folder used to be: a value that takes the escape
## never enters the cluster's overflow region, so that region stays small
## enough to keep clusters cheap to rewrite and compact.
##
## WHICH values take the escape is decided by the column policy (config.nim,
## cappedColumn): only a capped column whose value is wider than the column
## does. Text and bytes columns are variable-length and always stay inline.
## `sidecarThreshold` (1 KiB by default) is kept with the configuration, but no
## write path reads it, so it does not move a value. A column of slot kind
## "ref" is always an own-file reference to a payload here.
##
## Naming is content-addressed with two levels of fan-out, so a directory
## never accumulates more than 256 children at either level and identical
## payloads deduplicate for free.

import std/[os, strutils, tables]

import tyr

import runePragmas
import ./types
import ./crypto/hashing
import ./format
import ./textfile

const
  sidecarFolderName*: string = ".geist-sidecar"
    ## The folder inside a store folder that holds the sidecar payloads.
  sidecarsCompiled*: bool = defined(sidecars)
    ## Compile-time switch: `[define] sidecars` in configs/default.toml, or
    ## -d:sidecars. A build without it never writes a sidecar and refuses to
    ## read a row that names one. Inline values work either way.

type
  SidecarStore* {.role: truthState, tag: "sidecar|storageIo|types".} = object
    ## root: directory holding the fan-out tree; empty disables the store.
    ## threshold: byte size at or above which a value moves out of the row.
    ## escapes: whether NEW values may leave their rows (the runtime setting
    ##   `sidecars`). False still lets existing references be read.
    ## hash: content-hash family; the own-file tier addresses BY this hash.
    ## writes/reused: counters surfaced through database metadata.
    root*: string
    threshold*: uint32
    escapes*: bool
    hash*: HashKind
    writes*: uint32
    reused*: uint32
    bytesWritten*: uint64

proc initSidecarStore*(root: string,
    threshold: uint32 = defaultSidecarThreshold,
    hash: HashKind = hkBlake3): SidecarStore {.
    role: configurator, tag: "sidecar|storageIo".} =
  ## root: sidecar directory; created lazily on first write.
  ## threshold: size at or above which values are externalised.
  ## hash: content-hash family. Always applied at full width here, because
  ##   in this tier the digest is the path: truncating it would turn a
  ##   chosen-payload collision into a 2^64 search.
  result.root = root
  result.threshold = if threshold == 0'u32: defaultSidecarThreshold
    else: threshold
  result.escapes = true
  result.hash = hash

proc hexOf(A: openArray[uint8]): string {.role: helper,
    tag: "formatting|sidecar".} =
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
    tag: "sidecar|storageIo".} =
  ## A: content hash whose two-level fan-out path is returned.
  var
    h: string = ""
  h = hexOf(A)
  result = h[0 .. 1] & "/" & h[2 .. 3] & "/" & h

proc sidecarPath*(s: SidecarStore, locator: string): string {.role: helper,
    tag: "sidecar|storageIo".} =
  ## s: sidecar store whose root is joined with the locator.
  ## locator: fan-out relative path produced by `sidecarLocator`.
  result = s.root / locator

proc canEscape*(s: SidecarStore): bool {.role: parser, inline,
    tag: "sidecar|read".} =
  ## s: sidecar store. True when NEW values may leave their rows: this build has
  ## sidecars, the runtime setting allows them, and the store has a folder.
  result = sidecarsCompiled and s.escapes and s.root.len > 0

proc shouldExternalise*(s: SidecarStore, n: int): bool {.role: parser, inline,
    tag: "sidecar|read".} =
  ## s: sidecar store carrying the threshold.
  ## n: candidate value length in bytes. At or above the threshold, and only
  ## when `canEscape` says a value may leave its row.
  result = s.canEscape() and uint32(n) >= s.threshold

proc describeRef*(r: Ref): string {.role: helper,
    tag: "formatting|sidecar".} =
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
    tag: "sidecar|storageIo".} =
  ## r: own-file reference whose path is DERIVED, never stored. This is the
  ## whole reason the cell is 33 bytes instead of 118.
  result = sidecarLocator(r.hash)

proc putSidecar*(S: var SidecarStore, A: openArray[uint8]): Ref {.
    role: dataWriter, tag: "sidecar|storageIo|write".} =
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

const
  locatorSuffix*: string = ".locator"
    ## A locator names a payload that is NOT in the sidecar folder: a tracked
    ## file, where it lies. It sits beside where the payload would be.

type
  SidecarLocator* {.role: truthState, tag: "sidecar|types".} = object
    ## kind: "path", a tracked file read where it lies. Another kind names a
    ##   payload held elsewhere; reading that needs a network layer.
    ## hash: the content hash the row keeps. The payload must hash to it.
    ## size: bytes when the file was tracked. A different size means it changed.
    ## name: what the file is called, for a person reading the listing.
    ## target: the path, for kind "path".
    kind*: string
    hash*: ByteSeq
    size*: int64
    name*: string
    target*: string

proc locatorPathOf*(s: SidecarStore, hash: ByteSeq): string {.role: helper,
    tag: "sidecar|storageIo".} =
  ## s/hash: where the locator for this content hash is kept.
  result = s.sidecarPath(sidecarLocator(hash) & locatorSuffix)

proc locatorText*(l: SidecarLocator): string {.role: helper,
    tag: "sidecar|write".} =
  ## l: the locator as text, with its digest last (see textfile.nim).
  var
    pairs: seq[tuple[key, value: string]] = @[
      ("geist-locator", "1"), ("kind", l.kind), ("hash", hexText(l.hash)),
      ("size", $l.size), ("name", l.name), ("target", l.target)]
  result = renderFile(pairs)

proc parseLocator*(text: string): tuple[ok: bool, loc: SidecarLocator,
    err: string] {.role: parser, tag: "sidecar|read".} =
  ## text: a locator file. Refused when the digest does not match or a field is
  ## missing: a locator that cannot be trusted names nothing.
  var
    got: tuple[ok: bool, pairs: Table[string, string], err: string] =
      parseKeyFile(text)
  if not got.ok:
    result.err = got.err
    return
  for key in ["kind", "hash", "size", "target"]:
    if not got.pairs.hasKey(key):
      result.err = "a locator must say " & key
      return
  result.loc.kind = got.pairs["kind"]
  result.loc.hash = unhexText(got.pairs["hash"])
  if result.loc.hash.len == 0:
    result.err = "a locator's hash is not hex"
    return
  try:
    result.loc.size = parseBiggestInt(got.pairs["size"])
  except ValueError:
    result.err = "a locator's size is not a number"
    return
  result.loc.name = got.pairs.getOrDefault("name", "")
  result.loc.target = got.pairs["target"]
  result.ok = true

proc putLocator*(s: SidecarStore, l: SidecarLocator): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "sidecar|storageIo|write".} =
  ## s/l: write the locator for a payload that lives outside the sidecar folder.
  ## Written beside its name and renamed into place, so a crash leaves the old file
  ## or the new one. Refused while sidecars are off for this store.
  var
    path: string = locatorPathOf(s, l.hash)
    tmp: string = path & ".tmp"
  if not s.canEscape():
    return (false, "sidecars are off for this store, so no locator is written")
  createDir(parentDir(path))
  writeFile(tmp, locatorText(l))
  moveFile(tmp, path)
  result = (true, "")

proc hashFileFor*(k: HashKind, path: string): ByteSeq {.role: parser,
    tag: "cryptoBoundary|storageIo|read".} =
  ## k/path: the content hash of a file under family k. BLAKE3 is streamed, so a
  ## large file is hashed without being read whole. The other families read it.
  if k == hkBlake3:
    result = blake3HashFile(path, fullDigestBytes)
  else:
    result = geistHash(k, cast[ByteSeq](readFile(path)), fullDigestBytes)

proc readLocated*(s: SidecarStore, r: Ref, lf: string): tuple[ok: bool,
    data: ByteSeq, err: string] {.role: dataFetcher, tag: "sidecar|storageIo|read".} =
  ## s/r/lf: the payload of a reference whose locator is `lf`. Its locator names
  ## where the bytes lie, and they are verified against the row's hash before they
  ## are returned. A file that changed since it was tracked is refused.
  var
    parsed: tuple[ok: bool, loc: SidecarLocator, err: string] =
      parseLocator(readFile(lf))
    check: ByteSeq = @[]
  if not parsed.ok:
    result.err = "locator " & lf & " cannot be trusted: " & parsed.err
    return
  if parsed.loc.hash != r.hash:
    result.err = "locator " & lf & " names another payload than the row does"
    return
  if parsed.loc.kind != "path":
    result.err = "the payload is held by " & parsed.loc.target &
      "; reading it over the network needs nebel"
    return
  if not fileExists(parsed.loc.target):
    result.err = "tracked file is missing: " & parsed.loc.target
    return
  if getFileSize(parsed.loc.target) != parsed.loc.size:
    result.err = "tracked file changed size since it was tracked: " & parsed.loc.target
    return
  check = hashFileFor(s.hash, parsed.loc.target)
  if not constantTimeEq(check, r.hash):
    result.err = "tracked file failed hash verification (its content changed): " &
      parsed.loc.target
    return
  result.data = cast[ByteSeq](readFile(parsed.loc.target))
  result.ok = true

proc getSidecar*(s: SidecarStore, r: Ref): tuple[ok: bool, data: ByteSeq,
    err: string] {.role: dataFetcher,
    tag: "sidecar|storageIo|read".} =
  ## s: sidecar store to read from.
  ## r: reference produced by `putSidecar`; its hash is re-verified.
  when not sidecarsCompiled:
    return (false, @[], "this build was compiled with sidecars off, so a row " &
      "that names a sidecar cannot be read; build with [define] sidecars = true")
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
    if fileExists(s.sidecarPath(locator & locatorSuffix)):
      return readLocated(s, r, s.sidecarPath(locator & locatorSuffix))
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
    tag: "codecBoundary|sidecar|write".} =
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
    tag: "codecBoundary|sidecar|read".} =
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
  result.target = enumAt[RefTarget](A[0], "reference target")
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
