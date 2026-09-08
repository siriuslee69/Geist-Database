## ---------------------------------------------------------------------
## Format <- little-endian primitives and the seekable file header
## ---------------------------------------------------------------------
##
##  +----------------------------------------------------------------+
##  | header: magic | version | clusterCount | generation             |  32 B
##  +----------------------------------------------------------------+
##  | cluster index: N x IndexEntry                                   |  76 B each
##  |   role | mode | schemaId | rowCount | rowBytes                  |
##  |   at | len | auxAt | auxLen | hash32                            |
##  +----------------------------------------------------------------+
##  | cluster 0 ... cluster N-1   (schema | rows | aux)               |
##  +----------------------------------------------------------------+
##
## The index is 32 B + 80 B per cluster REGARDLESS of file size, so a
## reader learns row counts and per-cluster hashes for a multi-gigabyte
## database in a few hundred bytes. That is what lets the daemon observe
## a file it does not own. See docs/DESIGN_RATIONALE.md section 4.
##
## Every integer is written little-endian through explicit byte loops.
## Native struct punning would not survive x86 <-> ARM, and Geist targets
## Linux, Windows and Android on both.

import geistPragmas
import ./types

const
  geistMagic* = "GE1ST"
  geistFormatVersion* = 4'u16
  headerBytes* = 32
  indexEntryBytes* = 76

type
  IndexEntry* {.role: truthState, metaTags: {tagDb, tagStorageIo, tagTypes}.} = object
    ## One row of the seekable cluster index.
    ##
    ## Version 4 dropped the `layout` byte. It named a table-level cell
    ## layout that no longer exists -- storage is per column now, and
    ## whether rows vary is already told by `rowBytes == 0`. A stored byte
    ## that duplicates a derivable fact can disagree with it, so it went.
    role*: ClusterRole
    mode*: ClusterMode
    schemaId*: uint16
    rowCount*: uint32
    rowBytes*: uint32    ## 0 declares "rows vary; consult the offset table"
    at*: uint64          ## absolute offset of the cluster's schema block
    len*: uint64         ## schema block + rows
    auxAt*: uint64       ## absolute offset of the auxiliary region
    auxLen*: uint64      ## the row offset table, or 0 for a dense cluster
    hash*: ByteSeq       ## 32 B content hash, lets a reader detect change

  FileHeader* {.role: truthState, metaTags: {tagDb, tagStorageIo, tagTypes}.} = object
    version*: uint16
    clusterCount*: uint32
    generation*: uint64

proc putU16*(A: var ByteSeq, o: int, v: uint16) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/o/v: destination buffer, byte offset, value.
  A[o] = uint8(v and 0xFF)
  A[o + 1] = uint8((v shr 8) and 0xFF)

proc getU16*(A: openArray[uint8], o: int): uint16 {.role: parser,
    metaTags: {tagCodecBoundary, tagRead}.} =
  ## A/o: source buffer and byte offset.
  result = uint16(A[o]) or (uint16(A[o + 1]) shl 8)

proc putU32*(A: var ByteSeq, o: int, v: uint32) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/o/v: destination buffer, byte offset, value.
  var
    i: int = 0
  while i < 4:
    A[o + i] = uint8((v shr (i * 8)) and 0xFF)
    i = i + 1

proc getU32*(A: openArray[uint8], o: int): uint32 {.role: parser,
    metaTags: {tagCodecBoundary, tagRead}.} =
  ## A/o: source buffer and byte offset.
  var
    i: int = 0
  result = 0'u32
  while i < 4:
    result = result or (uint32(A[o + i]) shl (i * 8))
    i = i + 1

proc putU64*(A: var ByteSeq, o: int, v: uint64) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/o/v: destination buffer, byte offset, value.
  var
    i: int = 0
  while i < 8:
    A[o + i] = uint8((v shr (i * 8)) and 0xFF)
    i = i + 1

proc getU64*(A: openArray[uint8], o: int): uint64 {.role: parser,
    metaTags: {tagCodecBoundary, tagRead}.} =
  ## A/o: source buffer and byte offset.
  var
    i: int = 0
  result = 0'u64
  while i < 8:
    result = result or (uint64(A[o + i]) shl (i * 8))
    i = i + 1

proc addU16*(A: var ByteSeq, v: uint16) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/v: buffer extended by one little-endian u16.
  A.add uint8(v and 0xFF)
  A.add uint8((v shr 8) and 0xFF)

proc addU32*(A: var ByteSeq, v: uint32) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/v: buffer extended by one little-endian u32.
  var
    i: int = 0
  while i < 4:
    A.add uint8((v shr (i * 8)) and 0xFF)
    i = i + 1

proc addU64*(A: var ByteSeq, v: uint64) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/v: buffer extended by one little-endian u64.
  var
    i: int = 0
  while i < 8:
    A.add uint8((v shr (i * 8)) and 0xFF)
    i = i + 1

proc addBytes*(A: var ByteSeq, B: openArray[uint8]) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/B: destination buffer and appended source bytes.
  var
    i: int = 0
  while i < B.len:
    A.add B[i]
    i = i + 1

proc addText*(A: var ByteSeq, s: string) {.role: helper,
    metaTags: {tagCodecBoundary, tagWrite}.} =
  ## A/s: buffer extended by a u32 length prefix and the raw characters.
  var
    i: int = 0
  A.addU32(uint32(s.len))
  while i < s.len:
    A.add uint8(s[i])
    i = i + 1

proc readText*(A: openArray[uint8], o: var int): string {.role: parser,
    metaTags: {tagCodecBoundary, tagRead}.} =
  ## A: source buffer.
  ## o: cursor advanced past the length prefix and the characters.
  var
    n: int = 0
    i: int = 0
  n = int(A.getU32(o))
  o = o + 4
  result = newString(n)
  while i < n:
    result[i] = char(A[o + i])
    i = i + 1
  o = o + n

proc encodeHeader*(h: FileHeader): ByteSeq {.role: encryptor,
    metaTags: {tagCodecBoundary, tagStorageIo, tagWrite}.} =
  ## h: header written at offset zero of every Geist file.
  var
    i: int = 0
  result = newSeq[uint8](headerBytes)
  while i < geistMagic.len:
    result[i] = uint8(geistMagic[i])
    i = i + 1
  result.putU16(8, h.version)
  result.putU32(10, h.clusterCount)
  result.putU64(14, h.generation)

proc decodeHeader*(A: openArray[uint8]): tuple[ok: bool, h: FileHeader,
    err: string] {.role: parser,
    metaTags: {tagCodecBoundary, tagStorageIo, tagRead}.} =
  ## A: first `headerBytes` bytes of a candidate Geist file.
  var
    i: int = 0
  if A.len < headerBytes:
    return (false, FileHeader(), "file shorter than a Geist header")
  while i < geistMagic.len:
    if A[i] != uint8(geistMagic[i]):
      return (false, FileHeader(), "not a Geist file: bad magic")
    i = i + 1
  result.h.version = A.getU16(8)
  result.h.clusterCount = A.getU32(10)
  result.h.generation = A.getU64(14)
  if result.h.version != geistFormatVersion:
    return (false, result.h, "unsupported Geist format version " &
      $result.h.version)
  result.ok = true

proc encodeIndexEntry*(e: IndexEntry): ByteSeq {.role: encryptor,
    metaTags: {tagCodecBoundary, tagStorageIo, tagWrite}.} =
  ## e: one cluster index row.
  var
    i: int = 0
  result = newSeq[uint8](indexEntryBytes)
  result[0] = uint8(ord(e.role))
  result[1] = uint8(ord(e.mode))
  result.putU16(2, e.schemaId)
  result.putU32(4, e.rowCount)
  result.putU32(8, e.rowBytes)
  result.putU64(12, e.at)
  result.putU64(20, e.len)
  result.putU64(28, e.auxAt)
  result.putU64(36, e.auxLen)
  while i < 32 and i < e.hash.len:
    result[44 + i] = e.hash[i]
    i = i + 1

proc decodeIndexEntry*(A: openArray[uint8], o: int): IndexEntry {.role: parser,
    metaTags: {tagCodecBoundary, tagStorageIo, tagRead}.} =
  ## A/o: buffer and offset of one encoded index row.
  var
    i: int = 0
  result.role = ClusterRole(A[o])
  result.mode = ClusterMode(A[o + 1])
  result.schemaId = A.getU16(o + 2)
  result.rowCount = A.getU32(o + 4)
  result.rowBytes = A.getU32(o + 8)
  result.at = A.getU64(o + 12)
  result.len = A.getU64(o + 20)
  result.auxAt = A.getU64(o + 28)
  result.auxLen = A.getU64(o + 36)
  result.hash = newSeq[uint8](32)
  while i < 32:
    result.hash[i] = A[o + 44 + i]
    i = i + 1

proc encodeSchema*(s: Schema): ByteSeq {.role: encryptor,
    metaTags: {tagCodecBoundary, tagStorageIo, tagWrite}.} =
  ## s: schema block preceding a cluster's fixed rows.
  var
    i: int = 0
  result = @[]
  result.addText(s.typeName)
  result.addU32(uint32(s.names.len))
  while i < s.names.len:
    result.addText(s.names[i])
    i = i + 1
  i = 0
  result.add (if s.autoCollapse: 1'u8 else: 0'u8)
  result.addU32(uint32(s.slots.len))
  while i < s.slots.len:
    result.addU16(s.slots[i].nameId)
    result.add uint8(ord(s.slots[i].kind))
    result.add uint8(ord(s.slots[i].column))
    result.add uint8(ord(s.slots[i].onOverflow))
    result.addU32(s.slots[i].width)
    i = i + 1
  i = 0
  result.addU32(uint32(s.aliases.len))
  while i < s.aliases.len:
    result.addText(s.aliases[i].old)
    result.addText(s.aliases[i].current)
    i = i + 1

proc decodeSchema*(A: openArray[uint8], o: var int): Schema {.role: parser,
    metaTags: {tagCodecBoundary, tagStorageIo, tagRead}.} =
  ## A: buffer holding an encoded schema.
  ## o: cursor advanced past the schema block.
  var
    n: int = 0
    i: int = 0
    sl: Slot
    a: string = ""
    b: string = ""
  result.typeName = A.readText(o)
  n = int(A.getU32(o))
  o = o + 4
  while i < n:
    result.names.add A.readText(o)
    i = i + 1
  i = 0
  result.autoCollapse = A[o] != 0'u8
  o = o + 1
  n = int(A.getU32(o))
  o = o + 4
  while i < n:
    sl.nameId = A.getU16(o)
    sl.kind = SlotKind(A[o + 2])
    sl.column = ColumnKind(A[o + 3])
    sl.onOverflow = OverflowPolicy(A[o + 4])
    sl.width = A.getU32(o + 5)
    result.slots.add sl
    o = o + 9
    i = i + 1
  i = 0
  n = int(A.getU32(o))
  o = o + 4
  while i < n:
    a = A.readText(o)
    b = A.readText(o)
    result.aliases.add (old: a, current: b)
    i = i + 1
