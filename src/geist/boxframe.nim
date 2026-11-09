## ---------------------------------------------------------------------
## Box frame <- one record of a box log, as bytes (./boxlog says where they go)
## ---------------------------------------------------------------------
##
## All numbers little-endian. The layouts are drawn in ./boxlog, Def. 2 and 3.

import std/strutils

import runePragmas
import ./types
import ./textfile
import ./trust
import ./crypto/hashing
import ./crypto/hashwidths
import ./boxtypes

const
  boxCheckBytes* = 16

type
  BoxRecordKind* = enum
    brHead = 1, brItem = 2, brGone = 3

  BoxItemParts* {.role: preparedData, tag: "boxes|types".} = object
    ## Def. 3, read from a record.
    item*: BoxItem
    isBlob*: bool
    blobSize*: int64
    blobHash*: ByteSeq

proc textOfBytes*(A: openArray[uint8]): string {.role: helper, tag: "boxes".} =
  ## A: the same bytes as text.
  result = newString(A.len)
  if A.len > 0:
    copyMem(addr result[0], unsafeAddr A[0], A.len)

proc putLE*(A: var ByteSeq, v: uint64, n: int) {.role: dataWriter, inline.} =
  ## A/v/n: v as n little-endian bytes.
  var
    i: int = 0
  while i < n:
    A.add(uint8((v shr (8 * i)) and 255'u64))
    i = i + 1

proc putSized*(A: var ByteSeq, s: string, width: int) {.role: dataWriter, inline.} =
  ## A/s/width: s with its length in `width` bytes in front.
  putLE(A, uint64(s.len), width)
  A.add(textBytes(s))

proc getLE*(A: openArray[uint8], o: var int, n: int): uint64 {.role: parser.} =
  ## A/o/n: n little-endian bytes at o. Raises when they are not there.
  var
    i: int = 0
  if o + n > A.len:
    raise newException(ValueError, "box record is short")
  while i < n:
    result = result or (uint64(A[o + i]) shl (8 * i))
    i = i + 1
  o = o + n

proc getBytes*(A: openArray[uint8], o: var int, n: int): ByteSeq {.role: parser.} =
  ## A/o/n: n bytes at o. Raises when they are not there.
  if n < 0 or o + n > A.len:
    raise newException(ValueError, "box record is short")
  result = @(A.toOpenArray(o, o + n - 1))
  o = o + n

proc getSized*(A: openArray[uint8], o: var int, width: int): string {.role: parser.} =
  ## A/o/width: a text with its length in `width` bytes in front.
  var
    n: int = int(getLE(A, o, width))
  result = textOfBytes(getBytes(A, o, n))

proc trustText(T: TrustTable): string {.role: helper.} =
  ## T: one key per line: signer, algorithm, hex.
  var
    lines: seq[string] = @[]
  for k in T.keys:
    lines.add(k.signer & " " & k.algorithm & " " & hexText(k.publicKey))
  result = lines.join("\n")

proc trustOfText(s: string): TrustTable {.role: parser.} =
  ## s: as `trustText` wrote it.
  var
    p: seq[string] = @[]
  for line in s.splitLines():
    p = line.split(' ')
    if p.len == 3:
      result.keys.add(TrustedKey(signer: p[0], algorithm: p[1], publicKey: unhexText(p[2])))

proc encodeHead*(H: BoxHead, counter: uint64): ByteSeq {.role: dataWriter,
    tag: "boxes|wire".} =
  ## H/counter: kind 1 of Def. 2.
  putSized(result, H.kind, 2)
  putSized(result, H.id, 2)
  putSized(result, H.owner, 2)
  putSized(result, H.members.join("\n"), 4)
  putSized(result, H.whitelist.join("\n"), 4)
  putLE(result, counter, 8)
  putSized(result, trustText(H.trust), 4)

proc linesOf(s: string): seq[string] {.role: parser.} =
  ## s: the non-empty lines.
  for x in s.splitLines():
    if x.len > 0:
      result.add x

proc decodeHead*(A: openArray[uint8]): tuple[head: BoxHead, counter: uint64] {.
    role: parser, tag: "boxes|wire".} =
  ## A: kind 1 of Def. 2. Raises when malformed.
  var
    o: int = 0
  result.head.kind = getSized(A, o, 2)
  result.head.id = getSized(A, o, 2)
  result.head.owner = getSized(A, o, 2)
  result.head.members = linesOf(getSized(A, o, 4))
  result.head.whitelist = linesOf(getSized(A, o, 4))
  result.counter = getLE(A, o, 8)
  result.head.trust = trustOfText(getSized(A, o, 4))

proc encodeItemHead(R: BoxItem): ByteSeq {.role: dataWriter.} =
  ## R: Def. 3 up to the label.
  putSized(result, R.key, 2)
  putLE(result, R.number, 8)
  putLE(result, R.version, 8)
  putSized(result, R.writer, 2)
  putLE(result, R.atMs, 8)
  putSized(result, R.label, 4)

proc encodeItem*(R: BoxItem): ByteSeq {.role: dataWriter, tag: "boxes|wire".} =
  ## R: Def. 3, the data right here.
  result = encodeItemHead(R)
  result.add(0'u8)
  putLE(result, uint64(R.data.len), 4)
  result.add(R.data)

proc encodeBlobItem*(R: BoxItem, size: int64, hash: openArray[uint8]): ByteSeq {.
    role: dataWriter, tag: "boxes|wire".} =
  ## R/size/hash: Def. 3, the data in its own file.
  result = encodeItemHead(R)
  result.add(1'u8)
  putLE(result, uint64(size), 8)
  result.add(hash)

proc decodeItem*(A: openArray[uint8]): BoxItemParts {.role: parser,
    tag: "boxes|wire".} =
  ## A: Def. 3. Raises when malformed.
  var
    o: int = 0
    n: int = 0
  result.item.key = getSized(A, o, 2)
  result.item.number = getLE(A, o, 8)
  result.item.version = getLE(A, o, 8)
  result.item.writer = getSized(A, o, 2)
  result.item.atMs = getLE(A, o, 8)
  result.item.label = getSized(A, o, 4)
  if o >= A.len:
    raise newException(ValueError, "box record is short")
  result.isBlob = A[o] == 1'u8
  o = o + 1
  if result.isBlob:
    result.blobSize = int64(getLE(A, o, 8))
    result.blobHash = getBytes(A, o, fullDigestBytes)
    return
  n = int(getLE(A, o, 4))
  result.item.data = getBytes(A, o, n)

proc labelHead*(label: string): string {.role: helper, tag: "boxes|cryptoBoundary".} =
  ## label: a signed label -> what the next label must name as `prev`.
  var
    n: tuple[ok: bool, note: SidecarNote, err: string] = parseNote(label)
  if n.ok:
    result = hexText(geistHash(hkBlake3, textBytes(noteSignedText(n.note.fields)),
      fullDigestBytes))

proc frameOf*(kind: BoxRecordKind, body: openArray[uint8]): ByteSeq {.
    role: dataWriter, tag: "boxes|wire".} =
  ## kind/body: Def. 2, whole.
  putLE(result, uint64(body.len), 4)
  result.add(uint8(ord(kind)))
  result.add(body)
  result.add(geistHash(hkBlake3, result, boxCheckBytes))

