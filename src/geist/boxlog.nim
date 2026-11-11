## ---------------------------------------------------------------------
## Box log <- one append-only file per box; a write is one new record
## ---------------------------------------------------------------------
##
## On disk:
##
##   <root>/<kind>/<id>/box.log      the log
##   <root>/<kind>/<id>/blobs/<n>    the data of item number n, when it is large
##
## ╭─ ❧ Def. 1: the file 🌊
##
##   +--------+---------+---------+---------+-----+
##   | "GBX1" | logId   | record  | record  | ... |
##   | 4 B    | u64     |         |         |     |
##   +--------+---------+---------+---------+-----+
##
## ╭─ ❧ Def. 2: one record 🍣
##
##   +----------+------+------------------+------------------------------+
##   | bodyLen  | kind | body             | check                        |
##   | u32      | u8   | bodyLen bytes    | 16 B, BLAKE3 of all before   |
##   +----------+------+------------------+------------------------------+
##
##   kind 1 head   who owns it, who may use it, the counter
##   kind 2 item   one item
##   kind 3 gone   u16 + key: this item no longer exists
##
##   All numbers little-endian. With a key at rest the body is sealed; the
##   check covers the sealed bytes, so integrity can be checked without the key.
##
## ╭─ ❧ Def. 3: the item body 🐦‍🔥
##
##   u16+key | number u64 | version u64 | u16+writer | atMs u64 | u32+label |
##   then 00 | u32+data                  (small item, data right here)
##   or   01 | size u64 | hash 32        (large item, data in blobs/<number>)
##
## ╭─ ❧ Why a crash cannot reuse a number ⚠️
##
## The number of an item is written INSIDE that item's record. The box's counter
## is not stored for each write: reading the log back finds the highest number.
## So a number and its item are one write and cannot disagree.
##
##   record complete?   after a restart
##   -----------------  -----------------------------------------------------
##   no (cut short)     the incomplete tail is cut off; that write never happened
##   yes, check wrong   the box refuses to open and says where (`repairBox`)
##   yes                it counts
##
## `syncBox` is what makes a write durable. Several writes may share one sync.

import std/[algorithm, os, strutils, sysrand, tables]

import runePragmas
import ./types
import ./durable
import ./secrets
import ./textfile
import ./trust
import ./crypto/hashing
import ./crypto/hashwidths
import ./boxtypes
import ./boxframe

export boxframe except putLE, putSized, getLE, getBytes, getSized

const
  boxMagic = "GBX1"
  boxFileHeader = 12'i64
  boxFramePrefix = 5
  boxMaxBody = 64 * 1024 * 1024
  boxLogName* = "box.log"
  boxBlobDir* = "blobs"

proc logPath*(B: BoxFile): string {.role: helper, inline, tag: "boxes".} =
  ## B: the log of this box.
  result = B.dir / boxLogName

proc blobPath*(B: BoxFile, number: uint64): string {.role: helper, inline,
    tag: "boxes".} =
  ## B/number: the file of one large item.
  result = B.dir / boxBlobDir / $number

proc nameBytes(B: BoxFile): ByteSeq {.role: helper, inline.} =
  ## B: what every sealed body is tied to, so it cannot be moved to another box.
  result = textBytes(B.name)

proc sealBody(B: BoxFile, body: openArray[uint8]): ByteSeq {.role: encryptor.} =
  ## B/body: the body as it goes to disk (Def. 2).
  var
    s: SealedBlob = SealedBlob()
  if B.atRest == nil:
    return @body
  s = sealWithKey(B.atRest.secret, body, nameBytes(B))
  if not s.ok:
    raise newException(IOError, "box record could not be sealed: " & s.err)
  result = s.data

proc openBody(B: BoxFile, body: openArray[uint8]): ByteSeq {.role: decryptor.} =
  ## B/body: the body as it lay on disk.
  var
    s: SealedBlob = SealedBlob()
  if B.atRest == nil:
    return @body
  s = openWithKey(B.atRest.secret, body, nameBytes(B))
  if not s.ok:
    raise newException(ValueError, "box record does not open with this key")
  result = s.data

proc openBoxBody*(B: BoxFile, body: openArray[uint8]): ByteSeq {.role: decryptor,
    tag: "boxes".} =
  ## B/body: a record body as it lay on disk, opened.
  result = openBody(B, body)

proc forgetSlot(B: BoxFile, key: string) {.role: actor.} =
  ## B/key: this item is no longer live.
  var
    s: BoxSlot = BoxSlot()
  if not B.index.hasKey(key):
    return
  s = B.index[key]
  B.liveBytes = B.liveBytes - s.frameBytes
  B.keyOf.del(s.number)
  B.index.del(key)

proc noteItem(B: BoxFile, P: BoxItemParts, offset, frameBytes: int64) {.role: actor.} =
  ## B/P/offset/frameBytes: one item record, in memory.
  forgetSlot(B, P.item.key)
  B.index[P.item.key] = BoxSlot(number: P.item.number, version: P.item.version,
    atMs: P.item.atMs, writer: P.item.writer, offset: offset,
    frameBytes: frameBytes, blobBytes: P.blobSize)
  B.keyOf[P.item.number] = P.item.key
  B.liveBytes = B.liveBytes + frameBytes
  if B.numbers.len == 0 or P.item.number > B.numbers[^1]:
    B.numbers.add(P.item.number)
  B.counter = max(B.counter, P.item.number)
  if P.item.label.len > 0:
    B.chain = labelHead(P.item.label)

proc applyFrame*(B: BoxFile, kind: BoxRecordKind, body: openArray[uint8],
    offset, frameBytes: int64) {.role: truthBuilder, tag: "boxes".} =
  ## B/kind/body/offset/frameBytes: what one record means for the memory of the box.
  var
    h: tuple[head: BoxHead, counter: uint64] = (BoxHead(), 0'u64)
    o: int = 0
  case kind
  of brHead:
    h = decodeHead(body)
    B.head = h.head
    B.counter = max(B.counter, h.counter)
  of brItem:
    noteItem(B, decodeItem(body), offset, frameBytes)
  of brGone:
    forgetSlot(B, getSized(body, o, 2))

proc syncBox*(B: BoxFile): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "boxes|storageIo|write".} =
  ## B: everything appended so far is on the disk when this returns ok.
  if not B.dirty:
    return (true, "")
  try:
    flushFile(B.writer)
    if not syncFile(B.writer):
      return (false, "fsync failed on " & B.logPath())
    B.dirty = false
    result = (true, "")
  except CatchableError as e:
    result = (false, e.msg)

proc appendFrame*(B: BoxFile, kind: BoxRecordKind, body: openArray[uint8]) {.
    role: dataWriter, tag: "boxes|storageIo|write".} =
  ## B/kind/body: one record added, and what it says taken into memory. Not on
  ## the disk until `syncBox`. Raises when the disk refuses.
  var
    sealed: ByteSeq = sealBody(B, body)
    A: ByteSeq = frameOf(kind, sealed)
    at: int64 = B.size
  if A.len > 0 and B.writer.writeBuffer(addr A[0], A.len) != A.len:
    raise newException(IOError, "could not write to " & B.logPath())
  B.size = B.size + int64(A.len)
  B.dirty = true
  applyFrame(B, kind, body, at, int64(A.len))

proc readFrameAt*(f: File, at: int64): tuple[ok: bool, torn: bool,
    kind: BoxRecordKind, body: ByteSeq, frameBytes: int64] {.role: dataFetcher,
    tag: "boxes|storageIo|read".} =
  ## f/at: one record, its check verified. `torn` = the file ends inside it.
  ## ok = false and torn = false means the record is there and wrong.
  var
    prefix: array[boxFramePrefix, uint8] = default(array[boxFramePrefix, uint8])
    n: int = 0
    whole: ByteSeq = @[]
    o: int = 0
  f.setFilePos(at)
  if f.readBuffer(addr prefix[0], boxFramePrefix) != boxFramePrefix:
    result.torn = true
    return
  n = int(getLE(prefix, o, 4))
  if n < 0 or n > boxMaxBody or int(prefix[4]) notin 1 .. 3:
    return
  whole = newSeq[uint8](boxFramePrefix + n + boxCheckBytes)
  copyMem(addr whole[0], addr prefix[0], boxFramePrefix)
  if f.readBuffer(addr whole[boxFramePrefix], n + boxCheckBytes) != n + boxCheckBytes:
    result.torn = true
    return
  if not constantTimeEq(geistHash(hkBlake3,
      whole.toOpenArray(0, boxFramePrefix + n - 1), boxCheckBytes),
      whole.toOpenArray(boxFramePrefix + n, whole.len - 1)):
    return
  result.ok = true
  result.kind = BoxRecordKind(prefix[4])
  result.body = whole[boxFramePrefix ..< boxFramePrefix + n]
  result.frameBytes = int64(whole.len)

proc readRecordBody*(B: BoxFile, at: int64): tuple[ok: bool, body: ByteSeq] {.
    role: dataFetcher, tag: "boxes|storageIo|read".} =
  ## B/at: the opened body of the record at `at`, or ok = false when it is damaged.
  var
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
  if B.dirty:
    flushFile(B.writer)
  r = readFrameAt(B.reader, at)
  if not r.ok:
    return
  try:
    result = (true, openBody(B, r.body))
  except CatchableError:
    result = (false, @[])

proc readWholeItem*(B: BoxFile, s: BoxSlot): tuple[ok: bool, item: BoxItem] {.
    role: dataFetcher, tag: "boxes|storageIo|read".} =
  ## B/s: one live item with its data; a large item is read from its file and
  ## checked. ok = false when anything is damaged.
  var
    r: tuple[ok: bool, body: ByteSeq] = readRecordBody(B, s.offset)
    P: BoxItemParts = BoxItemParts()
    raw: ByteSeq = @[]
  if not r.ok:
    return
  try:
    P = decodeItem(r.body)
    if P.isBlob:
      raw = cast[ByteSeq](readFile(B.blobPath(P.item.number)))
    if P.isBlob and not constantTimeEq(geistHash(hkBlake3, raw, fullDigestBytes), P.blobHash):
      return
    if P.isBlob:
      P.item.data = openBody(B, raw)
  except CatchableError:
    return
  result = (true, P.item)

proc writeBlob*(B: BoxFile, number: uint64, data: openArray[uint8]): tuple[
    ok: bool, size: int64, hash: ByteSeq, err: string] {.role: dataWriter,
    tag: "boxes|storageIo|write".} =
  ## B/number/data: the file of one large item, on the disk BEFORE its record.
  var
    sealed: ByteSeq = sealBody(B, data)
    done: tuple[ok: bool, err: string] = writeDurable(B.blobPath(number), sealed)
  if not done.ok:
    return (false, 0'i64, @[], done.err)
  result = (true, int64(sealed.len), geistHash(hkBlake3, sealed, fullDigestBytes), "")

proc newLogId(): uint64 {.role: helper.} =
  ## 8 random bytes; never 0.
  var
    A: seq[uint8] = urandom(8)
    o: int = 0
  result = getLE(A, o, 8)
  if result == 0'u64:
    result = 1'u64

proc headerBytes(id: uint64): ByteSeq {.role: helper.} =
  ## id: Def. 1, the first 12 bytes.
  result = textBytes(boxMagic)
  putLE(result, id, 8)

proc openHandles(B: BoxFile) {.role: dataFetcher, tag: "boxes|storageIo|read".} =
  ## B: the two file handles, on the current log.
  if not open(B.reader, B.logPath(), fmRead):
    raise newException(IOError, "cannot read " & B.logPath())
  if not open(B.writer, B.logPath(), fmAppend):
    B.reader.close()
    raise newException(IOError, "cannot write " & B.logPath())

proc closeBoxFile*(B: BoxFile) {.role: actor, tag: "boxes|storageIo".} =
  ## B: the handles closed. Call `syncBox` first when writes are pending.
  if B.reader != nil: B.reader.close()
  if B.writer != nil: B.writer.close()
  B.reader = nil
  B.writer = nil

proc makeBoxFile*(dir, name: string, atRest: BoxKey): BoxFile {.
    role: configurator, tag: "boxes".} =
  ## dir/name/atRest: an empty BoxFile; nothing on disk yet.
  result = BoxFile(dir: dir, name: name, atRest: atRest,
    chain: boxZeroHead, index: initTable[string, BoxSlot](),
    keyOf: initTable[uint64, string]())

proc createBoxFile*(B: BoxFile, H: BoxHead): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "boxes|storageIo|write".} =
  ## B/H: the log made, with its head as the first record, durable.
  var
    id: uint64 = newLogId()
    start: tuple[ok: bool, err: string] = (false, "")
  try:
    createDir(B.dir)
    start = writeDurable(B.logPath(), headerBytes(id))
    if not start.ok:
      return start
    B.logId = id
    B.size = boxFileHeader
    openHandles(B)
    appendFrame(B, brHead, encodeHead(H, 0'u64))
    result = syncBox(B)
    if result.ok:
      result = syncDir(B.dir)
  except CatchableError as e:
    result = (false, e.msg)

proc replayFrames(B: BoxFile, f: File): string {.role: truthBuilder.} =
  ## B/f: every record taken into memory; "" or what is damaged. An incomplete
  ## last record is cut off (the file is shortened by `openBoxFile`).
  var
    at: int64 = boxFileHeader
    total: int64 = getFileSize(f)
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
  while at < total:
    r = readFrameAt(f, at)
    if r.torn:
      break
    if not r.ok:
      return "the record at byte " & $at & " of " & B.logPath() & " is damaged"
    applyFrame(B, r.kind, openBody(B, r.body), at, r.frameBytes)
    at = at + r.frameBytes
  B.size = at

proc readLogId(f: File): uint64 {.role: parser.} =
  ## f: the file header. Raises when it is not a box log.
  var
    A: array[12, uint8] = default(array[12, uint8])
    o: int = 4
  f.setFilePos(0)
  if f.readBuffer(addr A[0], 12) != 12 or
      textOfBytes(A.toOpenArray(0, 3)) != boxMagic:
    raise newException(ValueError, "this is not a box log")
  result = getLE(A, o, 8)

proc cutTornTail(B: BoxFile) {.role: actor.} =
  ## B: drops whatever lies past the last complete record. The kept part goes to
  ## a new file that replaces the old in one rename: std/os has no way to shorten
  ## a file on both systems, and this happens only after a crash.
  var
    tmp: string = B.logPath() & ".tmp"
    src: File = nil
    dst: File = nil
    left: int64 = B.size
    n: int = 0
    A: ByteSeq = newSeq[uint8](1024 * 1024)
  if getFileSize(B.logPath()) <= B.size:
    return
  if not open(src, B.logPath(), fmRead) or not open(dst, tmp, fmWrite):
    raise newException(IOError, "cannot repair " & B.logPath())
  while left > 0:
    n = src.readBuffer(addr A[0], int(min(left, int64(A.len))))
    if n <= 0 or dst.writeBuffer(addr A[0], n) != n:
      raise newException(IOError, "cannot repair " & B.logPath())
    left = left - int64(n)
  flushFile(dst)
  discard syncFile(dst)
  src.close()
  dst.close()
  moveFile(tmp, B.logPath())
  discard syncDir(B.dir)

proc openBoxFile*(B: BoxFile): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "boxes|storageIo|read".} =
  ## B: reads the log back into memory, cutting an incomplete tail.
  var
    f: File = nil
    damage: string = ""
  try:
    if not open(f, B.logPath(), fmRead):
      return (false, "cannot read " & B.logPath())
    B.logId = readLogId(f)
    damage = replayFrames(B, f)
    f.close()
    f = nil
    if damage.len > 0:
      return (false, damage)
    cutTornTail(B)
    openHandles(B)
    result = (true, "")
  except CatchableError as e:
    if f != nil: f.close()
    result = (false, e.msg)

proc repairBox*(dir, name: string, atRest: BoxKey): tuple[ok: bool,
    keptBytes: int64, err: string] {.role: actor, tag: "boxes|appApi|storageIo|write".} =
  ## dir/name/atRest: a box that refuses to open. Everything from the
  ## first damaged record on is cut off. An operator's decision: what is cut is
  ## gone, and is reported as `keptBytes` against the old size.
  var
    B: BoxFile = makeBoxFile(dir, name, atRest)
    f: File = nil
    at: int64 = boxFileHeader
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
  try:
    if not open(f, B.logPath(), fmRead):
      return (false, 0'i64, "cannot read " & B.logPath())
    B.logId = readLogId(f)
    r = readFrameAt(f, at)
    while r.ok:
      at = at + r.frameBytes
      r = readFrameAt(f, at)
    f.close()
    f = nil
    B.size = at
    cutTornTail(B)
    result = (true, at, "")
  except CatchableError as e:
    if f != nil: f.close()
    result = (false, 0'i64, e.msg)

proc copyFrame(B: BoxFile, s: BoxSlot, into: File): int64 {.role: dataWriter.} =
  ## B/s/into: the record of one live item copied as it lies. Returns its size.
  var
    A: ByteSeq = newSeq[uint8](int(s.frameBytes))
  B.reader.setFilePos(s.offset)
  if B.reader.readBuffer(addr A[0], A.len) != A.len or
      into.writeBuffer(addr A[0], A.len) != A.len:
    raise newException(IOError, "could not rewrite " & B.logPath())
  result = s.frameBytes

proc liveSlots(B: BoxFile): seq[BoxSlot] {.role: parser.} =
  ## B: every live item, oldest number first.
  for key, s in B.index.pairs:
    result.add(s)
  result.sort(proc (a, b: BoxSlot): int = cmp(a.number, b.number))

proc removeOrphanBlobs(B: BoxFile) {.role: actor.} =
  ## B: files in blobs/ that no live item names (a crash left them behind).
  for kind, path in walkDir(B.dir / boxBlobDir):
    if kind != pcFile:
      continue
    if not B.keyOf.hasKey(parseBiggestUInt(path.extractFilename())):
      removeFile(path)

proc needsCompacting*(B: BoxFile): bool {.role: parser, tag: "boxes".} =
  ## B: true when more than half of a log of any real size is dead.
  var
    dead: int64 = B.size - boxFileHeader - B.liveBytes
  result = dead > 64 * 1024 and dead > B.liveBytes

proc compactBox*(B: BoxFile): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "boxes|storageIo|write".} =
  ## B: the log written anew with only what is live: head first, then items in
  ## number order. The new file replaces the old in one rename; a crash leaves
  ## one or the other, whole. It gets a new logId.
  var
    tmp: string = B.logPath() & ".tmp"
    id: uint64 = newLogId()
    f: File = nil
    A: ByteSeq = @[]
  try:
    result = syncBox(B)
    if not result.ok:
      return
    if not open(f, tmp, fmWrite):
      return (false, "cannot write " & tmp)
    A = headerBytes(id) & frameOf(brHead, sealBody(B, encodeHead(B.head, B.counter)))
    discard f.writeBuffer(addr A[0], A.len)
    for s in liveSlots(B):
      discard copyFrame(B, s, f)
    flushFile(f)
    if not syncFile(f):
      f.close()
      return (false, "fsync failed on " & tmp)
    f.close()
    closeBoxFile(B)
    moveFile(tmp, B.logPath())
    result = syncDir(B.dir)
    if not result.ok:
      return
    B.index = initTable[string, BoxSlot]()
    B.keyOf = initTable[uint64, string]()
    B.numbers = @[]
    B.liveBytes = 0
    B.chain = boxZeroHead
    result = openBoxFile(B)
    if result.ok:
      removeOrphanBlobs(B)
  except CatchableError as e:
    if f != nil: f.close()
    result = (false, e.msg)
