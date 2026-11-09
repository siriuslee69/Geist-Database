## ---------------------------------------------------------------------
## Box copy <- one machine's log handed to another, record by record
## ---------------------------------------------------------------------
##
## Geist does not know another machine exists. It knows how to hand out bytes
## "from this place on" and how to take them in again. Whoever moves them is
## somebody else's business.
##
##   holder                                 copy
##   ------                                 ----
##   listBoxes             ───────────▶     what do I lack?
##   boxLogSince(id, 800)  ───────────▶     chunk: records from 800 on
##   boxBlobBytes(n)       ───────────▶     putBoxBlob (large items first)
##                                          applyBoxLog(chunk)
##
## Def. 1 (logId): names one version of a log. It changes when the log is
##   rewritten. A copy that asks with the wrong logId is sent the log from its
##   very start, and replaces what it had.
## Def. 2 (whole records): a chunk ends at the end of a record. The receiver
##   checks each record's hash before any of them counts.

import std/[os, tables]

import runePragmas
import ./types
import ./durable
import ./boxtypes
import ./boxlog
import ./boxshelf

const
  boxCopyChunkBytes* = 512 * 1024

type
  BoxListing* {.role: preparedData, tag: "boxes|types".} = object
    ## One box, as `listBoxes` sees it.
    kind*: string
    id*: string
    logId*: uint64
    size*: int64

  BoxCopyChunk* {.role: preparedData, tag: "boxes|types".} = object
    ## Records of one box. offset 0 means `bytes` starts with the file header.
    ok*: bool
    err*: string
    logId*: uint64
    offset*: int64
    bytes*: ByteSeq
    size*: int64
      ## where the holder's log ends now
    blobs*: seq[uint64]
      ## numbers of the large items named in this chunk

proc listBoxes*(S: BoxShelf): seq[BoxListing] {.role: dataFetcher,
    tag: "boxes|appApi|storageIo|read".} =
  ## S: every box on this shelf.
  var
    got: tuple[found: bool, box: BoxFile] = (false, nil)
    k: string = ""
    id: string = ""
  for kindEntry in walkDir(S.root):
    if kindEntry.kind != pcDir:
      continue
    k = kindEntry.path.extractFilename()
    for boxEntry in walkDir(kindEntry.path):
      id = boxEntry.path.extractFilename()
      got = S.boxOf(k, id)
      if got.found:
        result.add(BoxListing(kind: k, id: id, logId: got.box.logId, size: got.box.size))

proc noteBlobs(B: BoxFile, f: File, at, stop: int64, R: var BoxCopyChunk) {.
    role: parser.} =
  ## B/f/at/stop/R: the large items among the records from `at` to `stop`.
  var
    pos: int64 = at
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
    P: BoxItemParts = BoxItemParts()
  while pos < stop:
    r = readFrameAt(f, pos)
    if not r.ok:
      raise newException(IOError, "a record of this log is damaged")
    pos = pos + r.frameBytes
    if r.kind != brItem:
      continue
    P = decodeItem(openBoxBody(B, r.body))
    if P.isBlob:
      R.blobs.add(P.item.number)

proc wholeRecordsEnd(f: File, at, limit: int64): int64 {.role: parser.} =
  ## f/at/limit: where the last whole record that fits below `limit` ends.
  var
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
  result = at
  while result < limit:
    r = readFrameAt(f, result)
    if not r.ok or (result > at and result + r.frameBytes > limit):
      return
    result = result + r.frameBytes

proc boxLogSince*(S: BoxShelf, kind, id: string, logId: uint64, offset: int64,
    maxBytes: int = boxCopyChunkBytes): BoxCopyChunk {.role: dataFetcher,
    tag: "boxes|appApi|storageIo|read".} =
  ## S/kind/id: which log. logId/offset: where the copy stands. maxBytes: about
  ## how much to hand out. Asks no permission: whoever calls this already decided
  ## this machine may have a copy of everything.
  var
    got: tuple[found: bool, box: BoxFile] = S.boxOf(kind, id)
    at: int64 = offset
    stop: int64 = 0
    head: ByteSeq = @[]
  if not got.found:
    return BoxCopyChunk(err: boxRefused)
  discard syncBox(got.box)
  if logId != got.box.logId or offset <= 0:
    at = 12'i64
    result.offset = 0
    head = newSeq[uint8](12)
    got.box.reader.setFilePos(0)
    discard got.box.reader.readBuffer(addr head[0], 12)
  else:
    result.offset = offset
  result.logId = got.box.logId
  result.size = got.box.size
  try:
    stop = wholeRecordsEnd(got.box.reader, at, min(got.box.size, at + int64(maxBytes)))
    noteBlobs(got.box, got.box.reader, at, stop, result)
    result.bytes = head & newSeq[uint8](int(stop - at))
    got.box.reader.setFilePos(at)
    if stop > at:
      discard got.box.reader.readBuffer(addr result.bytes[head.len], int(stop - at))
    result.ok = true
  except CatchableError as e:
    result = BoxCopyChunk(err: e.msg)

proc boxBlobBytes*(S: BoxShelf, kind, id: string, number: uint64): tuple[ok: bool,
    bytes: ByteSeq] {.role: dataFetcher, tag: "boxes|appApi|storageIo|read".} =
  ## S/kind/id/number: the file of one large item, as it lies on the disk.
  var
    got: tuple[found: bool, box: BoxFile] = S.boxOf(kind, id)
  if not got.found or not fileExists(got.box.blobPath(number)):
    return
  result = (true, cast[ByteSeq](readFile(got.box.blobPath(number))))

proc putBoxBlob*(S: BoxShelf, kind, id: string, number: uint64,
    bytes: openArray[uint8]): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/number/bytes: a large item, kept before the record that names it.
  ## The record's hash is checked against these bytes when the item is read.
  if not validBoxId(id):
    return (false, boxRefused)
  result = writeDurable(S.boxDir(kind, id) / boxBlobDir / $number, bytes)

proc replaceLog(S: BoxShelf, kind, id: string, C: BoxCopyChunk): tuple[ok: bool,
    err: string] {.role: dataWriter, tag: "boxes|storageIo|write".} =
  ## S/kind/id/C: the log starts over with this chunk.
  var
    dir: string = S.boxDir(kind, id)
    name: string = boxName(kind, id)
    B: BoxFile = nil
    was: int64 = 0
  if S.open.hasKey(name):
    closeBoxFile(S.open[name])
    S.open.del(name)
  createDir(dir)
  if fileExists(dir / boxLogName):
    was = getFileSize(dir / boxLogName)
  result = replaceDurable(dir / boxLogName, C.bytes)
  if not result.ok:
    return
  B = makeBoxFile(dir, name, S.atRest)
  result = openBoxFile(B)
  if not result.ok:
    return
  S.rememberBox(name, B)
  S.charge(B.head.owner, if was == 0'i64: 1 else: 0, B.size - was)

proc appendRecords(S: BoxShelf, B: BoxFile, C: BoxCopyChunk): tuple[ok: bool,
    err: string] {.role: dataWriter, tag: "boxes|storageIo|write".} =
  ## S/B/C: records added at the end of the log, every one checked first.
  var
    tmp: string = B.logPath() & ".in"
    f: File = nil
    pos: int64 = 0
    r: tuple[ok: bool, torn: bool, kind: BoxRecordKind, body: ByteSeq,
      frameBytes: int64] = (false, false, brHead, @[], 0'i64)
    was: int64 = B.size
  writeFile(tmp, cast[string](C.bytes))
  if not open(f, tmp, fmRead):
    return (false, "cannot read " & tmp)
  while pos < int64(C.bytes.len):
    r = readFrameAt(f, pos)
    if not r.ok:
      f.close()
      removeFile(tmp)
      return (false, "a record of this chunk is damaged")
    pos = pos + r.frameBytes
  f.close()
  removeFile(tmp)
  if C.bytes.len > 0 and B.writer.writeBuffer(unsafeAddr C.bytes[0], C.bytes.len) != C.bytes.len:
    return (false, "could not write to " & B.logPath())
  B.dirty = true
  result = syncBox(B)
  if not result.ok:
    return
  closeBoxFile(B)
  B.index = initTable[string, BoxSlot]()
  B.keyOf = initTable[uint64, string]()
  B.numbers = @[]
  B.liveBytes = 0
  B.chain = boxZeroHead
  result = openBoxFile(B)
  if result.ok:
    S.charge(B.head.owner, 0, B.size - was)

proc applyBoxLog*(S: BoxShelf, kind, id: string, C: BoxCopyChunk): tuple[ok: bool,
    err: string] {.role: orchestrator, tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/C: a chunk from `boxLogSince`. A chunk that does not continue this
  ## log exactly, and is no fresh start either, is refused and changes nothing.
  var
    got: tuple[found: bool, box: BoxFile] = (false, nil)
  if not validBoxId(id) or S.rules.ruleOf(kind).ok == false:
    return (false, boxRefused)
  try:
    if C.offset == 0'i64:
      result = S.replaceLog(kind, id, C)
    else:
      got = S.boxOf(kind, id)
      if not got.found or got.box.logId != C.logId or got.box.size != C.offset:
        return (false, "this chunk does not continue the log here")
      result = S.appendRecords(got.box, C)
    got = S.boxOf(kind, id)
    if result.ok and got.found:
      S.counters[boxName(kind, id)] = got.box.counter
  except CatchableError as e:
    result = (false, e.msg)
