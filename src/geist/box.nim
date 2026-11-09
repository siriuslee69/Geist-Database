## ---------------------------------------------------------------------
## Box <- put, fetch, take, acknowledge: every write decided right here
## ---------------------------------------------------------------------
##
##   call         append      overwrite        queue        takeOnce
##   -----------  ----------  ---------------  -----------  -------------
##   putBoxItem   new key     version must     new key      new key
##                only        match; +1                     (owner only)
##   fetchBox...  after n     after n          after n      (owner only)
##   takeBoxItem  --          --               --           oldest, deleted
##   ackBoxItems  --          --               delete keys  --
##
## Every call checks the rule and the subject first. A refusal and a box that
## does not exist give the same answer.
##
## Example 1. Items get numbers as they are accepted, and a reader asks for what
## comes after the number it has:
##
##   box    1  2  3  4  5  6
##   phone  had up to 3 -> fetchBoxItems(after = 3) -> 4, 5, 6
##
## Example 2. Several writes, one trip to the disk. Nothing is reported as done
## before `flushShelf` said ok:
##
##   putBoxItem(.., flush = false)  x 100
##   flushShelf(S)
##
## ╭─ ❧ Signed boxes (Def. 5 of ./boxtypes) 🍣
##
## Each item carries a LABEL: a small text naming the box, the hash of the data
## and the chain head it was written after, signed with a key the box holds.
##
##   hash = ab12...            prev = <head>       store = vault/alice
##   kind = entry              signer = phone      sentAt = 1800000000000
##   sig  = dilithium87:3c..
##
## The check needs nothing but the box itself, so another machine can repeat it
## without trusting this one.

import std/[algorithm, strutils, tables]

import runePragmas
import ./types
import ./textfile
import ./crypto/hashing
import ./crypto/hashwidths
import ./boxtypes
import ./boxlog
import ./boxshelf

export boxtypes, boxshelf

const
  boxLabelKind = "entry"

proc refuseBox(why: string = boxRefused): BoxResult {.role: helper, inline.} =
  ## why: the refusal.
  result = BoxResult(ok: false, err: why)

proc checkedBox(S: BoxShelf, kind, id, subject: string, action: BoxAction): tuple[
    ok: bool, rule: BoxRule, box: BoxFile] {.role: parser, tag: "boxes|permission".} =
  ## S/kind/id/subject/action: the rule and box when the subject may act on it.
  var
    r: tuple[ok: bool, rule: BoxRule] = S.rules.ruleOf(kind)
    got: tuple[found: bool, box: BoxFile] = (false, nil)
  if not r.ok or not validBoxId(id):
    return
  got = S.boxOf(kind, id)
  if not got.found or not mayBox(r.rule, got.box.head, subject, action):
    return
  result = (true, r.rule, got.box)

proc overLimits(S: BoxShelf, owner: string, moreBoxes: int, moreBytes: int64): string {.
    role: parser, tag: "boxes".} =
  ## S/owner/moreBoxes/moreBytes: "" when this owner may use that much more.
  var
    u: BoxUsage = S.usage.getOrDefault(owner)
  if S.limits.maxBoxesPerOwner > 0 and moreBoxes > 0 and
      u.boxes + moreBoxes > S.limits.maxBoxesPerOwner:
    return "this owner has as many boxes as it may have"
  if S.limits.maxBytesPerOwner > 0 and u.bytes + moreBytes > S.limits.maxBytesPerOwner:
    return "this owner's storage is full"
  result = ""

proc createBox*(S: BoxShelf, kind, id, subject: string,
    trust: TrustTable = TrustTable()): BoxResult {.role: actor,
    tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/subject: makes the box; the subject owns it. An account box can
  ## only be made by that account. trust: the keys a signed box takes labels from.
  var
    r: tuple[ok: bool, rule: BoxRule] = S.rules.ruleOf(kind)
    H: BoxHead = BoxHead(kind: kind, id: id, owner: subject, trust: trust)
    B: BoxFile = nil
    made: tuple[ok: bool, err: string] = (false, "")
    full: string = ""
  if not r.ok or not validBoxId(id) or not mayBox(r.rule, H, subject, bxCreate):
    return refuseBox()
  if r.rule.signed and trust.keys.len == 0:
    return refuseBox("a signed box needs at least one key")
  if S.boxOf(kind, id).found:
    return refuseBox("the box exists already")
  full = S.overLimits(subject, 1, 0'i64)
  if full.len > 0:
    return refuseBox(full)
  B = makeBoxFile(S.boxDir(kind, id), boxName(kind, id), S.atRest)
  made = createBoxFile(B, H)
  if not made.ok:
    return refuseBox(made.err)
  S.rememberBox(boxName(kind, id), B)
  S.charge(subject, 1, B.size)
  result = BoxResult(ok: true)

proc setBoxPeople*(S: BoxShelf, kind, id, subject: string,
    members, whitelist: openArray[string]): BoxResult {.role: actor,
    tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/subject: the owner sets who else may use the box.
  ## members/whitelist: replace the lists.
  var
    c: tuple[ok: bool, rule: BoxRule, box: BoxFile] =
      S.checkedBox(kind, id, subject, bxAdmin)
    H: BoxHead = BoxHead()
    done: tuple[ok: bool, err: string] = (false, "")
  if not c.ok:
    return refuseBox()
  H = c.box.head
  H.members = @members
  H.whitelist = @whitelist
  appendFrame(c.box, brHead, encodeHead(H, c.box.counter))
  done = S.commitBox(c.box)
  if not done.ok:
    return refuseBox(done.err)
  result = BoxResult(ok: true, number: c.box.counter)

proc expired(R: BoxRule, atMs, nowMs: uint64): bool {.role: parser, inline.} =
  ## R/atMs/nowMs: true when the rule keeps items for a time and it is over.
  result = R.keepMs > 0'u64 and nowMs > atMs + R.keepMs

proc goneItems(S: BoxShelf, B: BoxFile, keys: openArray[string]): tuple[ok: bool,
    err: string] {.role: dataWriter, tag: "boxes|storageIo|write".} =
  ## S/B/keys: these items deleted, durably. Their space is the owner's again.
  var
    A: ByteSeq = @[]
    freed: int64 = 0
  for key in keys:
    if not B.index.hasKey(key):
      continue
    freed = freed + B.index[key].frameBytes + B.index[key].blobBytes
    if B.index[key].blobBytes > 0:
      B.drop.add(B.index[key].number)
    A = @[]
    A.add(uint8(key.len and 255))
    A.add(uint8((key.len shr 8) and 255))
    A.add(textBytes(key))
    appendFrame(B, brGone, A)
  result = S.commitBox(B)
  if result.ok:
    S.charge(B.head.owner, 0, -freed)

proc sweepOpen(S: BoxShelf, R: BoxRule, B: BoxFile, nowMs: uint64): int {.
    role: actor, tag: "boxes|storageIo|write".} =
  ## S/R/B/nowMs: expired items deleted. Returns how many.
  var
    old: seq[string] = @[]
  if R.keepMs == 0'u64:
    return 0
  for key, s in B.index.pairs:
    if expired(R, s.atMs, nowMs):
      old.add key
  if old.len > 0 and S.goneItems(B, old).ok:
    result = old.len

proc sweepBox*(S: BoxShelf, kind, id: string, nowMs: uint64): int {.role: actor,
    tag: "boxes|appApi|lifecycle|storageIo|write".} =
  ## S/kind/id/nowMs: items whose keep time is over, deleted. Returns how many.
  var
    r: tuple[ok: bool, rule: BoxRule] = S.rules.ruleOf(kind)
    got: tuple[found: bool, box: BoxFile] = (false, nil)
  if not r.ok or not validBoxId(id):
    return 0
  got = S.boxOf(kind, id)
  if got.found:
    result = S.sweepOpen(r.rule, got.box, nowMs)

proc putError(R: BoxRule, B: BoxFile, key: string, n: int, expectVersion: uint64): string {.
    role: parser, tag: "boxes".} =
  ## R/B/key/n/expectVersion: "" when this put may go ahead.
  var
    exists: bool = B.index.hasKey(key)
  if key.len == 0 or key.len > 256:
    return "an item key is 1 to 256 characters"
  if n > R.maxItemBytes:
    return "the item is larger than this box allows (" & $R.maxItemBytes & " bytes)"
  if R.mode != bmOverwrite and exists:
    return "that key is taken; items of this box are written once"
  if not exists and B.index.len >= R.maxItems:
    return "the box is full (" & $R.maxItems & " items)"
  if R.mode == bmOverwrite and not exists and expectVersion != 0'u64:
    return "no such item to replace; send version 0 for a new key"
  if R.mode == bmOverwrite and exists and B.index[key].version != expectVersion:
    return "stale version: the newest is " & $B.index[key].version
  result = ""

proc labelError(B: BoxFile, data: openArray[uint8], label: string): string {.
    role: sanitizer, tag: "boxes|cryptoBoundary".} =
  ## B/data/label: "" when the label is good for these bytes at this place.
  var
    n: tuple[ok: bool, note: SidecarNote, err: string] = parseNote(label)
  if not n.ok:
    return "the label cannot be read: " & n.err
  if noteValue(n.note, "kind") != boxLabelKind or noteValue(n.note, "store") != B.name:
    return "this label is not for this box"
  if noteValue(n.note, "prev") != B.chain:
    return "stale head: the newest is " & B.chain
  if not constantTimeEq(n.note.hash, geistHash(hkBlake3, data, fullDigestBytes)):
    return "the label is for other data"
  if trustOf(n.note, B.head.trust) != ntSigned:
    return "the signature does not belong to this box"
  result = ""

proc writeItem(S: BoxShelf, B: BoxFile, item: BoxItem): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "boxes|storageIo|write".} =
  ## S/B/item: the item appended, its large data on disk first; usage moved.
  var
    old: BoxSlot = B.index.getOrDefault(item.key)
    wasLive: int64 = B.liveBytes
    blob: tuple[ok: bool, size: int64, hash: ByteSeq, err: string] = (true, 0'i64, @[], "")
  if item.data.len >= boxInlineMax:
    blob = writeBlob(B, item.number, item.data)
    if not blob.ok:
      return (false, blob.err)
    appendFrame(B, brItem, encodeBlobItem(item, blob.size, blob.hash))
  else:
    appendFrame(B, brItem, encodeItem(item))
  if old.blobBytes > 0:
    B.drop.add(old.number)
  S.charge(B.head.owner, 0, B.liveBytes - wasLive + blob.size - old.blobBytes)
  result = (true, "")

proc sameAsStored(R: BoxRule, B: BoxFile, subject, key: string,
    data: openArray[uint8]): bool {.role: parser, tag: "boxes".} =
  ## R/B/subject/key/data: true when this very item is here already, from this
  ## very writer. A sender that lost the answer sends again; the second time must
  ## not be an error, or a write that worked would look as if it had failed.
  var
    got: tuple[ok: bool, item: BoxItem] = (false, BoxItem())
  if R.mode == bmOverwrite or not B.index.hasKey(key) or B.index[key].writer != subject:
    return false
  got = readWholeItem(B, B.index[key])
  result = got.ok and got.item.data == 

proc resent(B: BoxFile, key: string): BoxResult {.role: helper, inline.} =
  ## B/key: the answer to an item that was here already.
  result = BoxResult(ok: true, number: B.index[key].number,
    version: B.index[key].version, chainHead: B.chain)

proc putBoxItem*(S: BoxShelf, kind, id, subject, key: string,
    data: openArray[uint8], expectVersion, nowMs: uint64, label: string = "",
    flush: bool = true): BoxResult {.role: actor,
    tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/subject: who writes where.
  ## key/data: the item. expectVersion: overwrite only, the version this write
  ##   replaces (0 for a new key). nowMs: the clock. label: signed boxes only.
  ## flush: false shares one trip to the disk (Example 2).
  var
    c: tuple[ok: bool, rule: BoxRule, box: BoxFile] =
      S.checkedBox(kind, id, subject, bxWrite)
    item: BoxItem = BoxItem()
    err: string = ""
    wrote: tuple[ok: bool, err: string] = (false, "")
  if not c.ok:
    return refuseBox()
  if sameAsStored(c.rule, c.box, subject, key, data):
    return resent(c.box, key)
  if c.box.index.len >= c.rule.maxItems:
    discard S.sweepOpen(c.rule, c.box, nowMs)
  err = putError(c.rule, c.box, key, data.len, expectVersion)
  if err.len == 0 and c.rule.signed:
    err = labelError(c.box, data, label)
  if err.len == 0:
    err = S.overLimits(c.box.head.owner, 0, int64(data.len))
  if err.len > 0:
    return refuseBox(err)
  item = BoxItem(key: key, number: c.box.counter + 1'u64, version: expectVersion + 1'u64,
    writer: subject, atMs: nowMs, label: label, data: @data)
  try:
    wrote = S.writeItem(c.box, item)
    if wrote.ok and flush:
      wrote = S.commitBox(c.box)
  except CatchableError as e:
    wrote = (false, e.msg)
  if not wrote.ok:
    return refuseBox(wrote.err)
  S.counters[boxName(kind, id)] = c.box.counter
  result = BoxResult(ok: true, number: item.number, version: item.version,
    chainHead: c.box.chain)

proc firstAfter(B: BoxFile, afterNumber: uint64): int {.role: parser, inline.} =
  ## B/afterNumber: where the first number above it sits in B.numbers.
  result = B.numbers.upperBound(afterNumber)

proc pruneNumbers(B: BoxFile) {.role: actor, inline.} =
  ## B: numbers of items that are gone, dropped once there are many.
  var
    kept: seq[uint64] = @[]
  if B.numbers.len - B.keyOf.len < 128:
    return
  for n in B.numbers:
    if B.keyOf.hasKey(n):
      kept.add n
  B.numbers = kept

proc fetchBoxItems*(S: BoxShelf, kind, id, subject: string, afterNumber: uint64,
    limit: int, nowMs: uint64): BoxResult {.role: dataFetcher,
    tag: "boxes|appApi|storageIo|read".} =
  ## S/kind/id/subject: who reads where.
  ## afterNumber/limit: items numbered above this, oldest first, at most `limit`.
  ## `number` in the answer is the newest number in the box. An item that fails
  ## its check is left out and noted for the operator.
  var
    c: tuple[ok: bool, rule: BoxRule, box: BoxFile] =
      S.checkedBox(kind, id, subject, bxRead)
    i: int = 0
    n: uint64 = 0
    slot: BoxSlot = BoxSlot()
    got: tuple[ok: bool, item: BoxItem] = (false, BoxItem())
  if not c.ok or (c.rule.mode == bmTakeOnce and subject != c.box.head.owner):
    return refuseBox()
  result = BoxResult(ok: true, number: c.box.counter, chainHead: c.box.chain)
  i = c.box.firstAfter(afterNumber)
  while i < c.box.numbers.len and result.items.len < limit:
    n = c.box.numbers[i]
    i = i + 1
    if not c.box.keyOf.hasKey(n):
      continue
    slot = c.box.index[c.box.keyOf[n]]
    if expired(c.rule, slot.atMs, nowMs):
      continue
    got = readWholeItem(c.box, slot)
    if not got.ok:
      noteBoxDamage(c.box.name & ": item " & $n & " is damaged")
      continue
    result.items.add(got.item)

proc takeBoxItem*(S: BoxShelf, kind, id, subject: string, nowMs: uint64): BoxResult {.
    role: actor, tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/subject/nowMs: the oldest item of a takeOnce box, deleted durably
  ## before it is handed out. An empty box answers ok with no item.
  var
    c: tuple[ok: bool, rule: BoxRule, box: BoxFile] =
      S.checkedBox(kind, id, subject, bxTake)
    got: tuple[ok: bool, item: BoxItem] = (false, BoxItem())
    slot: BoxSlot = BoxSlot()
    done: tuple[ok: bool, err: string] = (false, "")
  if not c.ok:
    return refuseBox()
  result = BoxResult(ok: true, number: c.box.counter)
  c.box.pruneNumbers()
  for n in c.box.numbers:
    if not c.box.keyOf.hasKey(n):
      continue
    slot = c.box.index[c.box.keyOf[n]]
    if expired(c.rule, slot.atMs, nowMs):
      continue
    got = readWholeItem(c.box, slot)
    if not got.ok:
      return refuseBox(boxRefused)
    done = S.goneItems(c.box, [got.item.key])
    if not done.ok:
      return refuseBox(done.err)
    result.items = @[got.item]
    return

proc ackBoxItems*(S: BoxShelf, kind, id, subject: string,
    keys: openArray[string]): BoxResult {.role: actor,
    tag: "boxes|appApi|storageIo|write".} =
  ## S/kind/id/subject/keys: queue items that were read, deleted. Keys that are
  ## not there are skipped: acknowledging twice is harmless.
  var
    c: tuple[ok: bool, rule: BoxRule, box: BoxFile] =
      S.checkedBox(kind, id, subject, bxAck)
    n: int = 0
    done: tuple[ok: bool, err: string] = (false, "")
  if not c.ok:
    return refuseBox()
  for key in keys:
    if c.box.index.hasKey(key):
      n = n + 1
  done = S.goneItems(c.box, keys)
  if not done.ok:
    return refuseBox(done.err)
  c.box.pruneNumbers()
  result = BoxResult(ok: true, number: uint64(n))

proc boxCounter*(S: BoxShelf, kind, id: string): uint64 {.role: parser,
    tag: "boxes|appApi".} =
  ## S/kind/id: the newest number in this box, 0 when there is no such box. Asks
  ## no permission and reads no item: it exists so a watcher can see, for free,
  ## that nothing changed. The number is all that it tells.
  var
    name: string = boxName(kind, id)
    got: tuple[found: bool, box: BoxFile] = (false, nil)
  if S.counters.hasKey(name):
    return S.counters[name]
  got = S.boxOf(kind, id)
  if got.found:
    result = got.box.counter

proc boxEntryFields*(boxKind, boxId, signer: string, data: openArray[uint8],
    prev: string, sentAt: int64): seq[tuple[key, value: string]] {.role: helper,
    tag: "boxes|appApi|cryptoBoundary".} =
  ## boxKind/boxId/signer/data/prev/sentAt: what the writer of a signed box signs:
  ## `noteSignedText(fields)`, then `renderNote(fields, sig)` is the label.
  result = noteFields(geistHash(hkBlake3, data, fullDigestBytes), @[
    (key: "kind", value: boxLabelKind), (key: "prev", value: prev),
    (key: "sentAt", value: $sentAt), (key: "signer", value: signer),
    (key: "store", value: boxName(boxKind, boxId))])
