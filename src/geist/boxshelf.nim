## ---------------------------------------------------------------------
## Box shelf <- every box below one folder, the open ones, what each owner uses
## ---------------------------------------------------------------------
##
##   <root>/<kind>/<id>/box.log
##   <root>/.geist-lock             one program at a time (./lease)
##
## A box is read into memory when it is first used and stays open, up to
## `maxOpen` of them; the one unused for longest is closed first.
##
##   call         what it does
##   -----------  --------------------------------------------------------
##   openShelf    takes the lease, adds up what every owner uses
##   boxOf        the open box, opening it when needed
##   flushShelf   every pending write on the disk, then old files removed
##   closeShelf   flushes, closes every box, gives the lease back
##
## Def. 1 (at-rest key): handed over by the caller. Geist does not ask where it
##   came from. Without one, bodies are stored as given; that is correct for a
##   box whose items the writers sealed themselves.
## Def. 2 (usage): the live bytes of an owner's boxes, with what lies in blobs/.
##   Who wrote does not matter: a letter in my mailbox counts against me.

import std/[os, tables]

import runePragmas
import ./types
import ./lease
import ./boxtypes
import ./boxlog

const
  boxDefaultMaxOpen* = 512
  boxMaxDamageNotes = 64

type
  BoxDamage* {.role: memory, tag: "boxes|types".} = seq[string]
    ## What could not be read, for the operator.

var
  gBoxDamage*: BoxDamage = @[]
    ## Refusals say "no such box" to the asker; the real reason is noted here.

proc noteBoxDamage*(what: string) {.role: actor, tag: "boxes".} =
  ## what: one damaged thing, kept for the operator. The oldest go first.
  if gBoxDamage.len >= boxMaxDamageNotes:
    gBoxDamage.delete(0)
  gBoxDamage.add(what)

proc boxName*(kind, id: string): string {.role: helper, inline, tag: "boxes".} =
  ## kind/id: the name a box goes by.
  result = kind & "/" & id

proc boxDir*(S: BoxShelf, kind, id: string): string {.role: helper, inline,
    tag: "boxes".} =
  ## S/kind/id: the folder of one box.
  result = S.root / kind / id

proc dirBytes(dir: string): int64 {.role: parser.} =
  ## dir: the size of every file directly in this folder.
  for kind, p in walkDir(dir):
    if kind == pcFile:
      result = result + getFileSize(p)

proc readOwnerOf(dir, name: string, atRest: BoxKey): tuple[ok: bool,
    owner: string] {.role: dataFetcher, tag: "boxes|storageIo|read".} =
  ## dir/name/atRest: the owner of one box, read from its first record.
  var
    B: BoxFile = makeBoxFile(dir, name, atRest)
    r: tuple[ok: bool, body: ByteSeq] = (false, @[])
  try:
    if not open(B.reader, B.logPath(), fmRead):
      return
    r = readRecordBody(B, 12'i64)
    B.reader.close()
    if r.ok:
      result = (true, decodeHead(r.body).head.owner)
  except CatchableError:
    result = (false, "")

proc charge*(S: BoxShelf, owner: string, boxes: int, bytes: int64) {.role: actor,
    inline.} =
  ## S/owner/boxes/bytes: what this owner uses, moved by this much.
  var
    u: BoxUsage = S.usage.getOrDefault(owner)
  u.boxes = u.boxes + boxes
  u.bytes = max(0'i64, u.bytes + bytes)
  S.usage[owner] = u

proc addBoxToUsage(S: BoxShelf, dir, name: string) {.role: truthBuilder.} =
  ## S/dir/name: one box on disk, counted.
  var
    got: tuple[ok: bool, owner: string] = readOwnerOf(dir, name, S.atRest)
  if not got.ok:
    noteBoxDamage("cannot read the owner of " & name)
    return
  S.charge(got.owner, 1, getFileSize(dir / boxLogName) + dirBytes(dir / boxBlobDir))

proc scanUsage(S: BoxShelf) {.role: truthBuilder, tag: "boxes|storageIo|read".} =
  ## S: walks every kind and box once, at start-up.
  for kindEntry in walkDir(S.root):
    if kindEntry.kind != pcDir:
      continue
    for boxEntry in walkDir(kindEntry.path):
      if boxEntry.kind == pcDir and fileExists(boxEntry.path / boxLogName):
        S.addBoxToUsage(boxEntry.path, boxName(kindEntry.path.extractFilename(),
          boxEntry.path.extractFilename()))

proc openShelf*(root: string, rules: openArray[BoxRule],
    limits: BoxLimits = BoxLimits(), atRest: BoxKey = nil,
    maxOpen: int = boxDefaultMaxOpen): tuple[ok: bool, shelf: BoxShelf, err: string] {.
    role: orchestrator, tag: "boxes|appApi|storageIo".} =
  ## root: the folder. rules: every kind served. limits: per owner.
  ## atRest: Def. 1, nil for none. maxOpen: how many boxes stay in memory.
  ## Refused when another program holds this folder.
  var
    got: tuple[ok: bool, lease: Lease, err: string] = (false, Lease(), "")
    S: BoxShelf = nil
  try:
    createDir(root)
    got = acquireLease(root)
    if not got.ok:
      return (false, nil, got.err)
    S = BoxShelf(root: root, rules: @rules, limits: limits, atRest: atRest,
      lease: got.lease, maxOpen: max(1, maxOpen),
      open: initTable[string, BoxFile](), usage: initTable[string, BoxUsage](),
      counters: initTable[string, uint64]())
    S.scanUsage()
    result = (true, S, "")
  except CatchableError as e:
    result = (false, nil, e.msg)

proc commitBox*(S: BoxShelf, B: BoxFile): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "boxes|storageIo|write".} =
  ## S/B: the writes of this box on the disk; only then are replaced files
  ## removed, and only then is a mostly dead log rewritten.
  var
    was: int64 = 0
  result = syncBox(B)
  if not result.ok:
    return
  for n in B.drop:
    removeFile(B.blobPath(n))
  B.drop = @[]
  if not B.needsCompacting():
    return
  was = B.size
  result = compactBox(B)
  if result.ok:
    S.charge(B.head.owner, 0, B.size - was)

proc closeOne(S: BoxShelf, name: string) {.role: actor.} =
  ## S/name: one open box written out and closed.
  var
    B: BoxFile = S.open[name]
    done: tuple[ok: bool, err: string] = S.commitBox(B)
  if not done.ok:
    noteBoxDamage(name & ": " & done.err)
  closeBoxFile(B)
  S.open.del(name)

proc evictOldest(S: BoxShelf) {.role: actor.} =
  ## S: the box unused for longest, closed.
  var
    oldest: string = ""
    tick: uint64 = high(uint64)
  for name, B in S.open.pairs:
    if B.useTick < tick:
      tick = B.useTick
      oldest = name
  if oldest.len > 0:
    S.closeOne(oldest)

proc rememberBox*(S: BoxShelf, name: string, B: BoxFile) {.role: actor.} =
  ## S/name/B: an opened box joins the open ones, making room when needed.
  while S.open.len >= S.maxOpen:
    S.evictOldest()
  S.tick = S.tick + 1'u64
  B.useTick = S.tick
  S.open[name] = B
  S.counters[name] = B.counter

proc boxOf*(S: BoxShelf, kind, id: string): tuple[found: bool, box: BoxFile] {.
    role: dataFetcher, tag: "boxes|storageIo|read".} =
  ## S/kind/id: the box, opened when needed. found = false when there is none,
  ## or when it is damaged (noted for the operator).
  var
    name: string = boxName(kind, id)
    B: BoxFile = nil
    opened: tuple[ok: bool, err: string] = (false, "")
  if S.open.hasKey(name):
    S.tick = S.tick + 1'u64
    S.open[name].useTick = S.tick
    return (true, S.open[name])
  if not fileExists(S.boxDir(kind, id) / boxLogName):
    return
  B = makeBoxFile(S.boxDir(kind, id), name, S.atRest)
  opened = openBoxFile(B)
  if not opened.ok:
    noteBoxDamage(name & ": " & opened.err)
    return
  S.rememberBox(name, B)
  result = (true, B)

proc flushShelf*(S: BoxShelf): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "boxes|appApi|storageIo|write".} =
  ## S: every pending write on the disk. Stops at the first box that fails, and
  ## says so: the caller must not report those writes as done.
  var
    done: tuple[ok: bool, err: string] = (true, "")
  result = (true, "")
  for name, B in S.open.pairs:
    if not B.dirty and B.drop.len == 0:
      continue
    done = S.commitBox(B)
    if not done.ok:
      return (false, name & ": " & done.err)

proc closeShelf*(S: BoxShelf) {.role: orchestrator, tag: "boxes|appApi|storageIo".} =
  ## S: everything written out, every box closed, the lease given back.
  var
    names: seq[string] = @[]
  for name in S.open.keys:
    names.add name
  for name in names:
    S.closeOne(name)
  releaseLease(S.lease)
