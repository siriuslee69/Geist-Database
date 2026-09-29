## ---------------------------------------------------------------------
## Session sweep <- sidecar files no row, live or backed up, points at
## ---------------------------------------------------------------------
##
## A sidecar file is deleted only when NO generation that could ever be
## restored still names it: the live rows and every backup slot are read.
##
## Part of the Session; see ./session for how the parts fit.

import std/[os, strutils]

import runePragmas
import ./types
import ./row
import ./sidecar
import ./store
import ./backup
import ./keys
import ./sessioncore

## ------------------------- sidecar reclamation ----------------------
##
## A capped column too large for its row is stored in the sidecar tree
## under its own content hash. Nothing removes it when the row that
## referenced it is replaced, deleted or compacted away, so a database
## that churns large values grows a directory of payloads no row mentions.
##
## Reclaiming them is mark and sweep, and the mark phase has to be
## complete or it deletes live data:
##
##   live rows        every version in the LOG, not just the visible ones
##   backup slots     .b1/.b2/.b3 hold rows too, and restoring one whose
##                    payloads were swept would restore a broken database
##
## Backups are the part that is easy to get wrong: the rotation copies the
## data, keys and ledger, and NOT the sidecar, because payloads are shared
## between generations. That sharing is what makes them cheap and it is
## also why a sweep must look inside every slot before deleting anything.

proc externalRefsOf(s: Schema, raw: openArray[uint8],
    into: var seq[string]) {.role: parser, tag: "db|read|sidecar".} =
  ## s/raw/into: the sidecar locator of every column of one row that
  ## lives outside it.
  var
    offsets: seq[int] = fieldOffsets(s, raw)
    j: int = 0
  while j < s.slots.len:
    if s.isExternal(raw, j):
      into.add refLocator(decodeRef(s.rawAt(raw, offsets, j)))
    j = j + 1

proc sidecarRefsIn(s: Schema, C: ClusterBuild,
    into: var seq[string]) {.role: parser,
    tag: "db|read|sidecar".} =
  ## s/C: schema and cluster whose external column values are collected.
  ## into: locators appended, duplicates and all -- the caller only ever
  ##   asks whether a locator is present.
  var
    i: uint32 = 0'u32
  if not s.hasCapped():
    return
  while i < C.rowCount:
    externalRefsOf(s, C.rowBytesAt(i), into)
    i = i + 1

proc sidecarRefs*(s: Session): seq[string] {.role: parser,
    tag: "appApi|db|read|sidecar".} =
  ## s: session whose every stored row is scanned for sidecar references.
  ## Superseded versions count: they are still in the log, and a follower
  ## catching up will be sent them.
  sidecarRefsIn(s.entries.schema, s.entries, result)
  sidecarRefsIn(s.meta.schema, s.meta, result)
  sidecarRefsIn(s.journal.schema, s.journal, result)

proc allExist(A: openArray[string]): bool {.role: parser, inline,
    tag: "backup|storageIo".} =
  ## A: are all of these files there?
  for path in A:
    if not fileExists(path):
      return false
  result = true

proc refsInSlot(s: Session, slot: int, src: openArray[string]): tuple[
    ok: bool, refs: seq[string], err: string] {.role: parser,
    tag: "backup|db|read|sidecar".} =
  ## s/slot/src: the sidecar references held by one backup slot.
  ##
  ## A slot is opened the only way a store can be: copied into a scratch
  ## folder as generation 1, opened read-only, read, and removed again.
  var
    scratch: string = s.baseDir / (".geist-sweep-" & $slot)
    g: Generation = generationPaths(scratch, s.baseName, 1'u64)
    other: Session = default(Session)
  try:
    removeDir(scratch)
    createDir(scratch)
    copyFile(src[0], g.dataPath)
    if s.encrypted:
      copyFile(src[1], g.keyPath)
      copyFile(src[2], g.ledgerPath)
    discard commitManifest(scratch, 1'u64)
    other = openSessionWithSchema(scratch, s.baseName, Schema(), s.config,
      s.password, readOnly = true)
    result = (true, other.sidecarRefs(), "")
    other.close()
  except CatchableError as exc:
    result = (false, @[], "cannot read backup slot " & $slot & ": " & exc.msg)
  removeDir(scratch)

proc backupSidecarRefs(s: Session): tuple[ok: bool, refs: seq[string],
    err: string] {.role: parser,
    tag: "backup|db|read|sidecar".} =
  ## s: session whose BACKUP slots are scanned the same way.
  ##
  ## Each slot is opened where it lies, by copying the set into a scratch
  ## directory as generation 1 and reading it back. That is more work than
  ## reading the live file, and it is the only way to see inside a sealed
  ## slot: its rows are encrypted under its own ledger.
  var
    slot: int = 1
    live: seq[string] = @[]
    src: seq[string] = @[]
    one: tuple[ok: bool, refs: seq[string], err: string] = (false, @[], "")
  live = s.backupStems()
  while slot <= int(high(uint8)):
    src = restorePaths(live, slot)
    if not allExist(src):
      # Slots are filled in order, so the first gap is the end of them.
      break
    one = s.refsInSlot(slot, src)
    if not one.ok:
      return (false, @[], one.err)
    result.refs.add one.refs
    slot = slot + 1
  result.ok = true

proc sweepSidecar*(S: var Session): tuple[ok: bool, removed: int,
    bytes: uint64, err: string] {.role: orchestrator,
    tag: "appApi|db|maintenance|sidecar|write".} =
  ## S: session whose sidecar payloads are reclaimed.
  ##
  ## Deletes every payload no stored row references -- in this database or
  ## in any of its backup slots. Needs the write lease: another process
  ## could be storing a payload right now, and its row would not be
  ## visible here until it saves.
  ##
  ## Returns how much went, so a caller can report it rather than guess.
  var
    reachable: seq[string] = @[]
    fromBackups: tuple[ok: bool, refs: seq[string], err: string] =
      (false, @[], "")
    locator: string = ""
    size: uint64 = 0'u64
  if S.readOnly:
    return (false, 0, 0'u64, S.writeRefusal())
  if S.sidecarStore.root.len == 0 or not dirExists(S.sidecarStore.root):
    return (true, 0, 0'u64, "")
  reachable = S.sidecarRefs()
  fromBackups = S.backupSidecarRefs()
  if not fromBackups.ok:
    # Refusing is the only safe answer: a slot that cannot be read might
    # be the one referencing the payload about to be deleted.
    return (false, 0, 0'u64, fromBackups.err)
  reachable.add fromBackups.refs
  for path in walkDirRec(S.sidecarStore.root):
    # The locator is the fan-out path, which is how a reference names it.
    locator = path.relativePath(S.sidecarStore.root).replace('\\', '/')
    if locator in reachable:
      continue
    try:
      size = uint64(getFileSize(path))
      removeFile(path)
      result.removed = result.removed + 1
      result.bytes = result.bytes + size
    except CatchableError:
      discard
  result.ok = true

