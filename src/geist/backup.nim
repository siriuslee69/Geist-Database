## ---------------------------------------------------------------------
## Backup <- rotating .b1 / .b2 / .b3 copies on a write or time trigger
## ---------------------------------------------------------------------
##
##   rotation (newest first):
##       current  --copy-->  .b1
##       .b1      --move-->  .b2
##       .b2      --move-->  .b3        (.b3 falls off the end)
##
##   trigger: writeCount >= everyNWrites  OR  now - lastAt >= everySeconds
##
## An encrypted database is only recoverable with the data file, the key
## file AND the ledger. A backup that captures one without the others is
## worthless, so every rotation copies the whole artifact SET atomically
## from the caller's point of view: all three, or the rotation is refused.
##
## Rotation moves from the oldest slot down, so an interrupted rotation
## can lose at most the oldest copy and never corrupts a newer one.

import std/[os, times]

import geistPragmas

type
  BackupPolicy* {.role: configurator, metaTags: {tagBackup, tagConfig,
      tagTypes}.} = object
    ## copies: how many rotating slots to keep (.b1 .. .bN).
    ## everyNWrites: write-count trigger; 0 disables it.
    ## everySeconds: wall-clock trigger; 0 disables it.
    ## requireFullSet: refuse to rotate unless all artifacts are present.
    enabled*: bool
    copies*: uint8
    everyNWrites*: uint32
    everySeconds*: uint32
    requireFullSet*: bool

  BackupState* {.role: truthState, metaTags: {tagBackup, tagStatus,
      tagTypes}.} = object
    ## Counters surfaced through database metadata so an operator can see
    ## how close the next rotation is without reading the data file.
    writesSinceBackup*: uint32
    totalWrites*: uint64
    lastBackupAt*: int64
    rotations*: uint32
    lastError*: string

  BackupResult* {.role: truthState, metaTags: {tagBackup, tagStatus,
      tagTypes}.} = object
    performed*: bool
    reason*: string
    copied*: seq[string]
    err*: string

proc defaultBackupPolicy*(): BackupPolicy {.role: configurator,
    metaTags: {tagBackup, tagConfig}.} =
  ## Three rotating copies, rotated every 64 writes or every 15 minutes.
  result.enabled = true
  result.copies = 3'u8
  result.everyNWrites = 64'u32
  result.everySeconds = 900'u32
  result.requireFullSet = true

proc slotPath*(path: string, slot: int): string {.role: helper,
    metaTags: {tagBackup, tagStorageIo}.} =
  ## path: live artifact path.
  ## slot: 1-based rotation slot; 1 is the most recent copy.
  result = path & ".b" & $slot

proc shouldBackup*(p: BackupPolicy, S: BackupState,
    now: int64): tuple[yes: bool, reason: string] {.role: parser,
    metaTags: {tagBackup, tagRead, tagStatus}.} =
  ## p: policy.
  ## S: counters since the last rotation.
  ## now: current unix time.
  if not p.enabled:
    return (false, "backups disabled")
  if p.everyNWrites > 0'u32 and S.writesSinceBackup >= p.everyNWrites:
    return (true, "write count reached " & $S.writesSinceBackup)
  if p.everySeconds > 0'u32 and S.lastBackupAt > 0'i64 and
      now - S.lastBackupAt >= int64(p.everySeconds):
    return (true, "interval elapsed (" & $(now - S.lastBackupAt) & "s)")
  if p.everySeconds > 0'u32 and S.lastBackupAt == 0'i64 and
      S.writesSinceBackup > 0'u32:
    return (true, "first backup")
  result = (false, "no trigger met")

proc rotateOne(source, stem: string,
    copies: int): tuple[ok: bool, err: string] {.
    role: dataWriter, metaTags: {tagBackup, tagStorageIo, tagWrite}.} =
  ## source: the live artifact to copy.
  ## stem: the name the SLOTS are built from, which must not carry a
  ##   generation suffix -- a save publishes a new generation, so slots
  ##   named after the live file would start a fresh rotation on every
  ##   save and never actually rotate.
  ## copies: number of slots to maintain.
  ##
  ## Shifting starts at the OLDEST slot, so an interruption can only lose
  ## the oldest copy; newer slots are never left half-written.
  var
    i: int = 0
    src: string = ""
    dst: string = ""
  try:
    i = copies - 1
    while i >= 1:
      src = slotPath(stem, i)
      dst = slotPath(stem, i + 1)
      if fileExists(src):
        if fileExists(dst):
          removeFile(dst)
        moveFile(src, dst)
      i = i - 1
    if fileExists(source):
      copyFile(source, slotPath(stem, 1))
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc runBackup*(P: openArray[string], stems: openArray[string],
    p: BackupPolicy, S: var BackupState, now: int64 = 0'i64): BackupResult {.
    role: orchestrator, metaTags: {tagBackup, tagOrchestrator, tagStorageIo,
    tagWrite}.} =
  ## P: the full artifact set -- data, keys and ledger paths together.
  ## stems: the generation-free names the slots are built from, in the same
  ##   order. Kept separate from P because the live files move on every
  ##   save and the backup slots must not.
  ## p: rotation policy.
  ## S: counters reset on a successful rotation.
  ## now: unix time; zero asks for the current clock.
  var
    t: int64 = now
    decision: tuple[yes: bool, reason: string]
    step: tuple[ok: bool, err: string]
    i: int = 0
  if t == 0'i64:
    t = getTime().toUnix()
  decision = shouldBackup(p, S, t)
  result.reason = decision.reason
  if not decision.yes:
    return
  if p.requireFullSet:
    while i < P.len:
      if P[i].len > 0 and not fileExists(P[i]):
        result.err = "refusing to rotate an incomplete artifact set: " &
          "missing " & P[i]
        S.lastError = result.err
        return
      i = i + 1
  i = 0
  while i < P.len:
    if P[i].len > 0:
      step = rotateOne(P[i], stems[i], int(p.copies))
      if not step.ok:
        result.err = step.err
        S.lastError = step.err
        return
      result.copied.add slotPath(stems[i], 1)
    i = i + 1
  result.performed = true
  S.writesSinceBackup = 0'u32
  S.lastBackupAt = t
  S.rotations = S.rotations + 1'u32
  S.lastError = ""

proc noteWrite*(S: var BackupState) {.role: stateController, inline,
    metaTags: {tagBackup, tagStatus, tagWrite}.} =
  ## S: counters advanced after one committed write.
  S.writesSinceBackup = S.writesSinceBackup + 1'u32
  S.totalWrites = S.totalWrites + 1'u64

proc restorePaths*(P: openArray[string], slot: int): seq[string] {.
    role: helper, metaTags: {tagBackup, tagRead, tagStorageIo}.} =
  ## P: live artifact set.
  ## slot: rotation slot to restore from; 1 is the most recent.
  var
    i: int = 0
  while i < P.len:
    result.add slotPath(P[i], slot)
    i = i + 1

proc restoreFrom*(P: openArray[string], slot: int): tuple[ok: bool,
    err: string] {.role: dataWriter,
    metaTags: {tagBackup, tagStorageIo, tagWrite}.} =
  ## P: live artifact set to overwrite.
  ## slot: rotation slot to restore. The whole set is verified present
  ## before anything is overwritten, so a partial restore cannot happen.
  var
    src: seq[string] = @[]
    i: int = 0
  src = restorePaths(P, slot)
  while i < src.len:
    if not fileExists(src[i]):
      return (false, "cannot restore: missing " & src[i])
    i = i + 1
  i = 0
  try:
    while i < src.len:
      copyFile(src[i], P[i])
      i = i + 1
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)
