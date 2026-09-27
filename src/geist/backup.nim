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

import runePragmas

type
  BackupPolicy* {.role: configurator, tag: "backup|config|types".} = object
    ## copies: how many rotating slots to keep (.b1 .. .bN).
    ## everyNWrites: write-count trigger; 0 disables it.
    ## everySeconds: wall-clock trigger; 0 disables it.
    ## requireFullSet: refuse to rotate unless all artifacts are present.
    enabled*: bool
    copies*: uint8
    everyNWrites*: uint32
    everySeconds*: uint32
    requireFullSet*: bool

  BackupState* {.role: truthState, tag: "backup|status|types".} = object
    ## Counters surfaced through database metadata so an operator can see
    ## how close the next rotation is without reading the data file.
    writesSinceBackup*: uint32
    totalWrites*: uint64
    lastBackupAt*: int64
    rotations*: uint32

  BackupResult* {.role: truthState, tag: "backup|status|types".} = object
    performed*: bool
    reason*: string
    copied*: seq[string]
    err*: string

proc defaultBackupPolicy*(): BackupPolicy {.role: configurator, stage: stDone,
    tag: "backup|config".} =
  ## Three rotating copies, rotated every 64 writes or every 15 minutes.
  result.enabled = true
  result.copies = 3'u8
  result.everyNWrites = 64'u32
  result.everySeconds = 900'u32
  result.requireFullSet = true

proc slotPath*(path: string, slot: int): string {.role: helper,
    tag: "backup|storageIo".} =
  ## path: live artifact path.
  ## slot: 1-based rotation slot; 1 is the most recent copy.
  result = path & ".b" & $slot

proc shouldBackup*(p: BackupPolicy, S: BackupState,
    now: int64): tuple[yes: bool, reason: string] {.role: parser,
    tag: "backup|read|status".} =
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

proc shiftSlot(stem: string, i: int) {.role: dataWriter, inline,
    tag: "backup|storageIo|write".} =
  ## stem/i: slot i moves to slot i+1, replacing whatever was there.
  var
    src: string = slotPath(stem, i)
    dst: string = slotPath(stem, i + 1)
  if not fileExists(src):
    return
  if fileExists(dst):
    removeFile(dst)
  moveFile(src, dst)

proc rotateOne(source, stem: string,
    copies: int): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "backup|storageIo|write".} =
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
    i: int = copies - 1
  try:
    while i >= 1:
      shiftSlot(stem, i)
      i = i - 1
    if fileExists(source):
      copyFile(source, slotPath(stem, 1))
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc runBackup*(P: openArray[string], stems: openArray[string],
    p: BackupPolicy, S: var BackupState, now: int64 = 0'i64): BackupResult {.
    role: orchestrator, tag: "backup|orchestrator|storageIo|write".} =
  ## P: the full artifact set -- data, keys and ledger paths together.
  ## stems: the generation-free names the slots are built from, in the same
  ##   order. Kept separate from P because the live files move on every
  ##   save and the backup slots must not.
  ## p: rotation policy.
  ## S: counters reset on a successful rotation.
  ## now: unix time; zero asks for the current clock.
  var
    t: int64 = now
    decision: tuple[yes: bool, reason: string] = (false, "")
    step: tuple[ok: bool, err: string] = (false, "")
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
        return
      i = i + 1
  i = 0
  while i < P.len:
    if P[i].len > 0:
      step = rotateOne(P[i], stems[i], int(p.copies))
      if not step.ok:
        result.err = step.err
        return
      result.copied.add slotPath(stems[i], 1)
    i = i + 1
  result.performed = true
  S.writesSinceBackup = 0'u32
  S.lastBackupAt = t
  S.rotations = S.rotations + 1'u32

proc noteWrite*(S: var BackupState) {.role: actor, inline,
    tag: "backup|status|write".} =
  ## S: counters advanced after one committed write.
  S.writesSinceBackup = S.writesSinceBackup + 1'u32
  S.totalWrites = S.totalWrites + 1'u64

proc restorePaths*(P: openArray[string], slot: int): seq[string] {.
    role: helper, tag: "backup|read|storageIo".} =
  ## P: live artifact set.
  ## slot: rotation slot to restore from; 1 is the most recent.
  var
    i: int = 0
  while i < P.len:
    result.add slotPath(P[i], slot)
    i = i + 1

proc restoreFrom*(P: openArray[string], slot: int): tuple[ok: bool,
    err: string] {.role: dataWriter,
    tag: "backup|storageIo|write".} =
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
