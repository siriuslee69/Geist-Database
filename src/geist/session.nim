## ---------------------------------------------------------------------
## Session <- an open database: clusters, keys, ledger, backup, changefeed
## ---------------------------------------------------------------------
##
##   openSession -> put / find / save / checkpoint -> close
##                        `-> subscribe / poll for change following
##
## A session owns one artifact SET (data + keys + ledger) under one store
## root, plus the sidecar folder. Everything that must swap together is
## reachable from here, which is what makes the generation manifest the
## single atomic commit point.

import std/[os, strutils, times]

import tyr

import runePragmas
import ./types
import ./format
import ./lease
import ./mapper
import ./rowid
import ./row
import ./sidecar
import ./store
import ./config
import ./backup
import ./keys
import ./crypto/batch
import ./crypto/column
import ./show
import ./transpose

type
  FollowStep* {.role: truthState, tag: "appApi|db|status|types".} = tuple
    ## One look at a store this process does not own (`followStore`).
    ##   f        the index read now
    ##   changed  the clusters that differ from the previous look
    ##   path     the live file it was read from, which moves on every save
    ok: bool
    f: GeistFile
    changed: seq[int]
    path: string
    err: string

  Subscription* {.role: truthState, tag: "appApi|db|sync|types".} = object
    ## id: caller-chosen name, stable across reconnects.
    ## cursor: last change ordinal delivered.
    id*: string
    cursor*: uint64
    createdAt*: Timestamp

  ChangeKind* {.role: truthState, tag: "appApi|db|sync|types".} = enum
    ## What happened to a row. A follower needs the distinction: an update
    ## replaces what it holds, a delete removes it, and both arrive as an
    ## appended row that looks the same on disk.
    ckAdded, ckUpdated, ckDeleted, ckJournal

  ChangeEvent* {.role: truthState, tag: "appApi|db|sync|types".} = object
    ## ordinal: monotonic within a session, and the cursor a subscriber
    ##   resumes from.
    ## rowId: WHICH row, in words a peer also understands. Zero for a
    ##   database without identity, where only the position exists.
    ## rowIndex: position in the log, so a local subscriber can fetch the
    ##   row without a lookup.
    ordinal*: uint64
    kind*: ChangeKind
    cluster*: ClusterRole
    rowId*: RowId
    rowIndex*: uint32
    at*: Timestamp

  StorageStats* {.role: truthState, tag: "appApi|db|status|types".} = object
    ## What the column policy cost this session, per cluster and summed.
    ## `truncated` is the number that matters: `opTruncate` discards bytes
    ## by design and leaves nothing in the row to say so, so this counter
    ## and `truncatedIn` are the only record that it happened.
    rows*: uint32
    truncated*: uint32
    externalised*: uint32
    truncatedIn*: seq[FieldName]

  Session* {.role: truthState, tag: "appApi|db|types".} = object
    ## The single runtime handle. `dirty` gates writes; `generation` is the
    ## number published in the manifest.
    config*: GeistConfig
    baseDir*: string
    baseName*: string
    generation*: uint64
    entries*: ClusterBuild
    meta*: ClusterBuild
    journal*: ClusterBuild
    sidecarStore*: SidecarStore
    ## live: the newest version of every row id, rebuilt by one pass when
    ## the database opens and maintained incrementally after that. Empty
    ## for a database without identity, where the log IS the view.
    live*: LiveIndex
    keySet*: KeySet
    ledger*: Ledger          ## entry cluster
    metaLedger*: Ledger      ## meta cluster, when config.sealMeta
    journalLedger*: Ledger   ## journal cluster, when config.sealJournal
    backupPolicy*: BackupPolicy
    backupState*: BackupState
    subscriptions*: seq[Subscription]
    changes*: seq[ChangeEvent]
    changeOrdinal*: uint64
    ## logEpoch: bumped whenever the log is REWRITTEN rather than appended
    ## to -- compaction, today. A follower's cursor is a log position, so a
    ## rewrite makes the same number mean a different row; comparing epochs
    ## is how the follower learns it has to start again instead of quietly
    ## diverging. Stored in the meta cluster, so it survives a reopen.
    logEpoch*: uint64
    password*: string
    encrypted*: bool
    dirty*: bool
    readOnly*: bool
    ## writeLease: held for the whole life of a writable session. A session
    ## that could not take it is opened READ-ONLY rather than being allowed
    ## to republish a database somebody else is republishing.
    writeLease*: Lease
    ## leaseHolder: who has it, when we could not. Empty otherwise, so an
    ## application can tell "read-only because asked" from "read-only
    ## because another process is writing".
    leaseHolder*: string
    ## recoveredFrom: non-zero when the manifest named a generation that
    ## would not verify and the session fell back to an older one. Zero on
    ## every ordinary open, so a caller can warn on exactly the case that
    ## deserves a warning.
    recoveredFrom*: uint64
    ## lastSaveAt: wall clock of the last successful save, which is what
    ## `wmInterval` measures its window from. Set when the session opens so
    ## the first interval starts at open rather than at the epoch, which
    ## would make the very first write flush immediately.
    lastSaveAt*: Timestamp

proc dataPath*(s: Session): string {.role: helper,
    tag: "appApi|db|storageIo".} =
  ## s: session whose live data file path is returned.
  result = s.baseDir / (s.baseName & ".ge1st" & generationSuffix(s.generation))

proc keyPath*(s: Session): string {.role: helper,
    tag: "appApi|cryptoBoundary|db|storageIo".} =
  ## s: session whose live key file path is returned.
  result = s.baseDir / (s.baseName & keySuffix & generationSuffix(s.generation))

proc ledgerPath*(s: Session): string {.role: helper,
    tag: "appApi|db|ledger|storageIo".} =
  ## s: session whose live ledger path is returned.
  result = s.baseDir /
    (s.baseName & ledgerSuffix & generationSuffix(s.generation))

proc artifactSet*(s: Session): seq[string] {.role: helper,
    tag: "appApi|backup|db|storageIo".} =
  ## s: session whose three inseparable artifacts are listed together.
  ## Anything that copies, backs up or swaps a database must take all
  ## three: the data alone is unrecoverable without keys AND ledger.
  result = @[s.dataPath()]
  if s.encrypted:
    result.add s.keyPath()
    result.add s.ledgerPath()

proc backupStems*(s: Session): seq[string] {.role: helper,
    tag: "appApi|backup|db|storageIo".} =
  ## s: session whose backup slot names are returned, WITHOUT a generation
  ## suffix.
  ##
  ## The live files move on every save -- that is what a generation is --
  ## so slots named after them would start a fresh rotation each time and
  ## never rotate at all: one `.b1` per generation, growing forever, with
  ## nothing ever ageing out. The stem stays put and the slots rotate
  ## underneath it.
  result = @[s.baseDir / (s.baseName & ".ge1st")]
  if s.encrypted:
    result.add s.baseDir / (s.baseName & keySuffix)
    result.add s.baseDir / (s.baseName & ledgerSuffix)

proc noteChange(S: var Session, role: ClusterRole, rowIndex: uint32,
    kind: ChangeKind = ckAdded, id: RowId = 0'u64) {.
    role: actor, tag: "db|sync|write".} =
  ## S: session whose changefeed records one mutation.
  ## role/rowIndex: what moved, so a subscriber can fetch just that row.
  ## kind/id: what KIND of change, to which row -- the two things a remote
  ##   follower cannot work out for itself from a position.
  S.changeOrdinal = S.changeOrdinal + 1'u64
  S.changes.add ChangeEvent(ordinal: S.changeOrdinal, kind: kind,
    cluster: role, rowId: id, rowIndex: rowIndex,
    at: uint64(getTime().toUnix()))

proc verifyGeneration*(baseDir, baseName: string, n: uint64,
    encrypted: bool): tuple[ok: bool, err: string] {.role: parser,
    tag: "db|keyLifecycle|read|storageIo".}
  ## Forward-declared: opening a database has to check a generation before
  ## trusting it, and so does saving one.

## ------------------------- the id watermark -------------------------
##
## An id must never be reused, and "one past the largest id in the file"
## is not good enough to guarantee that:
##
##   ids 1..5 stored, 5 deleted, log compacted  ->  largest stored is 4
##   next allocation would hand out 5 again     ->  a peer still holding
##                                                  the tombstone for 5
##                                                  would delete the NEW row
##
## So the allocator's position is written down, in the meta cluster, as one
## ordinary Record. It is read back on open and never allowed to go
## backwards.

const
  watermarkLabel = "nextRowId"
  nodeTagLabel = "nodeTag"
    ## This database's own 24 bits, minted once and never changed. It is
    ## what makes an id issued here distinguishable from an id issued on
    ## another desktop -- see the composition note in rowid.nim.
  logEpochLabel = "logEpoch"
    ## Bumped whenever the LOG is rewritten rather than appended to -- which
    ## today means compaction. A follower's cursor is a log position, so a
    ## rewrite invalidates it: same number, different row. Comparing epochs
    ## is how a follower finds that out instead of quietly diverging.

proc readMetaCounter(s: Session, label: string): uint64 {.role: parser,
    tag: "db|read".} =
  ## s/label: one stored bookkeeping number, zero when it was never written.
  var
    i: uint32 = 0'u32
    r: Record = default(Record)
  while i < s.meta.rowCount:
    r = objectAt[Record](s.meta, i)
    if r.kind == rkVersion and r.label == label:
      return r.targetId
    i = i + 1

proc readIdWatermark(s: Session): RowId {.role: parser,
    tag: "db|read".} =
  ## s: session whose stored allocator position is returned, zero if none
  ## was ever written (a database from before this existed, or one that has
  ## never been saved).
  result = RowId(s.readMetaCounter(watermarkLabel))

proc stampMetaCounters(S: var Session) {.role: dataWriter,
    tag: "db|write".} =
  ## S: session whose meta cluster is rewritten to carry exactly one row per
  ## bookkeeping number. The meta cluster is `cmMutable`, so replacing it is
  ## what it is for; two rows with the same label would be ambiguous.
  var
    fresh: ClusterBuild = default(ClusterBuild)
    r: Record = default(Record)
    i: uint32 = 0'u32
    old: Record = default(Record)
  if not S.entries.schema.hasIdentity():
    return
  fresh = initClusterBuild(crMeta, cmMutable, S.meta.schema, S.sidecarStore,
    0'u16, S.config.chainHash, S.config.treeHash)
  r.kind = rkVersion
  r.targetId = S.live.nextCounter
  r.at = uint64(getTime().toUnix())
  r.label = watermarkLabel
  fresh.addRow(r)
  r = Record()
  r.kind = rkVersion
  r.targetId = S.live.nodeTag
  r.at = uint64(getTime().toUnix())
  r.label = nodeTagLabel
  fresh.addRow(r)
  r = Record()
  r.kind = rkVersion
  r.targetId = S.logEpoch
  r.at = uint64(getTime().toUnix())
  r.label = logEpochLabel
  fresh.addRow(r)
  # Anything else the meta cluster carried is preserved, minus the counters
  # just rewritten. Nothing else writes meta rows today; this is here so
  # that when something does, saving does not quietly delete them.
  while i < S.meta.rowCount:
    old = objectAt[Record](S.meta, i)
    if not (old.kind == rkVersion and
        (old.label == watermarkLabel or old.label == logEpochLabel or
         old.label == nodeTagLabel)):
      fresh.addRow(old)
    i = i + 1
  S.meta = fresh

proc indexLive*(S: var Session) {.role: truthBuilder,
    tag: "db|read|store".} =
  ## S: session whose live view is rebuilt from the log it just loaded.
  ##
  ## One pass. For each row it reads `__rowId` and `__flags` and nothing
  ## else, so the cost is two fixed columns per row rather than a decode.
  ##
  ##   log:  id=1 "a" | id=2 "b" | id=1 "a2" | id=2 tombstone
  ##          `- superseded          `- newest    `- newest, but removed
  ##   live: [2]                                     (only row 2 remains)
  var
    i: uint32 = 0'u32
    ident: tuple[id: RowId, flags: uint64] = (default(RowId), 0'u64)
    tag: uint64 = 0'u64
    seed: ByteSeq = @[]
  # A database that has never been saved has no tag yet: mint one. It is
  # 24 bits of the same randomness the key material uses, and it is fixed
  # for the life of the database -- every id it ever issues carries it.
  #
  # A tag already in hand is KEPT. This runs again after compaction, and
  # re-minting there would leave one database issuing ids under two tags,
  # with the rows it wrote this morning claiming to come from somewhere
  # else.
  tag = if S.live.nodeTag != 0'u64: S.live.nodeTag
        else: S.readMetaCounter(nodeTagLabel)
  if tag == 0'u64:
    seed = @(cryptoRandomBytes(3))
    tag = (uint64(seed[0]) or (uint64(seed[1]) shl 8) or
      (uint64(seed[2]) shl 16)) and rowIdNodeMask
    # Zero is the "no tag" marker, so a database that draws it takes one.
    if tag == 0'u64:
      tag = 1'u64
  S.live = initLiveIndex(tag)
  if not S.entries.schema.hasIdentity():
    return
  while i < S.entries.rowCount:
    ident = S.entries.schema.identityOf(S.entries.rowBytesAt(i))
    S.live.noteRow(ident.id, ident.flags, i)
    i = i + 1
  S.live.rebuildLive(S.entries)
  # The stored allocator position wins whenever it is ahead of what the
  # rows show, which is exactly the case compaction creates.
  if S.readIdWatermark() > S.live.nextCounter:
    S.live.nextCounter = S.readIdWatermark()
  S.logEpoch = S.readMetaCounter(logEpochLabel)

proc hasIdentity*(s: Session): bool {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## s: session asked whether its rows can be named, and therefore whether
  ## `set`, `delete` and `byId` are available at all.
  result = s.entries.schema.hasIdentity()

proc requireIdentity(s: Session) {.role: sanitizer,
    tag: "appApi|db|status".} =
  ## s: session checked before an operation that needs a row to have a name.
  if not s.hasIdentity():
    raise newException(ValueError,
      "this database stores rows without identity (preset '" &
      s.config.name & "' sets rowIdentity = false), so a row cannot be " &
      "addressed by id. Reopen with a configuration that enables it, or " &
      "use positional reads.")

proc resolveGeneration*(baseDir, baseName: string,
    encrypted: bool): tuple[n: uint64, repaired: bool] {.role: parser,
    tag: "db|keyLifecycle|read|storageIo".} =
  ## baseDir/baseName/encrypted: the database being opened.
  ##
  ## Normally this returns exactly what the manifest says. It walks down
  ## only when that generation will not verify -- a disk that lost the file,
  ## or a manifest restored from a backup ahead of its own data. Since the
  ## previous generation is retained until the next one has survived a
  ## cycle, there is always one step to fall back to.
  ##
  ##   manifest says 7 -> 7 verifies      -> open 7        (the normal case)
  ##   manifest says 7 -> 7 is truncated  -> open 6, say so
  var
    live: uint64 = 0'u64
    n: uint64 = 0'u64
    v: tuple[ok: bool, err: string] = (false, "")
  live = liveGeneration(baseDir)
  n = live
  result = (live, false)
  if not fileExists(generationPaths(baseDir, baseName, live).dataPath) and
      not fileExists(generationPaths(baseDir, baseName, live - 1'u64).dataPath):
    # Nothing on disk at all: a database being created, not a damaged one.
    return (live, false)
  while n >= 1'u64:
    v = verifyGeneration(baseDir, baseName, n, encrypted)
    if v.ok:
      return (n, n != live)
    n = n - 1'u64
  result = (live, false)

proc loadStore(S: var Session, baseDir, baseName: string, schemaIn: Schema,
    password: string) {.role: orchestrator,
    tag: "db|orchestrator|storageIo".} =
  ## S: a session whose lease question is already settled.
  ## baseDir/baseName/schemaIn/password: as for `openSessionWithSchema`.
  ##
  ## Everything an open reads: the live generation, the key file, the
  ## ledgers and the clusters. Raises when any of them will not read --
  ## a wrong password, a damaged file -- and `openSessionWithSchema` then
  ## gives the lease back.
  var
    resolved: tuple[n: uint64, repaired: bool] = (0'u64, false)
    schema: Schema = default(Schema)
    loadedKeys: tuple[ok: bool, keys: KeySet, err: string] =
      (false, default(KeySet), "")
    loadedLedger: tuple[ok: bool, ledgers: seq[Ledger], err: string] =
      (false, @[], "")
    recordSchema: Schema = default(Schema)
    index: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    applied: tuple[ok: bool, s: Schema, err: string] =
      (false, default(Schema), "")
    at: int = -1
  # The manifest names the live generation; `resolveGeneration` is what
  # happens when that generation will not read back.
  resolved = resolveGeneration(baseDir, baseName, S.encrypted)
  S.generation = resolved.n
  S.recoveredFrom = if resolved.repaired: liveGeneration(baseDir) else: 0'u64
  # Generations ABOVE the live one are the debris of a save that was
  # interrupted before it published. Only the writer clears them, and only
  # because it holds the lease: nobody else can be building one right now.
  if S.writeLease.held:
    discard sweepUncommitted(baseDir, baseName, S.generation)
  S.sidecarStore = initSidecarStore(baseDir / ".geist-sidecar",
    S.config.sidecarThreshold, S.config.contentHash)
  # Column policy is applied ONCE, here, so the schema written to disk is
  # already the one the policy asked for. A later reader needs no
  # configuration to interpret the file.
  # Identity FIRST, then the column policy: the policy names the caller's
  # own fields, and prepending afterwards would renumber every slot the
  # policy had already resolved.
  #
  # An EMPTY schema means "whatever the file says" -- the path a daemon, an
  # inspector or a sweep takes. There is nothing for a policy to name yet,
  # and the stored schema already carries the policy it was written with,
  # so applying one here would fail on every field it mentions.
  if schemaIn.slots.len == 0:
    schema = schemaIn
  else:
    applied = applyColumnPolicy(S.config,
      if S.config.rowIdentity: withIdentity(schemaIn) else: schemaIn)
    if not applied.ok:
      raise newException(ValueError, applied.err)
    schema = applied.s
  S.live = initLiveIndex()
  S.entries = initClusterBuild(crEntry, cmAppend, schema,
    S.sidecarStore, 0'u16,
    S.config.chainHash, S.config.treeHash)
  recordSchema = schemaFor[Record]()
  recordSchema.autoCollapse = S.config.autoCollapse
  S.meta = initClusterBuild(crMeta, cmMutable, recordSchema,
    S.sidecarStore, 0'u16,
    S.config.chainHash, S.config.treeHash)
  S.journal = initClusterBuild(crJournal, cmChained, recordSchema,
    S.sidecarStore, 0'u16,
    S.config.chainHash, S.config.treeHash)
  S.ledger.databaseId = baseName
  S.ledger.batchRows = S.config.batchRows
  S.ledger.groups = columnGroupsFor(S.config, schema)
  # Meta and journal carry Record, not T, so their groups resolve against
  # that schema. Each cluster gets its OWN ledger: batch coordinates are
  # (batchIndex, groupId) and would collide across clusters otherwise.
  S.metaLedger.databaseId = baseName & ":meta"
  S.metaLedger.batchRows = S.config.batchRows
  S.journalLedger.databaseId = baseName & ":journal"
  S.journalLedger.batchRows = S.config.batchRows
  if S.config.sealMeta:
    S.metaLedger.groups = columnGroupsFor(S.config, recordSchema)
  if S.config.sealJournal:
    S.journalLedger.groups = columnGroupsFor(S.config, recordSchema)
  if S.encrypted:
    if fileExists(S.keyPath()):
      # An EXISTING key file that will not open is a wrong password or a
      # tampered file. Minting a fresh key set here would silently orphan
      # every row already written, so it must fail loudly instead.
      loadedKeys = readKeyFile(S.keyPath(), password)
      if not loadedKeys.ok:
        raise newException(IOError, loadedKeys.err)
      S.keySet = loadedKeys.keys
    else:
      S.keySet = newKeySet()
      discard S.keySet.allocKeyRef("initial")
    loadedLedger = readLedgerFile(S.ledgerPath())
    if loadedLedger.ok:
      if loadedLedger.ledgers.len > 0:
        S.ledger = loadedLedger.ledgers[0]
      if loadedLedger.ledgers.len > 1:
        S.metaLedger = loadedLedger.ledgers[1]
      if loadedLedger.ledgers.len > 2:
        S.journalLedger = loadedLedger.ledgers[2]
    elif fileExists(S.ledgerPath()):
      raise newException(IOError, loadedLedger.err)
  if fileExists(S.dataPath()):
    index = readIndex(S.dataPath())
    if not index.ok:
      raise newException(IOError, index.err)
    at = index.f.findIndex(crMeta)
    if at >= 0:
      S.meta = readCluster(S.dataPath(), index.f.index[at],
        S.sidecarStore, S.config.chainHash, S.config.treeHash)
      if S.encrypted and S.metaLedger.groups.len > 0:
        openPacked(S.keySet.master, S.metaLedger,
          S.meta.rows, S.meta.rowOffsets, S.meta.rowCount,
          S.metaLedger.databaseId, geistFormatVersion)
    at = index.f.findIndex(crJournal)
    if at >= 0:
      S.journal = readCluster(S.dataPath(), index.f.index[at],
        S.sidecarStore, S.config.chainHash, S.config.treeHash)
      if S.encrypted and S.journalLedger.groups.len > 0:
        openPacked(S.keySet.master, S.journalLedger,
          S.journal.rows, S.journal.rowOffsets,
          S.journal.rowCount,
          S.journalLedger.databaseId, geistFormatVersion)
    at = index.f.findIndex(crEntry)
    if at >= 0:
      S.entries = readCluster(S.dataPath(), index.f.index[at],
        S.sidecarStore, S.config.chainHash, S.config.treeHash)
      if S.encrypted and S.entries.varyingRows():
        openPacked(S.keySet.master, S.ledger, S.entries.rows,
          S.entries.rowOffsets, S.entries.rowCount,
          S.baseName, geistFormatVersion)
      elif S.encrypted and S.ledger.groups.len > 0:
        openCluster(S.keySet.master, S.ledger,
          S.entries.schema, S.entries.rows,
          S.entries.rowCount,
          S.baseName, geistFormatVersion)
  # One pass over the decrypted rows rebuilds the live view. It reads two
  # fixed columns per row and no payload, and it is the same pass the load
  # above already paid for in cache terms.
  S.indexLive()


proc openSessionWithSchema*(baseDir, baseName: string, schemaIn: Schema,
    c: GeistConfig = appConfig(), password: string = "",
    readOnly: bool = false): Session {.
    role: orchestrator, tag: "appApi|db|orchestrator|storageIo".} =
  ## baseDir: store root holding the artifact set and the manifest.
  ## baseName: database stem, e.g. "main".
  ## schemaIn: entry-cluster schema. A schema loaded from an existing file
  ##   replaces it, so a tool that does not know the object type at compile
  ##   time can still open the database.
  ## c: configuration; a preset or a caller-composed value.
  ## password: required when the configuration selects a cipher.
  ## readOnly: open WITHOUT claiming the write lease. A follower -- a
  ##   daemon, an inspector, a second window -- must pass true, or it takes
  ##   a lease it never intends to use and locks the writer out.
  ##
  ## A writable open that finds the lease held does NOT fail: it opens
  ## read-only and records who has it in `leaseHolder`. Failing would make
  ## the common case (an app started twice) an error, when the useful
  ## behaviour is to show the data and refuse the writes.
  var
    validated: tuple[ok: bool, err: string] = (false, "")
    claimed: tuple[ok: bool, lease: Lease, err: string] =
      (false, default(Lease), "")
  result.config = normalizeGeistConfig(c)
  validated = validateGeistConfig(result.config)
  if not validated.ok:
    raise newException(ValueError, validated.err)
  result.encrypted = result.config.cipher != ckNone
  if result.encrypted and password.len == 0:
    raise newException(ValueError, result.config.name &
      " selects a cipher, so a non-empty password is required")
  result.baseDir = baseDir
  result.baseName = baseName
  result.password = password
  result.backupPolicy = result.config.backup
  result.lastSaveAt = uint64(getTime().toUnix())
  if not dirExists(baseDir):
    createDir(baseDir)
  # One writer per store root. A follower says so; anyone else finds out
  # here whether it is the writer or a reader.
  if readOnly:
    result.readOnly = true
  else:
    claimed = acquireLease(baseDir)
    if claimed.ok:
      result.writeLease = claimed.lease
    else:
      result.readOnly = true
      result.leaseHolder = claimed.err
  try:
    loadStore(result, baseDir, baseName, schemaIn, password)
  except CatchableError:
    # A failed open must hand the lease back. Kept, it would stay registered
    # to this process, and the retry -- the right password this time --
    # would find it "already held" and quietly open read-only.
    if result.writeLease.held:
      result.writeLease.releaseLease()
    raise

proc openSession*[T: object](baseDir, baseName: string,
    c: GeistConfig = appConfig(), password: string = "",
    readOnly: bool = false): Session {.
    role: orchestrator, tag: "appApi|db|orchestrator|storageIo".} =
  ## baseDir/baseName/c/password/readOnly: as for `openSessionWithSchema`.
  ## T: object type whose declaration order defines the entry schema.
  result = openSessionWithSchema(baseDir, baseName, schemaFor[T](), c,
    password, readOnly)

proc save*(S: var Session): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "appApi|db|orchestrator|storageIo|write".}
  ## Forward-declared: the write policy below has to be reachable from
  ## `put`, and it decides by calling this.

proc flushDue*(s: Session): bool {.role: parser,
    tag: "appApi|db|status".} =
  ## s: session asked whether its configuration wants a flush right now.
  ## Pure, so a caller driving `wmInterval` from its own event loop can ask
  ## without writing anything.
  case s.config.writeMode
  of wmManual, wmVolatile:
    result = false
  of wmOnChange:
    result = s.dirty
  of wmInterval:
    result = s.dirty and
      uint64(getTime().toUnix()) - s.lastSaveAt >=
        uint64(s.config.writeIntervalSeconds)

proc maybeFlush*(S: var Session): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|db|storageIo|write".} =
  ## S: session flushed if and only if `writeMode` says so.
  ##
  ## Called after every mutation, and safe to call from a timer as well:
  ## nothing here runs in the background, so an idle `wmInterval` database
  ## flushes on its next write rather than on the second it came due. A
  ## caller that needs the wall-clock guarantee calls this on a tick.
  if not S.flushDue():
    return (true, "")
  result = S.save()

proc writeRefusal*(s: Session): string {.role: helper,
    tag: "appApi|db|status".} =
  ## s: read-only session explaining ITSELF, because "read-only" alone does
  ## not tell an operator whether to close another window or fix their code.
  if s.leaseHolder.len > 0:
    result = "session is read-only: " & s.leaseHolder
  else:
    result = "session is read-only"

proc appendPacked(S: var Session, A: openArray[uint8], id: RowId,
    flags: uint64, kind: ChangeKind): uint32 {.role: dataWriter,
    tag: "db|store|write".} =
  ## S: session receiving one already-packed row.
  ## A: the row bytes.
  ## id/flags: its identity, for the live view and the changefeed.
  ## kind: what this append MEANS to a follower.
  ##
  ## Every write in the session funnels through here -- typed, dynamic,
  ## update, delete and rows arriving from a peer -- so the log, the live
  ## view and the changefeed can never be updated by three paths that
  ## disagree.
  if S.readOnly:
    raise newException(IOError, S.writeRefusal())
  result = S.entries.addRowBytes(A)
  if id != 0'u64:
    S.live.noteAppend(S.entries, id, flags, result)
  S.dirty = true
  S.backupState.noteWrite()
  S.noteChange(crEntry, result, kind, id)

proc packFor[T: object](S: var Session, x: T, id: RowId,
    flags: uint64): ByteSeq {.role: encryptor,
    tag: "db|store|write".} =
  ## S/x/id/flags: one object packed against the entry schema, with its
  ## identity columns filled in. Raises on a column policy violation, which
  ## is the caller's data being wrong rather than a defect here.
  var
    built: BuiltRow = default(BuiltRow)
    i: int = 0
  built = toRowBytes(x, S.entries.schema, S.sidecarStore, id, flags)
  if built.err.len > 0:
    raise newException(ValueError, built.err)
  S.entries.truncated = S.entries.truncated + built.truncated
  S.entries.externalised = S.entries.externalised + built.externalised
  while i < built.truncatedIn.len:
    if not (built.truncatedIn[i] in S.entries.truncatedIn):
      S.entries.truncatedIn.add built.truncatedIn[i]
    i = i + 1
  result = built.data

proc nextRowId(S: var Session): RowId {.role: actor,
    tag: "db|write".} =
  ## S: session allocating the next never-used identity. Zero when the
  ## database stores no identity, which is what tells the writers to skip
  ## the live view entirely.
  if not S.hasIdentity():
    return 0'u64
  result = S.live.freshRowId()

proc put*[T: object](S: var Session, x: T): RowId {.role: orchestrator,
    tag: "appApi|db|orchestrator|store|write",
    discardable.} =
  ## S: open session.
  ## x: object appended, then flushed if `writeMode` calls for it. A failed
  ##   automatic flush raises: the row is in memory either way, but a caller
  ##   who asked for durability per write must not be told it succeeded.
  ##
  ## Returns the row's ID, not its position. A position stops meaning the
  ## same row as soon as anything is replaced or removed; an id does not,
  ## which is what makes it the thing worth handing back.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  result = S.nextRowId()
  discard S.appendPacked(S.packFor(x, result, 0'u64), result, 0'u64, ckAdded)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc put*[T: object](S: var Session, A: openArray[T]): seq[RowId] {.
    role: orchestrator, tag: "appApi|db|orchestrator|store|write", discardable.} =
  ## S: open session.
  ## A: objects appended in order, then flushed ONCE. Under `wmOnChange`
  ##   that is the difference between one whole-file rewrite and `A.len` of
  ##   them; the batch is still atomic from a reader's point of view,
  ##   because a reader only ever sees a committed generation.
  var
    i: int = 0
    id: RowId = 0'u64
    written: tuple[ok: bool, err: string] = (false, "")
  while i < A.len:
    id = S.nextRowId()
    discard S.appendPacked(S.packFor(A[i], id, 0'u64), id, 0'u64, ckAdded)
    result.add id
    i = i + 1
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc set*[T: object](S: var Session, id: RowId, x: T): bool {.
    role: orchestrator, tag: "appApi|db|orchestrator|store|write", discardable.} =
  ## S: open session.
  ## id: the row being replaced.
  ## x: its new contents.
  ##
  ## Appends a NEW version rather than editing the stored one. Returns
  ## false for an id that was never allocated -- a typo must not silently
  ## create a row, because the caller believes it is editing one.
  ##
  ## Replacing a deleted row revives it: the tombstone is just the previous
  ## version, and a later version supersedes it like any other.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  S.requireIdentity()
  if S.live.positionOf(id) < 0:
    return false
  discard S.appendPacked(S.packFor(x, id, 0'u64), id, 0'u64, ckUpdated)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)
  result = true

proc delete*(S: var Session, id: RowId): bool {.role: orchestrator,
    tag: "appApi|db|orchestrator|store|write",
    discardable.} =
  ## S: open session.
  ## id: the row being removed.
  ##
  ## Appends a TOMBSTONE: an empty row carrying the id and the removal bit.
  ## The rows before it stay in the log, so a follower that is behind can
  ## still be told what happened, and `compact` is what actually reclaims
  ## the space.
  ##
  ## Returns false for an unknown id, and for one already deleted -- both
  ## mean "there was nothing here to remove", and appending a second
  ## tombstone would only grow the log.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    at: int = -1
  S.requireIdentity()
  at = S.live.positionOf(id)
  if at < 0:
    return false
  if S.entries.schema.rowFlagsOf(S.entries.rowBytesAt(uint32(at))).isTombstone():
    return false
  discard S.appendPacked(
    tombstoneRow(S.entries.schema, id, S.sidecarStore), id,
    tombstoneFlag, ckDeleted)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)
  result = true

proc putRow*(S: var Session, r: Row): RowId {.role: dataWriter,
    tag: "appApi|db|store|write", discardable.} =
  ## S: open session.
  ## r: a row already built against `S.entries.schema` -- the path a
  ## schema-driven tool uses when it has no compile-time object type, and
  ## the path a row arriving from a peer takes.
  ##
  ## The row's OWN identity columns are honoured: a peer sending version 3
  ## of row 12 stores it as version 3 of row 12, not as a new row. A row
  ## whose id is zero on a database that has identity is given the next
  ## free one, which is what a dynamic `geist put` produces.
  ##
  ## Dense and varying schemas are both accepted: a row is self-contained,
  ## so the only thing it must agree with is the schema it was packed
  ## against. `buildRow` in dynamic.nim produces exactly that.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    ident: tuple[id: RowId, flags: uint64] = (default(RowId), 0'u64)
    shaped: tuple[ok: bool, err: string] = (false, "")
    kind: ChangeKind = ckAdded
  if S.readOnly:
    raise newException(IOError, S.writeRefusal())
  # Check the SHAPE before reading anything out of it. This is the boundary
  # a hand-built row and a row from a peer both cross.
  shaped = validateRow(S.entries.schema, r.data)
  if not shaped.ok:
    raise newException(ValueError,
      "this row does not fit the schema: " & shaped.err)
  ident = S.entries.schema.identityOf(r.data)
  if S.hasIdentity() and ident.id == 0'u64:
    raise newException(ValueError,
      "this database gives every row an identity, but the row offered " &
      "carries id 0. Build it with buildRow(schema, values, store, id) " &
      "using the id from nextIdFor, or use put[T].")
  if ident.id != 0'u64 and S.live.positionOf(ident.id) >= 0:
    kind = if ident.flags.isTombstone(): ckDeleted else: ckUpdated
  elif ident.flags.isTombstone():
    kind = ckDeleted
  result = ident.id
  discard S.appendPacked(r.data, ident.id, ident.flags, kind)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc nextIdFor*(S: var Session): RowId {.role: actor,
    tag: "appApi|db|write".} =
  ## S: session handing out the id a schema-driven caller should stamp into
  ## the row it is about to build. Not consumed until that row is stored,
  ## so asking twice without storing gives the same answer.
  result = S.nextRowId()

proc compact*(S: var Session): tuple[ok: bool, removed: uint32,
    err: string] {.role: orchestrator, tag: "appApi|db|orchestrator|storageIo|write".} =
  ## S: session whose log is rewritten to hold only what is visible.
  ##
  ##   before  id1 v1 | id2 v1 | id1 v2 | id3 v1 | id3 tombstone
  ##   after   id2 v1 | id1 v2
  ##
  ## Ids and their contents survive; superseded versions and tombstones do
  ## not. That is the trade: the space comes back, and a follower that had
  ## not caught up can no longer be told what it missed row by row -- it
  ## has to take the whole cluster again.
  ##
  ## The allocator does NOT go backwards, even though the largest stored id
  ## may just have been removed. See the watermark note above.
  var
    fresh: ClusterBuild = default(ClusterBuild)
    i: int = 0
    keep: RowId = 0'u64
    before: uint32 = 0'u32
  if S.readOnly:
    return (false, 0'u32, S.writeRefusal())
  if not S.hasIdentity():
    return (false, 0'u32,
      "compaction needs row identity: without it every row is live and " &
      "there is nothing superseded to reclaim")
  before = S.entries.rowCount
  keep = S.live.nextCounter
  fresh = initClusterBuild(crEntry, cmAppend, S.entries.schema,
    S.sidecarStore, S.entries.schemaId, S.config.chainHash,
    S.config.treeHash)
  while i < S.live.live.len:
    fresh.addRowBytes(S.entries.rowBytesAt(S.live.live[i]))
    i = i + 1
  S.entries = fresh
  S.indexLive()
  if S.live.nextCounter < keep:
    S.live.nextCounter = keep
  # Positions now mean different rows. Anyone following by position has to
  # be told, and this is the only thing that tells them.
  S.logEpoch = S.logEpoch + 1'u64
  S.dirty = true
  result.removed = before - S.entries.rowCount
  result.ok = true

proc storageStats*(s: Session): StorageStats {.role: parser,
    tag: "appApi|db|read|status".} =
  ## s: session reporting what its column policy cost.
  ##
  ## Read this after a bulk load. A non-zero `truncated` means values were
  ## cut to fit a `colFixed` column carrying `opTruncate` -- legal, asked
  ## for, and invisible in the stored rows, so this is where it surfaces.
  ## `truncatedIn` names the columns responsible.
  result.rows = s.entries.rowCount
  result.truncated = s.entries.truncated + s.meta.truncated +
    s.journal.truncated
  result.externalised = s.entries.externalised + s.meta.externalised +
    s.journal.externalised
  result.truncatedIn = s.entries.truncatedIn

## ------------------------- reading the live view --------------------
##
## Two numbers, and they answer different questions:
##
##   entryCount   how many rows a CALLER has        <- the live view
##   logCount     how many rows are STORED          <- the append log
##
## They are equal until the first update or delete. After that the log
## keeps the superseded versions -- which is what a follower catching up
## needs -- and `compact` is what makes them equal again.

proc entryCount*(s: Session): uint32 {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## s: session whose VISIBLE row count is returned: current versions,
  ## tombstones excluded.
  if not s.hasIdentity():
    return s.entries.rowCount
  result = s.live.liveCount()

proc logCount*(s: Session): uint32 {.role: parser, inline,
    tag: "appApi|db|read|status".} =
  ## s: session whose STORED row count is returned, superseded versions
  ## and tombstones included. The number `compact` reduces.
  result = s.entries.rowCount

proc livePosition*(s: Session, i: uint32): uint32 {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: the i-th visible row resolved to its position in the log.
  ## Identity-free databases pass positions straight through, because there
  ## the log IS the view.
  if not s.hasIdentity():
    return i
  if int(i) >= s.live.live.len:
    raise newException(IndexDefect,
      "row " & $i & " is out of range for " & $s.live.live.len & " rows")
  result = s.live.live[int(i)]

proc rowIds*(s: Session): seq[RowId] {.role: parser,
    tag: "appApi|db|read".} =
  ## s: the ids of every visible row, in view order -- what a caller
  ## iterates when it intends to `set` or `delete` afterwards.
  var
    i: int = 0
  if not s.hasIdentity():
    return @[]
  while i < s.live.order.len:
    if s.live.positionOf(s.live.order[i]) >= 0 and
        not s.entries.schema.rowFlagsOf(
          s.entries.rowBytesAt(uint32(s.live.positionOf(s.live.order[i])))
        ).isTombstone():
      result.add s.live.order[i]
    i = i + 1

proc get*[T: object](s: Session, i: uint32): T {.role: parser,
    tag: "appApi|db|read".} =
  ## s: session to read from.
  ## i: index into the VISIBLE rows, not into the log. Superseded versions
  ##   and tombstones are not addressable this way -- `get(0)` is the first
  ##   row a caller would say it has.
  result = objectAt[T](s.entries, s.livePosition(i))

proc rawRowAt*(s: Session, i: uint32): Row {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: one row of the LOG, by log position, exactly as stored. For
  ## replication and inspection: `get` is what an application wants.
  result = s.entries.rowAt(i)

proc byId*[T: object](s: Session, id: RowId): tuple[found: bool, value: T] {.
    role: parser, tag: "appApi|db|read".} =
  ## s/id: the newest version of one row.
  ## `found` is false for an id that never existed AND for one that was
  ## deleted: both mean the caller has nothing to show.
  var
    at: int = -1
  if not s.hasIdentity():
    return (false, default(T))
  at = s.live.positionOf(id)
  if at < 0:
    return (false, default(T))
  if s.entries.schema.rowFlagsOf(
      s.entries.rowBytesAt(uint32(at))).isTombstone():
    return (false, default(T))
  result = (true, objectAt[T](s.entries, uint32(at)))

proc idAt*(s: Session, i: uint32): RowId {.role: parser,
    tag: "appApi|db|read".} =
  ## s/i: the id of the i-th visible row, so a caller that found something
  ## by reading can name it when changing it.
  if not s.hasIdentity():
    return 0'u64
  result = s.entries.schema.rowIdOf(
    s.entries.rowBytesAt(s.livePosition(i)))

proc find*[T: object](s: Session, field, value: string): seq[T] {.
    role: parser, tag: "appApi|db|read".} =
  ## s: session to search.
  ## field: object field name.
  ## value: exact text match.
  ##
  ## Visible rows only: a search that returned superseded versions would
  ## hand back text the caller already replaced.
  var
    slot: int = -1
    i: uint32 = 0'u32
    at: uint32 = 0'u32
    n: uint32 = 0'u32
    raw: ByteSeq = @[]
  slot = s.entries.schema.slotIndex(field)
  if slot < 0:
    raise newException(ValueError, "no such field in schema: " & field)
  # Compare the field in place: resolving offsets and reading one column
  # avoids materialising an object per candidate row.
  n = s.entryCount()
  while i < n:
    at = s.livePosition(i)
    raw = s.entries.rowBytesAt(at)
    if s.entries.schema.textAt(raw, fieldOffsets(s.entries.schema, raw), slot,
        s.sidecarStore) == value:
      result.add objectAt[T](s.entries, at)
    i = i + 1

proc findIds*(s: Session, field, value: string): seq[RowId] {.role: parser,
    tag: "appApi|db|read".} =
  ## s/field/value: the same search, returning IDS instead of objects --
  ## the call to make when the next step is `set` or `delete`.
  var
    slot: int = -1
    i: uint32 = 0'u32
    at: uint32 = 0'u32
    n: uint32 = 0'u32
    raw: ByteSeq = @[]
  s.requireIdentity()
  slot = s.entries.schema.slotIndex(field)
  if slot < 0:
    raise newException(ValueError, "no such field in schema: " & field)
  n = s.entryCount()
  while i < n:
    at = s.livePosition(i)
    raw = s.entries.rowBytesAt(at)
    if s.entries.schema.textAt(raw, fieldOffsets(s.entries.schema, raw), slot,
        s.sidecarStore) == value:
      result.add s.entries.schema.rowIdOf(raw)
    i = i + 1

proc verifyGeneration*(baseDir, baseName: string, n: uint64,
    encrypted: bool): tuple[ok: bool, err: string] {.role: parser,
    tag: "db|keyLifecycle|read|storageIo".} =
  ## baseDir/baseName/n: the generation being checked, before or after it is
  ##   published.
  ## encrypted: whether a key file and ledger belong to the set.
  ##
  ## Reads the header and cluster index -- a few hundred bytes -- and the
  ## ledger's own integrity hash. It cannot prove every row is intact, and
  ## it is not meant to: it catches the failure that actually happens, which
  ## is a write that stopped halfway. Publishing a truncated generation is
  ## the one mistake the manifest cannot undo.
  var
    g: Generation = default(Generation)
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    led: tuple[ok: bool, ledgers: seq[Ledger], err: string] = (false, @[], "")
  g = generationPaths(baseDir, baseName, n)
  idx = readIndex(g.dataPath)
  if not idx.ok:
    return (false, "generation " & $n & " is unreadable: " & idx.err)
  if idx.f.header.generation != n:
    return (false, "generation " & $n & " carries header generation " &
      $idx.f.header.generation)
  if not encrypted:
    return (true, "")
  if not fileExists(g.keyPath):
    return (false, "generation " & $n & " has no key file")
  led = readLedgerFile(g.ledgerPath)
  if not led.ok:
    return (false, "generation " & $n & " ledger: " & led.err)
  result = (true, "")

proc publishGeneration(S: var Session, next: uint64,
    staged: tuple[ok: bool, err: string]): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "db|keyLifecycle|orchestrator|storageIo|write".} =
  ## S: session whose live generation is being replaced.
  ## next: the generation already written to disk under its own name.
  ## staged: how the writing went. A failure is passed straight through
  ##   here rather than checked by every caller, so the cleanup of a
  ##   half-written generation lives in ONE place.
  ##
  ## The second half of every publish, whatever produced the bytes -- a
  ## save, or a restore from a backup slot:
  ##
  ##   verify -> commit the manifest -> retire N-1 -> become N+1
  ##
  ## Nothing before the commit is visible to a reader, so any failure up to
  ## that point throws the staged generation away and leaves the live one
  ## exactly as it was.
  var
    step: tuple[ok: bool, err: string] = (false, "")
  if not staged.ok:
    discard retireGeneration(S.baseDir, S.baseName, next)
    return staged
  # Verify BEFORE publishing. A generation that cannot be read back is
  # thrown away here, while the live one is still whatever it was.
  step = verifyGeneration(S.baseDir, S.baseName, next, S.encrypted)
  if step.ok:
    step = commitManifest(S.baseDir, next)
  if not step.ok:
    discard retireGeneration(S.baseDir, S.baseName, next)
    return step
  # Published. From here the session IS generation N+1, and N-1 is no
  # longer anyone's fallback -- N is.
  discard retireGeneration(S.baseDir, S.baseName, S.generation - 1'u64)
  S.generation = next
  # Publishing is proof of life: a writer that saves regularly can never
  # look abandoned to a process wondering whether to break the lease.
  S.writeLease.refreshLease()
  result = (true, "")

proc transposeDue(S: Session): bool {.role: parser,
    tag: "db|status".} =
  ## S: whether this save should rebuild the column copy.
  ##
  ## `tmInterval` measures from the copy's own modification time rather
  ## than from a counter on the session. A counter would restart every
  ## time the process did, and the file already knows when it was written.
  var
    found: tuple[path: string, generation: uint64] = ("", 0'u64)
    age: int64 = 0
  case S.config.transpose
  of tmNone, tmManual:
    return false
  of tmOnSave:
    return true
  of tmInterval:
    found = existingTransposed(S.baseDir, S.baseName)
    if found.path.len == 0:
      return true
    try:
      age = getTime().toUnix() -
        getLastModificationTime(found.path).toUnix()
    except CatchableError:
      return true
    result = age >= int64(S.config.transposeEverySeconds)

proc writeTransposedNow(S: Session,
    generation: uint64): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "db|storageIo|write".} =
  ## S/generation: build the column copy for one generation and drop the
  ## copies of every other. Old ones are not kept: nobody reads a stale
  ## column file, because a reader asks whether it is current first.
  result = writeTransposed(transposedPath(S.baseDir, S.baseName, generation),
    S.entries, generation)
  if result.ok:
    retireTransposed(S.baseDir, S.baseName, generation)
proc save*(S: var Session): tuple[ok: bool, err: string] =
  ## S: session published as a NEW generation, then rotated if the backup
  ## policy triggers. Backup takes the whole artifact set.
  ##
  ## An EXPLICIT save always writes, whatever `writeMode` says -- including
  ## `wmVolatile`. The mode governs what happens on its own; a caller who
  ## asks in so many words is answered.
  ##
  ##   write .gN+1  ->  fsync  ->  verify  ->  rename current  ->  drop .gN-1
  ##   ^^^^^^^^^^^                             ^^^^^^^^^^^^^^
  ##   invisible to readers, so a crash                the ONLY step that
  ##   here loses nothing but the new rows             changes what a
  ##                                                   reader sees
  ##
  ## Nothing is ever written over the live file. A reader that opened
  ## generation N keeps reading a complete N while N+1 is being built, and a
  ## crash at any point leaves N exactly as it was.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    br: BackupResult = default(BackupResult)
    onDisk: ClusterBuild = default(ClusterBuild)
    metaDisk: ClusterBuild = default(ClusterBuild)
    journalDisk: ClusterBuild = default(ClusterBuild)
    keyRef: KeyId = 0'u64
    next: uint64 = 0'u64
    staging: Generation = default(Generation)
  if S.readOnly:
    return (false, S.writeRefusal())
  next = S.generation + 1'u64
  staging = generationPaths(S.baseDir, S.baseName, next)
  # The allocator's position travels with the data, so a reopened database
  # never hands out an id that a peer has already seen retired.
  S.stampMetaCounters()
  # Seal COPIES: the live session keeps plaintext rows so a caller can
  # keep reading after save() without a decrypt round trip.
  onDisk = S.entries
  metaDisk = S.meta
  journalDisk = S.journal
  if S.encrypted:
    keyRef = if S.keySet.records.len > 0: S.keySet.records[0].keyId else: 1'u64
    if onDisk.varyingRows():
      # Variable rows have no column-range geometry, so the whole row is
      # the unit. See crypto/column.nim.
      sealPacked(S.keySet.master, S.ledger, onDisk.rows, onDisk.rowOffsets,
        onDisk.rowCount, S.baseName, geistFormatVersion, S.config.cipher,
        S.config.mac, keyRef, S.config.treeHash)
    elif S.ledger.groups.len > 0:
      sealCluster(S.keySet.master, S.ledger, onDisk.schema, onDisk.rows,
        onDisk.rowCount, S.baseName, geistFormatVersion,
        S.config.cipher, S.config.mac, keyRef, S.config.treeHash)
    # Meta and journal carry `Record`, whose text and payload columns make
    # its rows vary -- so they take the packed path, exactly like an entry
    # cluster with a text column. A column group is only a byte range when
    # every row has the same shape.
    if S.config.sealMeta and S.metaLedger.groups.len > 0:
      sealPacked(S.keySet.master, S.metaLedger, metaDisk.rows,
        metaDisk.rowOffsets, metaDisk.rowCount, S.metaLedger.databaseId,
        geistFormatVersion, S.config.cipher, S.config.mac, keyRef,
        S.config.treeHash)
    if S.config.sealJournal and S.journalLedger.groups.len > 0:
      sealPacked(S.keySet.master, S.journalLedger, journalDisk.rows,
        journalDisk.rowOffsets, journalDisk.rowCount,
        S.journalLedger.databaseId, geistFormatVersion, S.config.cipher,
        S.config.mac, keyRef, S.config.treeHash)
  written = writeGeistFile(staging.dataPath,
    @[metaDisk, journalDisk, onDisk], next)
  if written.ok and S.encrypted:
    written = writeKeyFile(staging.keyPath, S.password, S.keySet)
    if written.ok:
      written = writeLedgerFile(staging.ledgerPath,
        @[S.ledger, S.metaLedger, S.journalLedger])
  written = S.publishGeneration(next, written)
  if not written.ok:
    return written
  br = runBackup(S.artifactSet(), S.backupStems(), S.backupPolicy,
    S.backupState)
  if br.err.len > 0:
    return (false, br.err)
  S.dirty = false
  S.lastSaveAt = uint64(getTime().toUnix())
  # The column copy is written AFTER the generation is published, and its
  # failure does not fail the save: the rows are on disk either way, and a
  # save reported as failed would send a caller looking for lost data
  # rather than for a full disk. A copy that did not get written is stale,
  # which is a state the freshness check already has a name for.
  if S.transposeDue():
    discard S.writeTransposedNow(S.generation)
  result = (true, "")

proc checkpoint*(S: var Session, message: string = "checkpoint"): uint32 {.
    role: actor, tag: "appApi|db|stateController|sync|write", discardable.} =
  ## S: session whose journal receives a hash-chained checkpoint row.
  ## message: human-readable reason.
  var
    r: Record = default(Record)
    written: tuple[ok: bool, err: string] = (false, "")
  if not S.config.keepHistory:
    raise newException(ValueError,
      S.config.name & " configuration disables history")
  r.kind = rkCheckpoint
  r.at = uint64(getTime().toUnix())
  r.label = message
  r.parentHash = S.journal.chainHash
  result = S.journal.addRow(r)
  S.dirty = true
  S.noteChange(crJournal, result)
  written = S.maybeFlush()
  if not written.ok:
    raise newException(IOError, written.err)

proc close*(S: var Session) {.role: actor,
    tag: "appApi|db|lifecycle|stateController|storageIo".} =
  ## S: session persisted if dirty, then cleared from memory.
  ##
  ## `wmVolatile` DISCARDS instead. That is the whole meaning of the mode:
  ## a database that exists only while the process does. A caller who wants
  ## the rows kept calls `save` before closing, and gets them.
  ##
  ## The write lease is released LAST and unconditionally: a save that fails
  ## must still let the next process in, or one bad write locks the database
  ## until somebody deletes a file by hand.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  try:
    if S.dirty and not S.readOnly and S.config.writeMode != wmVolatile:
      written = S.save()
      if not written.ok:
        raise newException(IOError, written.err)
  finally:
    S.writeLease.releaseLease()
  S.entries = ClusterBuild()
  S.meta = ClusterBuild()
  S.journal = ClusterBuild()
  S.keySet = KeySet()

proc restoreSlot*(S: var Session, slot: int): tuple[ok: bool,
    err: string] {.role: orchestrator, tag: "appApi|backup|db|orchestrator|storageIo|write".} =
  ## S: session whose database is replaced by one of its backup slots.
  ## slot: 1 is the most recent copy.
  ##
  ## A restore publishes the backed-up bytes as a NEW generation, through
  ## exactly the protocol a save uses: write, verify, then rename the
  ## manifest. So a restore that fails half way leaves the current database
  ## untouched, and a reader mid-read keeps reading a complete file.
  ##
  ##   .b2 (the bytes)  ->  .gN+1  ->  verify  ->  manifest  ->  live
  ##
  ## The session must be REOPENED afterwards: the rows in memory are the
  ## ones just replaced.
  var
    stems: seq[string] = @[]
    src: seq[string] = @[]
    next: uint64 = 0'u64
    staging: Generation = default(Generation)
    dst: seq[string] = @[]
    i: int = 0
    step: tuple[ok: bool, err: string] = (false, "")
  if S.readOnly:
    return (false, S.writeRefusal())
  stems = S.backupStems()
  src = restorePaths(stems, slot)
  while i < src.len:
    if not fileExists(src[i]):
      return (false, "cannot restore: missing " & src[i])
    i = i + 1
  next = S.generation + 1'u64
  staging = generationPaths(S.baseDir, S.baseName, next)
  dst = @[staging.dataPath]
  if S.encrypted:
    dst.add staging.keyPath
    dst.add staging.ledgerPath
  if dst.len != src.len:
    return (false, "backup slot " & $slot & " has " & $src.len &
      " artifacts but this database needs " & $dst.len)
  try:
    i = 0
    while i < src.len:
      copyFile(src[i], dst[i])
      i = i + 1
    # The copied file still declares the generation it was written under.
    step = stampGeneration(staging.dataPath, next)
  except CatchableError as exc:
    step = (false, exc.msg)
  step = S.publishGeneration(next, step)
  if not step.ok:
    return step
  S.dirty = false
  result = (true, "")

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

proc sidecarRefsIn(s: Schema, C: ClusterBuild,
    into: var seq[string]) {.role: parser,
    tag: "db|read|sidecar".} =
  ## s/C: schema and cluster whose external column values are collected.
  ## into: locators appended, duplicates and all -- the caller only ever
  ##   asks whether a locator is present.
  var
    i: uint32 = 0'u32
    j: int = 0
    raw: ByteSeq = @[]
    offsets: seq[int] = @[]
  if not s.hasCapped():
    return
  while i < C.rowCount:
    raw = C.rowBytesAt(i)
    offsets = fieldOffsets(s, raw)
    j = 0
    while j < s.slots.len:
      if s.isExternal(raw, j):
        into.add refLocator(decodeRef(s.rawAt(raw, offsets, j)))
      j = j + 1
    i = i + 1

proc sidecarRefs*(s: Session): seq[string] {.role: parser,
    tag: "appApi|db|read|sidecar".} =
  ## s: session whose every stored row is scanned for sidecar references.
  ## Superseded versions count: they are still in the log, and a follower
  ## catching up will be sent them.
  sidecarRefsIn(s.entries.schema, s.entries, result)
  sidecarRefsIn(s.meta.schema, s.meta, result)
  sidecarRefsIn(s.journal.schema, s.journal, result)

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
    scratch: string = ""
    g: Generation = default(Generation)
    other: Session = default(Session)
    i: int = 0
    present: bool = false
  live = s.backupStems()
  while slot <= int(high(uint8)):
    src = restorePaths(live, slot)
    present = true
    i = 0
    while i < src.len:
      if not fileExists(src[i]):
        present = false
      i = i + 1
    if not present:
      # Slots are filled in order, so the first gap is the end of them.
      break
    scratch = s.baseDir / (".geist-sweep-" & $slot)
    try:
      if dirExists(scratch):
        removeDir(scratch)
      createDir(scratch)
      g = generationPaths(scratch, s.baseName, 1'u64)
      copyFile(src[0], g.dataPath)
      if s.encrypted:
        copyFile(src[1], g.keyPath)
        copyFile(src[2], g.ledgerPath)
      discard commitManifest(scratch, 1'u64)
      other = openSessionWithSchema(scratch, s.baseName, Schema(), s.config,
        s.password, readOnly = true)
      result.refs.add other.sidecarRefs()
      other.close()
      removeDir(scratch)
    except CatchableError as exc:
      if dirExists(scratch):
        removeDir(scratch)
      return (false, @[], "cannot read backup slot " & $slot & ": " & exc.msg)
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

## --------------------------- replication ----------------------------
##
## What one desktop sends another is ROWS OF THE LOG, and the cursor is a
## log position. That works because the log only ever grows and because a
## row carries its own identity:
##
##   follower has 12 rows  ->  "give me from 12"  ->  rows 12..N
##   each row says which id it is and whether it is a tombstone, so
##   applying it is the same operation whatever it turns out to be
##
## No separate change protocol, no per-event encoding, and a follower that
## was offline for a week catches up with the same call it uses when it was
## offline for a second.
##
## The one thing a position cannot survive is the log being REWRITTEN.
## `logEpoch` is what says that happened; a follower whose epoch differs
## has to take the whole thing again.

proc rowsSince*(s: Session, cursor: uint64, limit: int = 256,
    byteBudget: int = 0): seq[Row] {.role: parser,
    tag: "appApi|db|read|sync".} =
  ## s: session being read from.
  ## cursor: the follower's log position -- how many rows it already has.
  ## limit: maximum rows per call.
  ## byteBudget: stop once the rows total this many bytes, so an answer
  ##   stays inside one datagram and the expensive package path is not
  ##   needed for the ordinary case. Zero means no budget.
  ##
  ## The FIRST row is always included, however large it is. A budget that
  ## could return nothing would stall a follower on a single big row for
  ## ever, and the transport can package one oversized answer.
  ##
  ## Includes superseded versions and tombstones on purpose: they are what
  ## the follower missed, and replaying them in order reproduces exactly
  ## the state this session is in.
  var
    i: uint32 = 0'u32
    used: int = 0
  i = uint32(min(cursor, uint64(s.entries.rowCount)))
  while i < s.entries.rowCount and result.len < limit:
    if byteBudget > 0 and result.len > 0 and used >= byteBudget:
      break
    result.add s.entries.rowAt(i)
    used = used + result[^1].data.len
    i = i + 1'u32

proc applyRow*(S: var Session, r: Row): tuple[ok: bool, id: RowId,
    err: string] {.role: dataWriter, tag: "appApi|db|sync|write".} =
  ## S: session receiving one row FROM A PEER.
  ## r: the row exactly as the peer stored it, identity included.
  ##
  ## Appending it reproduces the peer's own operation: a new id adds, a
  ## known id supersedes, a tombstone removes. That is the whole apply
  ## logic, and it is the same three lines for all three cases -- which is
  ## the payoff for keeping identity inside the row.
  ##
  ## A row already present at the same version is skipped, so replaying an
  ## overlapping range is harmless. Peers retry; an apply that was not
  ## idempotent would turn a retry into a duplicate.
  var
    shaped: tuple[ok: bool, err: string] = (false, "")
    ident: tuple[id: RowId, flags: uint64] = (default(RowId), 0'u64)
    at: int = -1
    kind: ChangeKind = ckAdded
  if S.readOnly:
    return (false, 0'u64, S.writeRefusal())
  shaped = validateRow(S.entries.schema, r.data)
  if not shaped.ok:
    return (false, 0'u64, "row from peer does not fit the schema: " &
      shaped.err)
  ident = S.entries.schema.identityOf(r.data)
  if S.hasIdentity() and ident.id == 0'u64:
    return (false, 0'u64, "row from peer carries no identity")
  if ident.id != 0'u64:
    at = S.live.positionOf(ident.id)
    if at >= 0:
      if S.entries.rowBytesAt(uint32(at)) == r.data:
        # Already have exactly this version.
        return (true, ident.id, "")
      kind = if ident.flags.isTombstone(): ckDeleted else: ckUpdated
    elif ident.flags.isTombstone():
      kind = ckDeleted
  discard S.appendPacked(r.data, ident.id, ident.flags, kind)
  result = (true, ident.id, "")

proc applyRows*(S: var Session, R: openArray[Row]): tuple[ok: bool,
    applied: int, err: string] {.role: orchestrator,
    tag: "appApi|db|sync|write".} =
  ## S/R: a batch from a peer, applied IN ORDER and flushed once.
  ##
  ## Order matters and is the sender's: two versions of one row must not
  ## swap places on the way in, or the older one would win.
  var
    i: int = 0
    one: tuple[ok: bool, id: RowId, err: string] = (false, default(RowId), "")
    written: tuple[ok: bool, err: string] = (false, "")
    before: uint32 = 0'u32
  while i < R.len:
    before = S.logCount()
    one = S.applyRow(R[i])
    if not one.ok:
      return (false, result.applied, one.err)
    # Counted only when the log grew: a row this store already held (an
    # echo of its own push, a retried batch) is skipped and is not news.
    if S.logCount() > before:
      result.applied = result.applied + 1
    i = i + 1
  written = S.maybeFlush()
  if not written.ok:
    return (false, result.applied, written.err)
  result.ok = true

## --------------------------- change following -----------------------

proc subscribe*(S: var Session, id: string, replay: bool = false,
    fromOrdinal: uint64 = 0'u64): Subscription {.role: actor,
    tag: "appApi|db|sync|write", discardable.} =
  ## S: session whose changefeed gains a cursor.
  ## id: stable subscription name, reused across reconnects.
  ## replay: true rewinds to `fromOrdinal`; the default starts at the
  ##   current head, so a new subscriber sees what happens next rather
  ##   than being flooded with everything that already happened.
  ## fromOrdinal: explicit rewind point, only consulted when replaying.
  var
    i: int = 0
  result.id = id
  result.cursor = if replay: fromOrdinal else: S.changeOrdinal
  result.createdAt = uint64(getTime().toUnix())
  while i < S.subscriptions.len:
    if S.subscriptions[i].id == id:
      S.subscriptions[i] = result
      return
    i = i + 1
  S.subscriptions.add result

proc subscriptionAt(S: Session, id: string): int {.role: parser,
    tag: "db|read|sync".} =
  ## S/id: the position of that subscription, or -1.
  var
    i: int = 0
  while i < S.subscriptions.len:
    if S.subscriptions[i].id == id:
      return i
    i = i + 1
  result = -1

proc changesAfter(S: Session, cursor: uint64,
    limit: int): seq[ChangeEvent] {.role: parser, tag: "db|read|sync".} =
  ## S/cursor/limit: at most `limit` changes newer than `cursor`, oldest
  ## first.
  var
    j: int = 0
  while j < S.changes.len and result.len < limit:
    if S.changes[j].ordinal > cursor:
      result.add S.changes[j]
    j = j + 1

proc poll*(S: var Session, id: string,
    limit: int = 64): seq[ChangeEvent] {.role: parser,
    tag: "appApi|db|read|sync".} =
  ## S: session to drain.
  ## id: subscription whose cursor advances past the returned events.
  ## limit: maximum events per call.
  var
    at: int = S.subscriptionAt(id)
  if at < 0:
    raise newException(ValueError, "no such subscription: " & id)
  result = S.changesAfter(S.subscriptions[at].cursor, limit)
  if result.len > 0:
    S.subscriptions[at].cursor = result[^1].ordinal

proc unsubscribe*(S: var Session, id: string) {.role: actor,
    tag: "appApi|db|sync|write".} =
  ## S/id: session and subscription removed.
  var
    at: int = S.subscriptionAt(id)
  if at >= 0:
    S.subscriptions.delete(at)

## --------------------------- observation ----------------------------

proc observe*(path: string): tuple[ok: bool, f: GeistFile, err: string] {.
    role: dataFetcher, tag: "appApi|db|read|status".} =
  ## path: a Geist file this process does NOT own.
  ## Reads only the header and cluster index, so a daemon can follow a
  ## database without loading rows, taking a lease, or decrypting anything.
  result = readIndex(path)

proc observeStore*(baseDir: string,
    baseName: string = "main"): tuple[ok: bool, f: GeistFile, path: string,
    err: string] {.role: dataFetcher,
    tag: "appApi|db|read|status".} =
  ## baseDir/baseName: a store root this process does NOT own.
  ##
  ## Prefer this to `observe`. A save publishes a NEW generation, so the
  ## file name changes underneath anyone who remembered one; this resolves
  ## the live name through the manifest first and returns it alongside the
  ## index, so the next call can tell "the file moved on" from "the rows
  ## changed".
  var
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  result.path = liveDataPath(baseDir, baseName)
  idx = readIndex(result.path)
  result.ok = idx.ok
  result.f = idx.f
  result.err = idx.err

proc followStore*(before: GeistFile, baseDir: string,
    baseName: string = "main"): FollowStep {.role: orchestrator,
    tag: "appApi|db|read|status".} =
  ## before: the previous index read.
  ## baseDir/baseName: same store, re-resolved through the manifest.
  ##
  ## Returns which clusters moved, without reading a row and without caring
  ## which generation is live now. Cost is one manifest line plus one index.
  var
    now: tuple[ok: bool, f: GeistFile, path: string, err: string] =
      (false, default(GeistFile), "", "")
  now = observeStore(baseDir, baseName)
  if not now.ok:
    return (false, GeistFile(), @[], now.path, now.err)
  result.ok = true
  result.f = now.f
  result.path = now.path
  result.changed = changedClusters(before, now.f)


## ------------------------------ showing -----------------------------
##
## `echo db` on a store of any size. The rows that will not be printed are
## never decoded: `show` asks the style which positions it needs, fetches
## exactly those, and hands them over already selected. Printing twenty
## lines of a million-row store costs twenty rows.

proc visibleRow*(s: Session, i: uint32): Row {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## s/i: the i-th VISIBLE row -- superseded versions and tombstones are
  ## in the log, not in the list a person asked for.
  result = s.entries.rowAt(s.livePosition(i))

proc shownSlice(s: Session, limit: int): tuple[rows: seq[Row], at: seq[int],
    gapAfter: int] {.role: dataFetcher, tag: "db|read".} =
  ## s/limit: the head and tail this style will print, and nothing else.
  var
    n: int = int(s.entryCount())
    k: tuple[head, tail: int, elided: bool] = shownCount(n, limit)
  for i in shownIndexes(n, limit):
    result.rows.add s.visibleRow(uint32(i))
    result.at.add i
  result.gapAfter = if k.elided: k.head - 1 else: -1

proc show*(s: Session,
    style: ShowStyle = defaultShowStyle()): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## s/style: the visible rows as an aligned table, elided by default.
  var
    slice: tuple[rows: seq[Row], at: seq[int], gapAfter: int] = (@[], @[], 0)
  slice = s.shownSlice(style.maxRows)
  result = showSelection(s.entries.schema, slice.rows, slice.at,
    int(s.entryCount()), slice.gapAfter, style)

proc showTransposed*(s: Session,
    style: ShowStyle = defaultShowStyle()): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## s/style: the same rows with the axes swapped -- one line per field.
  var
    swapped: ShowStyle = style
    slice: tuple[rows: seq[Row], at: seq[int], gapAfter: int] = (@[], @[], 0)
  swapped.maxRows = style.maxColumns
  swapped.maxColumns = style.maxRows
  slice = s.shownSlice(swapped.maxRows)
  result = showSelection(s.entries.schema, slice.rows, slice.at,
    int(s.entryCount()), slice.gapAfter, swapped, transposed = true)

proc `$`*(s: Session): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## `echo db`, with the default style. A Session that printed its object
  ## fields instead would print a key set and a lease, which is both
  ## useless and the last thing anyone wants in a log.
  result = s.show()

## ---------------------------- fast search ---------------------------
##
## The column-first copy, and the two questions an operator has about it:
## is it current, and rebuild it now. The copy itself lives in
## transpose.nim; what belongs here is WHEN it is written, which only a
## session that just published a generation can know.


proc syncTransposed*(S: var Session): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|db|storageIo|write".} =
  ## S: rebuild the column copy from what is on disk NOW, whatever the
  ## configured mode says.
  ##
  ## This is the manual half of `tmManual`: write the store when you like,
  ## bring the search copy up to date when it suits. It refuses on an
  ## unsaved session rather than writing a copy of rows the store does not
  ## have yet -- the copy would then be the newer of the two, which is the
  ## one state the freshness check cannot express.
  if S.config.transpose == tmNone:
    return (false, "this database is configured with transpose = tmNone")
  if S.dirty:
    return (false, "there are unsaved rows; save first, or the column " &
      "copy would hold rows the store does not")
  result = S.writeTransposedNow(S.generation)

proc transposeState*(S: Session): TransposeStatus {.role: parser,
    tag: "appApi|db|read|status".} =
  ## S: which of the two copies is ahead, read from the files themselves.
  result = transposeState(S.baseDir, S.baseName)

proc transposedView*(S: Session): tuple[ok: bool, t: TransposedFile,
    err: string] {.role: parser, tag: "appApi|db|read".} =
  ## S: the column copy, opened for reading, IF it matches the live
  ## generation. A stale copy is refused rather than silently searched:
  ## the answer would be yesterday's rows, which is worse than a slow
  ## answer today.
  var
    state: TransposeStatus = S.transposeState()
  if state.state != tsCurrent:
    return (false, TransposedFile(),
      "column copy is " & describeTransposeState(state.state, state.live,
        state.built))
  result = openTransposed(state.path)

proc visibleIndexOf*(s: Session, logPosition: uint32): int {.role: parser,
    tag: "appApi|db|read".} =
  ## s/logPosition: where a row of the LOG appears in the visible list, or
  ## -1 when it does not appear at all.
  ##
  ## The inverse of `livePosition`, and the question anything that searched
  ## the log has to ask before it reports a hit: the log holds superseded
  ## versions and tombstones, and neither is an answer. Walking the live
  ## list costs one pass over a seq of positions -- no row is decoded, so
  ## it stays cheap next to the search that produced the hit.
  var
    i: int = 0
  if not s.hasIdentity():
    return (if logPosition < s.entries.rowCount: int(logPosition) else: -1)
  while i < s.live.live.len:
    if s.live.live[i] == logPosition:
      return i
    i = i + 1
  result = -1
