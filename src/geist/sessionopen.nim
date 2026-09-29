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

##
## This part OPENS a store: the Session type, where its files are, and
## everything read at open. Writing, reading and saving are ./sessioncore.
import std/[os, times]

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

proc noteChange*(S: var Session, role: ClusterRole, rowIndex: uint32,
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

proc stampMetaCounters*(S: var Session) {.role: dataWriter,
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

proc requireIdentity*(s: Session) {.role: sanitizer,
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

proc adoptLedgers(S: var Session, L: openArray[Ledger]) {.role: truthBuilder,
    tag: "cryptoBoundary|db|read".} =
  ## S/L: the ledgers the ledger file held, in their fixed order:
  ##
  ##   L[0] entries     L[1] meta     L[2] journal
  ##
  ## Fewer than three is a store written before that cluster was sealed;
  ## the ones missing keep the fresh ledger `loadStore` already made.
  if L.len > 0:
    S.ledger = L[0]
  if L.len > 1:
    S.metaLedger = L[1]
  if L.len > 2:
    S.journalLedger = L[2]

proc loadKeys(S: var Session, password: string) {.role: decryptor,
    tag: "cryptoBoundary|db|keyLifecycle|read".} =
  ## S/password: the key set and the ledgers of a sealed store.
  ##
  ## An EXISTING key file that will not open is a wrong password or a
  ## tampered file. Minting a fresh key set then would silently orphan every
  ## row already written, so it raises instead. No key file yet is a new
  ## store, and gets a fresh set.
  var
    loadedKeys: tuple[ok: bool, keys: KeySet, err: string] =
      (false, default(KeySet), "")
    loadedLedger: tuple[ok: bool, ledgers: seq[Ledger], err: string] =
      readLedgerFile(S.ledgerPath())
  if fileExists(S.keyPath()):
    loadedKeys = readKeyFile(S.keyPath(), password)
    if not loadedKeys.ok:
      raise newException(IOError, loadedKeys.err)
    S.keySet = loadedKeys.keys
  else:
    S.keySet = newKeySet()
    discard S.keySet.allocKeyRef("initial")
  if loadedLedger.ok:
    S.adoptLedgers(loadedLedger.ledgers)
  elif fileExists(S.ledgerPath()):
    raise newException(IOError, loadedLedger.err)

proc readRole(S: Session, f: GeistFile, role: ClusterRole): tuple[
    found: bool, c: ClusterBuild] {.role: dataFetcher,
    tag: "db|read|storageIo".} =
  ## S/f/role: that role's cluster from the live file, still sealed, or
  ## found = false when the file has none.
  var
    at: int = f.findIndex(role)
  if at < 0:
    return (false, default(ClusterBuild))
  result = (true, readCluster(S.dataPath(), f.index[at], S.sidecarStore,
    S.config.chainHash, S.config.treeHash))

proc openRecords(S: Session, C: var ClusterBuild, L: Ledger) {.
    role: decryptor, tag: "cryptoBoundary|db|read".} =
  ## S/C/L: a meta or journal cluster opened in place, when it was sealed.
  if S.encrypted and L.groups.len > 0:
    openPacked(S.keySet.master, L, C.rows, C.rowOffsets, C.rowCount,
      L.databaseId, geistFormatVersion)

proc openEntries(S: var Session) {.role: decryptor,
    tag: "cryptoBoundary|db|read".} =
  ## S: the entry cluster opened in place. Varying rows are sealed row by
  ## row (packed); fixed rows are sealed by column group.
  if S.encrypted and S.entries.varyingRows():
    openPacked(S.keySet.master, S.ledger, S.entries.rows,
      S.entries.rowOffsets, S.entries.rowCount, S.baseName,
      geistFormatVersion)
  elif S.encrypted and S.ledger.groups.len > 0:
    openCluster(S.keySet.master, S.ledger, S.entries.schema,
      S.entries.rows, S.entries.rowCount, S.baseName, geistFormatVersion)

proc loadClusters(S: var Session) {.role: orchestrator,
    tag: "db|read|storageIo".} =
  ## S: meta, journal and entries from the live file, opened. A store with
  ## no file yet keeps the empty clusters `loadStore` made.
  var
    index: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    got: tuple[found: bool, c: ClusterBuild] = (false, default(ClusterBuild))
  if not fileExists(S.dataPath()):
    return
  index = readIndex(S.dataPath())
  if not index.ok:
    raise newException(IOError, index.err)
  got = S.readRole(index.f, crMeta)
  if got.found:
    S.meta = got.c
    S.openRecords(S.meta, S.metaLedger)
  got = S.readRole(index.f, crJournal)
  if got.found:
    S.journal = got.c
    S.openRecords(S.journal, S.journalLedger)
  got = S.readRole(index.f, crEntry)
  if got.found:
    S.entries = got.c
    S.openEntries()

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
    recordSchema: Schema = default(Schema)
    applied: tuple[ok: bool, s: Schema, err: string] =
      (false, default(Schema), "")
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
    S.loadKeys(password)
  S.loadClusters()
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

