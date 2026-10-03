## ---------------------------------------------------------------------
## geist cli <- commands that open the store's files in this process
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point and says how the parts fit:
##
##   common   options, userconfig, opening a store, printing rows
##   direct   commands that open the files in this process (--path)
##   remote   commands sent to a running geistd (--remote), and sync

import std/[os, strutils, tables]

import runePragmas
import ../../geist/network
import ./common

## --------------------------- direct commands ------------------------

proc cmdInspect*(o: Options) {.role: actor,
    tag: "cli|read|status".} =
  ## o: options. Reads header and cluster index ONLY -- no rows, no
  ## password, no lease. This is the command that works on a database
  ## another process currently owns.
  var
    p: string = livePath(o)
    got: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  got = observe(p)
  if not got.ok:
    fail(got.err)
  echo "file:        ", p
  echo "size:        ", getFileSize(p), " B"
  echo "index cost:  ", got.f.indexBytes, " B  (read to produce this output)"
  echo "format:      v", got.f.header.version
  echo "generation:  ", got.f.header.generation
  echo "clusters:    ", got.f.header.clusterCount
  echo ""
  echo alignLeft("role", 12), alignLeft("mode", 11), alignLeft("rows", 8),
    alignLeft("rowBytes", 10), alignLeft("addressing", 12), "offsets"
  echo repeat('-', 62)
  for e in got.f.index:
    # rowBytes = 0 IS the declaration that rows vary, so the addressing
    # column is derived here rather than read from a stored byte.
    echo alignLeft($e.role, 12), alignLeft($e.mode, 11),
      alignLeft($e.rowCount, 8), alignLeft($e.rowBytes, 10),
      alignLeft((if e.rowBytes == 0'u32: "offsets" else: "arithmetic"), 12),
      $e.auxLen, " B"

proc cmdVerify*(o: Options) {.role: actor,
    tag: "cli|cryptoBoundary|read|status".} =
  ## o: options. Recomputes every sealed batch's Gimli digest -- no
  ## password, no lease, nothing changed. Works on a keyring folder too.
  ## Exit code 1 when any batch is damaged.
  var
    R: IntegrityReport = verifyStoreIntegrity(o.path)
  for p in R.problems:
    echo "  ", p
  echo (if R.ok: "intact" else: "DAMAGED"), ": ", R.batches, " sealed batch(es) checked"
  if not R.ok:
    quit(1)

proc cmdSchema*(o: Options) {.role: actor,
    tag: "cli|read|status".} =
  ## o: options. The schema block is stored in clear, so this needs no key.
  var
    p: string = livePath(o)
    got: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
    at: int = -1
    sc: tuple[s: Schema, schemaBytes: int] = (default(Schema), 0)
    i: int = 0
  got = observe(p)
  if not got.ok:
    fail(got.err)
  at = got.f.findIndex(crEntry)
  if at < 0:
    fail("no entry cluster in " & p)
  sc = readSchemaOf(p, got.f.index[at])
  echo "type:   ", sc.s.typeName
  # The spec is what a caller would DECLARE, so it leaves out the reserved
  # identity columns -- `geist init --schema` takes this string back.
  echo "spec:   ", describeSchema(withoutIdentity(sc.s))
  echo "rowBytes: ", sc.s.rowBytes()
  if sc.s.hasIdentity():
    echo "identity: yes (__rowId, __flags -- rows can be set and deleted)"
  else:
    echo "identity: no (append-only; set and delete are unavailable)"
  echo ""
  while i < sc.s.slots.len:
    # Only a dense schema has a fixed offset per column. When rows vary,
    # printing one would be a plausible-looking lie, so it says so instead.
    echo "  ", alignLeft($i, 4),
      alignLeft(sc.s.nameOf(sc.s.slots[i].nameId), 20),
      alignLeft(slotKindName(sc.s.slots[i].kind), 10),
      alignLeft($sc.s.slots[i].column, 12),
      alignLeft($sc.s.slots[i].width & " B", 8),
      (if sc.s.isDense(): "@ +" & $sc.s.slotAt(i) else: "per row")
    i = i + 1

proc cmdInit*(o: Options) {.role: actor,
    tag: "cli|db|write".} =
  ## o: options carrying --schema and optionally --type.
  var
    parsed: tuple[ok: bool, s: Schema, err: string] =
      (false, default(Schema), "")
    db: Session = default(Session)
    written: tuple[ok: bool, err: string] = (false, "")
  if o.schemaSpec.len == 0:
    fail("init needs --schema \"name:type,name:type\"")
  parsed = parseSchemaSpec(o.typeName, o.schemaSpec)
  if not parsed.ok:
    fail(parsed.err)
  db = openDirect(o, parsed.s, forWriting = true)
  written = db.save()
  if not written.ok:
    fail(written.err)
  db.close()
  echo "created ", storePaths(o).dir, " with preset '",
    (if o.preset.len > 0: o.preset else: geistDefaults().preset), "'"
  echo "schema: ", describeSchema(parsed.s)

proc cmdPut*(o: Options) {.role: actor,
    tag: "cli|db|write".} =
  ## o: options whose trailing arguments are `field=value` pairs.
  var
    id: RowId = 0'u64
    pairs: tuple[ok: bool, values: Table[string, string], err: string] =
      (false, default(Table[string, string]), "")
    built: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
  if o.args.len == 0:
    fail("put needs at least one field=value")
  pairs = parsePairs(o.args)
  if not pairs.ok:
    fail(pairs.err)
  writing(o, db):
    id = db.nextIdFor()
    built = buildRow(db.entries.schema, pairs.values, db.sidecarStore, id)
    if not built.ok:
      fail(built.err)
    discard db.putRow(Row(data: built.data))
    # The id, not the position: it is what `set` and `delete` take.
    if id != 0'u64:
      echo "stored row id ", id
    else:
      echo "appended row ", db.entryCount() - 1'u32

proc rowValues*(s: Schema, A: openArray[uint8]): Table[string, string] {.
    role: parser, tag: "cli|db|read".} =
  ## s/A: one stored row turned back into `field -> text`, so an edit can
  ## be applied over it. The reserved columns are left out: they are set
  ## from the id being edited, not from the old row's rendering.
  var
    cells: seq[string] = @[]
    i: int = 0
  result = initTable[string, string]()
  cells = renderRow(s, A)
  i = if s.hasIdentityColumns(): identityColumnCount else: 0
  while i < cells.len and i < s.slots.len:
    result[s.nameOf(s.slots[i].nameId)] = cells[i]
    i = i + 1

proc cmdSet*(o: Options) {.role: actor,
    tag: "cli|db|write".} =
  ## o: options; first argument is a row id, the rest are `field=value`.
  ##
  ## Fields NOT named keep what they had. A CLI edit that silently blanked
  ## every column the user did not mention would be a trap, even though the
  ## stored row is replaced whole.
  var
    id: RowId = 0'u64
    pairs: tuple[ok: bool, values: Table[string, string], err: string] =
      (false, default(Table[string, string]), "")
    merged: Table[string, string] = default(Table[string, string])
    built: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
    at: int = -1
  if o.args.len < 2:
    fail("set needs a row (id or @position) and at least one field=value")
  pairs = parsePairs(o.args[1 .. ^1])
  if not pairs.ok:
    fail(pairs.err)
  writing(o, db):
    id = resolveRowRef(db, o.args[0])
    if not db.hasIdentity():
      fail("this database stores rows without identity, so there is no id " &
        "to address. Recreate it with a preset that keeps identity.")
    at = db.live.positionOf(id)
    if at < 0:
      fail("no row with id " & $id)
    merged = rowValues(db.entries.schema, db.entries.rowBytesAt(uint32(at)))
    for k, v in pairs.values:
      merged[k] = v
    built = buildRow(db.entries.schema, merged, db.sidecarStore, id)
    if not built.ok:
      fail(built.err)
    discard db.putRow(Row(data: built.data))
    echo "updated row id ", id

proc cmdDelete*(o: Options) {.role: actor,
    tag: "cli|db|delete|write".} =
  ## o: options whose first argument is a row id.
  var
    id: RowId = 0'u64
  if o.args.len == 0:
    fail("delete needs a row (id or @position)")
  writing(o, db):
    id = resolveRowRef(db, o.args[0])
    if not db.hasIdentity():
      fail("this database stores rows without identity, so there is no id " &
        "to address.")
    if not db.delete(id):
      fail("no row with id " & $id & " (or it is already deleted)")
    echo "deleted row id ", id


proc cmdTranspose*(o: Options) {.role: actor,
    tag: "cli|db|status|write".} =
  ## o: report the column copy's state, and rebuild it unless only asked.
  ##
  ## One command for both questions, because they are the same question:
  ## an operator who runs this wants the copy to be current, and wants to
  ## be told whether it already was.
  var
    db: Session = default(Session)
    state: TransposeStatus = default(TransposeStatus)
    built: tuple[ok: bool, err: string] = (false, "")
  db = openDirect(o, forWriting = false)
  state = db.transposeState()
  echo "column copy:   ", describeTransposeState(state.state, state.live,
    state.built)
  echo "mode:          ", db.config.transpose,
    (if db.config.transpose == tmInterval:
       "  (every " & $db.config.transposeEverySeconds & "s)" else: "")
  if state.path.len > 0 and fileExists(state.path):
    echo "  ", extractFilename(state.path), "  ", getFileSize(state.path),
      " B   (rows: ", extractFilename(db.dataPath()), "  ",
      getFileSize(db.dataPath()), " B)"
  if o.args.len > 0 and o.args[0] == "status":
    db.close()
    return
  if db.config.transpose == tmNone:
    db.close()
    fail("this database is configured with transpose = tmNone; set " &
      "[runtime.storage] transpose in configs/default.toml, or the field on the GeistConfig")
  built = db.syncTransposed()
  db.close()
  if not built.ok:
    fail(built.err)
  state = transposeState(storePaths(o).dir, storePaths(o).name)
  echo "rebuilt:       ", describeTransposeState(state.state, state.live,
    state.built)
proc cmdSweep*(o: Options) {.role: actor,
    tag: "cli|db|maintenance|sidecar|write".} =
  ## o: options. Deletes sidecar payloads no stored row references -- in
  ## this database or in any of its backup slots.
  ##
  ## Run it AFTER `compact`: a superseded version still in the log is a
  ## reference like any other, so nothing is reclaimable until the log has
  ## let go of it.
  var
    db: Session = default(Session)
    swept: tuple[ok: bool, removed: int, bytes: uint64, err: string] =
      (false, 0, 0'u64, "")
  db = openDirect(o, forWriting = true)
  swept = db.sweepSidecar()
  if not swept.ok:
    db.close()
    fail(swept.err)
  echo "swept ", swept.removed, " unreferenced payload(s), ",
    swept.bytes, " B reclaimed"
  db.close()

proc cmdCompact*(o: Options) {.role: actor,
    tag: "cli|db|maintenance|write".} =
  ## o: options. Reclaims superseded versions and tombstones. Visible rows
  ## and their ids are untouched; the file gets smaller.
  var
    before: uint32 = 0'u32
    done: tuple[ok: bool, removed: uint32, err: string] = (false, 0'u32, "")
  writing(o, db):
    before = db.logCount()
    done = db.compact()
    if not done.ok:
      fail(done.err)
    echo "compacted: ", before, " stored rows -> ", db.logCount(),
      " (", done.removed, " reclaimed, ", db.entryCount(), " visible)"

proc cmdList*(o: Options) {.role: actor,
    tag: "cli|db|read".} =
  ## o: options; --limit caps the output.
  var
    db: Session = default(Session)
    rows: seq[Row] = @[]
    at: seq[int] = @[]
    i: uint32 = 0'u32
  db = openDirect(o)
  # The VISIBLE rows: superseded versions and tombstones are in the log,
  # not in the list a person asked for.
  while i < db.entryCount() and rows.len < o.limit:
    rows.add db.entries.rowAt(db.livePosition(i))
    at.add int(i)
    i = i + 1'u32
  emitRows(db.entries.schema, rows, o.json, at, o.transposed)
  if not o.json:
    echo ""
    echo rows.len, " of ", db.entryCount(), " rows"
  db.close()

proc cmdGet*(o: Options) {.role: actor,
    tag: "cli|db|read".} =
  ## o: options whose first argument is a row index.
  var
    db: Session = default(Session)
    idx: int = 0
  if o.args.len == 0:
    fail("get needs a row index")
  try:
    idx = parseInt(o.args[0])
  except ValueError:
    fail("row index must be a number, got '" & o.args[0] & "'")
  db = openDirect(o)
  if idx < 0 or uint32(idx) >= db.entryCount():
    fail("row " & $idx & " is out of range (" & $db.entryCount() & " rows)")
  emitRows(db.entries.schema,
    @[db.entries.rowAt(db.livePosition(uint32(idx)))], o.json, @[idx],
    o.transposed)
  db.close()

proc findInCopy*(db: Session, t: TransposedFile, o: Options,
    R: var seq[Row], A: var seq[int]): uint64 {.role: parser,
    tag: "cli|db|read".} =
  ## db/t: the session and its column copy.
  ## o: options whose arguments are a field name and an exact value.
  ## R/A: matching rows and their visible positions, appended to.
  ## Returns how many bytes the search read; 0 means the copy could not
  ## answer and the caller has to scan.
  ##
  ## The column copy holds the LOG: superseded versions and tombstones are
  ## in it, because that is what the entry cluster contains. A hit is only
  ## an answer if that row is still the visible version of its id, which
  ## `visibleIndexOf` decides -- without it, `find` would start returning
  ## rows that `list` does not show.
  var
    hit: tuple[ok: bool, rows: seq[uint32], read: uint64, err: string] =
      t.transposedFind(o.args[0], o.args[1])
    seen: int = -1
  if not hit.ok:
    return 0'u64
  for pos in hit.rows:
    seen = db.visibleIndexOf(pos)
    if seen >= 0 and R.len < o.limit:
      R.add t.transposedRow(pos)
      A.add seen
  result = hit.read

proc findByScan*(db: Session, o: Options, R: var seq[Row],
    A: var seq[int]) {.role: parser, tag: "cli|db|read".} =
  ## db/o: the session, and a field name and exact value in o.args.
  ## R/A: matching rows and their visible positions, appended to.
  var
    i: uint32 = 0'u32
    r: Row = Row()
  while i < db.entryCount() and R.len < o.limit:
    r = db.entries.rowAt(db.livePosition(i))
    if matchesText(db.entries.schema, r.data, o.args[0], o.args[1]):
      R.add r
      A.add int(i)
    i = i + 1'u32

proc cmdFind*(o: Options) {.role: actor,
    tag: "cli|db|read".} =
  ## o: options whose arguments are a field name and an exact value.
  ##
  ## Uses the column copy when there is one and it is current, because
  ## then the search reads one column instead of every row. The ANSWER is
  ## the same either way -- only what it cost differs -- so a stale or
  ## missing copy is not an error, it is the ordinary scan.
  var
    db: Session = default(Session)
    rows: seq[Row] = @[]
    at: seq[int] = @[]
    view: tuple[ok: bool, t: TransposedFile, err: string] =
      (false, default(TransposedFile), "")
    scanned: uint64 = 0'u64
  if o.args.len < 2:
    fail("find needs a field and a value")
  db = openDirect(o)
  if db.entries.schema.slotIndex(o.args[0]) < 0:
    fail("no field '" & o.args[0] & "' in schema (" &
      describeSchema(db.entries.schema) & ")")
  view = db.transposedView()
  if view.ok:
    scanned = findInCopy(db, view.t, o, rows, at)
  if scanned == 0'u64:
    findByScan(db, o, rows, at)
  emitRows(db.entries.schema, rows, o.json, at, o.transposed)
  if not o.json:
    echo ""
    echo rows.len, " match(es)",
      (if scanned > 0'u64: "  (read " & $scanned &
         " B of the column copy, not " & $getFileSize(db.dataPath()) &
         " B of rows)" else: "")
  db.close()

proc cmdInfo*(o: Options) {.role: actor,
    tag: "cli|read|status".} =
  ## o: options. Needs the password when the database is encrypted.
  var
    db: Session = default(Session)
    stats: StorageStats = default(StorageStats)
  db = openDirect(o)
  stats = db.storageStats()
  echo "preset:        ", db.config.name
  echo "writeMode:     ", db.config.writeMode,
    (if db.config.writeMode == wmInterval:
      "   every " & $db.config.writeIntervalSeconds & "s" else: "")
  echo "autoCollapse:  ", db.config.autoCollapse
  echo "addressing:    ", (if db.entries.schema.isDense():
    "arithmetic (" & $db.entries.schema.rowBytes() & " B rows)"
    else: "row offset table")
  echo "cipher:        ", db.config.cipher, "   batch checks: Gimli digest + BLAKE3 tag"
  echo "sealMeta:      ", db.config.sealMeta,
    "   sealJournal: ", db.config.sealJournal
  echo "batchRows:     ", db.config.batchRows
  echo "sidecar >=:    ", db.config.sidecarThreshold, " B"
  echo "generation:    ", db.generation
  block:
    # Only worth a line when the database asked for one. A store that is
    # row-major by choice should not be told about a file it does not have.
    var ts = db.transposeState()
    if db.config.transpose != tmNone or ts.state != tsAbsent:
      echo "column copy:   ", describeTransposeState(ts.state, ts.live,
        ts.built)
  echo "entries:       ", db.entryCount()
  # Truncation is legal, opt-in and leaves no mark in the stored row, so
  # this line is the only place a reader can learn it happened.
  echo "externalised:  ", stats.externalised, " values"
  echo "truncated:     ", stats.truncated, " values",
    (if stats.truncatedIn.len > 0: "   in: " & stats.truncatedIn.join(", ")
     else: "")
  echo "journal rows:  ", db.journal.rowCount
  echo "ledger rows:   ", db.ledger.entries.len,
    " (meta ", db.metaLedger.entries.len,
    ", journal ", db.journalLedger.entries.len, ")"
  echo "column groups: ", db.ledger.groups.len
  echo "backup:        every ", db.backupPolicy.everyNWrites, " writes / ",
    db.backupPolicy.everySeconds, "s, ", db.backupPolicy.copies, " copies"
  echo "  rotations:   ", db.backupState.rotations,
    "   writes since:  ", db.backupState.writesSinceBackup
  echo "artifacts:"
  for p in db.artifactSet():
    echo "  ", extractFilename(p), "  ",
      (if fileExists(p): $getFileSize(p) & " B" else: "MISSING")
  db.close()

proc cmdCheckpoint*(o: Options) {.role: actor,
    tag: "cli|db|write".} =
  ## o: options whose first argument is the checkpoint message.
  var
    at: uint32 = 0'u32
  writing(o, db):
    at = db.checkpoint(if o.args.len > 0: o.args[0] else: "checkpoint")
    echo "journal row ", at, " appended"

proc cmdBackup*(o: Options) {.role: actor,
    tag: "backup|cli|write".} =
  ## o: options. Forces a rotation regardless of the configured triggers.
  var
    db: Session = default(Session)
    policy: BackupPolicy = default(BackupPolicy)
    got: BackupResult = default(BackupResult)
  db = openDirect(o, forWriting = true)
  policy = db.backupPolicy
  policy.enabled = true
  policy.everyNWrites = 1'u32
  db.backupState.writesSinceBackup = max(1'u32,
    db.backupState.writesSinceBackup)
  got = runBackup(db.artifactSet(), db.backupStems(), policy, db.backupState)
  if got.err.len > 0:
    fail(got.err)
  if not got.performed:
    fail("no rotation performed: " & got.reason)
  for p in got.copied:
    echo "wrote ", extractFilename(p)
  db.close()

proc cmdRestore*(o: Options) {.role: actor,
    tag: "backup|cli|write".} =
  ## o: options; --slot selects the rotation slot, 1 being most recent.
  var
    db: Session = default(Session)
    paths: seq[string] = @[]
    got: tuple[ok: bool, err: string] = (false, "")
  db = openDirect(o, forWriting = true)
  paths = db.artifactSet()
  # Published as a new generation, like any other write: the current
  # database stays intact until the restored one verifies.
  got = db.restoreSlot(o.slot)
  if not got.ok:
    db.close()
    fail(got.err)
  echo "restored ", paths.len, " artifact(s) from slot ", o.slot,
    " as generation ", db.generation
  # The rows in memory are the ones just replaced, so nothing may be
  # written back from this session.
  db.readOnly = true
  db.close()

proc cmdRekey*(o: Options) {.role: actor,
    tag: "cli|cryptoBoundary|keyLifecycle|write".} =
  ## o: options. Re-keys only the batches at their epoch high-water mark;
  ## a fresh keyRef is a fresh nonce space, so no global rewrite happens.
  var
    db: Session = default(Session)
    due: seq[tuple[batchIndex: uint32, groupId: uint16]] = @[]
    fresh: KeyId = 0'u64
    i: int = 0
    written: tuple[ok: bool, err: string] = (false, "")
  db = openDirect(o, forWriting = true)
  if not db.encrypted:
    fail("this database is not encrypted; there is nothing to re-key")
  due = batchesNeedingRekey(db.ledger, db.config.rekeyAtEpoch)
  if due.len == 0:
    echo "no batch has reached the rekey high-water mark (",
      db.config.rekeyAtEpoch, ")"
    db.close()
    return
  while i < due.len:
    fresh = rekeyBatch(db.keySet, db.ledger, due[i].batchIndex, due[i].groupId)
    echo "batch ", due[i].batchIndex, " group ", due[i].groupId,
      " -> keyRef ", fresh
    i = i + 1
  written = db.save()
  if not written.ok:
    fail(written.err)
  echo "re-keyed ", due.len, " batch(es); the rest of the database was untouched"
  db.close()

proc cmdKeygen*(o: Options) {.role: actor,
    tag: "cli|cryptoBoundary|networkSurface|write".} =
  ## o: options carrying --identity, --pin-out and --subject.
  var
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
    written: tuple[ok: bool, err: string] = (false, "")
    pinPath: string = ""
  if o.identity.len == 0:
    fail("keygen needs --identity <file>")
  if resolvePassword(o).len == 0:
    fail("keygen needs a password: the identity's secret keys are sealed")
  mine = loadOrCreateIdentity(o.identity, resolvePassword(o), o.subject,
    geistSignatureSlots())
  if not mine.ok:
    fail(mine.err)
  pinPath = if o.pinOut.len > 0: o.pinOut else: o.identity & ".pin"
  written = savePin(pinPath, pinOf(mine.key))
  if not written.ok:
    fail(written.err)
  echo (if mine.created: "created " else: "loaded existing "), o.identity
  echo "wrote ", pinPath, "  <- hand this to the peer"
  echo ""
  echo describePin(pinOf(mine.key))

proc cmdPresets*() {.role: actor, tag: "cli|config|read".} =
  ## The public preset catalog.
  for p in geistConfigPresets():
    ## 18, not 16: `secure-collapsed` is 16 characters and would leave
    ## no gap at all before its purpose.
    echo alignLeft(p.name, 18), p.purpose

