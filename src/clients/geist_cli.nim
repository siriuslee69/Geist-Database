## ---------------------------------------------------------------------
## geist <- command line client, direct or against a daemon
## ---------------------------------------------------------------------
##
##   direct:  geist --path data/notes list
##   daemon:  geist --remote dac://127.0.0.1:47655 list
##
## The same commands run either way. `--path` opens the database files in
## this process; `--remote` sends the identical `Query` to geistd over
## Bifrost AME/DAC. That works because a serialised Query IS the wire
## body, so the CLI has no second code path for the network.
##
## Commands that need the at-rest password or rewrite local files -- init,
## checkpoint, compact, sweep, backup, restore, rekey -- are direct only:
## sending key material to a daemon to have it do local file work would
## widen the trust boundary for no benefit.
##
##   inspect  -> works WITHOUT a password: reads only header + index
##   list/get -> needs the password when the database is encrypted
##
## A `userconfig.toml` fills in anything not typed, and `configs/default.toml`
## carries the library defaults a preset is adjusted by. An option on the
## command line always wins over either.

import std/[os, strutils, tables]

import runePragmas
import ../geist/network

type
  Mode* {.role: truthState, tag: "cli|types".} = enum
    mDirect, mRemote

  Options* {.role: truthState, tag: "cli|parsing|types".} = object
    ## Exported, like the daemon's `DaemonConfig`, so option precedence can
    ## be tested without spawning a process. Nothing else imports this.
    ##
    ## given: the long option names ACTUALLY TYPED, which is the only way
    ##   to tell `--preset app` from a `preset` nobody mentioned. Several
    ##   of these fields have non-empty defaults, so their value cannot
    ##   answer that question -- and a config file silently winning over
    ##   something visible on the command line is the failure this exists
    ##   to prevent.
    mode*: Mode
    path*: string
    remote*: string
    password*: string
    passwordFile*: string
    preset*: string
    schemaSpec*: string
    typeName*: string
    limit*: int
    slot*: int
    identity*: string
    peerPin*: string
    pinOut*: string
    subject*: string
    json*: bool
    ## transposed: show the answer with the axes swapped -- one line per
    ##   field. What the column copy looks like, and the shape that fits a
    ##   terminal when the schema is wide and the answer is short.
    transposed*: bool
    config*: string
    args*: seq[string]
    command*: string
    given*: seq[string]

const
  usageText = """
geist <command> [options]

  --path <dir>            operate directly on a database directory
  --remote dac://host:port  operate through a running geistd
  --password <text>       at-rest password (prefer --password-file)
  --password-file <file>  read the password from a file
  --preset <name>         config preset, default app
  --schema "a:int,b:text" field list, only for `init`
  --type <name>           object type label for `init`
  --limit <n>             maximum rows, default 20
  --slot <n>              backup slot for `restore`, default 1
  --identity <file>       signing identity; created by `keygen`
  --peer-pin <file>       the daemon's public pin (required for --remote)
  --pin-out <file>        where `keygen` writes the shareable pin
  --subject <name>        identity subject for `keygen`, default geist-cli
  --json                  machine-readable output
  --transposed            show the answer with the axes swapped: one line
                          per field instead of one line per row
  --config <file>         userconfig.toml to read; defaults to the one in
                          the working directory, then ~/.config/geist

commands
  inspect                 header + cluster index; no password needed
  schema                  show the stored field list
  info                    config, counts, ledger and backup state
  init                    create a database from --schema
  put a=1 b=hello         append one row, printing its id
  set <row> b=hello       replace one row; <row> is an id or an @position
                          as shown by `list`. Unnamed fields keep their
                          current value
  delete <row>            remove one row, by id or @position
  compact                 reclaim superseded versions and tombstones
  sweep                   delete sidecar payloads no row references
  get <index>             show one visible row
  list                    list rows up to --limit
  find <field> <value>    exact text match; uses the column copy when it
                          is current, which reads one column instead of
                          every row
  transpose [status]      rebuild the column-first search copy, or report
                          whether it is still current
  sync                    catch this database (--path) up with a peer
                          (--remote), applying the rows it has and this
                          one does not. Needs both. Rows keep the identity
                          the peer stored them under, so a row that
                          started several desktops away arrives under the
                          id it was born with, and this database can be
                          followed onward by another.
  checkpoint <message>    append a hash-chained journal row
  backup                  force a rotation now
  restore                 restore from --slot
  rekey                   re-key every batch at its epoch high-water mark
  keygen                  create --identity and --pin-out, then exit
  presets                 list configuration presets
  help                    this text

Pinned trust means each side must already know the other's public keys, so
--remote needs both --identity and --peer-pin. Run `keygen` on each side and
exchange the .pin files; hand the daemon your pin with its --trust option.
"""

type
  GeistCliFailure* = object of CatchableError
    ## One operator-facing error. `fail` raises it and `runGeistCli` prints
    ## it and returns 1, so a command several calls deep can end the RUN
    ## without ending the PROCESS -- a test, or a program embedding the
    ## CLI, keeps going.

proc fail(msg: string) {.noreturn, role: helper, stage: stDone,
    tag: "cli|status".} =
  ## msg: operator-facing error; `runGeistCli` writes it to stderr and
  ## exits non-zero.
  raise newException(GeistCliFailure, msg)

proc resolvePassword(o: Options): string {.role: sanitizer,
    tag: "cli|cryptoBoundary|parsing".} =
  ## o: parsed options. A password file wins over an inline password,
  ## because the inline form is visible in the process list.
  if o.passwordFile.len > 0:
    if not fileExists(o.passwordFile):
      fail("no password file at " & o.passwordFile)
    return readFile(o.passwordFile).strip()
  result = o.password

proc needsValue(key: string): bool {.role: parser,
    tag: "cli|parsing".} =
  ## key: long option name that consumes the following argument.
  result = key in ["path", "remote", "password", "password-file", "preset",
    "schema", "type", "limit", "slot", "identity", "peer-pin", "pin-out",
    "subject", "config"]

proc parseOptions*(argv: openArray[string]): Options {.role: parser,
    tag: "cli|parsing|read".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    at: int = 0
  result.preset = "app"
  result.limit = 20
  result.slot = 1
  result.subject = "geist-cli"
  while i < argv.len:
    if not argv[i].startsWith("--"):
      if result.command.len == 0:
        result.command = argv[i]
      else:
        result.args.add argv[i]
      i = i + 1
      continue
    key = argv[i][2 .. ^1]
    value = ""
    at = key.find('=')
    if at > 0:
      value = key[at + 1 .. ^1]
      key = key[0 ..< at]
    elif needsValue(key):
      if i + 1 >= argv.len:
        fail("option --" & key & " needs a value")
      value = argv[i + 1]
      i = i + 1
    case key
    of "path": result.path = value
    of "remote": result.remote = value
    of "password": result.password = value
    of "password-file": result.passwordFile = value
    of "preset": result.preset = value
    of "schema": result.schemaSpec = value
    of "type": result.typeName = value
    of "limit": result.limit = parseInt(value)
    of "slot": result.slot = parseInt(value)
    of "identity": result.identity = value
    of "peer-pin": result.peerPin = value
    of "pin-out": result.pinOut = value
    of "subject": result.subject = value
    of "json": result.json = true
    of "transposed", "t": result.transposed = true
    of "config": result.config = value
    of "help", "h": result.command = "help"
    else: fail("unknown option --" & key)
    result.given.add key
    i = i + 1
  result.mode = if result.remote.len > 0: mRemote else: mDirect

proc withUserConfig*(o: Options): Options {.role: configurator,
    tag: "cli|config|parsing".} =
  ## o: options straight off the command line.
  ##
  ## Fills in only what was NOT typed. A config file is a way to stop
  ## repeating yourself, so an explicit option always wins over it -- the
  ## other way round, a stale file would quietly override what someone can
  ## see on their own command line.
  var
    where: string = ""
    loaded: tuple[ok: bool, user: UserConfig, err: string] =
      (false, default(UserConfig), "")
  result = o
  where = firstExisting(userConfigCandidates(o.config))
  if where.len == 0:
    if o.config.len > 0:
      fail("no config file at " & o.config)
    return
  loaded = loadUserConfig(where)
  if not loaded.ok:
    fail(loaded.err)
  # "Was it typed?", not "does it still look like the default?". `--preset
  # app` and `--limit 20` are things a person writes on purpose, and the
  # value alone cannot distinguish them from an option nobody passed.
  if "path" notin result.given:
    result.path = loaded.user.path
  if "preset" notin result.given and loaded.user.preset.len > 0:
    result.preset = loaded.user.preset
  if "password-file" notin result.given:
    result.passwordFile = loaded.user.passwordFile
  if "remote" notin result.given:
    result.remote = loaded.user.remote
  if "peer-pin" notin result.given:
    result.peerPin = loaded.user.peerPin
  if "limit" notin result.given and loaded.user.limit > 0:
    result.limit = loaded.user.limit
  result.mode = if result.remote.len > 0: mRemote else: mDirect

proc storePaths(o: Options): tuple[dir, name: string] {.role: parser,
    tag: "cli|parsing|storageIo".} =
  ## o: options whose --path is split into a store root and a stem.
  if o.path.len == 0:
    fail("--path or --remote is required")
  result.dir = o.path
  result.name = "main"
  if o.path.splitFile().ext.len > 0:
    result.dir = o.path.parentDir()
    result.name = o.path.splitFile().name

proc livePath(o: Options): string {.role: parser,
    tag: "cli|read|storageIo".} =
  ## o: options resolved to the current generation's data file, through the
  ## manifest -- every save publishes a new one, so the name is never fixed.
  var
    sp = storePaths(o)
  result = liveDataPath(sp.dir, sp.name)

proc openDirect(o: Options, schema: Schema = Schema(),
    forWriting: bool = false): Session {.
    role: orchestrator, tag: "cli|db|orchestrator".} =
  ## o: options.
  ## schema: used only when creating; an existing file supplies its own.
  ## forWriting: a command that intends to modify the database. It opens
  ##   with the write lease and STOPS if another process holds it, rather
  ##   than doing the work and discovering at save time that it may not.
  ##   Reading commands take no lease at all, so `geist list` never blocks
  ##   a running daemon or a live application.
  var
    sp = storePaths(o)
    c: GeistConfig = default(GeistConfig)
  try:
    # An unnamed preset means "whatever configs/default.toml says", which is the
    # library default when there is no such file.
    c = if o.preset == "app": defaultGeistConfig()
        else: applyDefaults(geistConfigPreset(o.preset), geistDefaults())
  except ValueError as exc:
    fail(exc.msg)
  result = openSessionWithSchema(sp.dir, sp.name, schema, c,
    resolvePassword(o), readOnly = not forWriting)
  if forWriting and result.readOnly:
    fail(result.writeRefusal())
  if result.recoveredFrom != 0'u64:
    stderr.writeLine("geist: generation " & $result.recoveredFrom &
      " would not read back; using generation " & $result.generation)

template writing(o: Options, db, body: untyped) =
  ## o: options for the command.
  ## db: the name the body reads the open session under.
  ## body: the change itself.
  ##
  ## Every modifying command has the same frame around it -- open with the
  ## write lease, do the one thing, save, close -- and only the middle
  ## differs. A save that fails STOPS the command: a CLI that printed
  ## "updated" for a change still in memory would be lying to a script.
  ##
  ## `fail` inside the body quits without reaching the close. That is safe:
  ## the lease releases itself on exit (see lease.nim), and nothing was
  ## saved, so nothing is half-written.
  var
    db {.inject.}: Session = openDirect(o, forWriting = true)
    saved: tuple[ok: bool, err: string] = (false, "")
  body
  saved = db.save()
  if not saved.ok:
    fail(saved.err)
  db.close()

## ------------------------------ output ------------------------------

proc emitRows(s: Schema, R: seq[Row], asJson: bool,
    at: seq[int] = @[], transposed: bool = false) {.role: helper,
    tag: "cli|formatting|status".} =
  ## s/R: schema and rows. Rows are self-contained, so no context is needed
  ## to render them.
  ## asJson: machine-readable output instead of an aligned table.
  ## at: each row's position in the visible list, shown as an `@` column.
  ##   That column is what a person types back: an id carries a node tag
  ##   and runs to twenty digits, and `set @2` is something fingers can do.
  ##   `@` rather than `#` because `#` starts a comment in every shell.
  ## transposed: one line per FIELD instead of one line per row.
  ##
  ## The table itself is drawn by `geist/show`, which is library code: a
  ## person with a Session in hand and a question about it should not have
  ## to shell out to this program to see an answer. What stays here is the
  ## CLI's own choice of style -- `--limit` has already decided how many
  ## rows there are to draw, so nothing is elided a second time.
  var
    style: ShowStyle = everything()
  if asJson:
    stdout.write showJson(s, R)
    return
  style.maxCellWidth = 42
  style.positions = at.len > 0
  if transposed:
    stdout.write showTransposed(s, R, style, at)
  else:
    stdout.write showTable(s, R, style, at)

proc resolveRowRef(db: Session, arg: string): RowId {.role: parser,
    tag: "cli|db|parsing|read".} =
  ## db/arg: a row named either way a person might name it.
  ##
  ##   @2            the third row of the visible list, as `list` shows it
  ##   1234567890    the id itself, as another machine would use it
  ##
  ## Positions are resolved against the list AS IT IS NOW, so they are
  ## fine for a person at a terminal and wrong for a script that stored one
  ## yesterday. Ids are for that.
  var
    pos: int = 0
  if arg.startsWith("@") or arg.startsWith("#"):
    try:
      pos = parseInt(arg[1 .. ^1])
    except ValueError:
      fail("'" & arg & "' is not a position; write @0, @1, ...")
    if pos < 0 or uint32(pos) >= db.entryCount():
      fail("position " & $pos & " is out of range (" & $db.entryCount() &
        " visible rows)")
    return db.idAt(uint32(pos))
  try:
    result = RowId(parseBiggestUInt(arg))
  except ValueError:
    fail("'" & arg & "' is neither a row id nor an @position")

## --------------------------- direct commands ------------------------

proc cmdInspect(o: Options) {.role: actor,
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

proc cmdSchema(o: Options) {.role: actor,
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

proc cmdInit(o: Options) {.role: actor,
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
  echo "created ", storePaths(o).dir, " with preset '", o.preset, "'"
  echo "schema: ", describeSchema(parsed.s)

proc cmdPut(o: Options) {.role: actor,
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

proc rowValues(s: Schema, A: openArray[uint8]): Table[string, string] {.
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

proc cmdSet(o: Options) {.role: actor,
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

proc cmdDelete(o: Options) {.role: actor,
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


proc cmdTranspose(o: Options) {.role: actor,
    tag: "cli|db|status|write".} =
  ## o: report the column copy's state, and rebuild it unless only asked.
  ##
  ## One command for both questions, because they are the same question:
  ## an operator who runs this wants the copy to be current, and wants to
  ## be told whether it already was.
  var
    db: Session = default(Session)
    state: tuple[state: TransposeState, live: uint64, built: uint64,
      path: string]
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
proc cmdSweep(o: Options) {.role: actor,
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

proc cmdCompact(o: Options) {.role: actor,
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

proc cmdList(o: Options) {.role: actor,
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

proc cmdGet(o: Options) {.role: actor,
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

proc findInCopy(db: Session, t: TransposedFile, o: Options,
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

proc findByScan(db: Session, o: Options, R: var seq[Row],
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

proc cmdFind(o: Options) {.role: actor,
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

proc cmdInfo(o: Options) {.role: actor,
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
  echo "cipher:        ", db.config.cipher, "   mac: ", db.config.mac
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

proc cmdCheckpoint(o: Options) {.role: actor,
    tag: "cli|db|write".} =
  ## o: options whose first argument is the checkpoint message.
  var
    at: uint32 = 0'u32
  writing(o, db):
    at = db.checkpoint(if o.args.len > 0: o.args[0] else: "checkpoint")
    echo "journal row ", at, " appended"

proc cmdBackup(o: Options) {.role: actor,
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

proc cmdRestore(o: Options) {.role: actor,
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

proc cmdRekey(o: Options) {.role: actor,
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

proc cmdKeygen(o: Options) {.role: actor,
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

proc cmdPresets() {.role: actor, tag: "cli|config|read".} =
  ## The public preset catalog.
  for p in geistConfigPresets():
    ## 18, not 16: `secure-collapsed` is 16 characters and would leave
    ## no gap at all before its purpose.
    echo alignLeft(p.name, 18), p.purpose

## --------------------------- remote commands ------------------------

proc remotePut(o: Options, link: var GeistLink) {.role: actor,
    tag: "cli|networkSurface|write".} =
  ## o: options whose trailing arguments are `field=value` pairs.
  ## link: an open session to the daemon.
  ##
  ## The row is built against the DAEMON's schema, which every reply
  ## carries, so a client needs no local copy of the database to add to
  ## it. The id is left at zero: this client has no id space of its own,
  ## so the receiving database names the row and reports what it chose.
  var
    pairs: tuple[ok: bool, values: Table[string, string], err: string] =
      (false, default(Table[string, string]), "")
    probe: tuple[ok: bool, reply: Reply, err: string] =
      (false, default(Reply), "")
    built: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
    sent: tuple[ok: bool, reply: Reply, err: string] =
      (false, default(Reply), "")
  if o.args.len == 0:
    fail("put needs at least one field=value")
  pairs = parsePairs(o.args)
  if not pairs.ok:
    fail(pairs.err)
  probe = link.send(Query(op: qoFind, limit: 0'u32))
  if not probe.ok:
    fail(probe.err)
  if not probe.reply.ok:
    fail(probe.reply.err)
  built = buildRow(probe.reply.schema, pairs.values)
  if not built.ok:
    fail(built.err)
  sent = link.pushRemote(@[Row(data: built.data)])
  if not sent.ok:
    fail(sent.err)
  if not sent.reply.ok:
    fail(sent.reply.err)
  echo "stored ", sent.reply.matched, " row(s) remotely"

proc connectRemote(o: Options): GeistLink {.role: orchestrator,
    tag: "ame|cli|networkSurface|orchestrator".} =
  ## o: options naming the peer, this side's identity and the peer's pin.
  ##
  ## Both halves of the pinning are required and neither has a default: a
  ## client that would connect without checking the pin is a client that
  ## can be answered by anyone who reaches the port first.
  var
    parsed: tuple[ok: bool, a: GeistDacAddress] =
      (false, default(GeistDacAddress))
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
    peer: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    got: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  parsed = parseDacAddress(o.remote)
  if not parsed.ok:
    fail("--remote must be dac://host:port, got '" & o.remote & "'")
  if o.identity.len == 0 or o.peerPin.len == 0:
    fail("--remote needs --identity and --peer-pin. Pinned trust means " &
      "each side must already know the other's public keys; run `geist " &
      "keygen` on both and exchange the .pin files.")
  mine = loadOrCreateIdentity(o.identity, resolvePassword(o), o.subject,
    geistSignatureSlots())
  if not mine.ok:
    fail(mine.err)
  peer = loadPin(o.peerPin)
  if not peer.ok:
    fail(peer.err)
  got = connectGeist(parsed.a, mine.key, peer.pin, defaultTierPolicy())
  if not got.ok:
    fail("connect failed: " & got.err)
  result = got.link

proc cmdSync(o: Options) {.role: orchestrator, tag: "ame|cli|db|networkSurface|orchestrator|sync|write".} =
  ## o: options naming BOTH a local database (--path) and a peer
  ## (--remote). This is the one command that is neither direct nor remote
  ## but both: it reads there and writes here.
  ##
  ## Catching up is what makes a chain of desktops work. Rows arrive with
  ## the identity the peer stored them under, so a row that started three
  ## desktops away keeps the id it was born with, and this database can be
  ## followed in turn by somebody else.
  var
    link: GeistLink = default(GeistLink)
    db: Session = default(Session)
    caught: tuple[ok: bool, applied: int, rounds: int, cursor: uint64,
      rewound: bool, err: string]
  if o.path.len == 0:
    fail("sync needs --path (the database rows are applied TO) as well as " &
      "--remote (the peer they come FROM)")
  link = connectRemote(o)
  db = openDirect(o, forWriting = true)
  # The default row limit is a display default, and a catch-up is not a
  # display: 20 rows a round would take twenty round trips to move a
  # small database. An explicit --limit still wins.
  caught = needRemote(db, link, o.remote,
    uint32(if o.limit == 20: 256 else: o.limit))
  link.close()
  db.close()
  if not caught.ok:
    fail(caught.err)
  if caught.rewound:
    echo "the peer's log was rewritten since last time, so this caught up " &
      "from the beginning"
  echo "applied ", caught.applied, " row(s) in ", caught.rounds,
    " request(s); now at log position ", caught.cursor

proc runRemote(o: Options, q: Query) {.role: orchestrator,
    tag: "ame|cli|networkSurface|orchestrator".} =
  ## o: options carrying --remote.
  ## q: the same Query the direct path would have run locally.
  var
    got: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
    answer: tuple[ok: bool, reply: Reply, err: string] =
      (false, default(Reply), "")
  got.link = connectRemote(o)
  # `put` is the one command that has to ASK before it can send: the row
  # must be built against the daemon's schema, and only the daemon has it.
  if o.command == "put":
    remotePut(o, got.link)
    got.link.close()
    return
  answer = got.link.send(q)
  got.link.close()
  if not answer.ok:
    fail("request failed: " & answer.err)
  if not answer.reply.ok:
    fail(answer.reply.err)
  if q.op == qoDelete:
    echo "deleted row id ", q.cursor
    return
  emitRows(answer.reply.schema, answer.reply.rows, o.json)
  if not o.json:
    echo ""
    echo answer.reply.rows.len, " row(s), ", answer.reply.matched, " matched"

proc remoteQuery(o: Options): Query {.role: truthBuilder,
    tag: "cli|networkSurface|parsing".} =
  ## o: options translated into the Query a daemon can answer.
  result.limit = uint32(o.limit)
  case o.command
  of "list":
    result.op = qoFind
  of "get":
    if o.args.len == 0:
      fail("get needs a row index")
    result.op = qoGet
    result.cursor = uint64(parseInt(o.args[0]))
  of "find":
    if o.args.len < 2:
      fail("find needs a field and a value")
    result.op = qoFind
    result.where = @[Predicate(field: o.args[0], text: o.args[1],
      isText: true)]
  of "info", "inspect", "schema":
    result.op = qoSync
  of "put":
    # Built later, against the schema the daemon reports. This placeholder
    # is never sent.
    result.op = qoFind
    result.limit = 0'u32
  of "delete", "del", "rm":
    if o.args.len == 0:
      fail("delete needs a row id")
    result.op = qoDelete
    try:
      result.cursor = parseBiggestUInt(o.args[0])
    except ValueError:
      fail("a remote delete needs the row ID, not an @position: the " &
        "positions `list` shows are this terminal's, and the row may have " &
        "moved by the time the daemon reads them")
  else:
    fail("command '" & o.command & "' is direct-only; it needs --path. " &
      "Commands that need the password or rewrite local files are never " &
      "sent to a daemon.")


## ------------------------------ entry -------------------------------

proc dispatchCli(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name.
  var
    o: Options = default(Options)
  o = parseOptions(argv)
  if o.command.len == 0 or o.command == "help":
    echo usageText
    return 0
  # A userconfig.toml fills in what was not typed, and nothing more.
  o = withUserConfig(o)
  # configs/default.toml carries the library defaults every preset is adjusted by.
  var defaults = initGeistNetworkDefaults()
  if not defaults.ok:
    fail(defaults.err)
  if o.command == "presets":
    cmdPresets()
    return 0
  if o.command == "keygen":
    cmdKeygen(o)
    return 0
  # `sync` is the one command that is BOTH: it reads a peer and writes this
  # database, so it belongs to neither dispatch and is answered before the
  # mode decides anything.
  if o.command == "sync":
    cmdSync(o)
    return 0
  if o.mode == mRemote:
    runRemote(o, remoteQuery(o))
    return 0
  case o.command
  of "inspect": cmdInspect(o)
  of "schema": cmdSchema(o)
  of "info": cmdInfo(o)
  of "init": cmdInit(o)
  of "put": cmdPut(o)
  of "set": cmdSet(o)
  of "delete", "del", "rm": cmdDelete(o)
  of "compact": cmdCompact(o)
  of "sweep": cmdSweep(o)
  of "transpose": cmdTranspose(o)
  of "get": cmdGet(o)
  of "list": cmdList(o)
  of "find": cmdFind(o)
  of "checkpoint": cmdCheckpoint(o)
  of "backup": cmdBackup(o)
  of "restore": cmdRestore(o)
  of "rekey": cmdRekey(o)
  else:
    fail("unknown command '" & o.command & "'; try `geist help`")
  result = 0

proc runGeistCli*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name -> the exit code.
  ##
  ##   dispatchCli  ->  0                  the command did its job
  ##                ->  GeistCliFailure    "geist: <why>" on stderr, 1
  try:
    result = dispatchCli(argv)
  except GeistCliFailure as e:
    stderr.writeLine("geist: " & e.msg)
    result = 1

when isMainModule:
  quit(runGeistCli(commandLineParams()))
