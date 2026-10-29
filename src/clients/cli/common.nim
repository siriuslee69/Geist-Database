## ---------------------------------------------------------------------
## geist cli <- options, settings, opening a store, printing rows
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point and says how the parts fit:
##
##   common    options, userconfig, opening a store, printing rows
##   direct    commands that open the files in this process (--path)
##   keys      the symmetric keys in the key folder (`geist keys ...`)
##   tables    export and import: the database as a JSON or TOML file
##   sidecars  track, folder and storage: the files beside a database
##
## Network options (--remote, --hop, --identity, --peer-pin, ...) are NOT
## here. They belong to nebel, which strips them from the command line
## and hands the rest to `parseOptions` below.

import std/[os, strutils]

import runePragmas
import ../../geist/args
import ../../geist/storage
import ../../geist

type
  Options* {.role: truthState, tag: "cli|parsing|types".} = object of RootObj
    ## Exported so option precedence can be tested without spawning a
    ## process. Nothing else imports this.
    ##
    ## given: the long option names ACTUALLY TYPED, which is the only way
    ##   to tell `--preset app` from a `preset` nobody mentioned. Several
    ##   of these fields have non-empty defaults, so their value cannot
    ##   answer that question -- and a config file silently winning over
    ##   something visible on the command line is the failure this exists
    ##   to prevent.
    path*: string
    password*: string
    passwordFile*: string
    preset*: string
    schemaSpec*: string
    typeName*: string
    limit*: int
    slot*: int
    keysDir*: string
    words*: string
    kind*: string
    showSecret*: bool
    json*: bool
    ## transposed: show the answer with the axes swapped -- one line per
    ##   field. What the column copy looks like, and the shape that fits a
    ##   terminal when the schema is wide and the answer is short.
    transposed*: bool
    ## seal/sealKey/sealPasswordFile/binary/freshIds: `export` and
    ##   `import` only. Which columns are sealed, by a symmetric key from
    ##   the key folder or by a password; how bytes are written; whether
    ##   imported rows get new ids.
    seal*: string
    sealKey*: string
    sealPasswordFile*: string
    binary*: string
    freshIds*: bool
    ## sidecars/storage/storagePolicy: this run's values for the runtime settings
    ##   of the same names (`--sidecars on|off`, `--storage a,b`,
    ##   `--storage-policy priority|speed`). Empty: the [default] value stands.
    sidecars*: string
    storage*: string
    storagePolicy*: string
    ## megabytes: the size of the write `storage bench` measures (`--mb`).
    megabytes*: int
    ## top/suffix: `track` only the files directly in a folder (`--top`), and only
    ##   names that end with suffix (`--suffix .txt`).
    top*: bool
    suffix*: string
    config*: string
    args*: seq[string]
    command*: string
    given*: seq[string]

const
  usageText* = """
geist <command> [options]

  --path <dir>            operate on a database directory
  --password <text>       at-rest password (prefer --password-file)
  --password-file <file>  read the password from a file
  --preset <name>         config preset, default: [storage] preset in configs/default.toml
  --schema "a:int,b:text" field list, only for `init`
  --type <name>           object type label for `init`
  --limit <n>             maximum rows, default 20
  --slot <n>              backup slot for `restore`, default 1
  --keys <dir>            key folder for `keys`
  --words "w1 w2 ..."     words for `keys import`
  --kind sym              what `keys import` rebuilds
  --secret                `keys show` also prints the secret words
  --json                  machine-readable output
  --transposed            show the answer with the axes swapped: one line
                          per field instead of one line per row
  --seal "a,b"            `export`: encrypt these columns, value by value
  --seal-key <name>       `export`/`import`: the symmetric key that seals
                          and opens them, from the key folder (--keys;
                          opened with --password, like `keys`)
  --seal-password-file <file>  ... or a password instead of a key
  --binary hex|escaped    `export`: how bytes and sealed values are written,
                          "486900ff" or "Hi\u0000ÿ"; default hex
  --fresh-ids             `import`: new ids instead of the file's
  --sidecars on|off       this run only: values may (on) or may not (off) leave
                          their rows; overrides [default] sidecars
  --storage "a,b"         this run only: folders for sidecar payloads, preferred
                          first; overrides [default] storage
  --storage-policy priority|speed  this run only; overrides [default] storagePolicy
  --mb <n>                `storage bench`: megabytes written and read, default 16
  --top                   `track`: only the files directly in the folder
  --suffix <text>         `track`: only names that end with this, e.g. .txt
  --config <file>         userconfig.toml to read; defaults to the one in
                          the working directory, then ~/.config/geist

commands
  inspect                 header + cluster index; no password needed
  verify                  check every sealed batch's integrity digest; no
                          password needed. Proves the bytes are the ones
                          written, not who wrote them (the password check
                          on opening does that)
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
  checkpoint <message>    append a hash-chained journal row
  backup                  force a rotation now
  restore                 restore from --slot
  rekey                   re-key every batch at its epoch high-water mark
  keys <what> [name]      the symmetric keys in the key folder (--keys,
                          default ~/.config/geist/keys):
                            list                 every key in the folder
                            new-sym <name>       32-byte symmetric key
                            show [name|number]   the 24 words with --secret
                            import <name> --kind sym [--words "..."]
                            drop <name|number>
                          Signing pairs and peer pins are nebel's:
                          `nebel keys ...`.
  convert <in> <out>      JSON <-> TOML by file extension; refuses what
                          the target format cannot hold, naming where
  export <file>           every visible row to a .json or .toml file;
                          --transposed writes one list per column instead
                          of one block per row
  import <file>           the rows of such a file back in; creates the
                          database from the file's schema when there is
                          none. A row keeps the file's id, so importing
                          twice replaces rather than doubles
  track <file|folder>     reference a file or a folder where it lies, without
                          writing it: one row per file with its name, path,
                          size and a reference. The database needs the columns
                          name:text,path:text,size:int,file:ref
                          (make it with: init --schema "name:text,path:text,
                          size:int,file:ref"). A changed file is refused when
                          it is read, and the row says so.
  folder show <dir>       force read: the folder's files and every database's
                          rows, as text or with --json. No checks, no writes
  folder adopt <dir>      give a folder without files its two files, so Geist
                          reads and writes it. Refused when it has files
  storage list            the drives found, and the storage folders in use,
                          with their free space and recorded speed
  storage bench <dir>     measure write and read speed in <dir> (--mb), and
                          record it in the folder, so the speed policy can use it
  presets                 list configuration presets
  help                    this text
"""

type
  GeistCliFailure* = object of CatchableError
    ## One operator-facing error. `fail` raises it and `runGeistCli` prints
    ## it and returns 1, so a command several calls deep can end the RUN
    ## without ending the PROCESS -- a test, or a program embedding the
    ## CLI, keeps going.

proc fail*(msg: string) {.noreturn, role: helper, stage: stDone,
    tag: "cli|status".} =
  ## msg: operator-facing error; `runGeistCli` writes it to stderr and
  ## exits non-zero.
  raise newException(GeistCliFailure, msg)

proc resolvePassword*(o: Options): string {.role: sanitizer,
    tag: "cli|cryptoBoundary|parsing".} =
  ## o: parsed options. A password file wins over an inline password,
  ## because the inline form is visible in the process list.
  if o.passwordFile.len > 0:
    if not fileExists(o.passwordFile):
      fail("no password file at " & o.passwordFile)
    return readFile(o.passwordFile).strip()
  result = o.password

const
  cliFlags*: array[8, string] = ["json", "transposed", "t", "help", "h",
    "secret", "fresh-ids", "top"]
    ## The options that take NO value; every other option takes one.

proc addWord*(o: var Options, word: string) {.role: truthBuilder, inline,
    tag: "cli|parsing".} =
  ## o/word: the first bare word is the command, the rest its arguments.
  if o.command.len == 0:
    o.command = word
  else:
    o.args.add word

proc parseOptions*(argv: openArray[string]): Options {.role: parser,
    tag: "cli|parsing|read".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    step: OptionStep = ("", "", false, 0)
  result.preset = ""   # "" = whatever configs/default.toml names
  result.limit = 20
  result.slot = 1
  result.megabytes = 16
  while i < argv.len:
    try:
      step = nextOption(argv, i, cliFlags)
    except ValueError as exc:
      fail(exc.msg)
    i = step.last
    if step.bare:
      result.addWord(step.value)
      i = i + 1
      continue
    key = step.key
    value = step.value
    case key
    of "path": result.path = value
    of "password": result.password = value
    of "password-file": result.passwordFile = value
    of "preset": result.preset = value
    of "schema": result.schemaSpec = value
    of "type": result.typeName = value
    of "limit": result.limit = parseInt(value)
    of "slot": result.slot = parseInt(value)
    of "keys": result.keysDir = value
    of "words": result.words = value
    of "kind": result.kind = value
    of "secret": result.showSecret = true
    of "json": result.json = true
    of "transposed", "t": result.transposed = true
    of "seal": result.seal = value
    of "seal-key": result.sealKey = value
    of "seal-password-file": result.sealPasswordFile = value
    of "binary": result.binary = value
    of "fresh-ids": result.freshIds = true
    of "sidecars": result.sidecars = value
    of "storage": result.storage = value
    of "storage-policy": result.storagePolicy = value
    of "mb": result.megabytes = parseInt(value)
    of "top": result.top = true
    of "suffix": result.suffix = value
    of "config": result.config = value
    of "help", "h": result.command = "help"
    else: fail("unknown option --" & key)
    result.given.add key
    i = i + 1

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

proc storePaths*(o: Options): tuple[dir, name: string] {.role: parser,
    tag: "cli|parsing|storageIo".} =
  ## o: options whose --path is split into a store root and a stem.
  if o.path.len == 0:
    fail("--path is required")
  result.dir = o.path
  result.name = "main"
  if o.path.splitFile().ext.len > 0:
    result.dir = o.path.parentDir()
    result.name = o.path.splitFile().name

proc livePath*(o: Options): string {.role: parser,
    tag: "cli|read|storageIo".} =
  ## o: options resolved to the current generation's data file, through the
  ## manifest -- every save publishes a new one, so the name is never fixed.
  var
    sp = storePaths(o)
  result = liveDataPath(sp.dir, sp.name)

proc onOffOf*(word: string): bool {.role: parser, tag: "cli|parsing".} =
  ## word: "on" or "off". Anything else is refused by name, so a typo cannot pass
  ## for off.
  case word
  of "on":
    result = true
  of "off":
    result = false
  else:
    fail("--sidecars takes on or off, got '" & word & "'")

proc policyOf*(word: string): StoragePolicy {.role: parser, tag: "cli|parsing".} =
  ## word: "priority" or "speed". Anything else is refused by name.
  case word
  of "priority":
    result = spPriority
  of "speed":
    result = spSpeed
  else:
    fail("--storage-policy takes priority or speed, got '" & word & "'")

proc listOf*(text: string): seq[string] {.role: parser, tag: "cli|parsing".} =
  ## text: comma-separated values. Blanks are dropped: "a, b,,c" gives a, b, c.
  for part in text.split(','):
    if part.strip().len > 0:
      result.add part.strip()

proc withRunOptions*(o: Options, c: GeistConfig): GeistConfig {.role: configurator,
    tag: "cli|config|parsing".} =
  ## o/c: the configuration with this run's typed options put over it. An option
  ## that was not typed leaves its value in c as it is.
  result = c
  if o.sidecars.len > 0:
    result.sidecars = onOffOf(o.sidecars)
    if result.sidecars and not sidecarsCompiled:
      fail("this build has sidecars compiled out, so --sidecars on has no effect; " &
        "build with [define] sidecars = true")
  if o.storage.len > 0:
    result.storagePaths = listOf(o.storage)
  if o.storagePolicy.len > 0:
    result.storagePolicy = policyOf(o.storagePolicy)

proc openDirect*(o: Options, schema: Schema = Schema(),
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
    c = if o.preset.len == 0: defaultGeistConfig()
        else: applyDefaults(geistConfigPreset(o.preset), geistDefaults())
  except ValueError as exc:
    fail(exc.msg)
  c = withRunOptions(o, c)
  result = openSessionWithSchema(sp.dir, sp.name, schema, c,
    resolvePassword(o), readOnly = not forWriting)
  if forWriting and result.readOnly:
    fail(result.writeRefusal())
  if result.recoveredFrom != 0'u64:
    stderr.writeLine("geist: generation " & $result.recoveredFrom &
      " would not read back; using generation " & $result.generation)

template writing*(o: Options, db, body: untyped) {.role: orchestrator.} =
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

proc emitRows*(s: Schema, R: seq[Row], asJson: bool,
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

proc resolveRowRef*(db: Session, arg: string): RowId {.role: parser,
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

