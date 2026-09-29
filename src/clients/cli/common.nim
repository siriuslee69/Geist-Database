## ---------------------------------------------------------------------
## geist cli <- options, settings, opening a store, printing rows
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point and says how the parts fit:
##
##   common   options, userconfig, opening a store, printing rows
##   direct   commands that open the files in this process (--path)
##   remote   commands sent to a running geistd (--remote), and sync

import std/[os, strutils]

import runePragmas
import ../../geist/args
import ../../geist/network

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
  usageText* = """
geist <command> [options]

  --path <dir>            operate directly on a database directory
  --remote dac://host:port  operate through a running geistd
  --password <text>       at-rest password (prefer --password-file)
  --password-file <file>  read the password from a file
  --preset <name>         config preset, default: [storage] preset in configs/default.toml
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
  convert <in> <out>      JSON <-> TOML by file extension; refuses what
                          the target format cannot hold, naming where
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
  cliFlags*: array[5, string] = ["json", "transposed", "t", "help", "h"]
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
  result.subject = "geist-cli"
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

proc storePaths*(o: Options): tuple[dir, name: string] {.role: parser,
    tag: "cli|parsing|storageIo".} =
  ## o: options whose --path is split into a store root and a stem.
  if o.path.len == 0:
    fail("--path or --remote is required")
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

