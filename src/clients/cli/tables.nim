## ---------------------------------------------------------------------
## geist cli <- export and import: a database as a JSON or TOML file
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point and says how the parts fit.
##
##   geist --path data/notes export notes.toml
##   geist --path data/notes export notes.json --transposed
##   geist --path data/notes export notes.toml --seal body \
##         --seal-key notes --binary escaped
##   geist --path data/copy  import notes.toml --seal-key notes
##
## The file layout is the library's (src/geist/tabletext.nim); this part
## only turns options into a style and picks the key.
##
##   what seals / opens        option
##   ------------------------  ---------------------------------------
##   nothing                   (none)
##   a symmetric key           --seal-key <name>   from `geist keys new-sym`
##   a password                --seal-password-file <file>

import std/[strutils, os]

import runePragmas
import ../../geist/network
import ../../geist/keyfolder
import ./common
import ./keys

proc tableStyleOf(o: Options): TableTextStyle {.role: parser,
    tag: "cli|parsing".} =
  ## o: --transposed, --binary and --seal as a style. The format follows
  ## the file name later.
  var
    binary: tuple[ok: bool, value: BinaryForm] =
      wordOf(if o.binary.len > 0: o.binary else: "hex", binaryWords)
  if not binary.ok:
    fail("--binary takes hex or escaped, not '" & o.binary & "'")
  result = defaultTableTextStyle()
  result.shape = if o.transposed: shColumns else: shRows
  result.binary = binary.value
  for name in o.seal.split(','):
    if name.strip().len > 0:
      result.sealed.add name.strip()

proc sealPassword(o: Options): string {.role: sanitizer,
    tag: "cli|cryptoBoundary|parsing".} =
  ## o: the password in --seal-password-file. A file and never an option,
  ## because an option is visible in the process list.
  if not fileExists(o.sealPasswordFile):
    fail("no password file at " & o.sealPasswordFile)
  result = readFile(o.sealPasswordFile).strip()

proc sealKeyOf(o: Options): KeyResult {.role: dataFetcher,
    tag: "cli|cryptoBoundary|read".} =
  ## o: the symmetric key named by --seal-key, from the key folder.
  result = openKeyFolder(keysDirOf(o), resolvePassword(o)).symmetricKey(
    o.sealKey)
  if not result.ok:
    fail("--seal-key " & o.sealKey & ": " & result.err)

proc exportedBy(o: Options, db: Session, path: string,
    style: TableTextStyle): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "cli|cryptoBoundary|db|write".} =
  ## o/db/path/style: the export, sealed the way the options say.
  if o.sealPasswordFile.len > 0:
    return db.exportTable(path, style, sealPassword(o))
  if o.sealKey.len > 0:
    return db.exportTable(path, style, sealKeyOf(o).value)
  result = db.exportTable(path, style)

proc readBy(o: Options, path: string): tuple[ok: bool, t: TextTable,
    err: string] {.role: orchestrator, tag: "cli|cryptoBoundary|read".} =
  ## o/path: the file read, opened the way the options say.
  if o.sealPasswordFile.len > 0:
    return readTableFile(path, sealPassword(o))
  if o.sealKey.len > 0:
    return readTableFile(path, sealKeyOf(o).value)
  result = readTableFile(path)

proc cmdExport*(o: Options) {.role: actor,
    tag: "cli|db|storageIo|write".} =
  ## o: options with one file argument; .json is JSON, anything else TOML.
  var
    db: Session = default(Session)
    done: tuple[ok: bool, err: string] = (false, "")
    count: uint32 = 0'u32
  if o.args.len != 1:
    fail("export needs one file: geist export notes.toml")
  db = openDirect(o)
  done = exportedBy(o, db, o.args[0], tableStyleOf(o))
  count = db.entryCount()
  db.close()
  if not done.ok:
    fail(done.err)
  echo "wrote ", count, " rows to ", o.args[0]

proc cmdImport*(o: Options) {.role: actor,
    tag: "cli|db|storageIo|write".} =
  ## o: options with one file argument. A database that does not exist yet
  ## is created from the file's own schema.
  var
    got: tuple[ok: bool, t: TextTable, err: string] =
      (false, TextTable(), "")
    done: tuple[ok: bool, added: int, err: string] = (false, 0, "")
    saved: tuple[ok: bool, err: string] = (false, "")
    db: Session = default(Session)
  if o.args.len != 1:
    fail("import needs one file: geist import notes.toml")
  got = readBy(o, o.args[0])
  if not got.ok:
    fail(got.err)
  db = openDirect(o, withoutIdentity(got.t.schema), forWriting = true)
  done = db.importRows(got.t, o.freshIds)
  if not done.ok:
    fail(done.err)
  saved = db.save()
  if not saved.ok:
    fail(saved.err)
  db.close()
  echo "imported ", done.added, " rows from ", o.args[0]
