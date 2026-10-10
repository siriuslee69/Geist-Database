## ---------------------------------------------------------------------
## Session table <- an open database written to, and read from, a file
## ---------------------------------------------------------------------
##
##   db.exportTable("notes.toml")              every visible row, as TOML
##   db.exportTable("notes.json", style, key)  JSON, some columns sealed
##   db.importTable("notes.toml")              the rows back in
##
##   the store  --visible rows--> tableText  --> notes.toml / notes.json
##   notes.*    --readTableFile--> TextTable --buildRow--> putRow --> store
##
## The file layout -- rows or columns, hex or escaped bytes, sealed
## columns -- is ./tabletext's; this is only the part that needs a Session.
##
## WHAT AN IMPORT DOES WITH IDS. A row keeps the id the file gives it, so
## importing the same file twice REPLACES those rows instead of doubling
## them, and a file exported here and imported elsewhere keeps its rows'
## names. `freshIds = true` gives every row a new id instead -- for adding
## the rows of a file as new ones, next to what is there.
##
##   file __rowId    target has ids    freshIds    stored as
##   ------------    --------------    --------    ---------------------
##   "17"            yes               false       row 17 (new or replaced)
##   "17"            yes               true        the next free id
##   (no column)     yes               either      the next free id
##   any             no                either      appended, no id
##
## AN IMPORT IS ALL OR NOTHING. Every row is built once BEFORE anything is
## stored, so a bad cell in row 900 stops the import with nothing written,
## instead of leaving 899 rows of a half-read file behind.
##
## Part of the Session; see ./session for how the parts fit.

import runePragmas
import ./types
import ./dynamic
import ./secret
import ./doc
import ./tabletext
import ./tableread
import ./sessioncore
import ./sessionview

export tabletext, tableread

## ------------------------------ export ------------------------------

proc visibleRows*(s: Session): seq[Row] {.role: dataFetcher,
    tag: "appApi|db|read".} =
  ## s: every visible row, in list order -- what `geist list` shows.
  var
    i: uint32 = 0'u32
  while i < s.entryCount():
    result.add s.visibleRow(i)
    i = i + 1'u32

proc writeTable(path: string, t: tuple[ok: bool, text: string,
    err: string]): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "db|storageIo|write".} =
  ## path/t: the rendered file, written -- or why it was not.
  if not t.ok:
    return (false, t.err)
  try:
    writeFile(path, t.text)
    result = (true, "")
  except IOError as exc:
    result = (false, path & ": " & exc.msg)

proc styledFor(path: string, style: TableTextStyle): TableTextStyle {.
    role: configurator, inline, tag: "db|config".} =
  ## path/style: the style with its format taken from the file name.
  result = style
  result.format = formatOf(path)

proc exportTable*[K: Secret | string](s: Session, path: string,
    style: TableTextStyle, sealer: K): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|cryptoBoundary|db|storageIo|write".} =
  ## s: the open database.
  ## path: where to write; `.json` is JSON, anything else TOML.
  ## style: shape, binary form and the columns to seal.
  ## sealer: what seals `style.sealed` -- a key (`newSealKey`, or one from
  ##   `geist keys new-sym`) or a password, whose salt the file keeps.
  result = writeTable(path, tableText(s.entries.schema, s.visibleRows(),
    styledFor(path, style), sealer, s.sidecarStore))

proc exportTable*(s: Session, path: string,
    style: TableTextStyle = defaultTableTextStyle()): tuple[ok: bool,
    err: string] {.role: orchestrator,
    tag: "appApi|db|storageIo|write".} =
  ## s/path/style: as above, nothing sealed.
  result = s.exportTable(path, style, initSecret([]))

## ------------------------------ import ------------------------------

proc fitProblem(t: TextTable, target: Schema): string {.role: sanitizer,
    tag: "db|read".} =
  ## t/target: a field of the file the database has no column for.
  var
    j: int = 0
    name: string = ""
  while j < t.schema.slots.len:
    name = t.schema.nameOf(t.schema.slots[j].nameId)
    if not t.schema.isIdSlot(j) and target.slotIndex(name) < 0:
      return "the file has a field '" & name & "' this database does " &
        "not (" & describeSchema(target) & ")"
    j = j + 1

proc identityFor(S: var Session, t: TextTable, i: int,
    freshIds: bool): tuple[id: RowId, flags: uint64] {.role: actor,
    tag: "db|write".} =
  ## S/t/i: the id and flags row i is stored under (see the table above).
  ## freshIds: ignore the file's ids.
  if not S.hasIdentity():
    return (0'u64, 0'u64)
  result = t.cellIdentity(i)
  if freshIds or result.id == 0'u64:
    result.id = S.nextIdFor()

proc checkRows(S: Session, t: TextTable): string {.role: sanitizer,
    tag: "db|read".} =
  ## S/t: every row built once with a stand-in id, so that a cell the
  ## database refuses -- "abc" for an int -- is found before anything is
  ## stored. Returns the first refusal, or nothing.
  var
    built: tuple[ok: bool, data: ByteSeq, err: string] = (true, @[], "")
    i: int = 0
  while i < t.cells.len:
    built = buildRow(S.entries.schema, t.cellValues(i), S.sidecarStore,
      1'u64, 0'u64)
    if not built.ok:
      return "row " & $i & ": " & built.err
    i = i + 1

proc storeRows(S: var Session, t: TextTable, freshIds: bool): int {.
    role: dataWriter, tag: "db|write".} =
  ## S/t/freshIds: every row stored; returns how many. Raises only on what
  ## `checkRows` cannot see in advance: a full disk, a read-only session.
  var
    ident: tuple[id: RowId, flags: uint64] = (0'u64, 0'u64)
    built: tuple[ok: bool, data: ByteSeq, err: string] = (true, @[], "")
  while result < t.cells.len:
    ident = S.identityFor(t, result, freshIds)
    built = buildRow(S.entries.schema, t.cellValues(result),
      S.sidecarStore, ident.id, ident.flags)
    discard S.putRow(Row(data: built.data))
    result = result + 1

proc importRows*(S: var Session, t: TextTable,
    freshIds: bool = false): tuple[ok: bool, added: int, err: string] {.
    role: orchestrator, tag: "appApi|db|write".} =
  ## S: the open database, writable.
  ## t: a table file already read (`readTableFile`).
  ## freshIds: new ids for every row instead of the file's.
  ##
  ## Stores in memory, like `put`; `save` (or the write policy) makes it
  ## durable.
  var
    refused: string = fitProblem(t, S.entries.schema)
  if refused.len == 0:
    refused = S.checkRows(t)
  if refused.len > 0:
    return (false, 0, refused)
  try:
    result = (true, S.storeRows(t, freshIds), "")
  except CatchableError as exc:
    result = (false, 0, exc.msg)

proc importTable*[K: Secret | string](S: var Session, path: string,
    sealer: K, freshIds: bool = false): tuple[ok: bool, added: int,
    err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|storageIo|write".} =
  ## S/path: the database, and a .json or .toml table file.
  ## sealer: the key or password that opens the file's sealed columns.
  ## freshIds: see the table at the top.
  var
    got: tuple[ok: bool, t: TextTable, err: string] =
      readTableFile(path, sealer)
  if not got.ok:
    return (false, 0, got.err)
  result = S.importRows(got.t, freshIds)

proc importTable*(S: var Session, path: string,
    freshIds: bool = false): tuple[ok: bool, added: int, err: string] {.
    role: orchestrator, tag: "appApi|db|storageIo|write".} =
  ## S/path/freshIds: as above, nothing sealed.
  result = S.importTable(path, initSecret([]), freshIds)
