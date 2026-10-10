## ---------------------------------------------------------------------
## Table text <- a whole table as a JSON or TOML file, and back
## ---------------------------------------------------------------------
##
##   schema + rows --tableText-------> text a person can open and edit
##   text          --readTableText---> schema + every cell as plain text
##
## The store packs rows into bytes only Geist can read. This module writes
## the same rows as an ordinary file -- to hand them to another program, to
## keep a copy in git, to fix one value in an editor and read it back.
##
## Def. 1  SHAPE. Which way round the table is written.
##
##   shRows      one block per ROW            (what `geist list` shows)
##   shColumns   one list per COLUMN          the table turned on its side,
##                                            like `--transposed`
##
##   rows, TOML                        columns, TOML
##   ----------                        -------------
##   [[rows]]                          [columns]
##   __rowId = "1"                     __rowId = ["1", "2"]
##   title = "first"                   title = ["first", "second"]
##                                     body = ["aa", "bb"]
##   [[rows]]
##   __rowId = "2"
##   title = "second"
##
##   rows, JSON                        columns, JSON
##   ----------                        -------------
##   "rows": [                         "columns": {
##     {"__rowId": "1", "title": ..},    "__rowId": ["1", "2"],
##     {"__rowId": "2", "title": ..}     "title": ["first", "second"]
##   ]                                 }
##
## Def. 2  BINARY FORM. JSON and TOML hold TEXT, not bytes. A `bytes`
## column, and every SEALED value (Def. 3), is a run of bytes from 00 to
## FF, so it has to be written in one of two ways:
##
##   bytes 48 69 00 FF
##   bfHex        "486900ff"          two letters per byte; safe anywhere
##   bfEscaped    "Hi\u0000ÿ"    a readable byte stays itself, every
##                                    other one becomes \u00HH
##
## `\u00HH` is the escape JSON and TOML both already know. A reader that
## knows nothing about Geist decodes it into the character U+00HH, and
## Geist turns each such character back into the byte HH. A character
## above U+00FF in an escaped field is therefore an error, not a byte.
##
## Def. 3  SEALED COLUMN. A column whose values are encrypted one by one
## before they are written, with `sealWithKey` (./secrets):
##
##   "hello"  --seal(key, context = "geist-table/body")-->  GSK1 | nonce |
##                                                          tag | ciphertext
##            --binary form (Def. 2)-->  body = "4753 4b31 ..."
##
## The context binds the value to its column: a sealed `body` pasted into
## the `title` column will not open there. A sealed value is always the
## plain TEXT of the value (`42`, `1.5`, `hello`), so any column kind can
## be sealed -- except the two identity columns, which a reader needs in
## order to know which row it is reading.
##
## The key is either a `Secret` (a symmetric key, e.g. from `geist keys
## new-sym`), or a password. A password is turned into a key ONCE per file
## with a fresh salt, and the salt is written into the file (`salt = ...`)
## so the same password opens it again.
##
## Def. 4  THE FILE. Header first, then the schema, then the body:
##
##   geist = "table"          what this file is
##   version = 1              the layout of this file
##   type = "Note"            the schema's type name
##   shape = "rows"           Def. 1
##   binary = "hex"           Def. 2
##   collapse = false         the schema's autoCollapse
##   sealed = ["body"]        Def. 3, may be empty
##   salt = "..."             only when a password sealed the file
##
##   [[schema]]               one per column, in slot order
##   name = "title"
##   kind = "text"            int | float | text | bytes | sealed | ref
##   column = "variable"      fixed | capped | variable
##   width = 0                bytes, for fixed and capped columns
##   overflow = "error"       error | truncate
##
## `__rowId` and `__flags` are always written as quoted numbers. An id
## carries the writing node's tag in its high bits, so it can be larger
## than the biggest integer TOML (and many JSON readers) can hold.
##
## RULES WHILE READING, AND WHY.
##
##   a missing cell        is the column's zero ("" or 0), the same as a
##                         collapsed value in the store
##   an unknown field      is an error: a typo in a data file would
##                         otherwise be data silently dropped
##   a wrongly typed cell  is an error, naming row and field
##
## Nothing here raises. Every failure comes back as `err`.

import std/[json, strutils, unicode]

import runePragmas
import ./types
import ./row
import ./sidecar
import ./dynamic
import ./secret
import ./secrets
import ./doc

const
  tableMark* = "table"
    ## The value of `geist = ...` in every table file.
  tableTextVersion* = 1
  sealContext* = "geist-table/"
    ## Prefix of the context a sealed value is bound to; the column name
    ## follows it.

type
  TextShape* {.role: configurator, tag: "db|formatting|types".} = enum
    ## Def. 1. shColumns is the transposed form.
    shRows, shColumns

  BinaryForm* {.role: configurator, tag: "db|formatting|types".} = enum
    ## Def. 2.
    bfHex, bfEscaped

  TableTextStyle* {.role: configurator,
      tag: "appApi|config|db|formatting|types".} = object
    ## format: JSON or TOML. The file functions take it from the extension.
    ## shape/binary: Def. 1 and Def. 2.
    ## sealed: names of the columns to encrypt (Def. 3).
    ## salt: set by the password functions, written to the file. Leave it
    ##   empty when sealing with a key.
    format*: DocFormat
    shape*: TextShape
    binary*: BinaryForm
    sealed*: seq[string]
    salt*: ByteSeq

  TextTable* {.role: truthState, tag: "appApi|db|types",
      expectedCount: [0, 4], lifeCycle: lcJob.} = object
    ## A table file, read. `cells[i][j]` is row i, schema slot j, as PLAIN
    ## text: an int in decimal, a float as Nim writes it, text and bytes as
    ## the bytes themselves -- already unsealed and un-hexed.
    ##
    ##   schema   __rowId  __flags  title    body
    ##   cells    "17"     "0"      "first"  "hello"
    schema*: Schema
    style*: TableTextStyle
    cells*: seq[seq[string]]

  Pairs = seq[tuple[key, lit: string]]
    ## Keys with values already written as JSON/TOML literals.

  TableLayout {.role: truthBuilder, expectedCount: 1,
      lifeCycle: lcScratch.} = object
    ## The file taken apart before it is written: the same pieces serve
    ## both formats, only the punctuation around them differs.
    header: Pairs
    schema: seq[Pairs]
    records: seq[Pairs]
    columns: Pairs

proc defaultTableTextStyle*(): TableTextStyle {.role: configurator,
    tag: "appApi|config|db".} =
  ## TOML, one block per row, bytes as hex, nothing sealed.
  result = TableTextStyle(format: dfToml, shape: shRows, binary: bfHex)

## ------------------------------ words -------------------------------
##
## Every word the file uses for an enum, as a table rather than a routine
## per enum: one list to read, and `wordOf` reads every one of them the
## same way, so a word can never be written one way and read another.

const
  shapeWords*: array[TextShape, string] = ["rows", "columns"]
  binaryWords*: array[BinaryForm, string] = ["hex", "escaped"]
  columnWords*: array[ColumnKind, string] = ["fixed", "capped", "variable"]
  overflowWords*: array[OverflowPolicy, string] = ["error", "truncate"]

proc wordOf*[T: enum](word: string, W: array[T, string]): tuple[ok: bool,
    value: T] {.role: parser, tag: "db|parsing".} =
  ## word/W: the enum value whose word in W is `word`.
  ##
  ##   wordOf("columns", shapeWords)  ->  (true, shColumns)
  ##   wordOf("sideways", shapeWords) ->  (false, shRows)
  for v in T:
    if W[v] == word:
      return (true, v)
  result = (false, default(T))

## ---------------------------- literals ------------------------------

proc escapedByte(b: uint8): string {.role: helper, inline,
    tag: "db|formatting".} =
  ## b: one byte inside an escaped string (Def. 2).
  ##
  ##   0x41 -> A     0x22 -> \"     0x5C -> \\     0x00 -> \u0000
  case char(b)
  of '"': result = "\\\""
  of '\\': result = "\\\\"
  of ' ' .. '!', '#' .. '[', ']' .. '~': result = $char(b)
  else: result = "\\u00" & toHex(int(b), 2).toLowerAscii()

proc binaryLiteral*(A: openArray[uint8], form: BinaryForm): string {.
    role: encryptor, tag: "db|formatting".} =
  ## A/form: bytes as a quoted string, valid in JSON and in TOML.
  ##
  ##   48 69 00 FF   bfHex      "486900ff"
  ##                 bfEscaped  "Hi\u0000ÿ"
  var
    i: int = 0
  result = "\""
  if form == bfHex:
    result.add toHex(bytesText(A)).toLowerAscii()
  while form == bfEscaped and i < A.len:
    result.add escapedByte(A[i])
    i = i + 1
  result.add "\""

proc decodeEscaped(s: string): tuple[ok: bool, data: ByteSeq,
    err: string] {.role: parser, tag: "db|parsing".} =
  ## s: an escaped string as a JSON/TOML reader hands it over -- each
  ## `\u00HH` already turned into the character U+00HH -> the bytes.
  for r in s.runes:
    if int(r) > 0xFF:
      return (false, @[], "character U+" & toHex(int(r), 4) &
        " is not a byte; an escaped field holds only U+0000..U+00FF")
    result.data.add uint8(int(r))
  result.ok = true

proc decodeBinary*(s: string, form: BinaryForm): tuple[ok: bool,
    data: ByteSeq, err: string] {.role: parser, tag: "db|parsing".} =
  ## s/form: the reverse of `binaryLiteral`, after the JSON/TOML reader has
  ## removed the quotes.
  if form == bfEscaped:
    return decodeEscaped(s)
  if s.len mod 2 != 0:
    return (false, @[], "hex text has an odd number of letters")
  try:
    result = (true, textBytes(parseHexStr(s)), "")
  except ValueError:
    result = (false, @[], "not hex: '" & s & "'")

proc numberLiteral(text: string): string {.role: helper, inline,
    tag: "db|formatting".} =
  ## text: a float's plain text. NaN and the infinities have no literal in
  ## JSON, so they are written quoted in both formats.
  result = if text in ["nan", "inf", "-inf"]: "\"" & text & "\"" else: text

proc zeroText*(k: SlotKind): string {.role: helper, inline,
    tag: "db|formatting".} =
  ## k: the plain text of a value that is not there.
  case k
  of skInt: result = "0"
  of skFloat: result = "0.0"
  else: result = ""

proc isIdSlot*(s: Schema, slot: int): bool {.role: parser, inline,
    tag: "db".} =
  ## s/slot: one of the two identity columns.
  result = s.hasIdentityColumns() and slot < identityColumnCount

## ----------------------------- writing ------------------------------
##
##   rows --plainCell--> plain text --cellLiteral--> literal (sealed or not)
##        --TableLayout--> renderJson / renderToml --> the file

proc plainCell(s: Schema, A: openArray[uint8], offsets: seq[int],
    slot: int, store: SidecarStore): string {.role: parser,
    tag: "db|read".} =
  ## s/A/offsets/slot: one stored value as plain text (see `TextTable`).
  ## store: follows a value that took the sidecar exit, so the file holds
  ##   the VALUE and not a reference into this machine's sidecar folder.
  if offsets[slot] < 0:
    return zeroText(s.slots[slot].kind)
  case s.slots[slot].kind
  of skInt:
    if s.isIdSlot(slot):
      return $s.u64At(A, offsets, slot)
    result = $cast[int64](s.u64At(A, offsets, slot))
  of skFloat:
    result = $cast[float64](s.u64At(A, offsets, slot))
  of skText, skBytes, skSealed, skRef:
    result = bytesText(s.resolve(A, offsets, slot, store))
  of skNull:
    result = ""

proc plainLiteral(s: Schema, slot: int, text: string,
    form: BinaryForm): string {.role: helper, tag: "db|formatting".} =
  ## s/slot/text/form: a cell nobody sealed, as its literal.
  case s.slots[slot].kind
  of skInt:
    result = if s.isIdSlot(slot): quoteToml(text) else: text
  of skFloat: result = numberLiteral(text)
  of skText: result = quoteToml(text)
  of skBytes, skSealed, skRef: result = binaryLiteral(textBytes(text), form)
  of skNull: result = "\"\""

proc sealedLiteral(name, text: string, form: BinaryForm,
    key: Secret): tuple[ok: bool, lit: string, err: string] {.
    role: encryptor, tag: "cryptoBoundary|db|write".} =
  ## name/text: the column and the cell's plain text (Def. 3).
  ## form/key: how to write the sealed bytes, and what seals them.
  var
    blob: SealedBlob = sealWithKey(key, textBytes(text),
      textBytes(sealContext & name))
  if not blob.ok:
    return (false, "", "sealing '" & name & "': " & blob.err)
  result = (true, binaryLiteral(blob.data, form), "")

proc rowLiterals(s: Schema, A: openArray[uint8], style: TableTextStyle,
    key: Secret, store: SidecarStore): tuple[ok: bool, lits: seq[string],
    err: string] {.role: encryptor, tag: "cryptoBoundary|db|write".} =
  ## s/A: one row -> every cell as its literal, in slot order.
  ## style/key/store: which columns to seal and how, and the sidecar.
  var
    offsets: seq[int] = fieldOffsets(s, A)
    name: string = ""
    text: string = ""
    sealed: tuple[ok: bool, lit: string, err: string] = (true, "", "")
    j: int = 0
  while j < s.slots.len:
    name = s.nameOf(s.slots[j].nameId)
    text = plainCell(s, A, offsets, j, store)
    sealed = if name in style.sealed: sealedLiteral(name, text,
               style.binary, key)
             else: (true, plainLiteral(s, j, text, style.binary), "")
    if not sealed.ok:
      return (false, @[], sealed.err)
    result.lits.add sealed.lit
    j = j + 1
  result.ok = true

proc headerPairs(s: Schema, style: TableTextStyle): Pairs {.role: helper,
    tag: "db|formatting".} =
  ## s/style: the lines at the top of the file (Def. 4).
  var
    names: seq[string] = @[]
  for n in style.sealed:
    names.add quoteToml(n)
  result.add ("geist", quoteToml(tableMark))
  result.add ("version", $tableTextVersion)
  result.add ("type", quoteToml(s.typeName))
  result.add ("shape", quoteToml(shapeWords[style.shape]))
  result.add ("binary", quoteToml(binaryWords[style.binary]))
  result.add ("collapse", (if s.autoCollapse: "true" else: "false"))
  result.add ("sealed", "[" & names.join(", ") & "]")
  if style.salt.len > 0:
    result.add ("salt", quoteToml(encodeSalt(style.salt)))

proc schemaPairs(s: Schema, slot: int): Pairs {.role: helper,
    tag: "db|formatting".} =
  ## s/slot: one `[[schema]]` entry.
  var
    sl: Slot = s.slots[slot]
  result.add ("name", quoteToml(s.nameOf(sl.nameId)))
  result.add ("kind", quoteToml(slotKindName(sl.kind)))
  result.add ("column", quoteToml(columnWords[sl.column]))
  result.add ("width", $sl.width)
  result.add ("overflow", quoteToml(overflowWords[sl.onOverflow]))

proc sealCheck*(s: Schema, style: TableTextStyle, key: Secret): string {.
    role: sanitizer, tag: "cryptoBoundary|db".} =
  ## s/style/key: why these columns cannot be sealed, or nothing.
  for n in style.sealed:
    if s.slotIndex(n) < 0:
      return "cannot seal '" & n & "': no such field (" & describeSchema(s) &
        ")"
    if n in [rowIdColumn, rowFlagsColumn]:
      return "cannot seal '" & n & "': a reader needs it to tell rows apart"
  if style.sealed.len > 0 and key.len == 0:
    result = "sealed columns (" & style.sealed.join(", ") &
      ") need a key or a password, and none was given"

proc addColumnLists(L: var TableLayout, s: Schema,
    G: seq[seq[string]]) {.role: truthBuilder, tag: "db|formatting".} =
  ## L: layout receiving one `name = [v0, v1, ...]` per column.
  ## s/G: schema and the literal grid, row first -- read here column first.
  var
    j: int = 0
    t: seq[string] = @[]
  while j < s.slots.len:
    t = @[]
    for line in G:
      t.add line[j]
    L.columns.add (s.nameOf(s.slots[j].nameId), "[" & t.join(", ") & "]")
    j = j + 1

proc addRecords(L: var TableLayout, s: Schema, G: seq[seq[string]]) {.
    role: truthBuilder, tag: "db|formatting".} =
  ## L: layout receiving one key/literal list per row.
  ## s/G: schema and the literal grid.
  var
    t: Pairs = @[]
    j: int = 0
  for line in G:
    t = @[]
    j = 0
    while j < line.len:
      t.add (s.nameOf(s.slots[j].nameId), line[j])
      j = j + 1
    L.records.add t

proc jsonObject(P: Pairs): string {.role: helper, tag: "db|formatting".} =
  ## P: pairs as one inline JSON object.
  var
    t: seq[string] = @[]
  for p in P:
    t.add quoteToml(p.key) & ": " & p.lit
  result = "{" & t.join(", ") & "}"

proc jsonList(P: seq[Pairs]): string {.role: helper, tag: "db|formatting".} =
  ## P: a list of objects, one per line.
  var
    t: seq[string] = @[]
  for p in P:
    t.add "    " & jsonObject(p)
  result = "[\n" & t.join(",\n") & (if t.len > 0: "\n  ]" else: "]")

proc renderJson(L: TableLayout, shape: TextShape): string {.
    role: dataWriter, tag: "db|formatting|write".} =
  ## L/shape: the whole file as JSON.
  var
    t: seq[string] = @[]
    cols: seq[string] = @[]
  for p in L.header:
    t.add "  " & quoteToml(p.key) & ": " & p.lit
  t.add "  \"schema\": " & jsonList(L.schema)
  for p in L.columns:
    cols.add "    " & quoteToml(p.key) & ": " & p.lit
  if shape == shRows:
    t.add "  \"rows\": " & jsonList(L.records)
  else:
    t.add "  \"columns\": {\n" & cols.join(",\n") & "\n  }"
  result = "{\n" & t.join(",\n") & "\n}\n"

proc tomlBlock(header: string, P: Pairs): string {.role: helper,
    tag: "db|formatting".} =
  ## header/P: `[header]` or `[[header]]` with one `key = value` per line.
  result = "\n" & header & "\n"
  for p in P:
    result.add tomlKey(p.key) & " = " & p.lit & "\n"

proc renderToml(L: TableLayout, shape: TextShape): string {.
    role: dataWriter, tag: "db|formatting|write".} =
  ## L/shape: the whole file as TOML. Plain keys before any table, which
  ## TOML requires.
  for p in L.header:
    result.add tomlKey(p.key) & " = " & p.lit & "\n"
  for P in L.schema:
    result.add tomlBlock("[[schema]]", P)
  for P in L.records:
    result.add tomlBlock("[[rows]]", P)
  if shape == shColumns:
    result.add tomlBlock("[columns]", L.columns)

proc literalGrid(s: Schema, R: openArray[Row], style: TableTextStyle,
    key: Secret, store: SidecarStore): tuple[ok: bool, G: seq[seq[string]],
    err: string] {.role: encryptor, tag: "cryptoBoundary|db|write".} =
  ## s/R: every row -> its literals, row i at `G[i]`.
  ## style/key/store: as for `rowLiterals`. Raises when a sidecar value
  ##   is missing; `tableText` turns that into an error.
  var
    line: tuple[ok: bool, lits: seq[string], err: string] = (true, @[], "")
  for r in R:
    line = rowLiterals(s, r.data, style, key, store)
    if not line.ok:
      return (false, @[], line.err)
    result.G.add line.lits
  result.ok = true

proc layoutOf(s: Schema, style: TableTextStyle,
    G: seq[seq[string]]): TableLayout {.role: truthBuilder,
    tag: "db|formatting".} =
  ## s/style/G: header, schema and body, ready for either renderer.
  var
    j: int = 0
  result.header = headerPairs(s, style)
  while j < s.slots.len:
    result.schema.add schemaPairs(s, j)
    j = j + 1
  if style.shape == shRows:
    result.addRecords(s, G)
  else:
    result.addColumnLists(s, G)

proc tableText*(s: Schema, R: openArray[Row],
    style: TableTextStyle, key: Secret,
    store: SidecarStore = SidecarStore()): tuple[ok: bool, text: string,
    err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|write".} =
  ## s/R: the schema and the rows to write.
  ## style: format, shape, binary form and sealed columns.
  ## key: seals `style.sealed`. Ignored when nothing is sealed.
  ## store: the sidecar, to follow values that left the row.
  ##
  ##   var t = tableText(db.entries.schema, rows, style, key)
  ##   if t.ok: writeFile("notes.toml", t.text)
  var
    L: TableLayout = TableLayout()
    grid: tuple[ok: bool, G: seq[seq[string]], err: string] = (true, @[], "")
    refused: string = sealCheck(s, style, key)
  if refused.len > 0:
    return (false, "", refused)
  try:
    grid = literalGrid(s, R, style, key, store)
  except CatchableError as exc:
    return (false, "", "reading a row: " & exc.msg)
  if not grid.ok:
    return (false, "", grid.err)
  L = layoutOf(s, style, grid.G)
  result.text = if style.format == dfJson: renderJson(L, style.shape)
                else: renderToml(L, style.shape)
  result.ok = true

proc tableText*(s: Schema, R: openArray[Row],
    style: TableTextStyle = defaultTableTextStyle(),
    store: SidecarStore = SidecarStore()): tuple[ok: bool, text: string,
    err: string] {.role: orchestrator, tag: "appApi|db|write".} =
  ## s/R/style/store: as above, with nothing sealed.
  result = tableText(s, R, style, initSecret([]), store)

proc tableText*(s: Schema, R: openArray[Row], style: TableTextStyle,
    password: string, store: SidecarStore = SidecarStore()): tuple[ok: bool,
    text: string, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|write".} =
  ## s/R/style/store: as above.
  ## password: turned into a key once, with a fresh salt the file keeps.
  var
    salted: TableTextStyle = style
  salted.salt = randomSalt()
  result = tableText(s, R, salted, deriveKey(password, salted.salt), store)
