## ---------------------------------------------------------------------
## Table read <- a table file back into a schema and plain cells
## ---------------------------------------------------------------------
##
##   text --parseDoc-----> one tree, JSON and TOML alike
##        --readHeader---> shape, binary form, sealed columns, salt
##        --readSchema---> Schema
##        --rows/columns-> one tree node per cell (nil = not written)
##        --decodeCell---> plain text: un-hexed, unsealed
##
##   var t = readTableFile("notes.toml", key)
##   t.t.cells[0]       -> @["17", "0", "first", "hello"]
##   t.t.cellValues(0)  -> {"title": "first", "body": "hello"}
##
## What the file looks like, and why, is written down once, in
## ./tabletext, which writes it. This half only reads, and trusts nothing:
## every cell is checked against the kind its column declares.

import std/[json, os, strutils, tables]

import runePragmas
import ./types
import ./dynamic
import ./secret
import ./secrets
import ./doc
import ./toml_read
import ./tabletext

type
  CellText = tuple[ok: bool, text: string, err: string]
    ## One cell as plain text, or why it is not one.

  CellNodes = seq[seq[JsonNode]]
    ## Row i, slot j -> the cell's tree node; nil when the file left it out.

  TableHead {.role: truthState, expectedCount: 1,
      lifeCycle: lcScratch.} = object
    ## What the lines above the schema said.
    style: TableTextStyle
    typeName: string
    collapse: bool

## ------------------------------ header ------------------------------

proc readHeader(n: JsonNode, f: DocFormat): tuple[ok: bool, h: TableHead,
    err: string] {.role: parser, tag: "db|parsing|read".} =
  ## n/f: the parsed file -> its header (Def. 4 in ./tabletext).
  var
    shape: tuple[ok: bool, value: TextShape] = (false, shRows)
    binary: tuple[ok: bool, value: BinaryForm] = (false, bfHex)
  if n.kind != JObject or n.setting("geist", "") != tableMark:
    return (false, TableHead(), "not a Geist table file: the first line " &
      "should be geist = \"table\"")
  if n.setting("version", 0) != tableTextVersion:
    return (false, TableHead(), "table file version " &
      $n.setting("version", 0) & "; this Geist reads version " &
      $tableTextVersion)
  shape = wordOf(n.setting("shape", "rows"), shapeWords)
  binary = wordOf(n.setting("binary", "hex"), binaryWords)
  if not shape.ok:
    return (false, TableHead(), "shape must be \"rows\" or \"columns\"")
  if not binary.ok:
    return (false, TableHead(), "binary must be \"hex\" or \"escaped\"")
  result.h.style = TableTextStyle(format: f, shape: shape.value,
    binary: binary.value, sealed: n.setting("sealed", newSeq[string]()),
    salt: decodeSalt(n.setting("salt", "")))
  result.h.typeName = n.setting("type", "Record")
  result.h.collapse = n.setting("collapse", false)
  result.ok = true

## ------------------------------ schema ------------------------------

proc addSlot(S: var Schema, e: JsonNode): string {.role: truthBuilder,
    tag: "db|parsing|read".} =
  ## S: schema receiving one column.
  ## e: one `[[schema]]` entry. Returns why it is refused, or nothing.
  var
    name: string = e.setting("name", "")
    kind: tuple[ok: bool, value: SlotKind] =
      wordOf(e.setting("kind", ""), slotKindWords)
    column: tuple[ok: bool, value: ColumnKind] =
      wordOf(e.setting("column", "variable"), columnWords)
    overflow: tuple[ok: bool, value: OverflowPolicy] =
      wordOf(e.setting("overflow", "error"), overflowWords)
  if name.len == 0:
    return "a schema entry has no name"
  if S.slotIndex(name) >= 0:
    return "field '" & name & "' is in the schema twice"
  if not kind.ok:
    return "field '" & name & "': kind must be int, float, text, bytes, " &
      "sealed or ref"
  if not column.ok:
    return "field '" & name & "': column must be fixed, capped or variable"
  if not overflow.ok:
    return "field '" & name & "': overflow must be error or truncate"
  S.slots.add Slot(nameId: S.intern(name), kind: kind.value,
    column: column.value, width: uint32(max(e.setting("width", 0), 0)),
    onOverflow: overflow.value)

proc readSchema(n: JsonNode, h: TableHead): tuple[ok: bool, s: Schema,
    err: string] {.role: parser, tag: "db|parsing|read".} =
  ## n/h: the parsed file and its header -> the schema it describes.
  var
    problem: string = ""
  result.s = Schema(typeName: h.typeName, autoCollapse: h.collapse)
  if not n.hasKey("schema") or n["schema"].kind != JArray or
      n["schema"].len == 0:
    return (false, Schema(), "the file has no [[schema]] entries")
  for e in n["schema"].items:
    problem = if e.kind == JObject: result.s.addSlot(e)
              else: "a schema entry is not a table"
    if problem.len > 0:
      return (false, Schema(), problem)
  result.ok = true

## ------------------------------- body -------------------------------

proc rowNodes(r: JsonNode, s: Schema, i: int): tuple[ok: bool,
    cells: seq[JsonNode], err: string] {.role: parser,
    tag: "db|parsing|read".} =
  ## r/s/i: row i of a rows-shaped file -> one node per slot.
  var
    j: int = 0
  if r.kind != JObject:
    return (false, @[], "row " & $i & " is not a table")
  result.cells = newSeq[JsonNode](s.slots.len)
  for key, v in r.pairs:
    j = s.slotIndex(key)
    if j < 0:
      return (false, @[], "row " & $i & ": no field '" & key &
        "' in the schema (" & describeSchema(s) & ")")
    result.cells[j] = v
  result.ok = true

proc rowsGrid(n: JsonNode, s: Schema): tuple[ok: bool, G: CellNodes,
    err: string] {.role: parser, tag: "db|parsing|read".} =
  ## n/s: a rows-shaped file -> every cell node. No `rows` at all is a
  ## table with no rows: TOML has no way to write an empty `[[rows]]`.
  var
    line: tuple[ok: bool, cells: seq[JsonNode], err: string] =
      (true, @[], "")
    i: int = 0
  result.ok = true
  if not n.hasKey("rows"):
    return
  if n["rows"].kind != JArray:
    return (false, @[], "rows must be a list of tables")
  for r in n["rows"].items:
    line = rowNodes(r, s, i)
    if not line.ok:
      return (false, @[], line.err)
    result.G.add line.cells
    i = i + 1

proc columnProblem(s: Schema, key: string, v: JsonNode,
    count: int): string {.role: sanitizer, tag: "db|parsing|read".} =
  ## s/key/v: one `name = [...]` line of a columns-shaped file.
  ## count: how many values the columns before it had (-1: none yet).
  if s.slotIndex(key) < 0:
    return "no field '" & key & "' in the schema (" & describeSchema(s) & ")"
  if v.kind != JArray:
    return "column '" & key & "' must be a list"
  if count >= 0 and v.len != count:
    result = "column '" & key & "' has " & $v.len & " values, the " &
      "columns before it have " & $count

proc placeColumn(G: var CellNodes, j: int, v: JsonNode) {.role: truthBuilder,
    tag: "db|parsing|read".} =
  ## G/j/v: the values of slot j written down the grid.
  var
    i: int = 0
  for item in v.items:
    G[i][j] = item
    i = i + 1

proc columnsGrid(n: JsonNode, s: Schema): tuple[ok: bool, G: CellNodes,
    err: string] {.role: parser, tag: "db|parsing|read".} =
  ## n/s: a columns-shaped (transposed) file -> every cell node, turned
  ## back so row i is `G[i]` exactly as for a rows-shaped file.
  var
    count: int = -1
    problem: string = ""
    i: int = 0
  result.ok = true
  if not n.hasKey("columns"):
    return
  if n["columns"].kind != JObject:
    return (false, @[], "columns must be a table of lists")
  for key, v in n["columns"].pairs:
    problem = columnProblem(s, key, v, count)
    if problem.len > 0:
      return (false, @[], problem)
    count = v.len
  while i < count:
    result.G.add newSeq[JsonNode](s.slots.len)
    i = i + 1
  for key, v in n["columns"].pairs:
    result.G.placeColumn(s.slotIndex(key), v)

## ------------------------------- cells ------------------------------

proc wrongKind(want: string): CellText {.role: helper, inline,
    tag: "db|parsing".} =
  ## want: what the column needed.
  result = (false, "", "expects " & want)

proc intText(n: JsonNode, isId: bool): CellText {.role: parser,
    tag: "db|parsing|read".} =
  ## n/isId: an integer cell. An identity value is unsigned and usually
  ## written quoted (see ./tabletext), so a string is accepted too.
  try:
    case n.kind
    of JInt:
      result = (true, $n.getBiggestInt(), "")
    of JString:
      result = (true, (if isId: $parseBiggestUInt(n.getStr())
                       else: $parseBiggestInt(n.getStr())), "")
    else:
      result = wrongKind("an integer")
  except ValueError:
    result = wrongKind("an integer")
  if result.ok and isId and result.text.len > 0 and result.text[0] == '-':
    result = wrongKind("an unsigned id")

proc floatText(n: JsonNode): CellText {.role: parser,
    tag: "db|parsing|read".} =
  ## n: a float cell. `1` is accepted for `1.0`; NaN and the infinities
  ## arrive quoted, because JSON has no literal for them.
  case n.kind
  of JFloat: result = (true, $n.getFloat(), "")
  of JInt: result = (true, $float64(n.getBiggestInt()), "")
  of JString:
    result = if n.getStr() in ["nan", "inf", "-inf"]: (true, n.getStr(), "")
             else: wrongKind("a number")
  else: result = wrongKind("a number")

proc binaryText(n: JsonNode, form: BinaryForm): CellText {.role: parser,
    tag: "db|parsing|read".} =
  ## n/form: a bytes cell, written as Def. 2 says.
  var
    raw: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
  if n.kind != JString:
    return wrongKind("a " & binaryWords[form] & " string")
  raw = decodeBinary(n.getStr(), form)
  result = (raw.ok, bytesText(raw.data), raw.err)

proc openedText(n: JsonNode, name: string, form: BinaryForm,
    key: Secret): CellText {.role: decryptor,
    tag: "cryptoBoundary|db|read".} =
  ## n/name: a sealed cell and its column (Def. 3).
  ## form/key: how its bytes were written, and what opens them.
  var
    blob: CellText = binaryText(n, form)
    opened: SealedBlob = SealedBlob()
  if not blob.ok:
    return blob
  opened = openWithKey(key, textBytes(blob.text),
    textBytes(sealContext & name))
  result = if opened.ok: (true, bytesText(opened.data), "")
           else: (false, "", "cannot open the sealed value: " & opened.err)

proc decodeCell(s: Schema, j: int, n: JsonNode, style: TableTextStyle,
    key: Secret): CellText {.role: decryptor,
    tag: "cryptoBoundary|db|read".} =
  ## s/j/n: slot j's node -> its plain text.
  ## style/key: binary form and sealed columns, and the key that opens them.
  var
    name: string = s.nameOf(s.slots[j].nameId)
  if n.isNil or n.kind == JNull:
    return (true, zeroText(s.slots[j].kind), "")
  if name in style.sealed:
    return openedText(n, name, style.binary, key)
  case s.slots[j].kind
  of skInt: result = intText(n, s.isIdSlot(j))
  of skFloat: result = floatText(n)
  of skText:
    result = if n.kind == JString: (true, n.getStr(), "")
             else: wrongKind("text")
  of skBytes, skSealed, skRef: result = binaryText(n, style.binary)
  of skNull: result = (true, "", "")

proc decodeRow(s: Schema, cells: seq[JsonNode], i: int,
    style: TableTextStyle, key: Secret): tuple[ok: bool,
    texts: seq[string], err: string] {.role: decryptor,
    tag: "cryptoBoundary|db|read".} =
  ## s/cells/i: row i's nodes -> its plain texts, or the first bad cell.
  var
    cell: CellText = (true, "", "")
    j: int = 0
  while j < cells.len:
    cell = decodeCell(s, j, cells[j], style, key)
    if not cell.ok:
      return (false, @[], "row " & $i & ", field '" &
        s.nameOf(s.slots[j].nameId) & "': " & cell.err)
    result.texts.add cell.text
    j = j + 1
  result.ok = true

## ------------------------------ reading -----------------------------

proc readTableNode(n: JsonNode, h: TableHead, key: Secret): tuple[ok: bool,
    t: TextTable, err: string] {.role: orchestrator,
    tag: "cryptoBoundary|db|read".} =
  ## n/h: the parsed file and its header.
  ## key: opens the sealed columns; may be empty when there are none.
  var
    schema: tuple[ok: bool, s: Schema, err: string] = readSchema(n, h)
    grid: tuple[ok: bool, G: CellNodes, err: string] = (true, @[], "")
    line: tuple[ok: bool, texts: seq[string], err: string] = (true, @[], "")
    refused: string = ""
    i: int = 0
  if not schema.ok:
    return (false, TextTable(), schema.err)
  refused = sealCheck(schema.s, h.style, key)
  if refused.len > 0:
    return (false, TextTable(), refused)
  grid = if h.style.shape == shRows: rowsGrid(n, schema.s)
         else: columnsGrid(n, schema.s)
  if not grid.ok:
    return (false, TextTable(), grid.err)
  result.t = TextTable(schema: schema.s, style: h.style)
  while i < grid.G.len:
    line = decodeRow(schema.s, grid.G[i], i, h.style, key)
    if not line.ok:
      return (false, TextTable(), line.err)
    result.t.cells.add line.texts
    i = i + 1
  result.ok = true

proc parsedHead(text: string, f: DocFormat): tuple[ok: bool, n: JsonNode,
    h: TableHead, err: string] {.role: parser, tag: "db|parsing|read".} =
  ## text/f: the file -> its tree and header, or why it is neither.
  var
    parsed: tuple[ok: bool, node: JsonNode, err: string] = parseDoc(text, f)
    head: tuple[ok: bool, h: TableHead, err: string] =
      (false, TableHead(), "")
  if not parsed.ok:
    return (false, nil, TableHead(), parsed.err)
  head = readHeader(parsed.node, f)
  result = (head.ok, parsed.node, head.h, head.err)

proc readTableText*(text: string, f: DocFormat, key: Secret): tuple[ok: bool,
    t: TextTable, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|read".} =
  ## text/f: a table file's contents and format.
  ## key: the key its sealed columns were sealed with.
  var
    p: tuple[ok: bool, n: JsonNode, h: TableHead, err: string] =
      parsedHead(text, f)
  if not p.ok:
    return (false, TextTable(), p.err)
  result = readTableNode(p.n, p.h, key)

proc readTableText*(text: string, f: DocFormat): tuple[ok: bool,
    t: TextTable, err: string] {.role: orchestrator,
    tag: "appApi|db|read".} =
  ## text/f: as above, for a file with nothing sealed.
  result = readTableText(text, f, initSecret([]))

proc readTableText*(text: string, f: DocFormat, password: string): tuple[
    ok: bool, t: TextTable, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|read".} =
  ## text/f: as above.
  ## password: what sealed it. The salt comes from the file itself.
  var
    p: tuple[ok: bool, n: JsonNode, h: TableHead, err: string] =
      parsedHead(text, f)
  if not p.ok:
    return (false, TextTable(), p.err)
  if p.h.style.sealed.len > 0 and p.h.style.salt.len == 0:
    return (false, TextTable(), "this file was sealed with a key, not a " &
      "password: there is no salt in it")
  result = readTableNode(p.n, p.h, deriveKey(password, p.h.style.salt))

proc fileText(path: string): tuple[ok: bool, text: string, err: string] {.
    role: dataFetcher, tag: "db|read|storageIo".} =
  ## path: a file's contents, or why it could not be read.
  if not fileExists(path):
    return (false, "", "no file at " & path)
  try:
    result = (true, readFile(path), "")
  except IOError as exc:
    result = (false, "", path & ": " & exc.msg)

proc readTableFile*[K: Secret | string](path: string, sealer: K): tuple[
    ok: bool, t: TextTable, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|db|read|storageIo".} =
  ## path: a .json or .toml table file; the extension decides the format.
  ## sealer: what opens its sealed columns -- the key they were sealed
  ##   with, or the password (whose salt is in the file).
  var
    got: tuple[ok: bool, text: string, err: string] = fileText(path)
  if not got.ok:
    return (false, TextTable(), got.err)
  result = readTableText(got.text, formatOf(path), sealer)

proc readTableFile*(path: string): tuple[ok: bool, t: TextTable,
    err: string] {.role: orchestrator, tag: "appApi|db|read|storageIo".} =
  ## path: as above, nothing sealed.
  result = readTableFile(path, initSecret([]))

## --------------------------- using a row ----------------------------

proc cellValues*(t: TextTable, i: int): Table[string, string] {.
    role: parser, tag: "appApi|db|read".} =
  ## t/i: row i as `field -> text`, without the two identity columns --
  ## exactly what `buildRow` takes, which is handed those separately.
  var
    j: int = 0
  result = initTable[string, string]()
  while j < t.schema.slots.len:
    if not t.schema.isIdSlot(j):
      result[t.schema.nameOf(t.schema.slots[j].nameId)] = t.cells[i][j]
    j = j + 1

proc cellIdentity*(t: TextTable, i: int): tuple[id: RowId, flags: uint64] {.
    role: parser, tag: "appApi|db|read".} =
  ## t/i: row i's id and flags; zero for a file whose schema has none.
  ## The texts were checked as unsigned numbers while reading.
  if not t.schema.hasIdentityColumns():
    return (0'u64, 0'u64)
  result = (RowId(parseBiggestUInt(t.cells[i][0])),
    uint64(parseBiggestUInt(t.cells[i][1])))
