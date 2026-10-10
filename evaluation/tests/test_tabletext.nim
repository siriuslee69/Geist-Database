## Table files: a whole table as JSON or TOML, row first or column first,
## bytes as hex or escaped, some columns sealed -- and back, unchanged.
##
##   suite 1  every kind of value survives every shape and format
##   suite 2  sealed columns: hidden in the file, opened only by the key
##   suite 3  a broken file is refused, naming row and field
##   suite 4  a Session exports and imports, all or nothing

import runePragmas
import std/[os, strutils, tables, unittest]

import geist

proc spec(): Schema {.role: helper.} =
  ## A schema with identity and one column of every kind a file can hold.
  var
    parsed: tuple[ok: bool, s: Schema, err: string] = parseSchemaSpec("Note",
      "title:text,n:int,x:float,raw:bytes")
  doAssert parsed.ok, parsed.err
  result = withIdentity(parsed.s)

proc rowOf(s: Schema, id: RowId, V: openArray[(string, string)]): Row {.
    role: helper.} =
  ## s/id/V: one row built the way the CLI builds one.
  var
    values: Table[string, string] = initTable[string, string]()
    built: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
  for (k, v) in V:
    values[k] = v
  built = buildRow(s, values, SidecarStore(), id)
  doAssert built.ok, built.err
  result = Row(data: built.data)

proc allBytes(): string {.role: helper.} =
  ## Every byte 00..FF once: the hardest thing a text file has to hold.
  var
    i: int = 0
  while i < 256:
    result.add char(i)
    i = i + 1

proc sample(): seq[Row] {.role: helper.} =
  ## Three rows that between them touch every awkward case.
  var
    s: Schema = spec()
  result.add rowOf(s, 18124389254678183937'u64, [("title", "say \"hi\"\n\t\x01"),
    ("n", "-42"), ("x", "1.5"), ("raw", allBytes())])
  result.add rowOf(s, 2'u64, [("title", "café 🌿"), ("n", "0"), ("x", "inf"),
    ("raw", "")])
  result.add rowOf(s, 3'u64, [("title", ""), ("n", "9223372036854775807"),
    ("x", "-0.001"), ("raw", "\\\"")])

proc styleOf(f: DocFormat, h: TextShape, b: BinaryForm): TableTextStyle {.
    role: helper.} =
  result = TableTextStyle(format: f, shape: h, binary: b)

proc plainOf(R: seq[Row]): seq[seq[string]] {.role: helper.} =
  ## R: what every reader of these rows should get back.
  var
    s: Schema = spec()
  for r in R:
    result.add renderRow(s, r.data)

suite "every kind of value survives every shape and format":

  # {.testKind: tkProperty.}
  test "rows and columns, JSON and TOML, hex and escaped: one answer":
    var
      written: tuple[ok: bool, text: string, err: string] = (false, "", "")
      back: tuple[ok: bool, t: TextTable, err: string] =
        (false, TextTable(), "")
      first: seq[seq[string]] = @[]
    for f in [dfToml, dfJson]:
      for h in [shRows, shColumns]:
        for b in [bfHex, bfEscaped]:
          written = tableText(spec(), sample(), styleOf(f, h, b))
          check written.ok
          back = readTableText(written.text, f)
          check back.ok
          check back.err == ""
          check back.t.cells.len == 3
          check back.t.cells[0][5] == allBytes()
          check back.t.cells[1][2] == "café 🌿"
          check back.t.cells[0][0] == "18124389254678183937"
          if first.len == 0:
            first = back.t.cells
          check back.t.cells == first

  # {.testKind: tkUnit.}
  test "the schema comes back as it was written":
    var
      back: tuple[ok: bool, t: TextTable, err: string] = readTableText(
        tableText(spec(), sample()).text, dfToml)
    check back.ok
    check describeSchema(back.t.schema) == describeSchema(spec())
    check back.t.schema.typeName == "Note"
    check back.t.schema.hasIdentityColumns()

  # {.testKind: tkUnit.}
  test "the two binary forms look the way Def. 2 says":
    check binaryLiteral([0x48'u8, 0x69, 0x00, 0xFF], bfHex) == "\"486900ff\""
    check binaryLiteral([0x48'u8, 0x69, 0x00, 0xFF], bfEscaped) ==
      "\"Hi\\u0000\\u00ff\""
    check binaryLiteral([0x22'u8, 0x5C], bfEscaped) == "\"\\\"\\\\\""

  # {.testKind: tkUnit.}
  test "the transposed form is one list per column":
    var
      text: string = tableText(spec(), sample(),
        styleOf(dfToml, shColumns, bfHex)).text
    check "[columns]" in text
    check "[[rows]]" notin text
    check "n = [-42, 0, 9223372036854775807]" in text

  # {.testKind: tkEdgeCase.}
  test "a table with no rows is written and read in both shapes":
    var
      back: tuple[ok: bool, t: TextTable, err: string] =
        (false, TextTable(), "")
    for f in [dfToml, dfJson]:
      for h in [shRows, shColumns]:
        back = readTableText(tableText(spec(), newSeq[Row](),
          styleOf(f, h, bfHex)).text, f)
        check back.ok
        check back.t.cells.len == 0

  # {.testKind: tkRegression.}
  test "rows rendered by the store and by the file agree":
    var
      back: tuple[ok: bool, t: TextTable, err: string] = readTableText(
        tableText(spec(), sample()).text, dfToml)
    check back.t.cells[0][0 .. 4] == plainOf(sample())[0][0 .. 4]

suite "sealed columns: hidden in the file, opened only by the key":

  # {.testKind: tkUnit.}
  test "a key seals and opens; the plain value is nowhere in the file":
    var
      key: Secret = newSealKey()
      style: TableTextStyle = styleOf(dfJson, shRows, bfHex)
      written: tuple[ok: bool, text: string, err: string] = (false, "", "")
      back: tuple[ok: bool, t: TextTable, err: string] =
        (false, TextTable(), "")
    style.sealed = @["title", "n"]
    written = tableText(spec(), sample(), style, key)
    check written.ok
    check "café" notin written.text
    check "-42" notin written.text
    back = readTableText(written.text, dfJson, key)
    check back.ok
    check back.t.cells[1][2] == "café 🌿"
    check back.t.cells[0][3] == "-42"

  # {.testKind: tkEdgeCase.}
  test "a wrong key, or no key, does not open it":
    var
      style: TableTextStyle = styleOf(dfToml, shColumns, bfEscaped)
      text: string = ""
      other: Secret = newSealKey()
    style.sealed = @["raw"]
    text = tableText(spec(), sample(), style, newSealKey()).text
    check not readTableText(text, dfToml, other).ok
    check "need a key" in readTableText(text, dfToml).err

  # {.testKind: tkUnit.}
  test "a password keeps its salt in the file and opens again":
    var
      style: TableTextStyle = styleOf(dfToml, shRows, bfHex)
      written: tuple[ok: bool, text: string, err: string] = (false, "", "")
    style.sealed = @["title"]
    written = tableText(spec(), sample(), style, "correct horse")
    check written.ok
    check "salt = " in written.text
    check readTableText(written.text, dfToml, "correct horse").t.cells[1][2] ==
      "café 🌿"
    check not readTableText(written.text, dfToml, "wrong horse").ok

  # {.testKind: tkEdgeCase.}
  test "a key-sealed file asked for with a password says so":
    var
      style: TableTextStyle = styleOf(dfToml, shRows, bfHex)
    style.sealed = @["title"]
    check "sealed with a key" in readTableText(tableText(spec(), sample(),
      style, newSealKey()).text, dfToml, "pw").err

  # {.testKind: tkEdgeCase.}
  test "a sealed value moved to another column does not open there":
    var
      key: Secret = newSealKey()
      style: TableTextStyle = styleOf(dfToml, shRows, bfHex)
      text: string = ""
      sealedTitle: string = ""
      sealedRaw: string = ""
    style.sealed = @["title", "raw"]
    text = tableText(spec(), sample()[1 .. 1], style, key).text
    for line in text.splitLines():
      if line.startsWith("title = "): sealedTitle = line[8 .. ^1]
      if line.startsWith("raw = "): sealedRaw = line[6 .. ^1]
    check sealedTitle.len > 10
    check sealedRaw.len > 10
    text = text.replace("raw = " & sealedRaw, "raw = " & sealedTitle)
    check "cannot open" in readTableText(text, dfToml, key).err

  # {.testKind: tkEdgeCase.}
  test "the identity columns, and unknown columns, cannot be sealed":
    var
      style: TableTextStyle = styleOf(dfToml, shRows, bfHex)
    style.sealed = @["__rowId"]
    check "tell rows apart" in tableText(spec(), sample(), style,
      newSealKey()).err
    style.sealed = @["nope"]
    check "no such field" in tableText(spec(), sample(), style,
      newSealKey()).err

suite "a broken file is refused, naming row and field":

  # {.testKind: tkEdgeCase.}
  test "a field the schema does not have":
    var
      text: string = tableText(spec(), sample()).text.replace(
        "title = \"\"", "titel = \"\"")
    check "no field 'titel'" in readTableText(text, dfToml).err

  # {.testKind: tkEdgeCase.}
  test "a value of the wrong kind":
    var
      text: string = tableText(spec(), sample()).text.replace("n = 0",
        "n = \"zero\"")
    check "row 1, field 'n': expects an integer" in
      readTableText(text, dfToml).err

  # {.testKind: tkEdgeCase.}
  test "columns of different lengths":
    var
      text: string = tableText(spec(), sample(),
        styleOf(dfToml, shColumns, bfHex)).text.replace(
        "n = [-42, 0, 9223372036854775807]", "n = [-42, 0]")
    check "has 2 values" in readTableText(text, dfToml).err

  # {.testKind: tkEdgeCase.}
  test "bad hex, and a character above U+00FF in an escaped field":
    check not decodeBinary("abc", bfHex).ok
    check not decodeBinary("zz", bfHex).ok
    check "is not a byte" in decodeBinary("é🌿", bfEscaped).err
    check decodeBinary("é", bfEscaped).data == @[0xE9'u8]

  # {.testKind: tkEdgeCase.}
  test "a file that is not a table file":
    check "not a Geist table file" in readTableText("a = 1\n", dfToml).err
    check "version" in readTableText(
      "geist = \"table\"\nversion = 9\n", dfToml).err

  # {.testKind: tkEdgeCase.}
  test "a missing cell is the column's zero":
    var
      text: string = tableText(spec(), sample()).text.replace(
        "x = -0.001\n", "")
      back: tuple[ok: bool, t: TextTable, err: string] =
        readTableText(text, dfToml)
    check back.ok
    check back.t.cells[2][4] == "0.0"

proc freshDb(name: string): Session {.role: helper.} =
  ## name: a new, empty database under the temp folder.
  var
    dir: string = getTempDir() / "geist_tabletext_test" / name
    parsed: tuple[ok: bool, s: Schema, err: string] = parseSchemaSpec("Note",
      "title:text,n:int,x:float,raw:bytes")
  removeDir(dir)
  result = openSessionWithSchema(dir, "main", parsed.s, defaultGeistConfig(),
    "")

suite "a Session exports and imports, all or nothing":

  # {.testKind: tkIntegration.}
  test "export, import elsewhere: same rows, same ids":
    var
      a: Session = freshDb("a")
      b: Session = freshDb("b")
      path: string = getTempDir() / "geist_tabletext_test" / "a.json"
      done: tuple[ok: bool, added: int, err: string] = (false, 0, "")
    for r in sample():
      discard a.putRow(Row(data: r.data))
    check a.exportTable(path).ok
    check readFile(path).startsWith("{")
    done = b.importTable(path)
    check done.ok
    check done.added == 3
    check b.rowIds() == a.rowIds()
    check renderRow(b.entries.schema, b.visibleRow(0).data) ==
      renderRow(a.entries.schema, a.visibleRow(0).data)
    a.close()
    b.close()

  # {.testKind: tkIntegration.}
  test "importing twice replaces; freshIds adds":
    var
      a: Session = freshDb("twice")
      path: string = getTempDir() / "geist_tabletext_test" / "twice.toml"
    for r in sample():
      discard a.putRow(Row(data: r.data))
    check a.exportTable(path).ok
    check a.importTable(path).ok
    check a.entryCount() == 3
    check a.importTable(path, freshIds = true).added == 3
    check a.entryCount() == 6
    a.close()

  # {.testKind: tkIntegration.}
  test "sealed with a password, transposed, escaped -- and back":
    var
      a: Session = freshDb("sealed")
      b: Session = freshDb("sealed2")
      path: string = getTempDir() / "geist_tabletext_test" / "sealed.toml"
      style: TableTextStyle = styleOf(dfToml, shColumns, bfEscaped)
    style.sealed = @["title", "raw"]
    for r in sample():
      discard a.putRow(Row(data: r.data))
    check a.exportTable(path, style, "pw").ok
    check "café" notin readFile(path)
    check not b.importTable(path, "nope").ok
    check b.entryCount() == 0
    check b.importTable(path, "pw").added == 3
    check renderRow(b.entries.schema, b.visibleRow(1).data)[2] == "café 🌿"
    a.close()
    b.close()

  # {.testKind: tkEdgeCase.}
  test "one bad row stops the import with nothing stored":
    var
      a: Session = freshDb("bad")
      path: string = getTempDir() / "geist_tabletext_test" / "bad.toml"
      text: string = tableText(spec(), sample()).text
    writeFile(path, text.replace("x = -0.001", "x = \"lots\""))
    check "row 2" in a.importTable(path).err
    check a.entryCount() == 0
    a.close()

  # {.testKind: tkEdgeCase.}
  test "a file with a field the database lacks is refused up front":
    var
      parsed: tuple[ok: bool, s: Schema, err: string] = parseSchemaSpec(
        "Note", "title:text")
      dir: string = getTempDir() / "geist_tabletext_test" / "narrow"
      a: Session = default(Session)
      path: string = getTempDir() / "geist_tabletext_test" / "wide.toml"
    removeDir(dir)
    a = openSessionWithSchema(dir, "main", parsed.s, defaultGeistConfig(), "")
    writeFile(path, tableText(spec(), sample()).text)
    check "field 'n' this database does not" in a.importTable(path).err
    check a.entryCount() == 0
    a.close()
