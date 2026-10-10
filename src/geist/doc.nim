## ---------------------------------------------------------------------
## Doc <- an ordinary Nim object as an editable TOML or JSON file
## ---------------------------------------------------------------------
##
##   T  --toDoc-->  JsonNode  --renderToml-->  a file a person can edit
##   T  <-fromDoc-  JsonNode  <-parseToml----  the file they edited
##
## The store packs an object into bytes nobody can read without Geist.
## That is right for a mailbox and wrong for a settings file: the whole
## point of a settings file is that someone opens it in an editor at
## three in the morning and changes one line.
##
## So this is the OTHER direction. Same objects, no cipher, no schema, no
## generation -- a plain file, written with every option present and a
## comment on the ones whose names do not explain themselves.
##
##   var s = readDoc("config.toml", defaultSettings())
##   s.value.theme = "dark"
##   discard writeDoc("config.toml", s.value, settingsNotes())
##
## THREE RULES, AND EACH ONE EXISTS BECAUSE OF A SPECIFIC FAILURE.
##
##   A MISSING KEY IS THE DEFAULT.        A person should be able to
##   delete a line they do not care about, and a program should be able
##   to add an option without invalidating every file already written.
##
##   A KEY THE OBJECT DOES NOT HAVE IS KEPT.  It is reported and it is
##   never applied, but it survives the round trip. A settings file that
##   silently deleted the section a future version will read -- or that
##   a person typed slightly wrong -- would destroy work on save.
##
##   A VALUE OF THE WRONG KIND IS THE DEFAULT.  `port = "80"` is a
##   mistake, and running on the documented default beats running on a
##   coerced guess. It is reported so it can be shown.
##
## NOTHING HERE RAISES. Every failure comes back in a `DocReport` -- a
## config reader that crashed on a stray brace would take the program down
## with it, and the person who typed the brace would see a stack trace
## instead of a line number.
##
## WHAT IS SUPPORTED. Enough for a settings file and no more:
##
##   string, int kinds, float, bool, enum   scalars; an enum is its NAME
##   seq[scalar]                            an inline array
##   object                                 a sub-table
##   seq[object]                            an array of tables, [[x]]
##   OrderedTable[string, object]           named sub-tables, [x.alice]
##   OrderedTable[string, string]           a plain map
##
## The last one is what per-friend and per-room settings are made of, and
## why the table is ORDERED: a file that reshuffles its sections on every
## save is unreadable in a diff.
##
## ONE THING THE THREE RULES DO NOT COVER, because it has no default to
## reach for: a named sub-table someone ADDED BY HAND. The caller's table
## has no entry for a name it has never seen, so every field they did not
## write takes the TYPE's zero rather than the application's default --
## and `[account."alice@..."]` with one line in it becomes an account with
## everything switched off. `sectionKeys` is the way out: read once to
## learn which sections exist, seed the fallback with a prototype for
## each, read again. See its own note for why that beats threading a
## prototype through this generic reader.

## The object <-> tree half is ./docnode, re-exported here.

import std/[json, os, strutils]

import fylgia_utils

import runePragmas
import ./docnode

export docnode

## ---------------------------- TOML rendering ------------------------

proc noteFor(style: DocStyle, path: string): string {.role: parser,
    tag: "config|docs".} =
  ## style/path: the comment attached to this dotted path, or nothing.
  var
    i: int = 0
  while i < style.notes.len:
    if style.notes[i].field == path:
      return style.notes[i].note
    i = i + 1
  result = ""

proc quoteToml*(s: string): string {.role: helper,
    tag: "config|formatting".} =
  ## s: a string as a TOML basic string -- which is also a valid JSON
  ## string, so the table writer (./tabletext) uses it for both.
  ##
  ##   say "hi"<TAB><0x01>   ->   "say \"hi\"\t\u0001"
  ##
  ## Every other control character becomes `\u00HH`. Written raw, one of
  ## them made a file no TOML or JSON reader would accept. Bytes from 0x80
  ## up are UTF-8 and stay as they are.
  var
    i: int = 0
    t: string = "\""
  while i < s.len:
    case s[i]
    of '"': t = t & "\\\""
    of '\\': t = t & "\\\\"
    of '\n': t = t & "\\n"
    of '\t': t = t & "\\t"
    of '\r': t = t & "\\r"
    of '\x00' .. '\x08', '\x0B', '\x0C', '\x0E' .. '\x1F', '\x7F':
      t = t & "\\u00" & toHex(ord(s[i]), 2).toLowerAscii()
    else: t = t & s[i]
    i = i + 1
  result = t & "\""

proc bareKey(s: string): bool {.role: parser,
    tag: "config|formatting".} =
  ## s: may this key be written without quotes?
  var
    i: int = 0
  if s.len == 0:
    return false
  while i < s.len:
    if not (s[i] in {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '_'}):
      return false
    i = i + 1
  result = true

proc tomlKey*(s: string): string {.role: helper, inline,
    tag: "config|formatting".} =
  ## s: one key, quoted only when it has to be.
  result = if bareKey(s): s else: quoteToml(s)

proc arrayText(n: JsonNode): string {.role: helper,
    tag: "config|formatting".}
  ## Forward-declared: a list may hold lists, and each is written by it.

proc scalarText(n: JsonNode): string {.role: helper,
    tag: "config|formatting".} =
  ## n: one leaf as TOML.
  ##
  ## A float always carries a point. Written as `1` it would come back as
  ## an integer and be reported as mistyped on the next read -- a file
  ## that reports a problem it created itself is worse than no report.
  case n.kind
  of JString: result = quoteToml(n.getStr())
  of JBool: result = (if n.getBool(): "true" else: "false")
  of JInt: result = $n.getInt()
  of JFloat: result = n.getFloat().formatFloat(ffDecimal, -1)
  of JArray: result = arrayText(n)
  of JNull: result = "\"\""
  else: result = "\"\""

proc arrayText(n: JsonNode): string =
  ## n: an array of leaves, inline; a list inside it is written the same
  ## way, so [[1, 2], [3]] survives.
  var
    t: seq[string] = @[]
  for item in n.items:
    t.add scalarText(item)
  result = "[" & t.join(", ") & "]"

proc isTableArray(n: JsonNode): bool {.role: parser,
    tag: "config|formatting".} =
  ## n: an array whose items are tables becomes `[[header]]` blocks.
  ##
  ## An EMPTY array is not one: there is no way to write zero
  ## array-of-table blocks that a reader can tell from an absent key, so
  ## it is rendered as `[]` and read back as the empty seq it was.
  if n.kind != JArray or n.len == 0:
    return false
  result = n[0].kind == JObject

proc tomlHeader(path: seq[string]): string {.role: helper,
    tag: "config|formatting".} =
  ## path: the segments of a table header, each quoted only if it has to
  ## be, then joined with the dots TOML uses for nesting.
  ##
  ## EVERY SEGMENT GOES THROUGH `tomlKey`. A raw join looks right until a
  ## key contains a dot -- and the keys most likely to are the ones this
  ## is for: an email address, a hostname, an account name.
  ##
  ##   raw join     [account.alice@example.com]
  ##                  -> re-reads as account -> "alice@example" -> "com"
  ##   quoted       [account."alice@example.com"]
  ##                  -> re-reads as the one key it was written from
  ##
  ## The failure is silent and it is a ROUND-TRIP failure: the file looks
  ## plausible, and the damage only appears when it is read back, by
  ## which time the settings have moved into a table nobody looks in.
  var
    i: int = 0
  while i < path.len:
    if i > 0:
      result = result & "."
    result = result & tomlKey(path[i])
    i = i + 1

proc renderTable(path: seq[string], n: JsonNode, style: DocStyle,
    indent: string, L: var seq[string]) {.role: dataWriter,
    tag: "config|formatting|write".}
  ## Forward-declared: the two block writers below call back into it.

proc renderLeaf(name: string, value: JsonNode, note, indent: string,
    L: var seq[string]) {.role: dataWriter, tag: "config|formatting|write".} =
  ## name/value: one scalar or plain array, written as `key = value`.
  ## note/indent/L: its comment, the leading spaces, the output lines.
  if note.len > 0:
    L.add indent & "# " & note
  if value.kind == JArray:
    L.add indent & tomlKey(name) & " = " & arrayText(value)
  else:
    L.add indent & tomlKey(name) & " = " & scalarText(value)

proc renderSubTable(sub: seq[string], value: JsonNode, style: DocStyle,
    note, indent: string, L: var seq[string]) {.role: dataWriter,
    tag: "config|formatting|write".} =
  ## sub/value: one nested table, written as `[a.b]` and its body.
  ## style/note/indent/L: as in `renderTable`.
  L.add ""
  if note.len > 0:
    L.add indent & "# " & note
  L.add indent & "[" & tomlHeader(sub) & "]"
  renderTable(sub, value, style, indent, L)

proc renderTableArray(sub: seq[string], value: JsonNode, style: DocStyle,
    note, indent: string, L: var seq[string]) {.role: dataWriter,
    tag: "config|formatting|write".} =
  ## sub/value: an array of tables, written as one `[[a.b]]` block each.
  ## The note goes above the FIRST block only.
  ## style/note/indent/L: as in `renderTable`.
  var
    i: int = 0
  while i < value.len:
    L.add ""
    if note.len > 0 and i == 0:
      L.add indent & "# " & note
    L.add indent & "[[" & tomlHeader(sub) & "]]"
    renderTable(sub, value[i], style, indent & docIndentUnit, L)
    i = i + 1

proc renderTable(path: seq[string], n: JsonNode, style: DocStyle,
    indent: string, L: var seq[string]) =
  ## path: the dotted header this table lives under.
  ## n: the table.
  ## style: where the comments come from.
  ## indent: leading spaces for bodies nested inside `[[array]]` blocks.
  ## L: output lines.
  ##
  ## Leaves first, then sub-tables. TOML binds a bare key to the header
  ## above it, so a scalar written after a sub-table header would silently
  ## join the wrong table -- this ordering is not cosmetic.
  var
    dotted: string = ""
    sub: seq[string] = @[]
  for name, value in n.pairs:
    if value.kind != JObject and not isTableArray(value):
      dotted = dottedPath(path.join("."), name)
      renderLeaf(name, value, style.noteFor(dotted), indent, L)
  for name, value in n.pairs:
    dotted = dottedPath(path.join("."), name)
    sub = path & @[name]
    if value.kind == JObject:
      renderSubTable(sub, value, style, style.noteFor(dotted), indent, L)
    elif isTableArray(value):
      renderTableArray(sub, value, style, style.noteFor(dotted), indent, L)

proc renderDocToml*(n: JsonNode, style: DocStyle): string {.role: dataWriter,
    tag: "config|formatting|write".} =
  ## n/style: the whole file, comments and all.
  var
    L: seq[string] = @[]
    i: int = 0
  while i < style.header.len:
    L.add "# " & style.header[i]
    i = i + 1
  if style.header.len > 0:
    L.add ""
  renderTable(@[], n, style, "", L)
  result = L.join("\n").strip(leading = false) & "\n"

## ---------------------------- files ---------------------------------

proc formatOf*(path: string): DocFormat {.role: parser, inline,
    tag: "config".} =
  ## path: TOML unless the name says JSON. TOML is the house format; JSON
  ## exists because something else already speaks it.
  result = if path.toLowerAscii().endsWith(".json"): dfJson else: dfToml

proc parseDoc*(text: string, f: DocFormat): tuple[ok: bool, node: JsonNode,
    err: string] {.role: parser, tag: "config|parsing|read".} =
  ## text/f: the file contents as a node, or the reason they are not one.
  try:
    if f == dfJson:
      result = (true, parseJson(text), "")
    else:
      result = (true, parseTomlNode(text), "")
  except CatchableError as exc:
    result = (false, newJObject(), exc.msg)

## ---------------------------- converting ----------------------------
##
##   text --parseDoc--> JsonNode --renderDoc--> text in the other format
##
## JSON can say things TOML has no word for. A converter that met one and
## wrote something anyway would hand back a file that is quietly missing
## data, so `tomlProblem` walks the document first and names the place:
##
##   JSON                              TOML
##   --------------------------------  ----------------------------------
##   {"a": null}                       no null: refused, "a is null"
##   [1, 2] at the top                 a document is a table: refused
##   {"a": [{"x": 1}, 2]}              tables and values in one list:
##                                     refused, "a mixes tables with
##                                     plain values"
##   {"a": [[1, 2], [3]]}              fine: nested lists of values

proc tomlProblem(n: JsonNode, path: string): string {.role: sanitizer,
    tag: "config|parsing".}
  ## Forward-declared: a table's values and a list's items are checked by
  ## the two helpers below, which call back into it.

proc tomlItemsProblem(n: JsonNode, path: string): string {.role: sanitizer,
    tag: "config|parsing".} =
  ## n/path: a list -- all tables or no tables, and every item sound.
  var
    tables: int = 0
    i: int = 0
  for item in n.items:
    if item.kind == JObject:
      tables = tables + 1
  if tables > 0 and tables < n.len:
    return path & " mixes tables with plain values"
  while i < n.len:
    result = tomlProblem(n[i], path & "[" & $i & "]")
    if result.len > 0:
      return
    i = i + 1

proc tomlFieldsProblem(n: JsonNode, path: string): string {.role: sanitizer,
    tag: "config|parsing".} =
  ## n/path: a table -- every value sound.
  for key, value in n.pairs:
    result = tomlProblem(value, dottedPath(path, key))
    if result.len > 0:
      return

proc tomlProblem(n: JsonNode, path: string): string =
  ## n: one value of the document; path: where it sits, for the message.
  ## Returns "" when TOML can hold it exactly, or what it cannot hold.
  case n.kind
  of JNull: result = (if path.len > 0: path else: "the document") &
    " is null, and TOML has no null"
  of JObject: result = tomlFieldsProblem(n, path)
  of JArray: result = tomlItemsProblem(n, path)
  else: result = ""

proc formatName*(f: DocFormat): string {.role: helper, inline, stage: stDone,
    tag: "config|formatting".} =
  ## f: the format as people write it.
  result = if f == dfJson: "JSON" else: "TOML"

proc renderDoc*(n: JsonNode, f: DocFormat,
    style: DocStyle = defaultDocStyle()): string {.role: dataWriter,
    tag: "config|formatting".} =
  ## n/f/style: a parsed document as text in one format. JSON is indented;
  ## TOML carries the style's header and field notes.
  if f == dfJson:
    result = n.pretty() & "\n"
  else:
    result = renderDocToml(n, style)

proc convertDoc*(text: string, source, target: DocFormat): tuple[ok: bool,
    text: string, err: string] {.role: orchestrator,
    tag: "appApi|config|parsing".} =
  ## text: a whole document; source/target: what it is and what it should
  ## become. Returns the new text, or why it cannot be written in that
  ## format -- never a lossy version of it.
  var
    parsed: tuple[ok: bool, node: JsonNode, err: string] = parseDoc(text,
      source)
    problem: string = ""
  if not parsed.ok:
    return (false, "", "not valid " & formatName(source) & ": " & parsed.err)
  if target == dfToml and parsed.node.kind != JObject:
    return (false, "", "a TOML document is a table, and this " &
      formatName(source) & " document is a list or a single value")
  if target == dfToml:
    problem = tomlProblem(parsed.node, "")
  if problem.len > 0:
    return (false, "", problem)
  result = (true, renderDoc(parsed.node, target), "")

proc convertFile*(source, target: string): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|config|storageIo".} =
  ## source/target: two paths; each one's format comes from its extension
  ## (`.json`, anything else is TOML). The target is written through a
  ## temporary file and a rename, so a failure never leaves half a file.
  var
    text: string = ""
    converted: tuple[ok: bool, text: string, err: string] = (false, "", "")
  try:
    if getFileSize(source) > maxDocBytes:
      return (false, source & " is larger than " & $maxDocBytes & " bytes")
    text = readFile(source)
  except CatchableError as exc:
    return (false, "cannot read " & source & ": " & exc.msg)
  converted = convertDoc(text, formatOf(source), formatOf(target))
  if not converted.ok:
    return (false, source & ": " & converted.err)
  try:
    writeFile(target & ".new", converted.text)
    moveFile(target & ".new", target)
  except CatchableError as exc:
    return (false, "cannot write " & target & ": " & exc.msg)
  result = (true, "")

proc toDocText*[T](x: T, f: DocFormat,
    style: DocStyle = defaultDocStyle()): string {.role: dataWriter,
    tag: "appApi|config|formatting".} =
  ## x/f/style: an object as JSON or TOML text, every field present.
  result = renderDoc(toNode(x), f, style)

proc fromDocText*[T](text: string, f: DocFormat, fallback: T): tuple[
    value: T, report: DocReport] {.role: parser,
    tag: "appApi|config|parsing".} =
  ## text/f: a document; fallback: every default, as an object.
  ## The same rules as `readDoc`, without a file: what the text does not
  ## mention keeps its default, and what it gets wrong is reported.
  var
    parsed: tuple[ok: bool, node: JsonNode, err: string] = parseDoc(text, f)
  result.value = fallback
  result.report.ok = parsed.ok
  result.report.err = parsed.err
  if not parsed.ok:
    return
  fromNode(parsed.node, result.value, "", result.report)
  collectUnknown(parsed.node, toNode(fallback), "", result.report)

proc sectionKeys*(n: JsonNode, path: string): seq[string] {.role: parser,
    tag: "config|parsing|read".} =
  ## n: a parsed document, or nil.
  ## path: a dotted path to a table of named sub-tables, e.g. `account`.
  ##
  ## THE PROBLEM THIS SOLVES. A missing key falls back to the caller's
  ## default, and for a named sub-table there is no such default: the
  ## caller's table has no entry for a name it has never seen, so a
  ## section someone ADDED BY HAND gets the type's zero value for every
  ## field they did not write.
  ##
  ##   [account."alice@example.com"]
  ##   signature = "-- Alice"
  ##
  ## That should mean "an account with the usual settings, plus this
  ## signature". Without a prototype it means an account with `notify =
  ## false` and `autoSync = false`, which is an account that silently does
  ## nothing -- the worst possible reading of a line someone typed on
  ## purpose.
  ##
  ## So a caller reads the file once to learn which sections exist, seeds
  ## its fallback with a prototype for each, and reads again:
  ##
  ##   var seeded = defaults()
  ##   for name in sectionKeys(first.node, "account"):
  ##     seeded.account[name] = defaultAccountSettings()
  ##   result = ensureDoc(path, seeded, notes())
  ##
  ## Cheap: a settings file is small and is read at startup. The
  ## alternative -- a prototype threaded through the generic reader -- is
  ## a second schema mechanism for one case that a caller can express in
  ## three lines.
  ##
  ## Returns names, not values, and never raises: a path that is absent,
  ## is not a table, or holds scalars comes back empty.
  var
    at: JsonNode = n
    parts: seq[string] = @[]
    i: int = 0
  result = @[]
  if n == nil or n.kind != JObject:
    return
  parts = path.split('.')
  while i < parts.len:
    if at.kind != JObject or not at.hasKey(parts[i]):
      return
    at = at[parts[i]]
    i = i + 1
  if at.kind != JObject:
    return
  for name, value in at.pairs:
    if value.kind == JObject:
      result.add name

proc readDoc*[T](path: string, fallback: T): tuple[value: T,
    node: JsonNode, report: DocReport] {.role: orchestrator,
    tag: "appApi|config|read|storageIo".} =
  ## path: the file, which need not exist.
  ## fallback: every default, as an object. This IS the schema: what is
  ##   not a field of it is not a setting.
  ##
  ## Returns the value, the raw node (so a writer can put the strays back)
  ## and what happened. A missing file is a success with the defaults --
  ## "no settings" is a valid state, and a program that refused to start
  ## without a config file it also ships defaults for is asking a question
  ## it already knows the answer to.
  var
    text: string = ""
    parsed: tuple[ok: bool, node: JsonNode, err: string] =
      (false, default(JsonNode), "")
  result.value = fallback
  result.node = newJObject()
  result.report.ok = true
  result.report.path = path
  if not fileExists(path):
    return
  try:
    if getFileSize(path) > maxDocBytes:
      result.report.ok = false
      result.report.err = "larger than " & $maxDocBytes & " bytes"
      return
    text = readFile(path)
  except CatchableError as exc:
    result.report.ok = false
    result.report.err = exc.msg
    return
  parsed = parseDoc(text, formatOf(path))
  if not parsed.ok:
    result.report.ok = false
    result.report.err = parsed.err
    return
  result.node = parsed.node
  fromNode(parsed.node, result.value, "", result.report)
  collectUnknown(parsed.node, toNode(fallback), "", result.report)

proc writeDoc*[T](path: string, x: T, style: DocStyle = defaultDocStyle(),
    keep: JsonNode = nil): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "appApi|config|storageIo|write".} =
  ## path: where to write; the directory is created if it is missing.
  ## x: the object, every field of which becomes a line.
  ## style: header and per-field comments.
  ## keep: the node a previous `readDoc` returned. Pass it to preserve the
  ##   keys the object has no field for; pass nothing to write only what
  ##   the object knows about.
  ##
  ## Writes through a temporary file and renames, so a process that dies
  ## mid-write leaves the previous settings rather than half of the new
  ## ones.
  var
    n: JsonNode = toNode(x)
    text: string = ""
    tmp: string = path & ".new"
  if style.keepUnknown and keep != nil:
    mergeUnknown(keep, n)
  text = renderDoc(n, formatOf(path), style)
  try:
    if path.parentDir().len > 0:
      createDir(path.parentDir())
    writeFile(tmp, text)
    moveFile(tmp, path)
  except CatchableError as exc:
    return (false, exc.msg)
  result = (true, "")

proc ensureDoc*[T](path: string, fallback: T,
    style: DocStyle = defaultDocStyle()): tuple[value: T, report: DocReport,
    written: bool] {.role: orchestrator,
    tag: "appApi|config|storageIo".} =
  ## path/fallback/style: read the file, then write it back out complete.
  ##
  ## The call an application makes at startup. After it, the file on disk
  ## lists EVERY option with a value -- the ones that were there, the
  ## defaults for the ones that were not, and the strays untouched -- so
  ## nobody has to read the source to find out what can be configured.
  ##
  ## `written` is false when the file could not be parsed. A file with a
  ## syntax error is left exactly as it is: overwriting it with defaults
  ## would delete the settings the person was in the middle of fixing.
  var
    t: tuple[value: T, node: JsonNode, report: DocReport] =
      (default(T), default(JsonNode), default(DocReport))
    w: tuple[ok: bool, err: string] = (false, "")
  t = readDoc(path, fallback)
  result.value = t.value
  result.report = t.report
  if not t.report.ok:
    return
  w = writeDoc(path, t.value, style, t.node)
  result.written = w.ok
  if not w.ok:
    result.report.ok = false
    result.report.err = w.err
