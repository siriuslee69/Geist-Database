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

import std/[json, os, strutils, tables]

import fylgia_utils

import geistPragmas

const
  docIndentUnit* = "  "
    ## What one level of nesting costs in a rendered TOML file. Only
    ## array-of-table bodies indent; top-level tables do not, because TOML
    ## headers carry their own full path and indenting them buys nothing.
  maxDocBytes* = 4 * 1024 * 1024
    ## The largest settings file that will be read. A config that has
    ## grown past four mebibytes is a database, and there is one of those
    ## in the next module along.

type
  DocFormat* {.role: configurator, metaTags: {tagConfig, tagTypes}.} = enum
    ## Which text the object becomes. Chosen from the file extension by
    ## `formatOf`, so a caller normally never names one.
    dfToml, dfJson

  DocNote* {.role: configurator, metaTags: {tagConfig, tagDocs, tagTypes}.} =
      object
    ## One comment, attached to a dotted field path.
    ##
    ##   DocNote(field: "storage.transposeEverySeconds",
    ##           note: "0 means never; only used when transpose = interval")
    ##
    ## Attached by PATH rather than declared beside the field because the
    ## objects being written are ordinary Nim objects that other modules
    ## own, and a settings writer has no business demanding pragmas on
    ## them.
    field*: string
    note*: string

  DocStyle* {.role: configurator, metaTags: {tagConfig, tagDocs, tagTypes}.} =
      object
    ## header: lines written at the top of the file, each prefixed `# `.
    ## notes: per-field comments.
    ## keepUnknown: write back keys the object does not have. On by
    ##   default -- see the second rule above.
    header*: seq[string]
    notes*: seq[DocNote]
    keepUnknown*: bool

  DocReport* {.role: truthState, metaTags: {tagConfig, tagStatus,
      tagTypes}.} = object
    ## What happened, in enough detail to show a person.
    ##
    ## `ok` is false only when the file could not be PARSED. A file full
    ## of unknown keys and mistyped values parses fine and reports both;
    ## that is a file with problems, not a failure to read one.
    ok*: bool
    err*: string
    path*: string
    missing*: seq[string]
    unknown*: seq[string]
    mistyped*: seq[string]

proc defaultDocStyle*(): DocStyle {.role: configurator,
    metaTags: {tagConfig, tagDocs}.} =
  ## No header, no notes, unknown keys preserved.
  result.keepUnknown = true

proc noteOn*(S: var DocStyle, field, note: string) {.role: configurator,
    inline, metaTags: {tagConfig, tagDocs}.} =
  ## S/field/note: attach one comment to one dotted path.
  S.notes.add DocNote(field: field, note: note)

proc hasProblems*(r: DocReport): bool {.role: parser, inline,
    metaTags: {tagConfig, tagStatus}.} =
  ## r: did anything in the file fail to apply?
  ##
  ## `missing` is deliberately NOT a problem: an absent option is the
  ## normal state of a file someone has trimmed.
  result = not r.ok or r.unknown.len > 0 or r.mistyped.len > 0

proc describe*(r: DocReport): string {.role: helper,
    metaTags: {tagConfig, tagDocs, tagStatus}.} =
  ## r: one line per thing worth telling the person who edited the file.
  var
    t: seq[string] = @[]
  if not r.ok:
    t.add r.path & ": " & r.err
  if r.unknown.len > 0:
    t.add r.path & ": kept " & $r.unknown.len &
      " setting(s) nothing reads: " & r.unknown.join(", ")
  if r.mistyped.len > 0:
    t.add r.path & ": wrong type, using the default: " & r.mistyped.join(", ")
  result = t.join("\n")

## ---------------------------- object -> node ------------------------

proc toNodeB[T](x: T): JsonNode

proc scalarNode[T](v: T): JsonNode {.role: encryptor,
    metaTags: {tagCodecBoundary, tagConfig}.} =
  ## v: one leaf value as the JSON kind TOML will render it from.
  ##
  ## An enum becomes its NAME. A settings file that said `writeMode = 2`
  ## would be unreadable and would silently mean something else the day a
  ## case is inserted above it.
  when T is string:
    result = newJString(v)
  elif T is bool:
    result = newJBool(v)
  elif T is enum:
    result = newJString($v)
  elif T is SomeFloat:
    result = newJFloat(float(v))
  else:
    result = newJInt(BiggestInt(v))

proc toNode*[T](x: T): JsonNode {.role: encryptor,
    metaTags: {tagCodecBoundary, tagConfig}.} =
  ## x: any supported value, turned into the node a renderer takes.
  ##
  ## `fieldPairs` unrolls lexically, so a nested level cannot reuse this
  ## loop's identifiers. `toNodeB` is the alternating twin that makes
  ## arbitrary depth work -- the same device `mapper.nim` uses, and for
  ## the same reason. Do not merge them.
  when T is JsonNode:
    result = x
  elif T is string or T is bool or T is enum or T is SomeNumber:
    result = scalarNode(x)
  elif T is seq:
    result = newJArray()
    for ia in x.items:
      result.add toNodeB(ia)
  elif T is OrderedTable:
    result = newJObject()
    for ka, va in x.pairs:
      result[ka] = toNodeB(va)
  elif T is Table:
    result = newJObject()
    for ka, va in x.pairs:
      result[ka] = toNodeB(va)
  elif T is object:
    result = newJObject()
    for fa, va in fieldPairs(x):
      result[fa] = toNodeB(va)
  else:
    result = newJNull()

proc toNodeB[T](x: T): JsonNode {.role: encryptor,
    metaTags: {tagCodecBoundary, tagConfig}.} =
  ## Alternating twin of `toNode`; see the note there.
  when T is JsonNode:
    result = x
  elif T is string or T is bool or T is enum or T is SomeNumber:
    result = scalarNode(x)
  elif T is seq:
    result = newJArray()
    for ib in x.items:
      result.add toNode(ib)
  elif T is OrderedTable:
    result = newJObject()
    for kb, vb in x.pairs:
      result[kb] = toNode(vb)
  elif T is Table:
    result = newJObject()
    for kb, vb in x.pairs:
      result[kb] = toNode(vb)
  elif T is object:
    result = newJObject()
    for fb, vb in fieldPairs(x):
      result[fb] = toNode(vb)
  else:
    result = newJNull()

## ---------------------------- node -> object ------------------------

proc dottedPath(prefix, name: string): string {.role: helper, inline,
    metaTags: {tagConfig}.} =
  ## prefix/name: the dotted path a report names a field by.
  result = if prefix.len > 0: prefix & "." & name else: name

proc fromNodeB[T](n: JsonNode, S: var T, prefix: string, R: var DocReport)

proc readScalar[T](n: JsonNode, S: var T, path: string,
    R: var DocReport) {.role: parser,
    metaTags: {tagCodecBoundary, tagConfig, tagParsing}.} =
  ## n/S/path/R: one leaf, left alone when the node is the wrong kind.
  ##
  ## An int is accepted for a float because `2` and `2.0` are the same
  ## number to everyone except a parser, and a person writing a settings
  ## file is not a parser.
  when T is string:
    if n.kind == JString: S = n.getStr()
    else: R.mistyped.add path
  elif T is bool:
    if n.kind == JBool: S = n.getBool()
    else: R.mistyped.add path
  elif T is enum:
    if n.kind != JString:
      R.mistyped.add path
    else:
      try:
        S = parseEnum[T](n.getStr())
      except ValueError:
        R.mistyped.add path
  elif T is SomeFloat:
    if n.kind == JFloat: S = T(n.getFloat())
    elif n.kind == JInt: S = T(n.getInt())
    else: R.mistyped.add path
  else:
    if n.kind == JInt: S = T(n.getInt())
    else: R.mistyped.add path

proc fromNode*[T](n: JsonNode, S: var T, prefix: string,
    R: var DocReport) {.role: parser,
    metaTags: {tagCodecBoundary, tagConfig, tagParsing}.} =
  ## n: the parsed file, or one branch of it.
  ## S: the value being filled, PRE-LOADED WITH THE DEFAULTS. Anything the
  ##   file does not mention keeps what it already had, which is what
  ##   makes a missing key mean "the default" without a second copy of the
  ##   defaults living here.
  ## prefix: dotted path, for the report.
  ## R: accumulating report.
  ##
  ## Alternates with `fromNodeB` for depth; see `toNode`.
  when T is JsonNode:
    S = n
  elif T is string or T is bool or T is enum or T is SomeNumber:
    readScalar(n, S, prefix, R)
  elif T is seq:
    if n.kind != JArray:
      R.mistyped.add prefix
    else:
      S = @[]
      for ia in n.items:
        var ta: typeof(S[0])
        fromNodeB(ia, ta, prefix & "[]", R)
        S.add ta
  elif T is OrderedTable or T is Table:
    if n.kind != JObject:
      R.mistyped.add prefix
    else:
      for ka, va in n.pairs:
        var ta: typeof(S[ka])
        if S.hasKey(ka):
          ta = S[ka]
        fromNodeB(va, ta, dottedPath(prefix, ka), R)
        S[ka] = ta
  elif T is object:
    if n.kind != JObject:
      R.mistyped.add prefix
    else:
      for fa, va in fieldPairs(S):
        if n.hasKey(fa):
          fromNodeB(n[fa], va, dottedPath(prefix, fa), R)
        else:
          R.missing.add dottedPath(prefix, fa)

proc fromNodeB[T](n: JsonNode, S: var T, prefix: string,
    R: var DocReport) {.role: parser,
    metaTags: {tagCodecBoundary, tagConfig, tagParsing}.} =
  ## Alternating twin of `fromNode`; see the note there.
  when T is JsonNode:
    S = n
  elif T is string or T is bool or T is enum or T is SomeNumber:
    readScalar(n, S, prefix, R)
  elif T is seq:
    if n.kind != JArray:
      R.mistyped.add prefix
    else:
      S = @[]
      for ib in n.items:
        var tb: typeof(S[0])
        fromNode(ib, tb, prefix & "[]", R)
        S.add tb
  elif T is OrderedTable or T is Table:
    if n.kind != JObject:
      R.mistyped.add prefix
    else:
      for kb, vb in n.pairs:
        var tb: typeof(S[kb])
        if S.hasKey(kb):
          tb = S[kb]
        fromNode(vb, tb, dottedPath(prefix, kb), R)
        S[kb] = tb
  elif T is object:
    if n.kind != JObject:
      R.mistyped.add prefix
    else:
      for fb, vb in fieldPairs(S):
        if n.hasKey(fb):
          fromNode(n[fb], vb, dottedPath(prefix, fb), R)
        else:
          R.missing.add dottedPath(prefix, fb)

## ---------------------------- unknown keys --------------------------

proc collectUnknown(have, want: JsonNode, prefix: string,
    R: var DocReport) {.role: parser,
    metaTags: {tagConfig, tagParsing}.} =
  ## have: the file as parsed.
  ## want: the same shape as the object produces.
  ## prefix/R: where we are, and what to add to.
  ##
  ## Walks only where BOTH sides are tables. A key present in the file and
  ## absent from the object is unknown at whatever depth it appears, and a
  ## whole unknown SECTION is reported once by its own name rather than
  ## once per leaf inside it -- one line about `[friend.alcie]` is more
  ## use than nine about its settings.
  var
    t: string = ""
  if have.kind != JObject or want.kind != JObject:
    return
  for key, value in have.pairs:
    t = dottedPath(prefix, key)
    if not want.hasKey(key):
      R.unknown.add t
    elif value.kind == JObject and want[key].kind == JObject:
      collectUnknown(value, want[key], t, R)

proc mergeUnknown(have, want: JsonNode) {.role: truthBuilder,
    metaTags: {tagConfig, tagWrite}.} =
  ## have: the file as it was read.
  ## want: the node about to be written, mutated to carry the strays.
  ##
  ## What makes a round trip lossless. The object's own values always
  ## win; only keys the object HAS NO FIELD FOR are copied across.
  if have.kind != JObject or want.kind != JObject:
    return
  for key, value in have.pairs:
    if not want.hasKey(key):
      want[key] = value
    elif value.kind == JObject and want[key].kind == JObject:
      mergeUnknown(value, want[key])

## ---------------------------- TOML rendering ------------------------

proc noteFor(style: DocStyle, path: string): string {.role: parser,
    metaTags: {tagConfig, tagDocs}.} =
  ## style/path: the comment attached to this dotted path, or nothing.
  var
    i: int = 0
  while i < style.notes.len:
    if style.notes[i].field == path:
      return style.notes[i].note
    i = i + 1
  result = ""

proc quoteToml(s: string): string {.role: helper,
    metaTags: {tagConfig, tagFormatting}.} =
  ## s: a string as a TOML basic string.
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
    else: t = t & s[i]
    i = i + 1
  result = t & "\""

proc bareKey(s: string): bool {.role: parser,
    metaTags: {tagConfig, tagFormatting}.} =
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

proc tomlKey(s: string): string {.role: helper, inline,
    metaTags: {tagConfig, tagFormatting}.} =
  ## s: one key, quoted only when it has to be.
  result = if bareKey(s): s else: quoteToml(s)

proc scalarText(n: JsonNode): string {.role: helper,
    metaTags: {tagConfig, tagFormatting}.} =
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
  of JNull: result = "\"\""
  else: result = "\"\""

proc arrayText(n: JsonNode): string {.role: helper,
    metaTags: {tagConfig, tagFormatting}.} =
  ## n: an array of leaves, inline.
  var
    t: seq[string] = @[]
  for item in n.items:
    t.add scalarText(item)
  result = "[" & t.join(", ") & "]"

proc isTableArray(n: JsonNode): bool {.role: parser,
    metaTags: {tagConfig, tagFormatting}.} =
  ## n: an array whose items are tables becomes `[[header]]` blocks.
  ##
  ## An EMPTY array is not one: there is no way to write zero
  ## array-of-table blocks that a reader can tell from an absent key, so
  ## it is rendered as `[]` and read back as the empty seq it was.
  if n.kind != JArray or n.len == 0:
    return false
  result = n[0].kind == JObject

proc tomlHeader(path: seq[string]): string {.role: helper,
    metaTags: {tagConfig, tagFormatting}.} =
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
    metaTags: {tagConfig, tagFormatting, tagWrite}.} =
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
    note: string = ""
    key: string = ""
    header: string = ""
    i: int = 0
    sub: seq[string] = @[]
  for name, value in n.pairs:
    dotted = path.join(".")
    dotted = dottedPath(dotted, name)
    if value.kind == JObject or isTableArray(value):
      continue
    note = style.noteFor(dotted)
    if note.len > 0:
      L.add indent & "# " & note
    key = tomlKey(name)
    if value.kind == JArray:
      L.add indent & key & " = " & arrayText(value)
    else:
      L.add indent & key & " = " & scalarText(value)
  for name, value in n.pairs:
    dotted = path.join(".")
    dotted = dottedPath(dotted, name)
    sub = path & @[name]
    header = tomlHeader(sub)
    if value.kind == JObject:
      note = style.noteFor(dotted)
      L.add ""
      if note.len > 0:
        L.add indent & "# " & note
      L.add indent & "[" & header & "]"
      renderTable(sub, value, style, indent, L)
    elif isTableArray(value):
      note = style.noteFor(dotted)
      i = 0
      while i < value.len:
        L.add ""
        if note.len > 0 and i == 0:
          L.add indent & "# " & note
        L.add indent & "[[" & header & "]]"
        renderTable(sub, value[i], style, indent & docIndentUnit, L)
        i = i + 1

proc renderDocToml*(n: JsonNode, style: DocStyle): string {.role: dataWriter,
    metaTags: {tagConfig, tagFormatting, tagWrite}.} =
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
    metaTags: {tagConfig}.} =
  ## path: TOML unless the name says JSON. TOML is the house format; JSON
  ## exists because something else already speaks it.
  result = if path.toLowerAscii().endsWith(".json"): dfJson else: dfToml

proc parseDoc*(text: string, f: DocFormat): tuple[ok: bool, node: JsonNode,
    err: string] {.role: parser, metaTags: {tagConfig, tagParsing, tagRead}.} =
  ## text/f: the file contents as a node, or the reason they are not one.
  try:
    if f == dfJson:
      result = (true, parseJson(text), "")
    else:
      result = (true, parseTomlNode(text), "")
  except CatchableError as exc:
    result = (false, newJObject(), exc.msg)

proc sectionKeys*(n: JsonNode, path: string): seq[string] {.role: parser,
    metaTags: {tagConfig, tagParsing, tagRead}.} =
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
    metaTags: {tagAppApi, tagConfig, tagRead, tagStorageIo}.} =
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
    parsed: tuple[ok: bool, node: JsonNode, err: string]
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
    metaTags: {tagAppApi, tagConfig, tagStorageIo, tagWrite}.} =
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
  if formatOf(path) == dfJson:
    text = n.pretty() & "\n"
  else:
    text = renderDocToml(n, style)
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
    metaTags: {tagAppApi, tagConfig, tagStorageIo}.} =
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
    t: tuple[value: T, node: JsonNode, report: DocReport]
    w: tuple[ok: bool, err: string]
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
