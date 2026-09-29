## ---------------------------------------------------------------------
## Doc node <- an ordinary Nim object as a JSON tree, and back
## ---------------------------------------------------------------------
##
##   T  --toNode-->    JsonNode   every field by name, nested objects,
##                                lists and tables included
##   T  <-fromNode--   JsonNode   starting from defaults: a missing key
##                                keeps its default, a mistyped one is
##                                reported, an unknown one is reported
##
## The tree is the middle of every conversion ./doc does -- to a TOML or
## JSON file, to text, into a sealed blob (./seal). This half knows nothing
## about text; ./doc knows nothing about objects.

import std/[json, os, strutils, tables]

import fylgia_utils

import runePragmas

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
  DocFormat* {.role: configurator, tag: "config|types".} = enum
    ## Which text the object becomes. Chosen from the file extension by
    ## `formatOf`, so a caller normally never names one.
    dfToml, dfJson

  DocNote* {.role: configurator, tag: "config|docs|types".} =
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

  DocStyle* {.role: configurator, tag: "config|docs|types".} =
      object
    ## header: lines written at the top of the file, each prefixed `# `.
    ## notes: per-field comments.
    ## keepUnknown: write back keys the object does not have. On by
    ##   default -- see the second rule above.
    header*: seq[string]
    notes*: seq[DocNote]
    keepUnknown*: bool

  DocReport* {.role: truthState, tag: "config|status|types".} = object
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

proc defaultDocStyle*(): DocStyle {.role: configurator, stage: stDone,
    tag: "config|docs".} =
  ## No header, no notes, unknown keys preserved.
  result.keepUnknown = true

proc noteOn*(S: var DocStyle, field, note: string) {.role: configurator,
    inline, tag: "config|docs".} =
  ## S/field/note: attach one comment to one dotted path.
  S.notes.add DocNote(field: field, note: note)

proc hasProblems*(r: DocReport): bool {.role: parser, inline,
    tag: "config|status".} =
  ## r: did anything in the file fail to apply?
  ##
  ## `missing` is deliberately NOT a problem: an absent option is the
  ## normal state of a file someone has trimmed.
  result = not r.ok or r.unknown.len > 0 or r.mistyped.len > 0

proc describe*(r: DocReport): string {.role: helper,
    tag: "config|docs|status".} =
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
    tag: "codecBoundary|config".} =
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
    tag: "codecBoundary|config".} =
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
    tag: "codecBoundary|config".} =
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

proc dottedPath*(prefix, name: string): string {.role: helper, inline,
    tag: "config".} =
  ## prefix/name: the dotted path a report names a field by.
  result = if prefix.len > 0: prefix & "." & name else: name

proc fromNodeB[T](n: JsonNode, S: var T, prefix: string, R: var DocReport)

proc readScalar[T](n: JsonNode, S: var T, path: string,
    R: var DocReport) {.role: parser,
    tag: "codecBoundary|config|parsing".} =
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
      return
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

proc fieldViaB[T](n: JsonNode, key: string, v: var T, prefix: string,
    R: var DocReport) {.role: parser, tag: "codecBoundary|config|parsing".} =
  ## n/key/v/prefix/R: one field of an object, read from the table
  ## through `fromNodeB` -- or reported missing, keeping its default.
  if n.hasKey(key):
    fromNodeB(n[key], v, dottedPath(prefix, key), R)
  else:
    R.missing.add dottedPath(prefix, key)

proc fromNode*[T](n: JsonNode, S: var T, prefix: string,
    R: var DocReport) {.role: parser,
    tag: "codecBoundary|config|parsing".} =
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
      return
    S = @[]
    for ia in n.items:
      var ta: typeof(S[0]) = default(typeof(S[0]))
      fromNodeB(ia, ta, prefix & "[]", R)
      S.add ta
  elif T is OrderedTable or T is Table:
    if n.kind != JObject:
      R.mistyped.add prefix
      return
    for ka, va in n.pairs:
      # what the table already holds for this key is the default
      var ta: typeof(S[ka]) = S.getOrDefault(ka)
      fromNodeB(va, ta, dottedPath(prefix, ka), R)
      S[ka] = ta
  elif T is object:
    if n.kind != JObject:
      R.mistyped.add prefix
      return
    for fa, va in fieldPairs(S):
      fieldViaB(n, fa, va, prefix, R)

proc fieldViaA[T](n: JsonNode, key: string, v: var T, prefix: string,
    R: var DocReport) {.role: parser, tag: "codecBoundary|config|parsing".} =
  ## Alternating twin of `fieldViaB`, through `fromNode`.
  if n.hasKey(key):
    fromNode(n[key], v, dottedPath(prefix, key), R)
  else:
    R.missing.add dottedPath(prefix, key)

proc fromNodeB[T](n: JsonNode, S: var T, prefix: string,
    R: var DocReport) {.role: parser,
    tag: "codecBoundary|config|parsing".} =
  ## Alternating twin of `fromNode`; see the note there.
  when T is JsonNode:
    S = n
  elif T is string or T is bool or T is enum or T is SomeNumber:
    readScalar(n, S, prefix, R)
  elif T is seq:
    if n.kind != JArray:
      R.mistyped.add prefix
      return
    S = @[]
    for ib in n.items:
      var tb: typeof(S[0]) = default(typeof(S[0]))
      fromNode(ib, tb, prefix & "[]", R)
      S.add tb
  elif T is OrderedTable or T is Table:
    if n.kind != JObject:
      R.mistyped.add prefix
      return
    for kb, vb in n.pairs:
      # what the table already holds for this key is the default
      var tb: typeof(S[kb]) = S.getOrDefault(kb)
      fromNode(vb, tb, dottedPath(prefix, kb), R)
      S[kb] = tb
  elif T is object:
    if n.kind != JObject:
      R.mistyped.add prefix
      return
    for fb, vb in fieldPairs(S):
      fieldViaA(n, fb, vb, prefix, R)

## ---------------------------- unknown keys --------------------------

proc collectUnknown*(have, want: JsonNode, prefix: string,
    R: var DocReport) {.role: parser,
    tag: "config|parsing".} =
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

proc mergeUnknown*(have, want: JsonNode) {.role: truthBuilder,
    tag: "config|write".} =
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

