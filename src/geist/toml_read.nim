## ---------------------------------------------------------------------
## Toml read <- the five things every settings file needs
## ---------------------------------------------------------------------
##
##   tomlOf(path)          a file, an empty table, or an error
##   runtimeOf(path)       its [runtime] table, the build preset laid over
##   section(node, name)   one table, or an empty one
##   checkKeys(...)        refuse a key nothing acts on
##   setting(n, key, fb)   one value, typed by its fallback
##
## Extracted so that the settings a STORAGE user cares about and the
## settings a NETWORK user cares about can live in different modules
## without either duplicating the reader or importing the other. It knows
## nothing about Geist; it is the TOML half of `settings.nim` and its
## transport counterpart.
##
## The parsing itself is Fylgia's (`parseTomlNode`), not another
## hand-rolled one. What is here is the rule that an unknown key is an
## ERROR rather than a shrug: a typo in a settings file otherwise looks
## exactly like a setting that had no effect.

import std/[json, os, strutils]

import fylgia_utils

import runePragmas
import var_invariants

const
  libraryConfigName* = "configs/default.toml"
    ## The library defaults file. Named here rather than in `settings.nim`
    ## because both halves of the reader -- storage and transport -- open
    ## the same file. Only its `[runtime]` table is read here; the other
    ## tables say how the program is BUILT and are read by config.nims.
  presetFiles {.strdefine.}: string = ""
    ## Handed in by config.nims: every configs/*.toml this build was made
    ## from, base first, separated by ';'. Only the FILE NAMES are used, so
    ## a program built with -d:preset=server looks for
    ## configs/default.toml and then configs/server.toml in its own working
    ## directory -- never at a path on the machine that compiled it.

proc tomlOf*(path: string): tuple[ok: bool, node: JsonNode, err: string] {.
    role: parser, tag: "config|parsing|read".} =
  ## path: a TOML file, or nothing.
  ##
  ## A missing file is OK with an empty table: "no settings" is a valid
  ## state. A file that is THERE and will not parse is an error, because
  ## the alternative is running with defaults the operator did not choose
  ## and cannot see.
  if not fileExists(path):
    return (true, newJObject(), "")
  try:
    result = (true, parseTomlNode(readFile(path)), "")
  except CatchableError as exc:
    result = (false, newJObject(), path & ": " & exc.msg)

proc section*(n: JsonNode, name: string): JsonNode {.role: parser,
    tag: "config|parsing".} =
  ## n/name: one table, or an empty one when it is absent.
  if n.kind == JObject and n.hasKey(name) and n[name].kind == JObject:
    return n[name]
  result = newJObject()

proc layKeys(a: JsonNode, b: JsonNode) {.role: truthBuilder, inline,
    tag: "config|parsing".} =
  ## a/b: two tables; every key of b replaces the same key of a.
  for key, value in b.pairs:
    a[key] = value

proc layOver(a: var JsonNode, b: JsonNode) {.role: truthBuilder,
    tag: "config|parsing".} =
  ## a/b: b's keys replace a's, one table level deep -- the same rule the
  ## build preset follows, so `[runtime.transport] startTier` in server.toml
  ## replaces only that one key of default.toml.
  ##
  ##   a  [storage] preset = "app"   sidecarThreshold = 1024
  ##   b  [storage] preset = "iot"
  ##   ->  [storage] preset = "iot"   sidecarThreshold = 1024
  for name, table in b.pairs:
    if a.hasKey(name) and a[name].kind == JObject and table.kind == JObject:
      a[name].layKeys(table)
    else:
      a[name] = table

proc overlayNames*(path: string): seq[string] {.role: parser,
    tag: "config|parsing",
    gives: result.len == 0 or path == libraryConfigName.} =
  ## path: the base file -> the preset files laid over it, as paths beside
  ## it. Empty unless the base is the library default AND the build named a
  ## preset.
  ##
  ##   presetFiles = "/build/configs/default.toml;/build/configs/iot.toml"
  ##   path        = "configs/default.toml"
  ##   ->            @["configs/iot.toml"]
  var
    A: seq[string] = @[]
    i: int = 1
  if path != libraryConfigName or presetFiles.len == 0:
    return @[]
  A = presetFiles.split(';')
  while i < A.len:
    result.add parentDir(path) / extractFilename(A[i])
    i = i + 1

proc runtimeOf*(path: string, overlays: seq[string] = overlayNames(path)):
    tuple[ok: bool, node: JsonNode, err: string] {.role: parser,
    tag: "config|parsing|read".} =
  ## path: a settings file -> its `[runtime]` table.
  ## overlays: files whose `[runtime]` is laid over it, in order. By default
  ## the build preset's own file (see `overlayNames`).
  ##
  ##   [runtime.storage]      ->  node["storage"]
  ##   [runtime.transport]    ->  node["transport"]
  ##
  ## Missing files are fine: "no settings" is a valid state. A file that
  ## is there and will not parse stops here, whichever layer it is.
  var
    doc: tuple[ok: bool, node: JsonNode, err: string] = tomlOf(path)
    layer: tuple[ok: bool, node: JsonNode, err: string] = (true, nil, "")
  if not doc.ok:
    return (false, newJObject(), doc.err)
  result = (true, doc.node.section("runtime"), "")
  for f in overlays:
    layer = tomlOf(f)
    if not layer.ok:
      return (false, newJObject(), layer.err)
    result.node.layOver(layer.node.section("runtime"))

proc checkKeys*(n: JsonNode, known: openArray[string],
    where: string): string {.role: sanitizer,
    tag: "config|parsing".} =
  ## n/known/where: every key in this table must be one we act on.
  ##
  ## Returns the complaint, empty when there is none. A misspelled setting
  ## that is silently ignored is indistinguishable from one that did not
  ## work, and the person who wrote it will believe it took effect.
  var
    unknown: seq[string] = @[]
  if n.kind != JObject:
    return ""
  for key, _ in n.pairs:
    if not (key in known):
      unknown.add key
  if unknown.len == 0:
    return ""
  result = where & ": unknown setting" & (if unknown.len > 1: "s " else: " ") &
    unknown.join(", ") & "; known: " & known.join(", ")

proc setting*[T: string | SomeInteger | bool](n: JsonNode, key: string,
    fallback: T): T {.role: parser, tag: "config|parsing".} =
  ## n/key/fallback: one setting of whatever type the fallback is.
  ##
  ## The fallback decides the type, so a caller writes what it wants and
  ## gets it: `storage.setting("preset", "app")`,
  ## `backup.setting("copies", 2'u8)`. A value of the wrong TOML kind is
  ## treated as absent -- `checkKeys` has already refused anything the
  ## schema does not know, so what is left is a type slip, and running on
  ## the documented default beats running on a coerced guess.
  result = fallback
  if not n.hasKey(key):
    return
  when T is string:
    if n[key].kind == JString:
      result = n[key].getStr()
  elif T is bool:
    if n[key].kind == JBool:
      result = n[key].getBool()
  else:
    if n[key].kind == JInt:
      result = T(n[key].getInt())

proc setting*(n: JsonNode, key: string, fallback: seq[string]): seq[string] {.
    role: parser, tag: "config|parsing".} =
  ## n/key/fallback: a list of strings, tolerating a bare string as a list
  ## of one -- `trust = "a.pin"` is what a person writes when there is only
  ## one, and refusing it would be pedantry rather than safety.
  result = fallback
  if not n.hasKey(key):
    return
  if n[key].kind == JString:
    return @[n[key].getStr()]
  if n[key].kind != JArray:
    return
  result = @[]
  for item in n[key].items:
    if item.kind == JString:
      result.add item.getStr()
