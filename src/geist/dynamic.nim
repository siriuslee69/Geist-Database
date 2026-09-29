## ---------------------------------------------------------------------
## Dynamic <- schema-driven row access for tools that do not know T
## ---------------------------------------------------------------------
##
##   "id:int,title:text,body:text"  --parseSchemaSpec-->  Schema
##   ["title=hello", "id=3"]        --buildRow-------->   Row
##   Row + Schema                   --renderRow------->   seq[string]
##
## The typed path (`toRow[T]` / `fromRow[T]`) is how applications use
## Geist. A CLI cannot use it: the object type lives in the caller's
## program, not in the tool. But the schema is stored IN the cluster, so a
## tool can read it back and work slot-by-slot without ever knowing T.
##
## This module is that path. It is deliberately separate from `mapper`,
## which stays compile-time and allocation-light.

import std/[strutils, tables]

import runePragmas
import ./types
import ./mapper
import ./row
import ./sidecar

proc slotKindFromName*(s: string): tuple[ok: bool, kind: SlotKind,
    err: string] {.role: parser, tag: "cli|parsing|read".} =
  ## s: type word from a schema spec.
  case s.strip().toLowerAscii()
  of "int", "i", "integer": result = (true, skInt, "")
  of "float", "f", "double": result = (true, skFloat, "")
  of "text", "t", "string", "str": result = (true, skText, "")
  of "bytes", "b", "blob": result = (true, skBytes, "")
  of "ref", "r", "sidecar": result = (true, skRef, "")
  else:
    result = (false, skNull,
      "unknown field type '" & s & "'; expected int, float, text, bytes or ref")

proc isVariableSlot*(k: SlotKind): bool {.role: parser, inline,
    tag: "cli|read".} =
  ## k: slot kind whose bytes live in the overflow region rather than the
  ## 8-byte fixed slot.
  result = k in {skText, skBytes, skSealed, skRef}

proc slotKindName*(k: SlotKind): string {.role: helper,
    tag: "cli|formatting".} =
  ## k: slot kind rendered for `schema` output and error messages.
  case k
  of skNull: result = "null"
  of skInt: result = "int"
  of skFloat: result = "float"
  of skText: result = "text"
  of skBytes: result = "bytes"
  of skSealed: result = "sealed"
  of skRef: result = "ref"

proc parseSchemaSpec*(typeName, spec: string): tuple[ok: bool, s: Schema,
    err: string] {.role: parser,
    tag: "cli|parsing|read".} =
  ## typeName: label stored with the cluster.
  ## spec: comma-separated `name:type` pairs, e.g. "id:int,title:text".
  ## Field ORDER is the slot order and therefore part of the format, so a
  ## spec is not a set -- reordering it produces a different database.
  var
    parts: seq[string] = @[]
    bits: seq[string] = @[]
    kind: tuple[ok: bool, kind: SlotKind, err: string] =
      (false, default(SlotKind), "")
    i: int = 0
    name: string = ""
  result.s.typeName = if typeName.len > 0: typeName else: "Record"
  parts = spec.split(',')
  while i < parts.len:
    if parts[i].strip().len == 0:
      i = i + 1
      continue
    bits = parts[i].split(':')
    if bits.len != 2:
      return (false, Schema(),
        "field '" & parts[i].strip() & "' must be written name:type")
    name = bits[0].strip()
    if name.len == 0:
      return (false, Schema(), "a field name must not be empty")
    # `__` is reserved for the columns Geist adds itself. A caller field by
    # that name would give a schema two columns claiming to be the row id.
    if name.startsWith("__"):
      return (false, Schema(), "field '" & name &
        "': names starting with __ are reserved for Geist's own columns (" &
        rowIdColumn & ", " & rowFlagsColumn & ")")
    kind = slotKindFromName(bits[1])
    if not kind.ok:
      return (false, Schema(), kind.err)
    result.s.slots.add defaultSlot(result.s.intern(name), kind.kind)
    i = i + 1
  if result.s.slots.len == 0:
    return (false, Schema(), "a schema needs at least one field")
  result.ok = true

proc describeSchema*(s: Schema): string {.role: helper,
    tag: "cli|formatting|read".} =
  ## s: schema rendered back into spec form.
  var
    i: int = 0
  while i < s.slots.len:
    if i > 0:
      result.add ","
    result.add s.nameOf(s.slots[i].nameId) & ":" & slotKindName(s.slots[i].kind)
    i = i + 1

proc fieldToString*(s: Schema, A: openArray[uint8], offsets: seq[int],
    slot: int): string {.role: parser,
    tag: "cli|formatting|read".} =
  ## s/A/offsets/slot: schema, stored row, resolved offsets and a column.
  ## A value that took the sidecar escape shows its reference rather than
  ## its bytes: a CLI listing must not dump a 40 MiB payload into a
  ## terminal, and resolving it would need the store anyway.
  var
    raw: ByteSeq = @[]
  if offsets[slot] < 0:
    return ""
  if s.isExternal(A, slot):
    return describeRef(decodeRef(s.rawAt(A, offsets, slot)))
  case s.slots[slot].kind
  of skInt:
    # The reserved identity columns are UNSIGNED: a row id carries a node
    # tag in its high bits, so half of them would print as negative numbers
    # that no command would accept back.
    if s.hasIdentityColumns() and slot < identityColumnCount:
      return $s.u64At(A, offsets, slot)
    result = $cast[int64](s.u64At(A, offsets, slot))
  of skFloat:
    result = $cast[float64](s.u64At(A, offsets, slot))
  of skText:
    result = s.textAt(A, offsets, slot)
  of skBytes:
    raw = s.rawAt(A, offsets, slot)
    result = "<" & $raw.len & "B>"
  of skRef:
    result = describeRef(decodeRef(s.rawAt(A, offsets, slot)))
  of skSealed:
    result = "<sealed>"
  of skNull:
    result = ""

proc renderRow*(s: Schema, A: openArray[uint8]): seq[string] {.role: parser,
    tag: "cli|formatting|read".} =
  ## s/A: every column of one row rendered in declaration order.
  var
    offsets: seq[int] = @[]
    i: int = 0
  offsets = fieldOffsets(s, A)
  while i < s.slots.len:
    result.add fieldToString(s, A, offsets, i)
    i = i + 1

proc parsePairs*(args: openArray[string]): tuple[ok: bool,
    values: Table[string, string], err: string] {.role: sanitizer,
    tag: "cli|parsing|read".} =
  ## args: `field=value` arguments from a command line.
  var
    i: int = 0
    at: int = 0
  result.values = initTable[string, string]()
  while i < args.len:
    at = args[i].find('=')
    if at <= 0:
      return (false, result.values,
        "expected field=value, got '" & args[i] & "'")
    result.values[args[i][0 ..< at]] = args[i][at + 1 .. ^1]
    i = i + 1
  result.ok = true

proc numberBits(k: SlotKind, name, text: string): tuple[bits: uint64,
    err: string] {.role: parser, tag: "cli|db|parsing".} =
  ## k: skInt or skFloat.
  ## name/text: the field and what was typed for it; empty means zero.
  ## Returns the 8 bytes the column stores, or why the text is not a number.
  ##
  ##   skInt    "42"    -> 42 as a two's-complement u64
  ##   skFloat  "1.5"   -> the IEEE-754 bits of 1.5
  if text.len == 0:
    return (0'u64, "")
  try:
    if k == skFloat:
      result.bits = cast[uint64](parseFloat(text))
    else:
      result.bits = cast[uint64](parseBiggestInt(text))
  except ValueError:
    result.err = "field '" & name & "' expects " &
      (if k == skFloat: "a number" else: "an integer") & ", got '" & text &
      "'"

proc textBytes(text: string): ByteSeq {.role: parser, inline,
    tag: "cli|db|parsing".} =
  ## text: typed text -> its raw bytes, unchanged.
  var
    j: int = 0
  result = newSeq[uint8](text.len)
  while j < text.len:
    result[j] = uint8(text[j])
    j = j + 1

proc buildRow*(s: Schema, values: Table[string, string],
    store: SidecarStore = SidecarStore(), id: RowId = 0'u64,
    flags: uint64 = 0'u64): tuple[ok: bool, data: ByteSeq,
    err: string] {.role: truthBuilder, tag: "cli|db|write".} =
  ## s: schema the row must match, including its per-column storage policy.
  ## values: field name -> text. An omitted field keeps its zero value; a
  ##   name not in the schema is an error rather than a silent no-op,
  ##   because a typo would otherwise look like a success.
  ## store: sidecar, used when a capped column overflows.
  ## id/flags: the reserved identity columns, when the schema carries them.
  ##   A tool takes `id` from `nextIdFor` for a new row, or from the row it
  ##   is replacing. Zero on an identified schema is refused by `putRow`
  ##   rather than stored, because an unnamed row could never be edited.
  var
    W: RowWriter = default(RowWriter)
    i: int = 0
    name: string = ""
    text: string = ""
    number: tuple[bits: uint64, err: string] = (0'u64, "")
  for key in values.keys:
    if s.slotIndex(key) < 0:
      return (false, @[], "no field '" & key & "' in schema (" &
        describeSchema(s) & ")")
  W = initRowWriter(s, store)
  if s.hasIdentityColumns():
    W.writeU64(id)
    W.writeU64(flags)
    i = identityColumnCount
  while i < s.slots.len:
    name = s.nameOf(s.slots[i].nameId)
    text = values.getOrDefault(name, "")
    case s.slots[i].kind
    of skInt, skFloat:
      number = numberBits(s.slots[i].kind, name, text)
      W.writeU64(number.bits)
    of skText, skBytes, skSealed, skRef:
      W.writeColumn(textBytes(text))
    of skNull:
      W.writeColumn(@[])
    if number.err.len > 0:
      return (false, @[], number.err)
    if W.err.len > 0:
      return (false, @[], W.err)
    i = i + 1
  result.data = W.finish()
  result.ok = true

proc matchesText*(s: Schema, A: openArray[uint8], field,
    value: string): bool {.role: parser,
    tag: "cli|db|read".} =
  ## s/A: schema and candidate row.
  ## field/value: exact text comparison against the rendered column.
  var
    slot: int = -1
  slot = s.slotIndex(field)
  if slot < 0:
    return false
  result = fieldToString(s, A, fieldOffsets(s, A), slot) == value
