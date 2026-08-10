## ---------------------------------------------------------------------
## Mapper <- T -> Schema, at compile time, via fieldPairs
## ---------------------------------------------------------------------
##
##   T --schemaFor--> Schema     (once per object kind, compile time)
##
## Only the SCHEMA is derived here. Turning an object into stored bytes is
## `row.nim`, which needs the schema anyway because storage policy lives
## per column.
##
## Nested objects flatten with dotted names (`attachment.locator`), which
## keeps clusters rectangular and the header index simple.
##
## fieldPairs unrolls lexically, so a nested level cannot reuse the outer
## loop identifiers. The `...B` twins below alternate identifier sets so
## recursion works at arbitrary depth. Do not merge them.

import ../analysis_pragmas
import ./types

## ------------------------------ schema ------------------------------

proc defaultSlot*(nameId: NameId, kind: SlotKind): Slot {.role: configurator,
    metaTags: {tagCodecBoundary, tagDb, tagTypes}.} =
  ## nameId/kind: the column being declared from a Nim field.
  ##
  ## Defaults chosen so an unannotated object stores correctly rather than
  ## cheaply. A caller who knows more -- that titles never exceed 64 bytes,
  ## that a blob belongs in the sidecar -- narrows it through the
  ## configuration's column policy.
  ##
  ##   int/float/bool/enum -> colFixed 8 B     exact, never overflows
  ##   Ref                 -> colFixed 33 B    an own-file reference
  ##   text/bytes          -> colVariable      no ceiling, so no data loss
  ##
  ## `opError` rather than `opTruncate` is the default overflow policy for
  ## the same reason: silently discarding the tail of a value is never the
  ## safe assumption.
  result.nameId = nameId
  result.kind = kind
  result.onOverflow = opError
  case kind
  of skInt, skFloat:
    result.column = colFixed
    result.width = defaultFixedWidth
  of skRef:
    result.column = colFixed
    result.width = uint32(ownFileRefBytes)
  of skText, skBytes, skSealed, skNull:
    result.column = colVariable

proc schemaOfB[T: object](x: T, S: var Schema, prefix: string)

proc schemaOf*[T: object](x: T, S: var Schema, prefix: string = "") {.
    role: truthBuilder, metaTags: {tagCodecBoundary, tagDb, tagTypes}.} =
  ## x: exemplar whose declaration order becomes the slot order.
  ## S: schema being built.
  ## prefix: dotted path for nested structs.
  for fa, va in fieldPairs(x):
    var
      na: string = ""
    na = if prefix.len > 0: prefix & "." & fa else: fa
    when va is Ref:
      S.slots.add defaultSlot(S.intern(na), skRef)
    elif va is seq[uint8]:
      S.slots.add defaultSlot(S.intern(na), skBytes)
    elif va is string:
      S.slots.add defaultSlot(S.intern(na), skText)
    elif va is enum:
      S.slots.add defaultSlot(S.intern(na), skInt)
    elif va is SomeFloat:
      S.slots.add defaultSlot(S.intern(na), skFloat)
    elif va is object:
      schemaOfB(va, S, na)
    else:
      S.slots.add defaultSlot(S.intern(na), skInt)

proc schemaOfB[T: object](x: T, S: var Schema, prefix: string) {.
    role: truthBuilder, metaTags: {tagCodecBoundary, tagDb, tagTypes}.} =
  ## Alternating twin of `schemaOf`; see the module note on fieldPairs.
  for fb, vb in fieldPairs(x):
    var
      nb: string = ""
    nb = if prefix.len > 0: prefix & "." & fb else: fb
    when vb is Ref:
      S.slots.add defaultSlot(S.intern(nb), skRef)
    elif vb is seq[uint8]:
      S.slots.add defaultSlot(S.intern(nb), skBytes)
    elif vb is string:
      S.slots.add defaultSlot(S.intern(nb), skText)
    elif vb is enum:
      S.slots.add defaultSlot(S.intern(nb), skInt)
    elif vb is SomeFloat:
      S.slots.add defaultSlot(S.intern(nb), skFloat)
    elif vb is object:
      schemaOf(vb, S, nb)
    else:
      S.slots.add defaultSlot(S.intern(nb), skInt)

proc schemaFor*[T: object](typeName: string = ""): Schema {.
    role: truthBuilder, metaTags: {tagAppApi, tagCodecBoundary, tagDb}.} =
  ## typeName: label stored with the cluster; defaults to T's own name.
  var
    x: T
  result.typeName = if typeName.len > 0: typeName else: $T
  schemaOf(x, result)

