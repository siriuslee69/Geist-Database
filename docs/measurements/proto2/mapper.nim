## ---------------------------------------------------------------
## Mapper <- the ONLY ingestion path: T <-> seq[Node] via fieldPairs
## ---------------------------------------------------------------

import ./nodes

proc emit(dst: var seq[Node], t: var NameTable, nm: string, v: string) =
  dst.add Node(role: nrField, nameId: t.intern(nm), kind: nkText, text: v)
proc emit(dst: var seq[Node], t: var NameTable, nm: string, v: SomeInteger) =
  dst.add Node(role: nrField, nameId: t.intern(nm), kind: nkInt, num: int64(v))
proc emit(dst: var seq[Node], t: var NameTable, nm: string, v: bool) =
  dst.add Node(role: nrField, nameId: t.intern(nm), kind: nkInt,
    num: int64(ord(v)))
proc emit(dst: var seq[Node], t: var NameTable, nm: string, v: SomeFloat) =
  dst.add Node(role: nrField, nameId: t.intern(nm), kind: nkFloat,
    f: float64(v))
proc emit(dst: var seq[Node], t: var NameTable, nm: string, v: seq[uint8]) =
  dst.add Node(role: nrField, nameId: t.intern(nm), kind: nkBytes, bytes: v)

proc toNodesB[T: object](x: T, t: var NameTable, prefix: string): seq[Node]

proc toNodes*[T: object](x: T, t: var NameTable,
    prefix: string = ""): seq[Node] =
  for fa, va in fieldPairs(x):
    var na = if prefix.len > 0: prefix & "." & fa else: fa
    when va is seq[uint8]: result.emit(t, na, va)
    elif va is enum:
      result.add Node(role: nrField, nameId: t.intern(na), kind: nkInt,
        num: int64(ord(va)))
    elif va is object: result.add toNodesB(va, t, na)
    else: result.emit(t, na, va)

proc toNodesB[T: object](x: T, t: var NameTable, prefix: string): seq[Node] =
  ## Alternating twin: fieldPairs unrolls lexically, so each nesting
  ## level needs its own loop-variable identifiers.
  for fb, vb in fieldPairs(x):
    var nb = if prefix.len > 0: prefix & "." & fb else: fb
    when vb is seq[uint8]: result.emit(t, nb, vb)
    elif vb is enum:
      result.add Node(role: nrField, nameId: t.intern(nb), kind: nkInt,
        num: int64(ord(vb)))
    elif vb is object: result.add toNodes(vb, t, nb)
    else: result.emit(t, nb, vb)

proc findNode(N: seq[Node], t: NameTable, nm: string): int =
  result = -1
  for i in 0 ..< N.len:
    if t.name(N[i].nameId) == nm: return i

proc fromNodes*[T: object](N: seq[Node], t: NameTable,
    prefix: string = ""): T =
  for fa, va in fieldPairs(result):
    var
      na = if prefix.len > 0: prefix & "." & fa else: fa
      i = -1
    when va is seq[uint8]:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkBytes: va = N[i].bytes
    elif va is enum:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkInt: va = type(va)(N[i].num)
    elif va is object:
      va = fromNodes[type(va)](N, t, na)
    elif va is string:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkText: va = N[i].text
    elif va is bool:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkInt: va = N[i].num != 0
    elif va is SomeFloat:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkFloat: va = type(va)(N[i].f)
    else:
      i = findNode(N, t, na)
      if i >= 0 and N[i].kind == nkInt: va = type(va)(N[i].num)
