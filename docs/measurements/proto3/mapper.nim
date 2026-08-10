## -------------------------------------------------------------------
## Mapper <- schema derived from T at COMPILE time; pack/unpack by
## declaration order, so the hot path never looks up a field name.
## -------------------------------------------------------------------

import ./row

proc schemaOfB[T: object](x: T, s: var Schema, prefix: string)

proc schemaOf*[T: object](x: T, s: var Schema, prefix: string = "") =
  for fa, va in fieldPairs(x):
    var na = if prefix.len > 0: prefix & "." & fa else: fa
    when va is seq[uint8]:  s.addSlot(na, skBytes)
    elif va is string:      s.addSlot(na, skText)
    elif va is enum:        s.addSlot(na, skInt)
    elif va is SomeFloat:   s.addSlot(na, skFloat)
    elif va is object:      schemaOfB(va, s, na)
    else:                   s.addSlot(na, skInt)

proc schemaOfB[T: object](x: T, s: var Schema, prefix: string) =
  for fb, vb in fieldPairs(x):
    var nb = if prefix.len > 0: prefix & "." & fb else: fb
    when vb is seq[uint8]:  s.addSlot(nb, skBytes)
    elif vb is string:      s.addSlot(nb, skText)
    elif vb is enum:        s.addSlot(nb, skInt)
    elif vb is SomeFloat:   s.addSlot(nb, skFloat)
    elif vb is object:      schemaOf(vb, s, nb)
    else:                   s.addSlot(nb, skInt)

proc packB[T: object](x: T, s: Schema, r: var Row, i: var int)

proc pack*[T: object](x: T, s: Schema, r: var Row, i: var int) =
  for fa, va in fieldPairs(x):
    when va is seq[uint8]: r.appendVar(s.slots[i].offset, va); i.inc
    elif va is string:
      var t = newSeq[uint8](va.len)
      for j in 0 ..< va.len: t[j] = uint8(va[j])
      r.appendVar(s.slots[i].offset, t); i.inc
    elif va is enum: r.data.putU64(s.slots[i].offset, uint64(ord(va))); i.inc
    elif va is SomeFloat:
      r.data.putU64(s.slots[i].offset, cast[uint64](float64(va))); i.inc
    elif va is object: packB(va, s, r, i)
    elif va is bool: r.data.putU64(s.slots[i].offset, uint64(ord(va))); i.inc
    else: r.data.putU64(s.slots[i].offset, uint64(va)); i.inc

proc packB[T: object](x: T, s: Schema, r: var Row, i: var int) =
  for fb, vb in fieldPairs(x):
    when vb is seq[uint8]: r.appendVar(s.slots[i].offset, vb); i.inc
    elif vb is string:
      var t = newSeq[uint8](vb.len)
      for j in 0 ..< vb.len: t[j] = uint8(vb[j])
      r.appendVar(s.slots[i].offset, t); i.inc
    elif vb is enum: r.data.putU64(s.slots[i].offset, uint64(ord(vb))); i.inc
    elif vb is SomeFloat:
      r.data.putU64(s.slots[i].offset, cast[uint64](float64(vb))); i.inc
    elif vb is object: pack(vb, s, r, i)
    elif vb is bool: r.data.putU64(s.slots[i].offset, uint64(ord(vb))); i.inc
    else: r.data.putU64(s.slots[i].offset, uint64(vb)); i.inc

proc unpackB[T: object](x: var T, s: Schema, r: Row, i: var int)

proc unpack*[T: object](x: var T, s: Schema, r: Row, i: var int) =
  for fa, va in fieldPairs(x):
    when va is seq[uint8]: va = r.readVar(s.slots[i].offset); i.inc
    elif va is string:
      var t = r.readVar(s.slots[i].offset)
      va = newString(t.len)
      for j in 0 ..< t.len: va[j] = char(t[j])
      i.inc
    elif va is enum: va = type(va)(r.data.getU64(s.slots[i].offset)); i.inc
    elif va is SomeFloat:
      va = type(va)(cast[float64](r.data.getU64(s.slots[i].offset))); i.inc
    elif va is object: unpackB(va, s, r, i)
    elif va is bool: va = r.data.getU64(s.slots[i].offset) != 0; i.inc
    else: va = type(va)(r.data.getU64(s.slots[i].offset)); i.inc

proc unpackB[T: object](x: var T, s: Schema, r: Row, i: var int) =
  for fb, vb in fieldPairs(x):
    when vb is seq[uint8]: vb = r.readVar(s.slots[i].offset); i.inc
    elif vb is string:
      var t = r.readVar(s.slots[i].offset)
      vb = newString(t.len)
      for j in 0 ..< t.len: vb[j] = char(t[j])
      i.inc
    elif vb is enum: vb = type(vb)(r.data.getU64(s.slots[i].offset)); i.inc
    elif vb is SomeFloat:
      vb = type(vb)(cast[float64](r.data.getU64(s.slots[i].offset))); i.inc
    elif vb is object: unpack(vb, s, r, i)
    elif vb is bool: vb = r.data.getU64(s.slots[i].offset) != 0; i.inc
    else: vb = type(vb)(r.data.getU64(s.slots[i].offset)); i.inc

proc toRow*[T: object](x: T, s: Schema, schemaId: uint16 = 0'u16): Row =
  var i = 0
  result = initRow(s, schemaId)
  pack(x, s, result, i)

proc fromRow*[T: object](r: Row, s: Schema): T =
  var i = 0
  unpack(result, s, r, i)
