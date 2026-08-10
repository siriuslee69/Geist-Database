## ---------------------------------------------------------------------
## Row <- a runtime packed tuple.
##   Schema (once per object kind)  ->  ordered slots + precomputed offsets
##   Row    (once per stored object) -> schemaId + one packed byte buffer
##
##   [ fixed region: slots in declaration order ][ tail: variable bytes ]
##     u64 | u64 | (u32 off,u32 len) | u64 ...    "case-note-7" "..." 
## ---------------------------------------------------------------------

type
  ByteSeq* = seq[uint8]
  NameId* = uint16
  KeyId* = uint64

  SlotKind* = enum
    skNull, skInt, skFloat, skText, skBytes, skSealed

  Slot* = object
    nameId*: NameId
    kind*: SlotKind
    offset*: uint32          ## byte offset into the fixed region

  Schema* = object
    typeName*: string
    names*: seq[string]      ## interned once per cluster
    slots*: seq[Slot]
    fixedBytes*: uint32

  Row* = object              ## the packed tuple
    schemaId*: uint16
    data*: ByteSeq

const
  fixedWidth: array[SlotKind, uint32] = [0'u32, 8, 8, 8, 8, 8]
    ## null:0  int:8  float:8  text/bytes/sealed: (u32 off, u32 len)

proc intern*(s: var Schema, n: string): NameId =
  for i in 0 ..< s.names.len:
    if s.names[i] == n: return NameId(i)
  s.names.add n
  result = NameId(s.names.len - 1)

proc addSlot*(s: var Schema, n: string, k: SlotKind) =
  s.slots.add Slot(nameId: s.intern(n), kind: k, offset: s.fixedBytes)
  s.fixedBytes = s.fixedBytes + fixedWidth[k]

# ---- little-endian primitives: explicit, so files move between hosts ----

proc putU64*(A: var ByteSeq, o: uint32, v: uint64) =
  for i in 0'u32 ..< 8'u32: A[int(o + i)] = uint8((v shr (i * 8)) and 0xFF)

proc getU64*(A: ByteSeq, o: uint32): uint64 =
  for i in 0'u32 ..< 8'u32: result = result or (uint64(A[int(o + i)]) shl (i * 8))

proc putU32*(A: var ByteSeq, o: uint32, v: uint32) =
  for i in 0'u32 ..< 4'u32: A[int(o + i)] = uint8((v shr (i * 8)) and 0xFF)

proc getU32*(A: ByteSeq, o: uint32): uint32 =
  for i in 0'u32 ..< 4'u32: result = result or (uint32(A[int(o + i)]) shl (i * 8))

# ---- variable-length tail ----

proc appendVar*(r: var Row, slotOffset: uint32, A: openArray[uint8]) =
  var start = uint32(r.data.len)
  for b in A: r.data.add b
  r.data.putU32(slotOffset, start)
  r.data.putU32(slotOffset + 4, uint32(A.len))

proc readVar*(r: Row, slotOffset: uint32): ByteSeq =
  var
    start = r.data.getU32(slotOffset)
    n = r.data.getU32(slotOffset + 4)
  result = newSeq[uint8](int(n))
  for i in 0'u32 ..< n: result[int(i)] = r.data[int(start + i)]

proc initRow*(s: Schema, schemaId: uint16): Row =
  result.schemaId = schemaId
  result.data = newSeq[uint8](int(s.fixedBytes))
