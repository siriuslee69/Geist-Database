## ---------------------------------------------------------------------
## Geist file format <- header index | clusters of fixed rows | overflow
##
##  +----------------------------------------------------------------+
##  | header: magic | version | clusterCount | overflowAt | overflowLen|
##  +----------------------------------------------------------------+
##  | cluster index: N x (role, mode, schemaId, rowCount, at, len)     |  <- seekable
##  +----------------------------------------------------------------+
##  | cluster 0  role=meta    : schema + fixed rows                    |
##  | cluster 1  role=schema  :                                        |
##  | cluster 2  role=entry   : row0 | row1 | row2 | ...  (all N bytes)|
##  +----------------------------------------------------------------+
##  | overflow region: every variable-length value in the file         |
##  +----------------------------------------------------------------+
##
##  A variable field's 8-byte slot holds (u32 start, u32 len) into overflow.
##  Fixed rows + one overflow region  =>  row i is at clusterAt + i*rowBytes.
## ---------------------------------------------------------------------

type
  ByteSeq* = seq[uint8]
  NameId* = uint16

  SlotKind* = enum
    skNull, skInt, skFloat, skText, skBytes, skSealed

  Slot* = object            ## 4 bytes. No offset: field i lives at i*8.
    nameId*: NameId
    kind*: SlotKind

  Schema* = object
    typeName*: string
    names*: seq[string]     ## interned once; cold path (migration) only
    slots*: seq[Slot]

  ClusterRole* = enum
    crMeta, crSchema, crKeyLedger, crJournal, crVersion, crEntry

  ClusterMode* = enum
    cmMutable, cmAppend, cmChained

  ClusterIndexEntry* = object   ## what a partial reader seeks on
    role*: ClusterRole
    mode*: ClusterMode
    schemaId*: uint16
    rowCount*: uint32
    at*: uint64
    len*: uint64

const
  slotBytes* = 8'u32
  magic* = "GE1ST\x01"

proc rowBytes*(s: Schema): uint32 = uint32(s.slots.len) * slotBytes
proc slotAt*(i: int): uint32 = uint32(i) * slotBytes

# ---- explicit little-endian: files must survive x86 <-> ARM ----

proc putU32*(A: var ByteSeq, o: int, v: uint32) =
  for i in 0 ..< 4: A[o + i] = uint8((v shr (i * 8)) and 0xFF)
proc getU32*(A: ByteSeq, o: int): uint32 =
  for i in 0 ..< 4: result = result or (uint32(A[o + i]) shl (i * 8))
proc putU64*(A: var ByteSeq, o: int, v: uint64) =
  for i in 0 ..< 8: A[o + i] = uint8((v shr (i * 8)) and 0xFF)
proc getU64*(A: ByteSeq, o: int): uint64 =
  for i in 0 ..< 8: result = result or (uint64(A[o + i]) shl (i * 8))

proc addU32*(A: var ByteSeq, v: uint32) =
  for i in 0 ..< 4: A.add uint8((v shr (i * 8)) and 0xFF)
proc addU64*(A: var ByteSeq, v: uint64) =
  for i in 0 ..< 8: A.add uint8((v shr (i * 8)) and 0xFF)
