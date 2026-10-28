## The byte layouts the README prints, checked against the code.
##
## README.md documents Geist at the byte level: offset tables for a row, a
## file header, an index entry, a request and a reply, plus the constants
## that decide when a payload is split across frames. Documentation like
## that is worth having and rots silently -- reordering an enum or moving
## a threshold leaves the prose describing a format that no longer exists,
## and nothing fails.
##
## So the numbers in the prose are asserted here. If one of these tests
## fails, the fix is usually BOTH: change the code deliberately, then
## change the README to match.

import std/[unittest]

import geist

suite "how bytes are written":

  # {.testKind: tkRegression.}
  test "text is a u32 length then the raw bytes":
    var b: ByteSeq = @[]
    b.addText("notes")
    check b.len == 4 + 5
    check b.getU32(0) == 5'u32
    check b[4] == uint8('n')
    check b[8] == uint8('s')

  # {.testKind: tkRegression.}
  test "integers are little-endian":
    var b: ByteSeq = @[]
    b.addU32(20'u32)
    check b == @[20'u8, 0'u8, 0'u8, 0'u8]
    b = @[]
    b.addU64(7'u64)
    check b[0] == 7'u8 and b[7] == 0'u8

suite "the file, as the README lays it out":

  # {.testKind: tkRegression.}
  test "header is 32 bytes and an index entry is 76":
    check headerBytes == 32
    check indexEntryBytes == 76
    check geistMagic == "GE1ST"
    check geistFormatVersion == 4'u16

  # {.testKind: tkRegression.}
  test "an index read costs 32 + 76 per cluster":
    # The claim behind observeStore's fixed cost.
    check headerBytes + 3 * indexEntryBytes == 260

  # {.testKind: tkRegression.}
  test "cluster roles and modes are numbered as documented":
    check ord(crMeta) == 0
    check ord(crSchema) == 1
    check ord(crKeyLedger) == 2
    check ord(crJournal) == 3
    check ord(crVersion) == 4
    check ord(crEntry) == 5
    check ord(cmMutable) == 0
    check ord(cmAppend) == 1
    check ord(cmChained) == 2

suite "the row, as the README lays it out":

  # {.testKind: tkRegression.}
  test "the bitmap prefix is one bit per column, rounded up":
    check nullBitmapBytes(4) == 1
    check nullBitmapBytes(8) == 1
    check nullBitmapBytes(9) == 2

  # {.testKind: tkRegression.}
  test "a plain schema has no row prefix at all":
    var s = Schema(slots: @[Slot(), Slot()])
    check s.headerBytesOf() == 0

  # {.testKind: tkRegression.}
  test "an id is a 24-bit tag over a 40-bit counter":
    check rowIdCounterBits == 40
    check rowIdNodeMask == 0xFFFFFF'u64
    check composeRowId(0x4A7AB8'u64, 1'u64) == 0x4A7AB80000000001'u64
    check nodeTagOf(0x4A7AB80000000001'u64) == 0x4A7AB8'u64
    check tombstoneFlag == 1'u64

  # {.testKind: tkRegression.}
  test "a sidecar reference is one tag byte and a 32-byte hash":
    var r = Ref(target: rtSidecar, hash: newSeq[uint8](32))
    check encodeRef(r).len == 33

suite "the derived files, as the README names them":

  # {.testKind: tkRegression.}
  test "the column copy is GETR1 in a .getr file":
    check transposedMagic == "GETR1"
    check transposedSuffix == ".getr"

