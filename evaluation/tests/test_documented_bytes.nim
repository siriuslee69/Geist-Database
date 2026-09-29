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
import geist/network

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

suite "the request, as the README lays it out":

  # {.testKind: tkRegression.}
  test "operations are numbered as documented":
    check ord(qoGet) == 0
    check ord(qoPut) == 1
    check ord(qoFind) == 2
    check ord(qoDelete) == 3
    check ord(qoSync) == 4
    check ord(qoFetch) == 5
    check ord(qoSubscribe) == 6
    check ord(qoPoll) == 7

  # {.testKind: tkRegression.}
  test "a find lands on the offsets the README prints":
    var q = Query(op: qoFind, collection: "notes", limit: 20'u32)
    q.where.add Predicate(field: "title", text: "hi", isText: true)
    var b = encodeQuery(q)
    check b.len == 58
    check b[0] == 2'u8                 # 0   op
    check b.getU32(1) == 5'u32         # 1   collection length
    check b[5] == uint8('n')           # 5   "notes"
    check b.getU32(10) == 1'u32        # 10  predicate count
    check b.getU32(14) == 5'u32        # 14  field length
    check b[23] == 1'u8                # 23  isText
    check b.getU32(24) == 2'u32        # 24  text length
    check b.getU32(38) == 20'u32       # 38  limit
    check b.getU64(42) == 0'u64        # 42  cursor
    check b.getU32(50) == 0'u32        # 50  subscriptionId length
    check b.getU32(54) == 0'u32        # 54  payload length

  # {.testKind: tkRegression.}
  test "a reply lands on the offsets the README prints":
    var r = Reply(ok: true, cursor: 3'u64, matched: 1'u32, epoch: 7'u64)
    r.rows.add Row(schemaId: 0'u16, data: @[0x68'u8, 0x69'u8])
    var b = encodeReply(r)
    check b[0] == 1'u8                 # 0   ok
    check b.getU32(1) == 0'u32         # 1   err length
    check b.getU64(5) == 3'u64         # 5   cursor
    check b.getU32(13) == 1'u32        # 13  matched
    check b.getU64(17) == 7'u64        # 17  epoch

  # {.testKind: tkRegression.}
  test "the frame and package thresholds are the documented ones":
    check geistWholeMaxBytes == 32_000
    check geistDacFrameMaxBytes == 65_507
    check replyRowBudget == 28_000

suite "the derived files, as the README names them":

  # {.testKind: tkRegression.}
  test "the column copy is GETR1 in a .getr file":
    check transposedMagic == "GETR1"
    check transposedSuffix == ".getr"

  # {.testKind: tkRegression.}
  test "a relay envelope is stream, sender, at, ordinal, body":
    var m = RelayMessage(stream: "voice", sender: "phone", at: 5'i64,
      ordinal: 3'u64, body: asBytes("hi"))
    var b = encodeMessage(m)
    check b.getU32(0) == 5'u32          # stream length
    check b.getU32(9) == 5'u32          # sender length, after "voice"
    var back = decodeMessage(b)
    check back.stream == "voice"
    check back.sender == "phone"
    check back.at == 5'i64
    check back.ordinal == 3'u64
    check asText(back.body) == "hi"

  # {.testKind: tkRegression.}
  test "an envelope row can never be read as a stored row":
    # 0xFFF1 is far outside the range a database assigns.
    check relayEnvelopeId == 0xFFF1'u16
