## Bytecheck: a buffer from another machine is walked before it is decoded.
##
## The decoders trust every length they read. These tests hold the promise
## that nothing malformed gets that far: every buffer the encoders write
## passes, and every way of breaking one -- cutting it short anywhere,
## naming an operation or a column kind that does not exist, claiming
## more bytes than there are, leaving bytes over -- is refused with a
## reason instead of read.

import std/[strutils, unittest]

import geist/types
import geist/format
import geist/transport
import geist/bytecheck
import runePragmas

proc sampleQuery(): Query {.role: configurator.} =
  ## A request using every field, so every part of the layout is walked.
  result = Query(op: qoFind, collection: "notes",
    where: @[Predicate(field: "title", isText: true, text: "hello"),
      Predicate(field: "id", isText: false, num: -7)],
    limit: 20'u32, cursor: 5'u64, subscriptionId: "mirror",
    payload: @[1'u8, 2, 3])

proc sampleReply(): Reply {.role: configurator.} =
  ## An answer with a two-column schema and two rows, one of them empty.
  result = Reply(ok: true, err: "", cursor: 9'u64,
    matched: 2'u32, epoch: 3'u64,
    schema: Schema(typeName: "Note", names: @["id", "title"],
      slots: @[Slot(nameId: 0'u16, kind: skInt, column: colFixed,
        width: 8'u32),
      Slot(nameId: 1'u16, kind: skText, column: colVariable,
        width: 0'u32)]),
    rows: @[Row(schemaId: 1'u16, data: @[1'u8, 2, 3, 4]),
      Row(schemaId: 1'u16, data: @[])])

suite "requests":
  # {.testKind: tkUnit, covers: "checkQueryBytes".}
  test "every request the encoder writes passes":
    check checkQueryBytes(encodeQuery(sampleQuery())) == ""
    check checkQueryBytes(encodeQuery(Query(op: qoPoll))) == ""
    check checkQueryBytes(encodeQuery(Query(op: qoPut,
      payload: newSeq[uint8](70_000)))) == ""

  # {.testKind: tkProperty, covers: "checkQueryBytes".}
  test "a request cut short anywhere is refused":
    var
      A: seq[uint8] = encodeQuery(sampleQuery())
      n: int = 0
    while n < A.len:
      check checkQueryBytes(A[0 ..< n]).len > 0
      n = n + 1

  # {.testKind: tkEdgeCase, covers: "checkQueryBytes".}
  test "an operation that does not exist is refused":
    var
      A: seq[uint8] = encodeQuery(sampleQuery())
    A[0] = uint8(ord(high(QueryOp)) + 1)
    check checkQueryBytes(A).contains("unknown operation")

  # {.testKind: tkEdgeCase, covers: "checkQueryBytes".}
  test "a length claiming four gigabytes is refused, not allocated":
    var
      A: seq[uint8] = @[uint8(ord(qoGet)), 0xFF'u8, 0xFF, 0xFF, 0xFF]
    check checkQueryBytes(A).contains("collection")

  # {.testKind: tkEdgeCase, covers: "checkQueryBytes".}
  test "bytes left over after a request are refused":
    var
      A: seq[uint8] = encodeQuery(sampleQuery())
    A.add 0'u8
    check checkQueryBytes(A).contains("trailing")

suite "answers":
  # {.testKind: tkUnit, covers: "checkReplyBytes".}
  test "every answer the encoder writes passes":
    check checkReplyBytes(encodeReply(sampleReply())) == ""
    check checkReplyBytes(encodeReply(Reply(ok: false,
      err: "refused"))) == ""

  # {.testKind: tkProperty, covers: "checkReplyBytes".}
  test "an answer cut short anywhere is refused":
    var
      A: seq[uint8] = encodeReply(sampleReply())
      n: int = 0
    while n < A.len:
      check checkReplyBytes(A[0 ..< n]).len > 0
      n = n + 1

  # {.testKind: tkEdgeCase, covers: "checkSchemaBytes".}
  test "a column kind that does not exist is refused":
    var
      A: seq[uint8] = encodeReply(sampleReply())
      at: int = 1 + 4 + 8 + 4 + 8
      slots: int = 0
    # `at`: where the schema starts -- past ok, the empty error text,
    # cursor, matched and epoch. `slots`: the first slot record -- past
    # the type name, the two names, autoCollapse and the slot count.
    slots = 4 + "Note".len + 4 + (4 + "id".len) + (4 + "title".len) + 1 + 4
    A[at + slots + 2] = 200'u8
    check checkReplyBytes(A).contains("unknown kind")

  # {.testKind: tkEdgeCase, covers: "checkReplyBytes".}
  test "bytes left over after an answer are refused":
    var
      A: seq[uint8] = encodeReply(sampleReply())
    A.add 7'u8
    check checkReplyBytes(A).contains("trailing")
