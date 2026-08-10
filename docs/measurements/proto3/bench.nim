import std/[times, strutils]
import ./row, ./mapper

type
  RefTarget = enum rtBlob, rtEntry, rtExternal
  Ref = object
    target: RefTarget
    locator: string
    hash: ByteSeq
    size: int64
    blobId: uint64
  ContactNote = object
    noteId: int
    title: string
    clearance: uint16
    body: string
    attachment: Ref

  # the variant-node model, for comparison
  NodeKind = enum nkNull, nkText, nkInt, nkFloat, nkBytes, nkSealed
  NodeRole = enum nrField, nrMeta
  Sealed = object
    algo: uint16
    keyRef: uint64
    nonce, tag, cipher: ByteSeq
  Node = object
    role: NodeRole
    nameId: uint16
    case kind: NodeKind
    of nkNull: discard
    of nkText: text: string
    of nkInt: num: int64
    of nkFloat: f: float64
    of nkBytes: bytes: ByteSeq
    of nkSealed: sealed: ref Sealed

const N = 100_000

proc heapOfRow(r: Row): int = sizeof(Row) + r.data.len + 16
proc heapOfNodes(ns: seq[Node]): int =
  result = 16 + ns.len * sizeof(Node)
  for n in ns:
    case n.kind
    of nkText:  result = result + n.text.len + 16
    of nkBytes: result = result + n.bytes.len + 16
    else: discard

when isMainModule:
  var
    s: Schema
    note = ContactNote(noteId: 7, title: "case-note-7", clearance: 42,
      body: "sensitive text",
      attachment: Ref(target: rtBlob, locator: "koerper/9f2a",
        hash: @[0xde'u8, 0xad, 0xbe, 0xef], size: 40960, blobId: 9))
  schemaOf(note, s)

  # equivalent node list for the same object
  var ns: seq[Node] = @[
    Node(kind: nkInt, nameId: 0, num: 7),
    Node(kind: nkText, nameId: 1, text: "case-note-7"),
    Node(kind: nkInt, nameId: 2, num: 42),
    Node(kind: nkText, nameId: 3, text: "sensitive text"),
    Node(kind: nkInt, nameId: 4, num: 0),
    Node(kind: nkText, nameId: 5, text: "koerper/9f2a"),
    Node(kind: nkBytes, nameId: 6, bytes: @[0xde'u8, 0xad, 0xbe, 0xef]),
    Node(kind: nkInt, nameId: 7, num: 40960),
    Node(kind: nkInt, nameId: 8, num: 9)]

  var r = toRow(note, s)
  echo "one object, 9 fields:"
  echo "  packed Row   : ", heapOfRow(r), " B, 1 allocation"
  echo "  seq[Node]    : ", heapOfNodes(ns), " B, ", 1 + 3, " allocations"
  echo "  ratio        : ", formatFloat(heapOfNodes(ns) / heapOfRow(r), ffDecimal, 2), "x"
  echo "  ", N, " objects: Row = ", (heapOfRow(r)*N) div (1024*1024),
    " MiB   Node = ", (heapOfNodes(ns)*N) div (1024*1024), " MiB"

  # hot-path field read: schema offset vs name scan
  var t0 = cpuTime()
  var acc1: uint64 = 0
  for i in 0 ..< N:
    acc1 = acc1 + r.data.getU64(s.slots[7].offset)   # attachment.size, O(1)
  var t1 = cpuTime()
  var acc2: int64 = 0
  for i in 0 ..< N:
    for n in ns:                                      # scan to find slot 7
      if n.nameId == 7'u16:
        acc2 = acc2 + n.num
        break
  var t2 = cpuTime()
  echo "\nread one field ", N, "x:"
  echo "  Row  offset lookup : ", formatFloat((t1-t0)*1000, ffDecimal, 2), " ms"
  echo "  Node linear scan   : ", formatFloat((t2-t1)*1000, ffDecimal, 2), " ms"
  echo "  (checksums ", acc1, " ", acc2, ")"
