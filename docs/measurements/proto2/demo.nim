import std/strutils
import ./nodes, ./mapper, ./policy

type
  RefTarget = enum rtBlob, rtEntry, rtExternal
  Ref = object                      ## typed struct: real invariant
    target: RefTarget
    locator: string
    hash: ByteSeq
    size: int64
    blobId: uint64

  ContactNote = object              ## an ordinary app object
    noteId: int
    title: string
    clearance: uint16
    body: string
    attachment: Ref                 ## nested -> flattens to dotted names

proc show(N: seq[Node], t: NameTable) =
  for n in N:
    var v = case n.kind
      of nkText:   "\"" & n.text & "\""
      of nkInt:    $n.num
      of nkFloat:  $n.f
      of nkBytes:  $n.bytes.len & "B"
      of nkSealed: "SEALED cipher=" & $n.sealed.cipher.len &
                     "B keyRef=" & $n.sealed.keyRef
      of nkNull:   "-"
    echo "  ", alignLeft($n.kind, 9), alignLeft(t.name(n.nameId), 20), v

when isMainModule:
  var
    tbl: NameTable
    note = ContactNote(noteId: 7, title: "case-note-7", clearance: 42,
      body: "sensitive text",
      attachment: Ref(target: rtBlob, locator: "koerper/9f2a",
        hash: @[0xde'u8, 0xad, 0xbe, 0xef], size: 40960, blobId: 9))
    N = toNodes(note, tbl)
    back = fromNodes[ContactNote](N, tbl)

  echo "sizeof(Node) = ", sizeof(Node), " B"
  echo "\n=== 1. toNodes[ContactNote] ==="
  show(N, tbl)
  echo "  name table (stored once per cluster): ", tbl.names

  echo "\n=== 2. round-trip before sealing ==="
  echo "  equal: ", back == note

  echo "\n=== 3. applyPolicy: seal only `body` ==="
  applyPolicy(N, tbl, @[FieldPolicy(field: "body", seal: true)],
    @[0x5A'u8, 0x3C], 77'u64)
  show(N, tbl)

  echo "\n=== 4. a second object kind reuses the SAME table ==="
  var other = Ref(target: rtEntry, locator: "entry/12", hash: @[1'u8],
    size: 8, blobId: 0)
  var N2 = toNodes(other, tbl)
  echo "  new names added: ", tbl.names.len, " total -> ", tbl.names
  echo "  round-trip: ", fromNodes[Ref](N2, tbl) == other
