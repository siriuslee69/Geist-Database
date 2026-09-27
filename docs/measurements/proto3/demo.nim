import std/strutils
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

when isMainModule:
  var
    s: Schema = default(Schema)
    note = ContactNote(noteId: 7, title: "case-note-7", clearance: 42,
      body: "sensitive text",
      attachment: Ref(target: rtBlob, locator: "koerper/9f2a",
        hash: @[0xde'u8, 0xad, 0xbe, 0xef], size: 40960, blobId: 9))
  s.typeName = "ContactNote"
  schemaOf(note, s)

  echo "=== schema (stored ONCE per cluster) ==="
  echo "  fixed region = ", s.fixedBytes, " B, ", s.slots.len, " slots"
  for sl in s.slots:
    echo "    +", align($sl.offset, 3), "  ", alignLeft($sl.kind, 8),
      s.names[int(sl.nameId)]

  var r = toRow(note, s)
  echo "\n=== row (per object) ==="
  echo "  sizeof(Row) = ", sizeof(Row), " B header, data = ", r.data.len,
    " B  -> ONE allocation"
  echo "  bytes: ", r.data[0 ..< min(24, r.data.len)], " ..."

  var back = fromRow[ContactNote](r, s)
  echo "\n=== round-trip ==="
  echo "  equal: ", back == note
  echo "  title=", back.title, " ref.locator=", back.attachment.locator,
    " ref.hash=", back.attachment.hash
