## Schema derivation and the unified row codec: three column kinds,
## two optional bitmaps, one format.

import std/[os, strutils, unittest]

import ../src/geist

type
  Flat = object
    a*: int
    b*: float
    c*: int
    d*: bool
    e*: int

  Note = object
    id*: int
    score*: float
    title*: string
    body*: string

  Nested = object
    id*: int
    label*: string
    payload*: Ref

  Signed = object
    neg*: int
    pos*: int
    flag*: bool

  Wide = object
    a*: int
    b*: string
    c*: int
    d*: string
    e*: int
    f*: string
    g*: int
    h*: string

suite "schema derivation":

  test "columns take defaults from their Nim type":
    var s = schemaFor[Note]()
    check s.slots.len == 4
    # Numbers are exact and dense; text has no ceiling, so no data loss.
    check s.slots[0].column == colFixed
    check s.slots[0].width == defaultFixedWidth
    check s.slots[1].column == colFixed
    check s.slots[2].column == colVariable
    check s.slots[3].column == colVariable
    # Truncation is never an implicit default.
    check s.slots[0].onOverflow == opError

  test "an all-fixed schema is dense and has a row width":
    var s = schemaFor[Flat]()
    check s.isDense()
    check s.rowBytes() == 40'u32
    check s.slotAt(2) == 16'u32
    check s.nameOf(s.slots[1].nameId) == "b"

  test "one variable column is enough to make rows vary":
    var s = schemaFor[Note]()
    check not s.isDense()
    # Zero is how a reader is told to consult the offset table.
    check s.rowBytes() == 0'u32

  test "collapsing makes even an all-fixed schema vary":
    var s = schemaFor[Flat]()
    check s.isDense()
    s.autoCollapse = true
    check not s.isDense()
    check s.rowBytes() == 0'u32

  test "a Ref is one atomic column, not six flattened fields":
    var s = schemaFor[Nested]()
    check s.slotIndex("payload") >= 0
    check s.slots[s.slotIndex("payload")].kind == skRef
    check s.slots[s.slotIndex("payload")].column == colFixed
    check s.slots[s.slotIndex("payload")].width == uint32(ownFileRefBytes)

suite "row codec":

  test "a full row round-trips":
    var s = schemaFor[Note]()
    var x = Note(id: 42, score: 1.5, title: "hello", body: "world")
    var built = toRowBytes(x, s)
    check built.err == ""
    check fromRowBytes[Note](built.data, s) == x

  test "negative integers survive":
    var s = schemaFor[Signed]()
    for x in [Signed(neg: -99999, pos: 7, flag: true),
              Signed(neg: -1, pos: -1, flag: false),
              Signed(neg: low(int) + 1, pos: high(int), flag: true)]:
      check fromRowBytes[Signed](toRowBytes(x, s).data, s) == x

  test "nested objects flatten and round-trip":
    var s = schemaFor[Nested]()
    var r = Ref(target: rtSidecar, hash: newSeq[uint8](fullDigestBytes))
    r.hash[0] = 9'u8
    var x = Nested(id: 3, label: "deep", payload: r)
    var back = fromRowBytes[Nested](toRowBytes(x, s).data, s)
    check back.id == 3
    check back.label == "deep"
    check back.payload.hash == r.hash

  test "a dense row is exactly its declared width":
    var s = schemaFor[Flat]()
    var built = toRowBytes(Flat(a: 1, b: 2.0, c: 3, d: true, e: 5), s)
    check built.data.len == int(s.rowBytes())
    check built.data.len == 40

suite "column kinds":

  test "colFixed refuses an oversized value by default":
    var s = schemaFor[Note]()
    var at = s.slotIndex("title")
    s.slots[at].column = colFixed
    s.slots[at].width = 8'u32
    var built = toRowBytes(Note(id: 1, title: "far too long for eight"), s)
    check built.err.len > 0
    check built.err.contains("title")
    check built.data.len == 0

  test "colFixed truncates when told to, and only then":
    var s = schemaFor[Note]()
    var at = s.slotIndex("title")
    s.slots[at].column = colFixed
    s.slots[at].width = 8'u32
    s.slots[at].onOverflow = opTruncate
    var built = toRowBytes(Note(id: 1, title: "far too long for eight"), s)
    check built.err == ""
    var back = fromRowBytes[Note](built.data, s)
    check back.title.len == 8
    check back.title == "far too "

  test "colCapped keeps a short value inline":
    var s = schemaFor[Note]()
    var at = s.slotIndex("title")
    s.slots[at].column = colCapped
    s.slots[at].width = 48'u32
    var built = toRowBytes(Note(id: 1, title: "short"), s)
    check built.err == ""
    check not s.isExternal(built.data, at)
    check fromRowBytes[Note](built.data, s).title == "short"

  test "colCapped externalises a long value into the same space":
    var root = getTempDir() / "geist_t_capped"
    removeDir(root)
    var store = initSidecarStore(root, 1'u32)
    var s = schemaFor[Note]()
    var at = s.slotIndex("body")
    s.slots[at].column = colCapped
    s.slots[at].width = 48'u32
    var big = newString(4096)
    for i in 0 ..< big.len:
      big[i] = char(ord('a') + (i mod 26))
    var built = toRowBytes(Note(id: 1, title: "t", body: big), s, store)
    check built.err == ""
    check s.isExternal(built.data, at)
    # The reference occupies the column's declared width, not more.
    var offs = fieldOffsets(s, built.data)
    check s.rawAt(built.data, offs, at).len == 48
    check fromRowBytes[Note](built.data, s, store).body == big
    removeDir(root)

  test "a capped column narrower than a reference is rejected":
    var c = appConfig()
    c.columnPolicy = @[ColumnPolicy(field: "title", column: colCapped,
      width: 8'u32)]
    var applied = applyColumnPolicy(c, schemaFor[Note]())
    check not applied.ok
    check applied.err.contains("reference needs")

  test "a policy naming a field that does not exist is an error":
    var c = appConfig()
    c.columnPolicy = @[fixedColumn("nosuchfield", 8'u32)]
    var applied = applyColumnPolicy(c, schemaFor[Note]())
    check not applied.ok
    check applied.err.contains("nosuchfield")

  test "cappedColumn raises a too-small width rather than accepting it":
    check cappedColumn("x", 4'u32).width == minCappedWidth

suite "collapsing":

  test "omitting zeros is lossless":
    var s = schemaFor[Note]()
    s.autoCollapse = true
    var x = Note(id: 0, score: 0.0, title: "", body: "only-this")
    var built = toRowBytes(x, s)
    var back = fromRowBytes[Note](built.data, s)
    check back == x
    check back.id == 0
    check back.title == ""

  test "an empty object collapses to nothing but its bitmap":
    var s = schemaFor[Note]()
    s.autoCollapse = true
    var built = toRowBytes(Note(), s)
    check built.data.len == nullBitmapBytes(s.slots.len)
    check fromRowBytes[Note](built.data, s) == Note()

  test "a sparse row is much smaller than a dense one":
    var s = schemaFor[Wide]()
    s.autoCollapse = true
    var dense = toRowBytes(Wide(a: 1, b: "bbbb", c: 3, d: "dddd", e: 5,
      f: "ffff", g: 7, h: "hhhh"), s)
    var sparse = toRowBytes(Wide(e: 5), s)
    check sparse.data.len < dense.data.len
    check sparse.data.len == nullBitmapBytes(8) + 8
    check fromRowBytes[Wide](sparse.data, s) == Wide(e: 5)

  test "row statistics report what the bitmaps did":
    var s = schemaFor[Wide]()
    s.autoCollapse = true
    var built = toRowBytes(Wide(a: 1, e: 5), s)
    var st = rowStats(s, built.data)
    check st.present == 2
    check st.omitted == 6
    check st.external == 0

  test "collapsing works on an all-fixed schema too":
    var s = schemaFor[Flat]()
    s.autoCollapse = true
    var x = Flat(a: 7, e: 9)
    var built = toRowBytes(x, s)
    # 5 columns -> 1 bitmap byte; two present ints -> 16 bytes.
    check built.data.len == 1 + 16
    check fromRowBytes[Flat](built.data, s) == x
