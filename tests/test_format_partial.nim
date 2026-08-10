## Format/store: seekable index, single-row reads, change detection.
import std/[os, unittest]
import geist

type
  Row3 = object
    id: int
    name: string
    score: uint16

suite "format":
  setup:
    var
      root = getTempDir() / "geist_t_format"
      path = root / "c.ge1st"
      s = schemaFor[Row3]()
      c = initClusterBuild(crEntry, cmAppend, s,
        initSidecarStore(root / "sc"))
    removeDir(root)
    createDir(root)
    for i in 0 ..< 12:
      c.addRow(Row3(id: i, name: "row-" & $i, score: uint16(i * 3)))
    check writeGeistFile(path, @[c]).ok

  test "index read cost is independent of row count":
    var r = readIndex(path)
    check r.ok
    check r.f.indexBytes == headerBytes + indexEntryBytes
    check r.f.index[0].rowCount == 12'u32

  test "a single row is addressable without loading the cluster":
    # This schema has a text column, so its rows vary and addressing goes
    # through the offset table. `seekRow` picks the right path from the
    # schema; the raw `readRowAt` is only valid for a dense cluster.
    var h = openSeek(path)
    check h.ok
    check not h.h.isDenseHandle()
    var row = h.h.seekRow(7'u32)
    var offs = fieldOffsets(h.h.schema, row.data)
    check h.h.schema.u64At(row.data, offs, 0) == 7'u64
    check h.h.schema.u64At(row.data, offs, 2) == 21'u64
    check h.h.seekObject[:Row3](7'u32).name == "row-7"

  test "an all-fixed schema stays dense and addresses arithmetically":
    type Dense = object
      a*: int
      b*: int
    var droot = getTempDir() / "geist_t_dense"
    removeDir(droot)
    var col = openCollection[Dense](droot, "d", appConfig(), "", false)
    for i in 0 ..< 10:
      col.add Dense(a: i, b: i * 3)
    check col.save().ok
    var dp = col.session.dataPath()
    col.close()
    var dh = openSeek(dp)
    check dh.ok
    check dh.h.isDenseHandle()
    # Two declared columns plus the two reserved identity columns, all
    # colFixed at 8 B. Identity does not cost density -- only width.
    check dh.h.entry.rowBytes == 32'u32
    check dh.h.seekObject[:Dense](4'u32).b == 12
    removeDir(droot)

  test "a full cluster read reconstructs objects":
    var
      r = readIndex(path)
      full = readCluster(path, r.f.index[0])
    check full.rowCount == 12'u32
    check objectAt[Row3](full, 5'u32).name == "row-5"

  test "changed clusters are detected from the index alone":
    var
      before = readIndex(path)
      c2 = readCluster(path, before.f.index[0])
    c2.addRow(Row3(id: 99, name: "new", score: 1))
    check writeGeistFile(path, @[c2]).ok
    var after = readIndex(path)
    check changedClusters(before.f, after.f) == @[0]
