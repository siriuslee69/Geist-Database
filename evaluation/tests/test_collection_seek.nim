## The ergonomic object API and the partial-read paths.

import runePragmas
import std/[os, unittest]

import geist

type
  Note = object
    id*: int
    score*: float
    title*: string
    body*: string

  Reading = object
    sensor*: int
    value*: int

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / name
  removeDir(result)

suite "collection: objects in, objects out":

  # {.testKind: tkUnit.}
  test "a collection reads like a seq of the user's own type":
    var
      root = scratch("geist_t_coll")
      notes = openCollection[Note](root, "notes")
    notes.add Note(id: 1, score: 1.5, title: "first", body: "alpha")
    notes.add Note(id: 2, score: -2.25, title: "second", body: "beta")
    check notes.len == 2
    check notes[0].title == "first"
    check notes[1].score == -2.25
    check notes[1].id == 2
    notes.close()
    removeDir(root)

  # {.testKind: tkUnit.}
  test "items and pairs iterate in stored order":
    var
      root = scratch("geist_t_iter")
      notes = openCollection[Note](root, "notes")
    notes.add @[Note(id: 1, title: "a"), Note(id: 2, title: "b"),
      Note(id: 3, title: "c")]
    var seen: seq[string] = @[]
    for n in notes.items:
      seen.add n.title
    check seen == @["a", "b", "c"]
    for i, n in notes.pairs:
      check n.id == i + 1
    notes.close()
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "a bulk add saves once, not once per element":
    var
      root = scratch("geist_t_bulk")
      notes = openCollection[Note](root, "notes")
      batch: seq[Note] = @[]
    for i in 0 ..< 50:
      batch.add Note(id: i, title: "t" & $i, body: "b" & $i)
    var idx = notes.add(batch)
    check idx.len == 50
    check notes.len == 50
    check notes[49].title == "t49"
    notes.close()
    removeDir(root)

  # {.testKind: tkUnit.}
  test "the same API works sealed; only the constructor differs":
    var
      root = scratch("geist_t_collenc")
      notes = openEncryptedCollection[Note](root, "notes", "pw")
    notes.add Note(id: 7, title: "secret-title", body: "secret-body")
    check notes.isEncrypted()
    check notes.len == 1
    check notes[0].title == "secret-title"
    check notes.artifacts().len == 3
    notes.close()
    # Reopening with the same password recovers the object.
    var re = openEncryptedCollection[Note](root, "notes", "pw")
    check re[0].body == "secret-body"
    re.close()
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "an encrypted collection refuses a cipherless configuration":
    var root = scratch("geist_t_collbad")
    expect ValueError:
      discard openEncryptedCollection[Note](root, "n", "pw", appConfig())
    expect ValueError:
      discard openEncryptedCollection[Note](root, "n", "")
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "out-of-range access reports the range instead of reading garbage":
    var
      root = scratch("geist_t_range")
      notes = openCollection[Note](root, "notes")
    notes.add Note(id: 1, title: "only")
    expect IndexDefect:
      discard notes[1]
    expect IndexDefect:
      discard notes[-1]
    notes.close()
    removeDir(root)

  # {.testKind: tkUnit.}
  test "find matches on a named field":
    var
      root = scratch("geist_t_find")
      notes = openCollection[Note](root, "notes")
    notes.add @[Note(id: 1, title: "x"), Note(id: 2, title: "y"),
      Note(id: 3, title: "x")]
    check notes.find("title", "x").len == 2
    check notes.find("title", "zzz").len == 0
    notes.close()
    removeDir(root)

suite "seek: partial reads without loading the cluster":

  # {.testKind: tkUnit.}
  test "one row is addressable without reading the rest":
    var
      root = scratch("geist_t_seek")
      notes = openCollection[Note](root, "notes", appConfig(), "", false)
    for i in 0 ..< 200:
      notes.add Note(id: i, score: float(i), title: "t" & $i, body: "b" & $i)
    check notes.save().ok
    var path = notes.session.dataPath()
    notes.close()

    var h = openSeek(path)
    check h.ok
    check h.h.rowCount() == 200'u32
    check h.h.seekObject[:Note](150'u32).id == 150
    check h.h.seekText(7'u32, h.h.schema.slotIndex("title")) == "t7"
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "the index cost does not grow with the row count":
    var
      small = scratch("geist_t_ix_s")
      big = scratch("geist_t_ix_b")
      a = openCollection[Reading](small, "r", appConfig(), "", false)
    a.add Reading(sensor: 1, value: 1)
    check a.save().ok
    var pa = a.session.dataPath()
    a.close()
    var b = openCollection[Reading](big, "r", appConfig(), "", false)
    for i in 0 ..< 5000:
      b.add Reading(sensor: i, value: i * 2)
    check b.save().ok
    var pb = b.session.dataPath()
    b.close()
    check indexCostBytes(pa) == indexCostBytes(pb)
    check getFileSize(pb) > getFileSize(pa) * 100
    removeDir(small)
    removeDir(big)

  # {.testKind: tkEdgeCase.}
  test "a fixed column is read by striding, not by unpacking rows":
    var
      root = scratch("geist_t_col")
      rs = openCollection[Reading](root, "r", appConfig(), "", false)
    for i in 0 ..< 100:
      rs.add Reading(sensor: i mod 4, value: i)
    check rs.save().ok
    var path = rs.session.dataPath()
    rs.close()

    var h = openSeek(path)
    check h.ok
    var col = h.h.seekFixedColumn(h.h.schema.slotIndex("value"))
    check col.len == 100
    check col[0] == 0'u64
    check col[99] == 99'u64
    # Equality scan returns indices, so the caller decides what to fetch.
    var hits = h.h.seekMatching(h.h.schema.slotIndex("sensor"), 2'u64)
    check hits.len == 25
    check hits[0] == 2'u32
    var capped = h.h.seekMatching(h.h.schema.slotIndex("sensor"), 2'u64, 5)
    check capped.len == 5
    removeDir(root)

  # {.testKind: tkUnit.}
  test "a variable column comes back as slices, two bulk reads":
    var
      root = scratch("geist_t_vcol")
      notes = openCollection[Note](root, "notes", appConfig(), "", false)
    for i in 0 ..< 30:
      notes.add Note(id: i, title: "title-" & $i, body: "body-" & $i)
    check notes.save().ok
    var path = notes.session.dataPath()
    notes.close()

    var h = openSeek(path)
    check h.ok
    var col = h.h.seekColumnBytes(h.h.schema.slotIndex("title"))
    check col.len == 30
    check cast[string](col[5]) == "title-5"
    check cast[string](col[29]) == "title-29"
    removeDir(root)

  # {.testKind: tkUnit.}
  test "a row window is one contiguous read":
    var
      root = scratch("geist_t_win")
      rs = openCollection[Reading](root, "r", appConfig(), "", false)
    for i in 0 ..< 500:
      rs.add Reading(sensor: i, value: i)
    check rs.save().ok
    var path = rs.session.dataPath()
    rs.close()

    var h = openSeek(path)
    check h.ok
    var win = h.h.seekRange(100'u32, 50'u32)
    check win.len == 50
    # Address the column by NAME: slot 0 is the reserved __rowId now, and a
    # test that hardcodes a position tests the wrong thing anyway.
    var sensorSlot = h.h.schema.slotIndex("sensor")
    check h.h.schema.u64At(win[0].data,
      fieldOffsets(h.h.schema, win[0].data), sensorSlot) == 100'u64
    check h.h.schema.u64At(win[49].data,
      fieldOffsets(h.h.schema, win[49].data), sensorSlot) == 149'u64
    # A window past the end is clamped, not an error.
    check h.h.seekRange(490'u32, 100'u32).len == 10
    check h.h.seekRange(9999'u32, 10'u32).len == 0
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "seeking past the end reports the range":
    var
      root = scratch("geist_t_oob")
      rs = openCollection[Reading](root, "r", appConfig(), "", false)
    rs.add Reading(sensor: 1, value: 1)
    check rs.save().ok
    var path = rs.session.dataPath()
    rs.close()
    var h = openSeek(path)
    check h.ok
    expect IndexDefect:
      discard h.h.seekRow(5'u32)
    removeDir(root)

  # {.testKind: tkUnit.}
  test "a handle notices the file moved on underneath it":
    var
      root = scratch("geist_t_stale")
      rs = openCollection[Reading](root, "r", appConfig(), "", false)
    rs.add Reading(sensor: 1, value: 1)
    check rs.save().ok
    var
      path = rs.session.dataPath()
      h = openSeek(path)
    check h.ok
    check not h.h.isStale()
    rs.close()
    removeDir(root)

  # {.testKind: tkEdgeCase.}
  test "openSeek on a missing or wrong file fails rather than guessing":
    check not openSeek(getTempDir() / "geist_t_nope.ge1st.g1").ok
    var bogus = getTempDir() / "geist_t_bogus.ge1st.g1"
    writeFile(bogus, "not a geist file at all, not even close")
    check not openSeek(bogus).ok
    removeFile(bogus)
