## Row identity: naming a row, changing it, removing it, reclaiming space.
##
## The property under test throughout is that a NAME survives what a
## position does not. Every test that mutates does so after something else
## has moved, because a position that happens to still be right proves
## nothing.

import std/[os, strutils, tables, unittest]
import geist

type
  Note = object
    noteId: int
    title: string
    body: string

  Reading = object
    sensor: int
    value: int

proc freshRoot(name: string): string =
  result = getTempDir() / name
  removeDir(result)

suite "identity":
  test "a stored row gets an id, and the id is what comes back":
    var root = freshRoot("geist_t_id1")
    var db = openGeist[Note](root, appConfig())
    var a = db.put(Note(noteId: 1, title: "first", body: "x"))
    var b = db.put(Note(noteId: 2, title: "second", body: "y"))
    # An id is this database's node tag plus a counter, so the numbers are
    # large and the SEQUENCE is what is guaranteed -- see rowid.nim.
    check a != 0'u64
    check b == a + 1'u64
    check a.nodeTagOf() == b.nodeTagOf()
    check a.counterOf() == 1'u64
    check db.hasIdentity()
    check byId[Note](db, a).value.title == "first"
    check byId[Note](db, b).found
    check not byId[Note](db, 99'u64).found
    db.close()

  test "ids survive save and reopen":
    var root = freshRoot("geist_t_id2")
    var db = openGeist[Note](root, appConfig())
    var ids = db.put(@[Note(noteId: 1, title: "a"), Note(noteId: 2, title: "b")])
    check db.save().ok
    db.close()
    var re = openGeist[Note](root, appConfig())
    check byId[Note](re, ids[0]).value.title == "a"
    check byId[Note](re, ids[1]).value.title == "b"
    # The allocator continues where it left off rather than colliding.
    check re.put(Note(noteId: 3, title: "c")) == ids[1] + 1'u64
    re.close()

  test "set replaces the row without moving anyone else":
    var root = freshRoot("geist_t_id3")
    var db = openGeist[Note](root, appConfig())
    var a = db.put(Note(noteId: 1, title: "draft", body: "x"))
    var b = db.put(Note(noteId: 2, title: "other", body: "y"))
    check db.set(a, Note(noteId: 1, title: "final", body: "x2"))
    check byId[Note](db, a).value.title == "final"
    check byId[Note](db, b).value.title == "other"
    # One row visible per id, whatever the log holds.
    check db.entryCount() == 2'u32
    check db.logCount() == 3'u32
    # The view keeps first-appearance order, so an update does not shuffle
    # the list under a caller that is iterating it.
    check get[Note](db, 0'u32).title == "final"
    check get[Note](db, 1'u32).title == "other"
    check db.set(999'u64, Note(noteId: 9, title: "nope")) == false
    db.close()

  test "delete hides the row and keeps the tombstone in the log":
    var root = freshRoot("geist_t_id4")
    var db = openGeist[Note](root, appConfig())
    var a = db.put(Note(noteId: 1, title: "a"))
    var b = db.put(Note(noteId: 2, title: "b"))
    var c = db.put(Note(noteId: 3, title: "c"))
    check db.delete(b)
    check db.entryCount() == 2'u32
    check db.logCount() == 4'u32
    check not byId[Note](db, b).found
    check byId[Note](db, a).found
    check byId[Note](db, c).found
    check get[Note](db, 1'u32).title == "c"
    # Deleting twice is not an error and does not grow the log.
    check db.delete(b) == false
    check db.logCount() == 4'u32
    check db.delete(4242'u64) == false
    db.close()

  test "updates and deletes survive a reopen":
    var root = freshRoot("geist_t_id5")
    var db = openGeist[Note](root, appConfig())
    var ids = db.put(@[Note(noteId: 1, title: "a"), Note(noteId: 2, title: "b"),
      Note(noteId: 3, title: "c")])
    check db.set(ids[0], Note(noteId: 1, title: "a-changed"))
    check db.delete(ids[2])
    check db.save().ok
    db.close()
    var re = openGeist[Note](root, appConfig())
    check re.entryCount() == 2'u32
    check byId[Note](re, ids[0]).value.title == "a-changed"
    check byId[Note](re, ids[1]).value.title == "b"
    check not byId[Note](re, ids[2]).found
    re.close()

  test "a deleted row can be brought back by name":
    var root = freshRoot("geist_t_id6")
    var db = openGeist[Note](root, appConfig())
    var a = db.put(Note(noteId: 1, title: "here"))
    check db.delete(a)
    check not byId[Note](db, a).found
    # The tombstone is just the previous version; a newer one supersedes it.
    check db.set(a, Note(noteId: 1, title: "back"))
    check byId[Note](db, a).value.title == "back"
    check db.entryCount() == 1'u32
    db.close()

  test "find and findIds see current versions only":
    var root = freshRoot("geist_t_id7")
    var db = openGeist[Note](root, appConfig())
    var a = db.put(Note(noteId: 1, title: "keep"))
    var b = db.put(Note(noteId: 2, title: "keep"))
    check db.set(a, Note(noteId: 1, title: "changed"))
    check find[Note](db, "title", "keep").len == 1
    check db.findIds("title", "keep") == @[b]
    check find[Note](db, "title", "changed").len == 1
    check db.delete(b)
    check find[Note](db, "title", "keep").len == 0
    db.close()

suite "identity and encryption":
  test "the id columns are sealed with the row":
    var root = freshRoot("geist_t_idenc")
    var db = openGeist[Note](root, secureAppConfig(), "pw")
    var a = db.put(Note(noteId: 1, title: "SECRET", body: "MARKER"))
    check db.set(a, Note(noteId: 1, title: "SECRET2", body: "MARKER2"))
    check db.save().ok
    db.close()
    var raw = readFile(liveDataPath(root))
    check not raw.contains("MARKER")
    var re = openGeist[Note](root, secureAppConfig(), "pw")
    check byId[Note](re, a).value.body == "MARKER2"
    check re.entryCount() == 1'u32
    re.close()

suite "compaction":
  test "compact drops superseded versions and keeps the visible ones":
    var root = freshRoot("geist_t_comp1")
    var db = openGeist[Note](root, appConfig())
    var ids = db.put(@[Note(noteId: 1, title: "a"), Note(noteId: 2, title: "b"),
      Note(noteId: 3, title: "c")])
    check db.set(ids[0], Note(noteId: 1, title: "a2"))
    check db.set(ids[0], Note(noteId: 1, title: "a3"))
    check db.delete(ids[2])
    check db.logCount() == 6'u32
    check db.entryCount() == 2'u32
    var done = db.compact()
    check done.ok
    check done.removed == 4'u32
    check db.logCount() == 2'u32
    check db.entryCount() == 2'u32
    check byId[Note](db, ids[0]).value.title == "a3"
    check byId[Note](db, ids[1]).value.title == "b"
    check not byId[Note](db, ids[2]).found
    db.close()

  test "compaction never hands a retired id back out":
    var root = freshRoot("geist_t_comp2")
    var db = openGeist[Note](root, appConfig())
    var ids = db.put(@[Note(noteId: 1, title: "a"), Note(noteId: 2, title: "b")])
    check db.delete(ids[1])          # the HIGHEST id is the one removed
    discard db.compact()
    check db.save().ok
    db.close()
    # A peer may still be holding the tombstone for that id. Reusing it
    # would make that tombstone delete a different row.
    var re = openGeist[Note](root, appConfig())
    var fresh = re.put(Note(noteId: 3, title: "new"))
    check fresh != ids[0]
    check fresh != ids[1]
    # Same database, so the same node tag, and the counter has moved past
    # the one the removed row used.
    check fresh.nodeTagOf() == ids[1].nodeTagOf()
    check fresh.counterOf() > ids[1].counterOf()
    re.close()

suite "databases without identity":
  test "a telemetry preset stores no identity and says so":
    var root = freshRoot("geist_t_noid")
    var db = openGeist[Reading](root, iotConfig(), "pw")
    discard db.put(Reading(sensor: 1, value: 10))
    discard db.put(Reading(sensor: 2, value: 20))
    check not db.hasIdentity()
    check db.entryCount() == 2'u32
    check get[Reading](db, 1'u32).value == 20
    # Naming a row is refused with an explanation rather than a wrong answer.
    expect ValueError:
      discard db.delete(1'u64)
    check db.save().ok
    db.close()

  test "identity-free rows stay dense":
    var root = freshRoot("geist_t_noid2")
    var db = openGeist[Reading](root, iotConfig(), "pw")
    discard db.put(Reading(sensor: 1, value: 10))
    check db.save().ok
    var path = db.dataPath()
    db.close()
    var h = openSeek(path)
    check h.ok
    check h.h.isDenseHandle()
    check h.h.entry.rowBytes == 16'u32     # two columns, no reserved pair
    removeDir(root)

suite "the schema-driven path":
  test "a dynamic row carries the id it was built with":
    var root = freshRoot("geist_t_dyn")
    var spec = parseSchemaSpec("Note", "id:int,title:text")
    check spec.ok
    var db = openSessionWithSchema(root, "main", spec.s, appConfig())
    var id = db.nextIdFor()
    var built = buildRow(db.entries.schema,
      {"id": "1", "title": "hello"}.toTable, db.sidecarStore, id)
    check built.ok
    check db.putRow(Row(data: built.data)) == id
    check db.entryCount() == 1'u32
    check db.idAt(0'u32) == id
    # A row offered without an id on an identified database is refused
    # rather than stored as something nobody could ever address.
    var anon = buildRow(db.entries.schema,
      {"id": "2", "title": "anon"}.toTable, db.sidecarStore)
    check anon.ok
    expect ValueError:
      discard db.putRow(Row(data: anon.data))
    db.close()

  test "a caller cannot declare a reserved column":
    var spec = parseSchemaSpec("Bad", "__rowId:int,title:text")
    check not spec.ok
    check spec.err.contains("reserved")

  test "a malformed row is refused, not decoded":
    var root = freshRoot("geist_t_badrow")
    var db = openGeist[Note](root, appConfig())
    expect ValueError:
      db.putRow(Row(data: @[1'u8, 2'u8, 3'u8]))
    db.close()

suite "the changefeed says what happened":
  test "add, update and delete are distinguishable, and name the row":
    var root = freshRoot("geist_t_feed")
    var db = openGeist[Note](root, appConfig())
    discard db.subscribe("watcher")
    var a = db.put(Note(noteId: 1, title: "a"))
    check db.set(a, Note(noteId: 1, title: "a2"))
    check db.delete(a)
    var events = poll(db, "watcher")
    check events.len == 3
    check events[0].kind == ckAdded
    check events[1].kind == ckUpdated
    check events[2].kind == ckDeleted
    for e in events:
      check e.rowId == a
    db.close()

## ---------------------------------------------------------------------
## The live view is maintained incrementally, and that has to STAY true.
##
## `appendPacked` used to rebuild the whole live list on every append,
## walking every id and decoding its flags. Storing N rows therefore cost
## O(N^2): 10k rows took 8 seconds and 50k took 210. It is the kind of
## defect that never shows up in a correctness test, because the answers
## are right -- only the cost is wrong -- and never shows up in a small
## fixture either, because at 100 rows quadratic is free.
## ---------------------------------------------------------------------

import std/[monotimes, times]

suite "appending stays cheap as the log grows":
  test "the live view is correct when appends, updates and deletes mix":
    # The O(1) append path may only be taken for a brand new id. This
    # interleaves the three cases so a wrong shortcut shows up as a wrong
    # answer rather than as a fast wrong one.
    var
      root = freshRoot("geist_t_live_mix")
      db = openGeist[Note](root, appConfig())
      ids: seq[RowId] = @[]
    for i in 0 ..< 200:
      ids.add db.put(Note(noteId: i, title: "t" & $i, body: "b"))
      if i mod 3 == 0 and ids.len > 1:
        check db.set(ids[^2], Note(noteId: i, title: "updated", body: "b"))
      if i mod 7 == 0 and ids.len > 2:
        check db.delete(ids[^3])
    check db.save().ok
    var visible = db.entryCount()
    var idsNow = db.rowIds()
    check idsNow.len == int(visible)
    # Reopening rebuilds the view by a full pass, which is the independent
    # answer: the incremental path must agree with it exactly.
    db.close()
    var re = openGeist[Note](root, appConfig())
    check re.entryCount() == visible
    check re.rowIds() == idsNow
    re.close()

  test "storing four times the rows costs about four times as much":
    # A ratio, not a wall clock, so it means the same on a slow machine.
    # Linear is ~4x; the quadratic version this guards against was ~16x.
    proc appendCost(n: int, name: string): float =
      var db = openGeist[Note](freshRoot(name), appConfig())
      var t0 = getMonoTime()
      for i in 0 ..< n:
        discard db.put(Note(noteId: i, title: "t", body: "b"))
      var t1 = getMonoTime()
      check db.save().ok
      db.close()
      result = float((t1 - t0).inNanoseconds)

    var small = appendCost(10_000, "geist_t_grow_small")
    var large = appendCost(40_000, "geist_t_grow_large")
    var ratio = large / small
    # Generous: linear lands near 4, and anything under 8 cannot be
    # quadratic at this spread.
    check ratio < 8.0
    if ratio >= 8.0:
      echo "  4x the rows cost ", ratio, "x the time -- appends are not linear"
