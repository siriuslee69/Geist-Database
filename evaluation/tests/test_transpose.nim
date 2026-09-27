## The column-first copy: exact on the way back, cheaper on the way in.
##
## Two claims are worth guarding, and they pull in opposite directions.
## The copy has to be EXACT -- every row must come back byte for byte, or
## a search that consults it answers differently from one that does not --
## and it has to be CHEAPER, or there is no reason for it to exist. So
## there is a reconstruction test over every shape of schema, and a cost
## test that compares bytes read against the row-major file.
##
## The third claim is freshness. A copy that is out of date must say so
## rather than answer with yesterday's rows, which is the one failure that
## would look like the database being wrong.

import runePragmas
import std/[os, strutils, unittest]

import geist

type
  Note = object
    noteId: int
    title: string
    body: string
    tag: string

  Reading = object
    deviceId: int
    metric: int
    capturedAt: int
    value: int

proc freshRoot(name: string): string {.role: helper.} =
  result = "build/test-transpose-" & name
  removeDir(result)

proc fill(db: var Session, n: int) {.role: dataWriter.} =
  for i in 1 .. n:
    db.put(Note(noteId: i, title: "title" & $i, body: "body-" & $i,
      tag: (if i mod 7 == 0: "seven" else: "other")))

suite "a rebuilt row is the row that was stored":

  test "every row of a varying schema comes back byte for byte":
    var
      root = freshRoot("exact")
      db = openGeist[Note](root, appConfig())
    db.fill(200)
    discard db.save()
    check writeTransposed(transposedPath(root, "main", db.generation),
      db.entries, db.generation).ok
    var t = openTransposed(transposedPath(root, "main", db.generation))
    check t.ok
    check t.t.rowCount == 200'u32
    var i = 0'u32
    while i < t.t.rowCount:
      check t.t.transposedRow(i).data == db.entries.rowAt(i).data
      i = i + 1'u32
    db.close()

  test "a dense schema addresses its columns arithmetically":
    var
      root = freshRoot("dense")
      db = openGeist[Reading](root, iotConfig(), "sensor password")
    for i in 1 .. 100:
      db.put(Reading(deviceId: 1, metric: i mod 4, capturedAt: 1700 + i,
        value: i * 3))
    discard db.save()
    # iotConfig seals, and a sealed store refuses the copy -- so this
    # exercises the writer directly, which is the layer under test.
    check writeTransposed(transposedPath(root, "main", db.generation),
      db.entries, db.generation).ok
    var t = openTransposed(transposedPath(root, "main", db.generation))
    check t.ok
    for c in t.t.columns:
      check c.dense
    var i = 0'u32
    while i < t.t.rowCount:
      check t.t.transposedRow(i).data == db.entries.rowAt(i).data
      i = i + 1'u32
    db.close()

  test "a collapsing schema keeps its omitted columns omitted":
    var
      root = freshRoot("collapse")
      c = appConfig()
    c.autoCollapse = true
    var db = openGeist[Note](root, c)
    # Half the rows leave `body` and `tag` empty, so the null bitmap is
    # doing work and the columns are no longer the same width per row.
    for i in 1 .. 50:
      if i mod 2 == 0:
        db.put(Note(noteId: i, title: "title" & $i))
      else:
        db.put(Note(noteId: i, title: "title" & $i, body: "b" & $i,
          tag: "t"))
    discard db.save()
    check writeTransposed(transposedPath(root, "main", db.generation),
      db.entries, db.generation).ok
    var t = openTransposed(transposedPath(root, "main", db.generation))
    check t.ok
    for c2 in t.t.columns:
      check not c2.dense           # collapsing takes arithmetic away
    var i = 0'u32
    while i < t.t.rowCount:
      check t.t.transposedRow(i).data == db.entries.rowAt(i).data
      i = i + 1'u32
    db.close()

  test "a rebuilt row still decodes as the object it was":
    var
      root = freshRoot("object")
      db = openGeist[Note](root, appConfig())
    db.fill(20)
    discard db.save()
    check writeTransposed(transposedPath(root, "main", db.generation),
      db.entries, db.generation).ok
    var t = openTransposed(transposedPath(root, "main", db.generation))
    check t.ok
    var back = fromRowBytes[Note](t.t.transposedRow(6'u32).data, t.t.schema)
    check back.noteId == 7
    check back.title == "title7"
    check back.tag == "seven"
    db.close()

suite "a search reads one column":

  test "the answer matches the row scan, and costs less":
    var
      root = freshRoot("find")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(500)
    discard db.save()
    var view = db.transposedView()
    check view.ok
    var hit = view.t.transposedFind("title", "title42")
    check hit.ok
    check hit.rows == @[41'u32]
    # What the row scan would have said.
    var scanned: seq[uint32] = @[]
    for i in 0'u32 ..< db.entryCount():
      if matchesText(db.entries.schema, db.visibleRow(i).data, "title",
          "title42"):
        scanned.add i
    check scanned == hit.rows
    # And the point of the exercise: fewer bytes than the rows occupy.
    check hit.read < uint64(getFileSize(db.dataPath()))
    db.close()

  test "a column with many matches finds all of them":
    var
      root = freshRoot("many")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(700)
    discard db.save()
    var view = db.transposedView()
    check view.ok
    var hit = view.t.transposedFind("tag", "seven")
    check hit.ok
    check hit.rows.len == 100          # every seventh of 700
    db.close()

  test "a limit stops the scan early":
    var
      root = freshRoot("limit")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(200)
    discard db.save()
    var view = db.transposedView()
    check view.ok
    check view.t.transposedFind("tag", "seven", 3).rows.len == 3
    db.close()

  test "an unknown column is an error, not an empty answer":
    var
      root = freshRoot("nocol")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(5)
    discard db.save()
    var view = db.transposedView()
    check view.ok
    var hit = view.t.transposedFind("nosuchfield", "x")
    check not hit.ok
    check "no column 'nosuchfield'" in hit.err
    db.close()

  test "the copy holds the log, so superseded rows are still in it":
    # The property a caller MUST know about: a hit is a log position, and
    # deciding whether it is visible is the session's job. This is the
    # test that would fail if the CLI stopped asking.
    var
      root = freshRoot("log")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(5)
    discard db.save()
    var id = db.entries.schema.rowIdOf(db.visibleRow(2'u32).data)
    discard db.set(id, Note(noteId: 3, title: "changed", body: "b", tag: "x"))
    discard db.save()
    var view = db.transposedView()
    check view.ok
    # The old value is still in the column copy...
    check view.t.transposedFind("title", "title3").rows.len == 1
    # ...but it is not a visible row any more.
    var stale = view.t.transposedFind("title", "title3").rows[0]
    check db.visibleIndexOf(stale) < 0
    # And the new one is.
    var fresh = view.t.transposedFind("title", "changed").rows[0]
    check db.visibleIndexOf(fresh) >= 0
    db.close()

suite "which copy is newer":

  test "absent, then current, then stale":
    var
      root = freshRoot("state")
      c = appConfig()
    c.transpose = tmManual
    var db = openGeist[Note](root, c)
    db.fill(10)
    discard db.save()
    check db.transposeState().state == tsAbsent
    check db.syncTransposed().ok
    check db.transposeState().state == tsCurrent
    db.put(Note(noteId: 99, title: "later", body: "b", tag: "x"))
    discard db.save()
    var st = db.transposeState()
    check st.state == tsStale
    check st.built < st.live
    check "STALE" in describeTransposeState(st.state, st.live, st.built)
    db.close()

  test "a stale copy is refused rather than searched":
    var
      root = freshRoot("refuse")
      c = appConfig()
    c.transpose = tmManual
    var db = openGeist[Note](root, c)
    db.fill(10)
    discard db.save()
    check db.syncTransposed().ok
    db.put(Note(noteId: 11, title: "later", body: "b", tag: "x"))
    discard db.save()
    var view = db.transposedView()
    check not view.ok
    check "STALE" in view.err
    db.close()

  test "an unsaved session will not build a copy":
    var
      root = freshRoot("dirty")
      c = appConfig()
    c.transpose = tmManual
    var db = openGeist[Note](root, c)
    db.fill(3)
    var built = db.syncTransposed()
    check not built.ok
    check "unsaved rows" in built.err
    db.close()

  test "tmNone says so instead of building one":
    var
      root = freshRoot("none")
      db = openGeist[Note](root, appConfig())
    db.fill(3)
    discard db.save()
    var built = db.syncTransposed()
    check not built.ok
    check "tmNone" in built.err
    check db.transposeState().state == tsAbsent
    db.close()

suite "when the copy is written":

  test "tmOnSave keeps it current and retires the old ones":
    var
      root = freshRoot("onsave")
      c = appConfig()
    c.transpose = tmOnSave
    var db = openGeist[Note](root, c)
    db.fill(5)
    discard db.save()
    check db.transposeState().state == tsCurrent
    db.put(Note(noteId: 6, title: "six", body: "b", tag: "x"))
    discard db.save()
    check db.transposeState().state == tsCurrent
    # Exactly one column file: an old one is derived data nobody reads.
    var copies = 0
    for kind, path in walkDir(root):
      if path.extractFilename().contains(".getr."):
        copies = copies + 1
    check copies == 1
    db.close()

  test "tmInterval waits for its window":
    var
      root = freshRoot("interval")
      c = appConfig()
    c.transpose = tmInterval
    c.transposeEverySeconds = 3600'u32
    var db = openGeist[Note](root, c)
    db.fill(5)
    discard db.save()
    # The first save has no copy to compare against, so it builds one.
    check db.transposeState().state == tsCurrent
    db.put(Note(noteId: 6, title: "six", body: "b", tag: "x"))
    discard db.save()
    # The second is inside the window, so the copy stays where it was.
    check db.transposeState().state == tsStale
    db.close()

suite "configuration refuses what it cannot do":

  test "a sealed store may not keep a plaintext column copy":
    var c = secureAppConfig()
    c.transpose = tmOnSave
    var checked = validateGeistConfig(c)
    check not checked.ok
    check "plaintext column copy" in checked.err
    check "encryption at rest" in checked.err

  test "an interval of zero is not an interval":
    var c = appConfig()
    c.transpose = tmInterval
    c.transposeEverySeconds = 0'u32
    var checked = validateGeistConfig(c)
    check not checked.ok
    check "transposeEverySeconds" in checked.err

  test "config.toml names the mode, and a typo is refused":
    var dir = freshRoot("settings")
    createDir(dir)
    writeFile(dir / "config.toml", "[runtime.storage]\ntranspose = \"onSave\"\n")
    var good = loadGeistDefaults(dir / "config.toml")
    check good.ok
    check good.defaults.transpose == "onSave"
    check applyDefaults(appConfig(), good.defaults).transpose == tmOnSave
    writeFile(dir / "config.toml", "[runtime.storage]\ntranspose = \"onsave\"\n")
    var bad = loadGeistDefaults(dir / "config.toml")
    check not bad.ok
    check "must be none, onSave, interval or manual" in bad.err

  test "a file that says nothing leaves the preset alone":
    var dir = freshRoot("silent")
    createDir(dir)
    writeFile(dir / "config.toml", "[runtime.storage]\npreset = \"app\"\n")
    var loaded = loadGeistDefaults(dir / "config.toml")
    check loaded.ok
    var c = appConfig()
    c.transpose = tmManual
    check applyDefaults(c, loaded.defaults).transpose == tmManual

suite "a damaged copy is refused":

  test "a truncated file does not decode into nonsense":
    var
      root = freshRoot("truncated")
      db = openGeist[Note](root, appConfig())
    db.fill(50)
    discard db.save()
    var path = transposedPath(root, "main", db.generation)
    check writeTransposed(path, db.entries, db.generation).ok
    var whole = readFile(path)
    writeFile(path, whole[0 ..< whole.len div 2])
    var opened = openTransposed(path)
    check not opened.ok
    check "past its own end" in opened.err or "truncated" in opened.err
    db.close()

  test "a file that is not a column copy is named as such":
    var root = freshRoot("notours")
    createDir(root)
    writeFile(root / "main.getr.g1", "this is not a transposed file at all")
    var opened = openTransposed(root / "main.getr.g1")
    check not opened.ok
    check "not a transposed file" in opened.err
