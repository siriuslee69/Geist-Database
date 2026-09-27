## ---------------------------------------------------------------
## Geist Fast Search <- printing a store, and turning it on its side
## ---------------------------------------------------------------
##
## Run from the repo root:
##   nimble exampleFastSearch
##
## Two things that go together more often than not: looking at what is in
## a store, and finding something in it without reading all of it.
##
## `echo db` prints the table, and elides a big one the way a big matrix
## is written -- corners, with the middle marked -- because printing half
## a million rows is never what anyone meant.
##
## `transpose = tmOnSave` keeps a second copy of the rows written column
## first, so a search over one column reads that column instead of every
## row. The copy is derived: the row-major generation stays the truth.

import std/[os, strutils, times]

import geist

type
  Note = object
    noteId: int
    title: string
    body: string
    tag: string

when isMainModule:
  var
    root: string = ""
    db: Session = default(Session)
    view: tuple[ok: bool, t: TransposedFile, err: string] =
      (false, default(TransposedFile), "")
    hit: tuple[ok: bool, rows: seq[uint32], read: uint64, err: string] =
      (false, @[], 0'u64, "")
    state: tuple[state: TransposeState, live: uint64, built: uint64,
      path: string]
    c: GeistConfig = default(GeistConfig)
    started: float = 0.0
    rowMs: float = 0.0
    colMs: float = 0.0
    matched: int = 0
    i: uint32 = 0'u32

  root = getTempDir() / "geist_fast_search_example"
  removeDir(root)

  # tmOnSave rewrites the column copy with every save. Never stale, and
  # the slowest of the four modes -- see tmInterval and tmManual for the
  # trades a busier store might want instead.
  c = appConfig()
  c.transpose = tmOnSave
  db = openGeist[Note](root, c)
  for n in 1 .. 5_000:
    db.put(Note(noteId: n, title: "title" & $n,
      body: "a body of about sixty characters, number " & $n,
      tag: (if n mod 100 == 0: "hit" else: "miss")))
  discard db.save()

  echo "-- echo db, elided like a matrix ------------------------------"
  echo db
  echo "-- the same rows, axes swapped -------------------------------"
  var narrow = defaultShowStyle()
  narrow.maxColumns = 3
  echo db.showTransposed(narrow)

  echo "-- the column copy -------------------------------------------"
  state = db.transposeState()
  echo "state:       ", describeTransposeState(state.state, state.live,
    state.built)
  echo "row-major:   ", getFileSize(db.dataPath()), " B"
  echo "column copy: ", getFileSize(state.path), " B"

  # The same question asked twice: once by walking every row, once by
  # reading one column. The ANSWER has to match -- only the cost differs.
  started = cpuTime()
  matched = 0
  while i < db.entryCount():
    if matchesText(db.entries.schema, db.visibleRow(i).data, "tag", "hit"):
      matched = matched + 1
    i = i + 1'u32
  rowMs = (cpuTime() - started) * 1000

  view = db.transposedView()
  doAssert view.ok, view.err
  started = cpuTime()
  hit = view.t.transposedFind("tag", "hit")
  colMs = (cpuTime() - started) * 1000

  doAssert hit.ok, hit.err
  doAssert hit.rows.len == matched
  echo ""
  echo "find tag=hit"
  echo "  row scan:    ", rowMs.formatFloat(ffDecimal, 2), " ms, reading ",
    getFileSize(db.dataPath()), " B of rows"
  echo "  column scan: ", colMs.formatFloat(ffDecimal, 2), " ms, reading ",
    hit.read, " B"
  echo "  both found:  ", matched, " rows"

  # A hit is a LOG position. Superseded versions and tombstones are in the
  # copy because they are in the log, so anything reporting a hit has to
  # ask whether it is still visible.
  echo ""
  echo "first hit is visible row @",
    db.visibleIndexOf(hit.rows[0]), " of ", db.entryCount()
  echo "and it decodes as an ordinary object: ",
    fromRowBytes[Note](view.t.transposedRow(hit.rows[0]).data,
      view.t.schema).title

  db.close()
