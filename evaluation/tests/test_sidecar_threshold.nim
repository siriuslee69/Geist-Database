## -------------------------------------------------------------------------
## Sidecar threshold tests <- a value at or above the threshold leaves the row
## -------------------------------------------------------------------------
##
##   suite                              what it holds down
##   ---------------------------------  -----------------------------------------
##   "a value at the threshold"         the escape, the round trip, the off switch
##   "the sweep"                        a payload a row names stays; a dropped one goes
##   "search"                           a needle in a long value is found

import std/[unittest, os, strutils]

import runePragmas
import geist
import geist/search
import geist/sidecar
import null_query_apis as nq

type
  Doc = object
    id: int
    title: string
    body: string

const
  expectSidecars: int = int(sidecarsCompiled)
    ## How many payloads one long value leaves behind: one when this build has
    ## sidecars compiled in, none when it was built with sidecars off.

proc docConfig(threshold: uint32): GeistConfig {.role: configurator.} =
  ## A configuration with the given sidecar threshold and no backup copies.
  result = appConfig()
  result.sidecarThreshold = threshold
  result.backup.enabled = false

proc payloadsIn(dir: string): seq[string] {.role: helper.} =
  ## Every payload file in the store's sidecar folder.
  if not dirExists(dir / sidecarFolderName):
    return
  for f in walkDirRec(dir / sidecarFolderName):
    result.add f

suite "a value at the threshold":

  # {.testKind: tkIntegration, covers: "writeColumn|shouldExternalise".}
  test "a long text leaves the row for the sidecar, and reads back whole":
    var
      dir = getTempDir() / "geist_threshold_escape"
      longBody = "w".repeat(2000)
    removeDir(dir)
    var
      db: Session = openGeist[Doc](dir, docConfig(1024'u32), "")
      id = db.put(Doc(id: 1, title: "long", body: longBody))
      shortId = db.put(Doc(id: 2, title: "short", body: "s".repeat(100)))
    check db.save().ok
    check payloadsIn(dir).len == expectSidecars
    var
      back = byId[Doc](db, id)
      small = byId[Doc](db, shortId)
    check back.found
    check back.value.body == longBody
    check small.found
    check small.value.body == "s".repeat(100)
    db.close()
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "writeColumn|shouldExternalise".}
  test "a threshold no value reaches keeps every value inline":
    var
      dir = getTempDir() / "geist_threshold_off"
    removeDir(dir)
    var
      db: Session = openGeist[Doc](dir, docConfig(4294967295'u32), "")
      id = db.put(Doc(id: 1, title: "long", body: "q".repeat(5000)))
    check db.save().ok
    check payloadsIn(dir).len == 0
    check byId[Doc](db, id).value.body == "q".repeat(5000)
    db.close()
    removeDir(dir)

suite "the sweep":

  # {.testKind: tkRegression, covers: "sweepSidecar|externalRefsOf".}
  test "a payload a row names survives a sweep, and goes once the row is compacted away":
    var
      dir = getTempDir() / "geist_threshold_sweep"
    removeDir(dir)
    var
      db: Session = openGeist[Doc](dir, docConfig(1024'u32), "")
      id = db.put(Doc(id: 1, title: "t", body: "k".repeat(3000)))
    check db.save().ok
    var
      kept = db.sweepSidecar()
    check kept.ok
    check kept.removed == 0
    check payloadsIn(dir).len == expectSidecars
    check db.delete(id)
    check db.save().ok
    discard db.compact()
    check db.save().ok
    var
      dropped = db.sweepSidecar()
    check dropped.ok
    check dropped.removed == expectSidecars
    check payloadsIn(dir).len == 0
    db.close()
    removeDir(dir)

suite "search":

  # {.testKind: tkIntegration, covers: "searchStore|typedSeekSource".}
  test "a needle in a long body is found, and the typed source reads the whole body":
    var
      dir = getTempDir() / "geist_threshold_search"
      body = "x".repeat(2500) & " needle"
    removeDir(dir)
    var
      db: Session = openGeist[Doc](dir, docConfig(1024'u32), "")
      id = db.put(Doc(id: 1, title: "t", body: body))
    check db.save().ok
    db.close()
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("body:contains=needle").p])
      found = searchStore(dir, q)
    check found.ok
    check found.res.hits.len == 1
    if found.res.hits.len == 1:
      check nq.valueText(found.res.hits[0].obj.fieldOf("body").value) == body
    var
      typed = typedSeekSource[Doc](liveDataPath(dir, storeBaseName), docConfig(1024'u32))
    check typed.ok
    check nq.nullSearchAll(@[typed.src], q).hits.len == 1
    nq.close(typed.src)
    removeDir(dir)

suite "sidecars off":

  # {.testKind: tkEdgeCase, covers: "writeColumn|canEscape".}
  test "with sidecars off a long value stays in its row, and no payload is written":
    var
      dir = getTempDir() / "geist_sidecars_off"
      cfg = docConfig(1024'u32)
    cfg.sidecars = false
    removeDir(dir)
    var
      db: Session = openGeist[Doc](dir, cfg, "")
      id = db.put(Doc(id: 1, title: "t", body: "z".repeat(4000)))
    check db.save().ok
    check payloadsIn(dir).len == 0
    check byId[Doc](db, id).value.body == "z".repeat(4000)
    db.close()
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "writeCapped".}
  test "a capped value too wide for its column is refused with sidecars off, unless the column truncates":
    var
      refused = Doc(id: 1, title: "x".repeat(200))
      s = schemaFor[Doc]()
      at = s.slotIndex("title")
    s.slots[at].column = colCapped
    s.slots[at].width = 48'u32
    var
      off = initSidecarStore("")
    off.escapes = false
    var refusedRow = toRowBytes(refused, s, off)
    check refusedRow.err.contains("sidecars are off")
    s.slots[at].onOverflow = opTruncate
    var cutRow = toRowBytes(refused, s, off)
    check cutRow.err.len == 0
    check cutRow.truncated == 1
    check fromRowBytes[Doc](cutRow.data, s).title == "x".repeat(46)

  # {.testKind: tkUnit, covers: "initGeistDefaults|rubricOf".}
  test "the [default] table is the run-time rubric, and it names the three settings":
    var loaded = loadGeistDefaults()
    check loaded.ok
    check loaded.defaults.sidecars == sidecarsCompiled
    check loaded.defaults.sidecarThreshold == 1024'u32
    check loaded.defaults.follow == "named"
