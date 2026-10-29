## -------------------------------------------------------------------------
## Search tests <- Geist stores and files, searched through Null-QueryAPIs
## -------------------------------------------------------------------------
##
##   suite                                  what it holds down
##   -------------------------------------  --------------------------------------
##   "a plain store, read from disk"        streamed and all-at-once agree
##   "the live view"                        updated and removed rows, as a session sees them
##   "typed rows"                           a T is read one row at a time
##   "searchStore"                          one call, with and without a ring
##   "sealed stores"                        refused without the password, read with it
##   "files"                                lines, JSON lines, and an unknown kind

import std/[unittest, os, strutils]

import runePragmas
import geist
import geist/search
import geist/sidecar
import null_query_apis as nq

type
  Note = object
    id: int
    title: string
    score: float
    done: bool

proc noteAt(i: int): Note {.role: helper.} =
  ## The i-th test row: title "note-<i>", score i/2, done on even numbers.
  result = Note(id: i, title: "note-" & $i, score: float(i) / 2.0, done: i mod 2 == 0)

proc buildStore(dir: string, n: int, cfg: GeistConfig, password: string) {.role: helper.} =
  ## Writes n rows into a fresh store folder, sealed when the config says so.
  removeDir(dir)
  var
    db: Session = openGeist[Note](dir, cfg, password)
  for i in 0 ..< n:
    discard db.put(noteAt(i))
  doAssert db.save().ok
  db.close()

proc numbersOf(R: nq.NullResult): seq[int] {.role: helper.} =
  ## The object number of every hit, in order.
  for h in R.hits:
    result.add h.number

suite "a plain store, read from disk":

  # {.testKind: tkIntegration, covers: "openStore|seekSource|nullSearchStream".}
  test "streaming from disk gives the same hits as reading everything at once":
    var
      dir = getTempDir() / "geist_search_plain"
    buildStore(dir, 200, appConfig(), "")
    var
      opened = openStore(dir)
    check opened.ok
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("title:prefix=note-1").p])
      whole = nq.nullSearchAll(@[opened.src], q)
      streamed = nq.nullSearchStream(@[opened.src], q, 7)
    check whole.hits.len == 111
    check numbersOf(streamed) == numbersOf(whole)
    check streamed.scanned == 200
    check streamed.complete
    nq.close(opened.src)
    removeDir(dir)

suite "the live view":

  # {.testKind: tkRegression, covers: "openStore|typedSeekSource|rowObject".}
  test "an updated row is searched at its newest version, and a removed row is not searched":
    var
      dir = getTempDir() / "geist_search_live"
    removeDir(dir)
    var
      db: Session = openGeist[Note](dir, appConfig(), "")
      ids: seq[RowId] = @[]
    for i in 0 ..< 3:
      ids.add db.put(noteAt(i))
    check db.set(ids[0], Note(id: 0, title: "note-0-edited", score: 0.0, done: true))
    check db.delete(ids[1])
    doAssert db.save().ok
    db.close()
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("title:prefix=note").p])
      found = searchStore(dir, q)
    check found.ok
    check found.res.hits.len == 2
    check nq.valueText(found.res.hits[0].obj.fieldOf("title").value) == "note-0-edited"
    check nq.valueText(found.res.hits[1].obj.fieldOf("title").value) == "note-2"
    check not found.res.hits[0].obj.fieldOf("__rowId").found
    var
      typed = typedSeekSource[Note](liveDataPath(dir, storeBaseName))
    check typed.ok
    check nq.nullSearchAll(@[typed.src], q).hits.len == 2
    nq.close(typed.src)
    removeDir(dir)

suite "typed rows":

  # {.testKind: tkIntegration, covers: "typedSeekSource|toNullObject".}
  test "a typed store is searched one row at a time, with the fields as the type names them":
    var
      dir = getTempDir() / "geist_search_typed"
    buildStore(dir, 50, appConfig(), "")
    var
      src = typedSeekSource[Note](liveDataPath(dir, storeBaseName))
    check src.ok
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("id:range=10..19").p])
      found = nq.nullSearchStream(@[src.src], q, 3)
    check found.hits.len == 10
    check nq.valueText(found.hits[0].obj.fieldOf("title").value) == "note-10"
    check found.hits[0].obj.fieldOf("done").value.kind == nq.nkBool
    nq.close(src.src)
    removeDir(dir)

suite "searchStore":

  # {.testKind: tkIntegration, covers: "searchStore".}
  test "one call searches a store, reading all rows or a ring of them, with the same answer":
    var
      dir = getTempDir() / "geist_search_one_call"
    buildStore(dir, 120, appConfig(), "")
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("done:range=1..1").p])
      whole = searchStore(dir, q)
      ringed = searchStore(dir, q, capacity = 4)
    check whole.ok
    check ringed.ok
    check whole.res.hits.len == 60
    check numbersOf(ringed.res) == numbersOf(whole.res)
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "openStore".}
  test "a folder that holds no store is refused by name":
    var
      res = searchStore(getTempDir() / "geist_search_absent_store",
        nq.initNullQuery())
    check not res.ok
    check res.err.contains("no store at")

suite "sealed stores":

  # {.testKind: tkIntegration, covers: "openStore|sessionSource".}
  test "a sealed store is refused without its password and read with it":
    var
      dir = getTempDir() / "geist_search_sealed"
    buildStore(dir, 30, secureAppConfig(), "pw-7")
    var
      refused = openStore(dir)
    check not refused.ok
    check refused.err.contains("sealed")
    var
      opened = sealedSource[Note](dir, "pw-7", secureAppConfig())
    check opened.ok
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("title:exact=note-7").p])
      found = nq.nullSearchAll(@[opened.src], q)
    check found.hits.len == 1
    check nq.valueText(found.hits[0].obj.fieldOf("id").value) == "7"
    nq.close(opened.src)
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "openStore".}
  test "a wrong password is refused with an error, not a crash":
    var
      dir = getTempDir() / "geist_search_wrong_password"
    buildStore(dir, 5, secureAppConfig(), "right")
    var
      opened = sealedSource[Note](dir, "wrong", secureAppConfig())
    check not opened.ok
    check opened.err.len > 0
    removeDir(dir)

proc cappedConfig(): GeistConfig {.role: configurator.} =
  ## A configuration where `title` is capped narrow, so a longer title takes the
  ## sidecar escape (Def. 4 in search.nim).
  result = appConfig()
  result.columnPolicy = @[cappedColumn("title", 64'u32)]
  result.backup.enabled = false

proc writeCappedStore(dir: string) {.role: helper.} =
  ## Two notes: a short title, and a long title that ends in "needle".
  removeDir(dir)
  var
    db: Session = openGeist[Note](dir, cappedConfig(), "")
  discard db.put(Note(id: 0, title: "short", score: 0.0, done: true))
  discard db.put(Note(id: 1, title: "x".repeat(120) & " needle", score: 1.0, done: false))
  doAssert db.save().ok
  db.close()

proc sidecarPayloads(dir: string): seq[string] {.role: helper.} =
  ## Every payload file in the store's sidecar folder.
  for f in walkDirRec(dir / sidecarFolderName):
    result.add f

suite "sidecars":

  # {.testKind: tkRegression, covers: "rowObject|typedSeekSource|searchStore".}
  test "a capped column's long value is searched by its real text, not by its reference":
    var
      cfg: GeistConfig = appConfig()
    cfg.columnPolicy = @[cappedColumn("title", 64'u32)]
    cfg.backup.enabled = false
    var
      dir = getTempDir() / "geist_search_sidecar"
    removeDir(dir)
    var
      db: Session = openGeist[Note](dir, cfg, "")
    discard db.put(Note(id: 0, title: "short", score: 0.0, done: true))
    discard db.put(Note(id: 1, title: "x".repeat(120) & " needle", score: 1.0, done: false))
    doAssert db.save().ok
    db.close()
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("title:contains=needle").p])
      found = searchStore(dir, q)
    check found.ok
    check found.res.hits.len == 1
    if found.res.hits.len == 1:
      check nq.valueText(found.res.hits[0].obj.fieldOf("title").value).endsWith("needle")
    var
      typed = typedSeekSource[Note](liveDataPath(dir, storeBaseName))
    check typed.ok
    check nq.nullSearchAll(@[typed.src], q).hits.len == 1
    nq.close(typed.src)
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "searchStore|FollowSidecars".}
  test "a search that never follows sidecars sees the reference text, and keeps the row":
    var
      dir = getTempDir() / "geist_search_sidecar_never"
    writeCappedStore(dir)
    var
      needle = nq.initNullQuery(@[nq.parsePredicateSpec("title:contains=needle").p])
      everything = nq.initNullQuery(@[nq.parsePredicateSpec("id:range=0..1").p])
      never = searchStore(dir, needle, follow = fsNever)
      rows = searchStore(dir, everything, follow = fsNever)
    check never.ok
    check never.res.hits.len == 0
    check rows.res.hits.len == 2
    if rows.res.hits.len == 2:
      check nq.valueText(rows.res.hits[1].obj.fieldOf("title").value).startsWith("<sidecar ")
    removeDir(dir)

  # {.testKind: tkRegression, covers: "searchStore|rowObjectFollowing".}
  test "a sidecar value is read for the fields a query names, or for every field when asked":
    var
      dir = getTempDir() / "geist_search_sidecar_named"
    writeCappedStore(dir)
    var
      byId = nq.initNullQuery(@[nq.parsePredicateSpec("id:range=0..1").p])
      named = searchStore(dir, byId)
      always = searchStore(dir, byId, follow = fsAlways)
    check named.res.hits.len == 2
    check always.res.hits.len == 2
    if named.res.hits.len == 2:
      check nq.valueText(named.res.hits[1].obj.fieldOf("title").value).startsWith("<sidecar ")
    if always.res.hits.len == 2:
      check nq.valueText(always.res.hits[1].obj.fieldOf("title").value).endsWith("needle")
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "sidecarValue".}
  test "a damaged sidecar payload is shown as its reason, and the untyped search goes on":
    var
      dir = getTempDir() / "geist_search_sidecar_damaged"
    writeCappedStore(dir)
    var
      payloads: seq[string] = sidecarPayloads(dir)
    check payloads.len == 1
    if payloads.len == 1:
      writeFile(payloads[0], "damaged")
    var
      needle = nq.initNullQuery(@[nq.parsePredicateSpec("title:contains=needle").p])
      everything = nq.initNullQuery(@[nq.parsePredicateSpec("id:range=0..1").p])
      found = searchStore(dir, needle)
      rows = searchStore(dir, everything, follow = fsAlways)
    check found.ok
    check found.res.hits.len == 0
    check rows.ok
    check rows.res.hits.len == 2
    if rows.res.hits.len == 2:
      check nq.valueText(rows.res.hits[1].obj.fieldOf("title").value).startsWith("<sidecar: ")
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "typedSeekSource".}
  test "a typed search stops with the reason when a sidecar payload is damaged":
    var
      dir = getTempDir() / "geist_search_sidecar_typed_damaged"
    writeCappedStore(dir)
    var
      payloads: seq[string] = sidecarPayloads(dir)
    check payloads.len == 1
    if payloads.len == 1:
      writeFile(payloads[0], "damaged")
    var
      typed = typedSeekSource[Note](liveDataPath(dir, storeBaseName), cappedConfig())
      q = nq.initNullQuery(@[nq.parsePredicateSpec("id:range=0..1").p])
      raised: string = ""
    check typed.ok
    try:
      discard nq.nullSearchAll(@[typed.src], q)
    except IOError as e:
      raised = e.msg
    check raised.contains("sidecar")
    nq.close(typed.src)
    removeDir(dir)

suite "files":

  # {.testKind: tkIntegration, covers: "openFileSource".}
  test "lines and JSON lines are searched like a store":
    var
      dir = getTempDir() / "geist_search_files"
    removeDir(dir)
    createDir(dir)
    writeFile(dir / "a.txt", "buy milk\nwalk dog\n")
    writeFile(dir / "b.jsonl", "{\"title\": \"milk run\"}\n{\"title\": \"tea\"}\n")
    var
      lines = openFileSource("lines", @[dir / "a.txt"])
      json = openFileSource("jsonl", @[dir / "b.jsonl"])
    check lines.ok
    check json.ok
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("*:contains=milk").p])
    check nq.nullSearchAll(@[lines.src], q).hits.len == 1
    check nq.nullSearchAll(@[json.src], q).hits.len == 1
    nq.close(lines.src)
    nq.close(json.src)
    removeDir(dir)

  # {.testKind: tkEdgeCase, covers: "openFileSource".}
  test "an unknown file kind is refused, and the message names the kinds":
    var
      res = openFileSource("spreadsheet", @["x"])
    check not res.ok
    check res.err.contains("lines, jsonl or frames")
