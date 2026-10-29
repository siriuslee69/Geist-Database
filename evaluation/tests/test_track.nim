## -------------------------------------------------------------------------
## Track tests <- files and folders that Geist references and never writes
## -------------------------------------------------------------------------
##
##   suite                                  what it holds down
##   -------------------------------------  ----------------------------------------
##   "a tracked file"                       read through its reference, never written;
##                                          a changed or missing file refused and named
##   "a tracked folder"                     recursive, top only, by suffix; one row per file
##   "the sweep"                            locators of tracked files are kept

import std/[unittest, os, strutils, times]

import runePragmas
import geist
import geist/search
import geist/track
import geist/sidecar
import null_query_apis as nq

type
  Tracked = object
    id: int
    file: Ref
    label: string

proc trackConfig(): GeistConfig {.role: configurator.} =
  result = appConfig()
  result.backup.enabled = false

proc makeTree(root: string) {.role: helper.} =
  ## root/a.txt, root/b.md and root/sub/c.txt: three files, one of them nested.
  removeDir(root)
  createDir(root / "sub")
  writeFile(root / "a.txt", "alpha text")
  writeFile(root / "b.md", "beta text")
  writeFile(root / "sub" / "c.txt", "gamma text")

suite "a tracked file":

  # {.testKind: tkIntegration, covers: "trackFile|getSidecar|readLocated".}
  test "a tracked file is read through its reference, and it is never written":
    var
      src = getTempDir() / "geist_track_src"
      file = src / "needle.txt"
      db: Session = default(Session)
      tracked: tuple[ok: bool, t: TrackedFile, err: string] = (false, TrackedFile(), "")
    removeDir(src)
    createDir(src)
    writeFile(file, "x".repeat(60) & " needle")
    var
      before = getLastModificationTime(file)
      content = readFile(file)
    var dbDir = getTempDir() / "geist_track_db"
    removeDir(dbDir)
    db = openGeist[Tracked](dbDir, trackConfig(), "")
    tracked = trackFile(db.sidecarStore, file)
    check tracked.ok
    discard db.put(Tracked(id: 1, file: tracked.t.file, label: "needle"))
    check db.save().ok
    var got = getSidecar(db.sidecarStore, tracked.t.file)
    check got.ok
    check cast[string](got.data) == content
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("file:contains=needle").p])
      found = searchStore(dbDir, q)
    check found.ok
    check found.res.hits.len == 1
    check getLastModificationTime(file) == before
    check readFile(file) == content
    db.close()
    removeDir(dbDir)
    removeDir(src)

  # {.testKind: tkRegression, covers: "readLocated".}
  test "a file that changed is refused by its hash, and a file that is gone is named":
    var
      src = getTempDir() / "geist_track_changed"
      file = src / "held.txt"
      dbDir = getTempDir() / "geist_track_changed_db"
      db: Session = default(Session)
    removeDir(src)
    removeDir(dbDir)
    createDir(src)
    writeFile(file, "a".repeat(40))
    db = openGeist[Tracked](dbDir, trackConfig(), "")
    var tracked = trackFile(db.sidecarStore, file)
    check tracked.ok
    writeFile(file, "b".repeat(40))
    var changed = getSidecar(db.sidecarStore, tracked.t.file)
    check not changed.ok
    check changed.err.contains("failed hash verification")
    removeFile(file)
    var gone = getSidecar(db.sidecarStore, tracked.t.file)
    check not gone.ok
    check gone.err.contains("tracked file is missing")
    db.close()
    removeDir(dbDir)
    removeDir(src)

suite "a tracked folder":

  # {.testKind: tkIntegration, covers: "trackFolder|trackFolderInto".}
  test "a folder is tracked recursively, at the top only, or by suffix, one row per file":
    var
      tree = getTempDir() / "geist_track_tree"
      dbDir = getTempDir() / "geist_track_tree_db"
      db: Session = default(Session)
    makeTree(tree)
    removeDir(dbDir)
    db = openGeist[Tracked](dbDir, trackConfig(), "")
    var
      everything = trackFolder(db.sidecarStore, tree, true)
      topOnly = trackFolder(db.sidecarStore, tree, false)
      texts = trackFolder(db.sidecarStore, tree, true, ".txt")
    check everything.ok
    check everything.tracked.len == 3
    check topOnly.tracked.len == 2
    check texts.tracked.len == 2
    var names: seq[string] = @[]
    for t in everything.tracked:
      names.add t.name
    check "sub/c.txt" in names
    var stored = trackFolderInto[Tracked](db, tree,
      proc (t: TrackedFile): Tracked = Tracked(id: 0, file: t.file, label: t.name),
      true, ".txt")
    check stored.ok
    check stored.ids.len == 2
    check db.save().ok
    db.close()
    removeDir(dbDir)
    removeDir(tree)

suite "the sweep":

  # {.testKind: tkRegression, covers: "sweepSidecar|locatorPathOf".}
  test "the sweep keeps the locators of tracked files, and the files stay where they were":
    var
      src = getTempDir() / "geist_track_sweep"
      file = src / "kept.txt"
      dbDir = getTempDir() / "geist_track_sweep_db"
      db: Session = default(Session)
    removeDir(src)
    removeDir(dbDir)
    createDir(src)
    writeFile(file, "keep me")
    db = openGeist[Tracked](dbDir, trackConfig(), "")
    var tracked = trackFile(db.sidecarStore, file)
    check tracked.ok
    discard db.put(Tracked(id: 1, file: tracked.t.file, label: "kept"))
    check db.save().ok
    var swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 0
    check fileExists(locatorPathOf(db.sidecarStore, tracked.t.file.hash))
    check readFile(file) == "keep me"
    check getSidecar(db.sidecarStore, tracked.t.file).ok
    db.close()
    removeDir(dbDir)
    removeDir(src)
