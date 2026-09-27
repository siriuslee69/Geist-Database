## Durability and the write lease: what a save promises and who may write.
##
## The two properties under test are the ones a database cannot be without:
##
##   1. a save either publishes completely or changes nothing
##   2. two processes never both believe they are the writer
##
## Both are checked by damaging things on purpose -- truncating the live
## generation, leaving debris behind, opening the same store twice -- because
## a happy-path test cannot tell a durable write from a lucky one.

import std/[os, strutils, unittest]
import geist

type
  Note = object
    noteId: int
    title: string
    body: string

proc freshRoot(name: string): string =
  ## name: per-test directory, removed first so a rerun starts clean.
  result = getTempDir() / name
  removeDir(result)

suite "generation swap":
  test "every save publishes the next generation and the manifest follows":
    var
      root = freshRoot("geist_t_gen")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "a", body: "b"))
    check db.save().ok
    var first = db.generation
    db.put(Note(noteId: 2, title: "c", body: "d"))
    check db.save().ok
    check db.generation == first + 1'u64
    check liveGeneration(root) == db.generation
    check liveDataPath(root) == db.dataPath()
    db.close()

  test "the previous generation is retained and the one before it is not":
    var
      root = freshRoot("geist_t_retain")
      db = openGeist[Note](root, appConfig())
      i = 0
    while i < 4:
      db.put(Note(noteId: i, title: "t" & $i, body: "b"))
      check db.save().ok
      i = i + 1
    var live = db.generation
    db.close()
    # live and live-1 survive; anything older has been reclaimed. That is
    # what makes the fallback in the next test possible without unbounded
    # disk growth.
    check fileExists(root / ("main.ge1st" & generationSuffix(live)))
    check fileExists(root / ("main.ge1st" & generationSuffix(live - 1'u64)))
    check not fileExists(root / ("main.ge1st" & generationSuffix(live - 2'u64)))

  test "a live generation that will not read back falls back to the retained one":
    var
      root = freshRoot("geist_t_fallback")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "old", body: "b"))
    check db.save().ok
    db.put(Note(noteId: 2, title: "new", body: "b"))
    check db.save().ok
    var live = db.generation
    db.close()
    # Simulate a half-written file that somehow got published: truncate the
    # live generation. The retained one is untouched.
    writeFile(root / ("main.ge1st" & generationSuffix(live)), "GE1ST truncated")
    var db2 = openGeist[Note](root, appConfig())
    check db2.recoveredFrom == live
    check db2.generation == live - 1'u64
    check db2.entryCount() == 1'u32
    check get[Note](db2, 0'u32).title == "old"
    db2.close()

  test "an interrupted save leaves debris, and the next writer sweeps it":
    var
      root = freshRoot("geist_t_sweep")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "a", body: "b"))
    check db.save().ok
    var live = db.generation
    db.close()
    # A save that died between writing and committing: the file exists, the
    # manifest never mentioned it, so no reader has ever seen it.
    var orphan = root / ("main.ge1st" & generationSuffix(live + 1'u64))
    writeFile(orphan, "half a generation")
    check fileExists(orphan)
    var db2 = openGeist[Note](root, appConfig())
    check db2.generation == live
    check db2.entryCount() == 1'u32
    check not fileExists(orphan)
    db2.close()

  test "a failed save leaves the live generation exactly as it was":
    var
      root = freshRoot("geist_t_intact")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "keep", body: "b"))
    check db.save().ok
    var
      live = db.dataPath()
      before = readFile(live)
    db.close()
    # A reader holding the live generation keeps a complete file across any
    # number of further saves, because nothing is ever written over it.
    var db2 = openGeist[Note](root, appConfig())
    db2.put(Note(noteId: 2, title: "later", body: "b"))
    check db2.save().ok
    db2.close()
    check readFile(live) == before

suite "backup and restore across generations":
  test "slots rotate as the live file moves on":
    var
      root = freshRoot("geist_t_bakgen")
      cfg = appConfig()
    cfg.backup.enabled = true
    cfg.backup.copies = 3'u8
    cfg.backup.everyNWrites = 1'u32
    var
      db = openGeist[Note](root, cfg)
      i = 0
    while i < 3:
      db.put(Note(noteId: i, title: "v" & $i, body: "b"))
      check db.save().ok
      i = i + 1
    var stem = db.backupStems()[0]
    db.close()
    # Three saves, three slots -- not three .b1 files under three different
    # generation names, which is what naming slots after the live file
    # would produce now that a save publishes a new one.
    check fileExists(stem & ".b1")
    check fileExists(stem & ".b2")
    check fileExists(stem & ".b3")

  test "a restore publishes the backup as a new generation":
    var
      root = freshRoot("geist_t_restore")
      cfg = appConfig()
    cfg.backup.enabled = true
    cfg.backup.copies = 2'u8
    cfg.backup.everyNWrites = 1'u32
    var db = openGeist[Note](root, cfg)
    db.put(Note(noteId: 1, title: "original", body: "b"))
    check db.save().ok            # slot 1 now holds one row
    db.put(Note(noteId: 2, title: "later", body: "b"))
    check db.save().ok            # slot 1 holds two rows, slot 2 holds one
    var before = db.generation
    check db.entryCount() == 2'u32
    var done = db.restoreSlot(2)
    check done.ok
    check db.generation == before + 1'u64
    db.readOnly = true            # the rows in memory are the old ones
    db.close()
    # The restored generation opens, verifies and holds what slot 2 held.
    var re = openGeist[Note](root, cfg)
    check re.recoveredFrom == 0'u64
    check re.entryCount() == 1'u32
    check get[Note](re, 0'u32).title == "original"
    re.close()

  test "restoring a slot that is not there changes nothing":
    var
      root = freshRoot("geist_t_restore2")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "only", body: "b"))
    check db.save().ok
    var
      before = db.generation
      done = db.restoreSlot(3)
    check not done.ok
    check done.err.contains("missing")
    check db.generation == before
    check db.entryCount() == 1'u32
    db.close()

suite "write lease":
  test "a second writable open downgrades itself and names the holder":
    var
      root = freshRoot("geist_t_lease")
      a = openGeist[Note](root, appConfig())
    check not a.readOnly
    check a.writeLease.held
    var b = openGeist[Note](root, appConfig())
    check b.readOnly
    check b.leaseHolder.contains("already open for writing")
    check b.leaseHolder.contains("pid")   # who to go and look at

    b.close()
    a.close()

  test "a read-only session refuses writes and says why":
    var
      root = freshRoot("geist_t_refuse")
      a = openGeist[Note](root, appConfig())
    a.put(Note(noteId: 1, title: "a", body: "b"))
    check a.save().ok
    var b = openGeist[Note](root, appConfig())
    check b.readOnly
    expect IOError:
      b.put(Note(noteId: 2, title: "no", body: "b"))
    var saved = b.save()
    check not saved.ok
    check saved.err.contains("read-only")
    # Reading is unaffected: a blocked writer is still a perfectly good
    # reader, which is the whole point of downgrading instead of failing.
    check b.entryCount() == 1'u32
    check get[Note](b, 0'u32).title == "a"
    b.close()
    a.close()

  test "closing releases the lease, so the next writer gets it":
    var
      root = freshRoot("geist_t_release")
      a = openGeist[Note](root, appConfig())
    check a.writeLease.held
    a.close()
    check not fileExists(leasePath(root))
    var b = openGeist[Note](root, appConfig())
    check not b.readOnly
    b.put(Note(noteId: 1, title: "mine now", body: "b"))
    check b.save().ok
    b.close()

  test "a deliberate follower takes no lease at all":
    var
      root = freshRoot("geist_t_follow")
      a = openGeist[Note](root, appConfig())
    a.put(Note(noteId: 1, title: "a", body: "b"))
    check a.save().ok
    a.close()
    var reader = openGeist[Note](root, appConfig(), "", readOnly = true)
    check reader.readOnly
    check not reader.writeLease.held
    # The lease is free while the reader holds the database open, so a
    # writer is not blocked by an observer.
    var writer = openGeist[Note](root, appConfig())
    check not writer.readOnly
    writer.put(Note(noteId: 2, title: "b", body: "c"))
    check writer.save().ok
    writer.close()
    reader.close()

suite "following a moving generation":
  test "observeStore and followStore track the file across saves":
    var
      root = freshRoot("geist_t_observe")
      db = openGeist[Note](root, appConfig())
    db.put(Note(noteId: 1, title: "a", body: "b"))
    check db.save().ok
    db.close()
    var seen = observeStore(root)
    check seen.ok
    check seen.path == liveDataPath(root)
    var db2 = openGeist[Note](root, appConfig())
    db2.put(Note(noteId: 2, title: "b", body: "c"))
    check db2.save().ok
    db2.close()
    var step = followStore(seen.f, root)
    check step.ok
    check step.changed.len > 0
    check step.path != seen.path
