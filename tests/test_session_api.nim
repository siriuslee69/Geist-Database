## Session/facade: the API surface an app actually uses.
import std/[os, strutils, unittest]
import geist

type
  Note = object
    noteId: int
    title: string
    body: string

suite "session":
  test "open, put, find, save, reopen":
    var root = getTempDir() / "geist_t_sess"
    removeDir(root)
    var db = openGeist[Note](root, appConfig())
    for i in 0 ..< 20:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    check db.entryCount() == 20'u32
    check db.save().ok
    db.close()
    var db2 = openGeist[Note](root, appConfig())
    check db2.entryCount() == 20'u32
    check get[Note](db2, 11'u32).title == "t11"
    check find[Note](db2, "title", "t5").len == 1
    db2.close()

  test "encryption leaves no plaintext on disk and reopens":
    var root = getTempDir() / "geist_t_enc"
    removeDir(root)
    var db = openGeist[Note](root, secureAppConfig(), "pw")
    for i in 0 ..< 40:
      db.put(Note(noteId: i, title: "t" & $i, body: "MARKER-" & $i))
    check db.save().ok
    db.close()
    # The live file is whatever the manifest says, never a fixed .g1: every
    # save publishes the NEXT generation.
    check not readFile(liveDataPath(root)).contains("MARKER")
    var db2 = openGeist[Note](root, secureAppConfig(), "pw")
    check db2.entryCount() == 40'u32
    check get[Note](db2, 37'u32).body == "MARKER-37"
    db2.close()

  test "a wrong password fails loudly instead of minting a new key set":
    var root = getTempDir() / "geist_t_pw"
    removeDir(root)
    var db = openGeist[Note](root, secureAppConfig(), "right")
    db.put(Note(noteId: 1, title: "a", body: "b"))
    check db.save().ok
    db.close()
    expect IOError:
      discard openGeist[Note](root, secureAppConfig(), "wrong")

  test "the encrypted artifact set is all three files":
    var root = getTempDir() / "geist_t_set"
    removeDir(root)
    var db = openGeist[Note](root, secureAppConfig(), "pw")
    db.put(Note(noteId: 1, title: "a", body: "b"))
    check db.save().ok
    check db.artifactSet().len == 3
    for p in db.artifactSet(): check fileExists(p)
    db.close()

  test "subscribe starts at head, replay rewinds":
    var root = getTempDir() / "geist_t_sub"
    removeDir(root)
    var db = openGeist[Note](root, appConfig())
    for i in 0 ..< 5: db.put(Note(noteId: i, title: "t" & $i))
    discard db.subscribe("live")
    discard db.subscribe("all", replay = true)
    db.put(Note(noteId: 99, title: "late"))
    check poll(db, "live").len == 1
    check poll(db, "all").len == 6
    check poll(db, "live").len == 0        # cursor advanced
    db.close()

  test "history can be disabled and checkpoint then refuses":
    var root = getTempDir() / "geist_t_hist"
    removeDir(root)
    var db = openGeist[Note](root, streamConfig(), "pw")
    db.put(Note(noteId: 1, title: "a"))
    expect ValueError:
      discard db.checkpoint("nope")
    db.close()
