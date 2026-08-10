## ------------------------------------------------------
## Geist Quickstart <- open, store, query, save, observe
## ------------------------------------------------------
##
## Run from the repo root:
##   nimble exampleQuickstart

import std/os

import geist

type
  Note = object
    noteId: int
    title: string
    body: string

when isMainModule:
  var
    root: string = ""
    db: Session
    found: seq[Note]
    seen: tuple[ok: bool, f: GeistFile, path: string, err: string]
    later: tuple[ok: bool, f: GeistFile, changed: seq[int], path: string,
      err: string]

  root = getTempDir() / "geist_quickstart"
  removeDir(root)

  db = openGeist[Note](root, appConfig())
  db.put(Note(noteId: 1, title: "first", body: "hello"))
  db.put(Note(noteId: 2, title: "second", body: "world"))
  discard db.subscribe("watcher")
  db.put(Note(noteId: 3, title: "third", body: "after subscribe"))
  discard db.checkpoint("initial import")
  echo "stored: ", db.entryCount()
  echo "save:   ", db.save()

  found = find[Note](db, "title", "second")
  echo "find title=second -> ", found

  echo "changes since subscribe: ", poll(db, "watcher").len
  db.close()

  # observeStore resolves the live generation through the manifest, so it
  # keeps working after a save has published a new file name.
  seen = observeStore(root)
  echo "index-only observe: ", seen.f.indexBytes, " B of ",
    getFileSize(seen.path), " B"

  db = openGeist[Note](root, appConfig())
  db.put(Note(noteId: 4, title: "fourth", body: "later"))
  discard db.save()
  db.close()

  later = followStore(seen.f, root)
  echo "clusters changed since first observation: ", later.changed
  echo "live file now:                            ", later.path.extractFilename
