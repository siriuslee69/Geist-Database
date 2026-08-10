## A pure disk-writing backend: rows in, rows out, nothing else.
##
## This file exists to be COMPILED WITHOUT BIFROST ON THE PATH, by
## `nimble checkModular`. It is not run by `nimble test` and it asserts
## nothing at runtime -- the assertion is that it builds at all.
##
## If someone makes the storage half of the library import the network
## half again, this stops compiling, which is the entire point. A comment
## saying "please keep these separate" would not have caught it.

import std/os

import geist

type
  Note = object
    noteId: int
    title: string
    body: string

const storeRoot = "build/modular-check"

proc main() =
  # From scratch every run: the row count below is an assertion, and a
  # store left behind by the previous run would make it fail for a reason
  # that has nothing to do with what this file is checking.
  removeDir(storeRoot)
  var db = openGeist[Note](storeRoot, appConfig())
  var id = db.put(Note(noteId: 1, title: "written", body: "with no sockets"))
  discard db.set(id, Note(noteId: 1, title: "corrected", body: "still none"))
  discard db.save()
  # The parts a disk-only embedder actually uses: identity, the live view,
  # settings, seeking, and the durable generation swap.
  doAssert db.entryCount() == 1'u32
  doAssert byId[Note](db, id).value.title == "corrected"
  doAssert defaultGeistConfig().rowIdentity
  doAssert loadGeistDefaults("config.toml").ok
  db.close()
  echo "storage-only build: ok"

main()
