## Fixture for test_durability_lease: a program that ENDS with a writable
## session still open. Run by the test as its own process, because what is
## under test is what happens as a process exits.
##
##   exit_open_session <store root>   -> exit code 0, and no .geist-lock left

import std/os

import runePragmas
import geist

type
  Note = object
    id: int

when isMainModule:
  var
    db: Session = openGeist[Note](paramStr(1), appConfig())
  discard db.put(Note(id: 1))
  doAssert not db.readOnly, "the fixture must hold the write lease"
