## ---------------------------------------------------------------
## Geist Observe <- following a database this process does not own
## ---------------------------------------------------------------
##
## Run from the repo root:
##   nimble exampleObserve
##
## A daemon does not need the rows, a lease, or the password to know that
## something changed. Reading the header plus the cluster index is enough,
## and that cost does not grow with the file.

import std/[os, strutils]

import geist

type
  Reading = object
    deviceId: int
    metric: int
    capturedAt: int
    value: int

when isMainModule:
  var
    root: string = ""
    path: string = ""
    writer: Session = default(Session)
    seen: tuple[ok: bool, f: GeistFile, path: string, err: string] =
      (false, default(GeistFile), "", "")
    step: FollowStep = default(FollowStep)
    i: int = 0

  root = getTempDir() / "geist_observe_example"
  removeDir(root)

  # iotConfig gives every column a fixed width, so the rows are dense and
  # the cluster needs no auxiliary region at all.
  writer = openGeist[Reading](root, iotConfig(), "sensor password")
  while i < 500:
    writer.put(Reading(deviceId: 1, metric: i mod 4, capturedAt: 1700000 + i,
      value: i * 7))
    i = i + 1
  discard writer.save()
  writer.close()

  # The observer never names a file. It asks the store which generation is
  # live, because the writer publishes a new one on every save.
  seen = observeStore(root)
  path = seen.path
  echo "live file:        ", path.extractFilename
  echo "file size:        ", getFileSize(path), " B"
  echo "index read cost:  ", seen.f.indexBytes, " B  (header + ",
    seen.f.header.clusterCount, " index rows)"
  echo "clusters:"
  for e in seen.f.index:
    echo "  ", alignLeft($e.role, 10), " rows=", align($e.rowCount, 5),
      " rowBytes=", e.rowBytes, " auxLen=", e.auxLen
  echo "note: auxLen is 0 -- dense rows are addressed by arithmetic, so"
  echo "      there is no row offset table to store"

  writer = openGeist[Reading](root, iotConfig(), "sensor password")
  writer.put(Reading(deviceId: 2, metric: 9, capturedAt: 1800000, value: 1))
  discard writer.save()
  writer.close()

  step = followStore(seen.f, root)
  echo "changed clusters after one more write: ", step.changed
  echo "the file moved on too:                 ",
    path.extractFilename, " -> ", step.path.extractFilename
  echo "still only ", step.f.indexBytes, " B read to find out"
