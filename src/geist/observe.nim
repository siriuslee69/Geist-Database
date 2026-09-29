## ---------------------------------------------------------------------
## Observe <- follow a store this process does not own
## ---------------------------------------------------------------------
##
## Reads only the header and cluster index -- a few hundred bytes -- so a
## daemon can see that a file moved without loading a row.
##
## Part of the Session; see ./session for how the parts fit.


import runePragmas
import ./store
import ./keys
import ./sessioncore

## --------------------------- observation ----------------------------

proc observe*(path: string): tuple[ok: bool, f: GeistFile, err: string] {.
    role: dataFetcher, tag: "appApi|db|read|status".} =
  ## path: a Geist file this process does NOT own.
  ## Reads only the header and cluster index, so a daemon can follow a
  ## database without loading rows, taking a lease, or decrypting anything.
  result = readIndex(path)

proc observeStore*(baseDir: string,
    baseName: string = "main"): tuple[ok: bool, f: GeistFile, path: string,
    err: string] {.role: dataFetcher,
    tag: "appApi|db|read|status".} =
  ## baseDir/baseName: a store root this process does NOT own.
  ##
  ## Prefer this to `observe`. A save publishes a NEW generation, so the
  ## file name changes underneath anyone who remembered one; this resolves
  ## the live name through the manifest first and returns it alongside the
  ## index, so the next call can tell "the file moved on" from "the rows
  ## changed".
  var
    idx: tuple[ok: bool, f: GeistFile, err: string] =
      (false, default(GeistFile), "")
  result.path = liveDataPath(baseDir, baseName)
  idx = readIndex(result.path)
  result.ok = idx.ok
  result.f = idx.f
  result.err = idx.err

proc followStore*(before: GeistFile, baseDir: string,
    baseName: string = "main"): FollowStep {.role: orchestrator,
    tag: "appApi|db|read|status".} =
  ## before: the previous index read.
  ## baseDir/baseName: same store, re-resolved through the manifest.
  ##
  ## Returns which clusters moved, without reading a row and without caring
  ## which generation is live now. Cost is one manifest line plus one index.
  var
    now: tuple[ok: bool, f: GeistFile, path: string, err: string] =
      (false, default(GeistFile), "", "")
  now = observeStore(baseDir, baseName)
  if not now.ok:
    return (false, GeistFile(), @[], now.path, now.err)
  result.ok = true
  result.f = now.f
  result.path = now.path
  result.changed = changedClusters(before, now.f)


