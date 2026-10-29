## ---------------------------------------------------------------------
## Track <- reference a file or a folder that Geist does not own
## ---------------------------------------------------------------------
##
## Tracking hashes a file that already exists and records where it lies. The row
## keeps the hash, exactly as it keeps the hash of a payload Geist wrote. The file
## itself is never written, moved or renamed: Geist only reads it.
##
##   row --Ref(hash)--> sidecar folder: <hash>.locator --path--> the user's file
##                      (text: kind, hash, size, name, target)
##
## Def. 1 (tracked file): a file outside Geist, named by a locator. A read hashes it
##   again, and a file whose content or size changed is refused: it is not the
##   file the row names.
## Def. 2 (tracked folder): every file under a folder, each one a tracked file. A
##   tracked file's name is its path relative to the folder, with '/' between parts.
## Def. 3 (what is not covered): a backup copies the database files, not the sidecar
##   folder. A restored database needs its locator files copied across as well.
## Def. 4 (sidecars are required): tracking writes locators into the sidecar folder,
##   so it refuses while sidecars are off for the store.

import std/[os, strutils]

import runePragmas
import ./types
import ./sidecar
import ./sessioncore

type
  TrackedFile* {.role: truthState, tag: "appApi|db|types".} = object
    ## path: where the file lies. name: what it is called in the tracked set.
    ## size: bytes at tracking time. file: the reference a row keeps.
    path*: string
    name*: string
    size*: int64
    file*: Ref

proc trackFile*(s: SidecarStore, path: string, name: string = ""): tuple[ok: bool,
    t: TrackedFile, err: string] {.role: orchestrator, tag: "sidecar|storageIo|read|write".} =
  ## s/path/name: track one existing file. Its hash is streamed from disk, and a
  ## locator is written unless a payload with the same hash is already stored.
  var
    hash: ByteSeq = @[]
    size: int64 = 0
    loc: SidecarLocator = SidecarLocator()
    put: tuple[ok: bool, err: string] = (false, "")
  if not s.canEscape():
    result.err = "sidecars are off for this store, so a file cannot be tracked"
    return
  if not fileExists(path):
    result.err = "no file to track at " & path
    return
  hash = hashFileFor(s.hash, path)
  size = getFileSize(path)
  loc.kind = "path"
  loc.hash = hash
  loc.size = size
  loc.name = if name.len > 0: name else: extractFilename(path)
  loc.target = absolutePath(path)
  if not fileExists(s.sidecarPath(sidecarLocator(hash))):
    put = putLocator(s, loc)
    if not put.ok:
      result.err = put.err
      return
  result.t = TrackedFile(path: loc.target, name: loc.name, size: size,
    file: Ref(target: rtSidecar, hash: hash))
  result.ok = true

proc trackFolder*(s: SidecarStore, dir: string, recursive: bool = true,
    suffix: string = ""): tuple[ok: bool, tracked: seq[TrackedFile],
    err: string] {.role: orchestrator, tag: "sidecar|storageIo|read|write".} =
  ## s/dir/recursive/suffix: track every file under `dir`. recursive: go into
  ## sub-folders too. suffix: track only names that end with it, e.g. ".txt".
  var
    files: seq[string] = @[]
    rel: string = ""
    got: tuple[ok: bool, t: TrackedFile, err: string] = (false, TrackedFile(), "")
  if recursive:
    for f in walkDirRec(dir):
      files.add f
  else:
    for f in walkFiles(dir / "*"):
      files.add f
  for f in files:
    if suffix.len > 0 and not f.endsWith(suffix):
      continue
    rel = f.relativePath(dir).replace('\\', '/')
    got = trackFile(s, f, rel)
    if not got.ok:
      result.err = got.err
      return
    result.tracked.add got.t
  result.ok = true

proc trackFolderInto*[T: object](S: var Session, dir: string,
    make: proc (t: TrackedFile): T {.closure.}, recursive: bool = true,
    suffix: string = ""): tuple[ok: bool, ids: seq[RowId], err: string] {.
    role: orchestrator, tag: "sidecar|storageIo|db|write".} =
  ## S/dir/make/recursive/suffix: track a folder and store one row per file. `make`
  ## turns a tracked file into the user's row type, so the row can carry its own
  ## metadata fields as well as the reference.
  var
    got: tuple[ok: bool, tracked: seq[TrackedFile], err: string] =
      (false, @[], "")
  got = trackFolder(S.sidecarStore, dir, recursive, suffix)
  if not got.ok:
    result.err = got.err
    return
  for t in got.tracked:
    result.ids.add S.put(make(t))
  result.ok = true
