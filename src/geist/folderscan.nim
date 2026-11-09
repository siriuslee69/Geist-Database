## ---------------------------------------------------------------------
## Folder scan <- which files in a folder changed since the last look
## ---------------------------------------------------------------------
##
##   var last: seq[FolderEntry] = @[]
##   loop, every so often:
##     var now = scanFolder("photos", last)
##     for c in now.changes: ...
##     last = now.entries
##
## Polling instead of the system's change events: it behaves the same on Linux
## and Windows, it cannot miss a change while the program was off, and the cost
## is one directory walk. A file is hashed only when its size or time moved.
##
## Def. 1 (change): cfAdded, cfChanged (same path, other hash) or cfRemoved. A
##   file touched without its content changing is not a change.
## Def. 2 (skipped): names starting with a dot, and temporary names ending in
##   .tmp or .part. Symbolic links are never followed, so a link cannot make the
##   scan leave the folder.
## Def. 3 (relative path): always with '/', on every system, so two machines
##   agree on what a file is called.

import std/[algorithm, os, strutils, tables, times]

import tyr/hashes/blake3 as tyr_blake3

import runePragmas
import ./textfile

type
  FolderEntry* {.role: truthState, tag: "folderscan|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## One file as it was last seen.
    path*: string
    size*: int64
    mtimeMs*: int64
    hash*: string

  FolderChangeKind* = enum
    cfAdded, cfChanged, cfRemoved

  FolderChange* {.role: preparedData, tag: "folderscan|types".} = object
    ## One difference.
    kind*: FolderChangeKind
    entry*: FolderEntry

  FolderScan* {.role: preparedData, tag: "folderscan|types".} = object
    ## What one look found.
    entries*: seq[FolderEntry]
    changes*: seq[FolderChange]

proc skipped(name: string): bool {.role: parser, inline.} =
  ## name: Def. 2.
  result = name.len == 0 or name[0] == '.' or name.endsWith(".tmp") or
    name.endsWith(".part")

proc anyPartHidden(A: openArray[string]): bool {.role: parser, inline.} =
  ## A: the parts of a path. True when a folder on the way is hidden.
  for s in A:
    if s.len > 0 and s[0] == '.':
      return true

proc relativeName(dir, path: string): string {.role: helper, inline.} =
  ## dir/path: Def. 3.
  result = path.relativePath(dir).replace('\\', '/')

proc toUnixFloatMs(t: Time): int64 {.role: helper, inline.} =
  ## t: milliseconds since 1970, so two quick edits in one second still differ.
  result = t.toUnix() * 1000 + int64(t.nanosecond() div 1_000_000)

proc hashOfEntry(path, name: string, size, mtimeMs: int64,
    known: Table[string, FolderEntry]): FolderEntry {.role: truthBuilder.} =
  ## path/name/size/mtimeMs/known: one file; hashed only when it may have changed.
  result = FolderEntry(path: name, size: size, mtimeMs: mtimeMs)
  if known.hasKey(name) and known[name].size == size and known[name].mtimeMs == mtimeMs:
    result.hash = known[name].hash
    return
  result.hash = hexText(blake3HashFile(path, 32))

proc diffEntries(entries: seq[FolderEntry], known: Table[string, FolderEntry]): seq[
    FolderChange] {.role: parser.} =
  ## entries/known: what is new or different, then what is gone.
  var
    seen: Table[string, bool] = initTable[string, bool]()
  for e in entries:
    seen[e.path] = true
    if not known.hasKey(e.path):
      result.add(FolderChange(kind: cfAdded, entry: e))
    elif known[e.path].hash != e.hash:
      result.add(FolderChange(kind: cfChanged, entry: e))
  for path, e in known.pairs:
    if not seen.hasKey(path):
      result.add(FolderChange(kind: cfRemoved, entry: e))

proc scanFolder*(dir: string, last: openArray[FolderEntry]): FolderScan {.
    role: dataFetcher, tag: "folderscan|appApi|storageIo|read".} =
  ## dir: the folder. last: what the previous look returned, or nothing. A file
  ## that vanishes during the scan is simply not listed.
  var
    known: Table[string, FolderEntry] = initTable[string, FolderEntry]()
    name: string = ""
  for e in last:
    known[e.path] = e
  for path in walkDirRec(dir, followFilter = {pcDir}):
    name = relativeName(dir, path)
    if skipped(path.extractFilename()) or name.split('/').anyPartHidden():
      continue
    try:
      result.entries.add(hashOfEntry(path, name, getFileSize(path),
        getLastModificationTime(path).toUnixFloatMs(), known))
    except CatchableError:
      continue
  result.entries.sort(proc (a, b: FolderEntry): int = cmp(a.path, b.path))
  result.changes = diffEntries(result.entries, known)
