## ---------------------------------------------------------------------
## geist cli <- `track`, `folder`, `storage`: the files beside a database
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point. What the three commands act on:
##
##   track    src/geist/track.nim     files that stay where they are
##   folder   src/geist/folder.nim    the hashed files of a database folder
##   storage  src/geist/storage.nim   drives, free space, recorded speeds
##
##   geist --path data/files track ~/Documents --suffix .txt
##   geist folder show data/files --json
##   geist storage bench /mnt/fast --mb 256
##   geist storage list

import std/[os, strutils, tables]

import runePragmas
import ../../geist
import ../../geist/folder
import ../../geist/storage
import ../../geist/textfile
import ../../geist/track
import ./common

const
  trackedColumns*: array[4, string] = ["name", "path", "size", "file"]
    ## The columns `track` writes. A database may have more; `set` fills those.

proc missingColumns(s: Schema): seq[string] {.role: parser, tag: "cli|db|read".} =
  ## s: the schema of an open database. The `track` columns it lacks, in order.
  for name in trackedColumns:
    if s.slotIndex(name) < 0:
      result.add name

proc rowFor(t: TrackedFile): Table[string, string] {.role: helper,
    tag: "cli|db|formatting".} =
  ## t: one tracked file as the text of its `track` row.
  result = initTable[string, string]()
  result["name"] = t.name
  result["path"] = t.path
  result["size"] = $t.size
  result["file"] = "sidecar:" & hexText(t.file.hash)

proc cmdTrack*(o: Options) {.role: orchestrator,
    tag: "cli|db|write|storageIo".} =
  ## o: `track <file or folder>`, with --path, --top and --suffix. One row per file.
  ## Nothing is written to the files themselves.
  var
    target: string = ""
    lacking: seq[string] = @[]
    tracked: seq[TrackedFile] = @[]
    one: tuple[ok: bool, t: TrackedFile, err: string] = (false, TrackedFile(), "")
    got: tuple[ok: bool, tracked: seq[TrackedFile], err: string] = (false, @[], "")
    id: RowId = 0'u64
    built: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    count: int = 0
  if o.args.len == 0:
    fail("track needs a file or a folder: geist --path <db> track <file|folder>")
  target = absolutePath(o.args[0])
  if not fileExists(target) and not dirExists(target):
    fail("nothing to track at " & o.args[0])
  writing(o, db):
    lacking = missingColumns(db.entries.schema)
    if lacking.len > 0:
      fail("this database has no column " & lacking.join(", ") & "; make one with " &
        "init --schema \"name:text,path:text,size:int,file:ref\"")
    if dirExists(target):
      got = trackFolder(db.sidecarStore, target, not o.top, o.suffix)
      if not got.ok:
        fail(got.err)
      tracked = got.tracked
    else:
      one = trackFile(db.sidecarStore, target)
      if not one.ok:
        fail(one.err)
      tracked = @[one.t]
    for t in tracked:
      id = db.nextIdFor()
      built = buildRow(db.entries.schema, rowFor(t), db.sidecarStore, id)
      if not built.ok:
        fail(built.err)
      discard db.putRow(Row(data: built.data))
      count = count + 1
  echo "tracked ", count, " file(s) from ", target, "; none of them was written"

proc cmdFolder*(o: Options) {.role: orchestrator, tag: "cli|storageIo|read|write".} =
  ## o: `folder show <dir>` (force read) or `folder adopt <dir>`. The folder is the
  ## word after `show` or `adopt`, or --path when that is not given.
  var
    what: string = if o.args.len > 0: o.args[0] else: ""
    dir: string = if o.args.len > 1: o.args[1] else: o.path
    adopted: tuple[ok: bool, err: string] = (false, "")
  if dir.len == 0:
    fail("folder " & what & " needs a folder: folder " & what & " <dir>")
  case what
  of "show":
    echo inspectFolder(dir, o.json)
  of "adopt":
    adopted = adoptFolder(dir)
    if not adopted.ok:
      fail(adopted.err)
    echo "adopted ", dir, ": it may now be read, written and given sidecars"
  else:
    fail("folder takes show or adopt, got '" & what & "'")

proc humanBytes(n: uint64): string {.role: helper, tag: "formatting".} =
  ## n: a byte count as a short figure with its unit, e.g. "1.2 GB".
  const
    units: array[5, string] = ["B", "KB", "MB", "GB", "TB"]
  var
    x: float = float(n)
    i: int = 0
  while x >= 1024.0 and i < units.high:
    x = x / 1024.0
    i = i + 1
  result = formatFloat(x, ffDecimal, 1) & " " & units[i]

proc speedText(mbs: float): string {.role: helper, tag: "formatting".} =
  ## mbs: a recorded write or read speed, or 0 when none was recorded.
  if mbs > 0.0:
    result = formatFloat(mbs, ffDecimal, 1) & " MB/s"
  else:
    result = "not measured"

proc roomText(r: FreeSpace): string {.role: helper, tag: "formatting".} =
  ## r: free and total bytes of a folder's disk, or why they are not known.
  if r.ok:
    result = "free " & humanBytes(r.free) & " of " & humanBytes(r.total)
  else:
    result = "free space not known"

proc printStorage(o: Options) {.role: actor, tag: "cli|storageIo|read".} =
  ## o: lists the drives found, and the storage folders in use, with room and speed.
  var
    paths: seq[string] = if o.storage.len > 0: listOf(o.storage)
      else: geistDefaults().storagePaths
  echo "drives found (the first mount point of each disk):"
  for d in listDrives():
    echo "  ", d, "   ", roomText(freeSpaceOf(d)), "   ", speedText(measuredSpeedOf(d))
  echo "storage paths in use ([default] storage, or --storage):"
  if paths.len == 0:
    echo "  none: payloads stay in each database's own folder"
  for p in paths:
    echo "  ", p, "   ", roomText(freeSpaceOf(p)), "   ", speedText(measuredSpeedOf(p))

proc benchStorage(o: Options) {.role: orchestrator, tag: "cli|storageIo|read|write".} =
  ## o: `storage bench <dir>`, with --mb. The result is recorded in the folder, so a
  ## later run's speed policy can use it.
  var
    dir: string = if o.args.len > 1: o.args[1] else: ""
    got: SpeedResult = SpeedResult()
    saved: tuple[ok: bool, err: string] = (false, "")
  if dir.len == 0:
    fail("storage bench needs a folder: storage bench <dir>")
  got = speedTestOf(dir, o.megabytes)
  if not got.ok:
    fail(got.err)
  saved = recordSpeed(dir, got)
  if not saved.ok:
    fail(saved.err)
  echo "write ", speedText(got.writeMBs), ", read ", speedText(got.readMBs),
    " (", o.megabytes, " MB in ", dir, ")"
  echo "recorded in ", dir / speedFileName

proc cmdStorage*(o: Options) {.role: orchestrator, tag: "cli|storageIo|read".} =
  ## o: `storage list` or `storage bench <dir>`.
  var
    what: string = if o.args.len > 0: o.args[0] else: "list"
  case what
  of "list":
    printStorage(o)
  of "bench":
    benchStorage(o)
  else:
    fail("storage takes list or bench, got '" & what & "'")
