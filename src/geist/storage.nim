## ---------------------------------------------------------------------
## Storage <- the folders sidecar payloads may go to, and how fast each one is
## ---------------------------------------------------------------------
##
## A list of storage paths, in order, names the folders where sidecar payloads
## may be written ([default] storage in configs/default.toml, or a flag). Geist
## can measure each folder: its free space, and how fast it writes and reads.
##
##   policy priority   the first path in the list that has room is used
##   policy speed      the fastest MEASURED path that has room is used; a path
##                     that was never measured counts as slowest, and ties keep
##                     the order of the list
##
## Def. 1 (speed test): write `sizeMb` megabytes to a temporary file, flush it to
##   the disk, then read it back. The temporary file is removed at the end. A
##   read may come from the operating system's cache, so a file larger than the
##   RAM gives the disk's own read speed.
## Def. 2 (room): the free space of a path, as the operating system reports it,
##   for the user running Geist. A path whose free space cannot be read is taken
##   as having room: the write itself says so if it does not. A path whose
##   folder is not there is never used (sidecar.nim, writeRootFor).
## Def. 3 (recorded speed): a speed test's result, kept in `.geist-speed` INSIDE
##   the storage path, so the drive keeps its speed wherever it is mounted. A run
##   reads that file once, the first time it needs the speed of the path.

import std/[os, strutils, tables, times]

when defined(posix):
  import std/posix

import runePragmas
import ./textfile

const
  speedFileName*: string = ".geist-speed"
    ## The recorded speed test of a storage path. Written by `recordSpeed`.

type
  StoragePolicy* {.role: configurator, tag: "appApi|config|types".} = enum
    ## priority: the first path with room. speed: the fastest measured path with room.
    spPriority,
    spSpeed

  FreeSpace* {.role: truthState, tag: "appApi|types".} = object
    ok*: bool
    free*: uint64
    total*: uint64
    err*: string

  SpeedResult* {.role: truthState, tag: "appApi|types".} = object
    ok*: bool
    path*: string
    sizeMb*: int
    writeMBs*: float
    readMBs*: float
    err*: string

var
  gSpeeds*: Table[string, float] = initTable[string, float]()
    ## Write speed in MB/s by absolute storage path, as this run has read it
    ## (Def. 3). The speed policy reads it and never measures by itself.

proc freeSpaceOf*(path: string): FreeSpace {.role: parser, tag: "storageIo|read".} =
  ## path: a folder. Its free and total bytes for the user running Geist.
  when defined(posix):
    var
      st: Statvfs
    if statvfs(path.cstring, st) != 0:
      result.err = "cannot read the free space of " & path
      return
    result.free = uint64(st.f_bavail) * uint64(st.f_frsize)
    result.total = uint64(st.f_blocks) * uint64(st.f_frsize)
    result.ok = true
  else:
    result.err = "free space is not measured on this system yet: " & path

proc speedTestOf*(path: string, sizeMb: int = 16): SpeedResult {.role: orchestrator,
    tag: "storageIo|read|write".} =
  ## path/sizeMb: measure write and read speed in `path`. The temporary file is
  ## named for this process, and it is removed at the end whatever happens.
  var
    tmp: string = path / (".geist-speedtest-" & $getCurrentProcessId() & ".tmp")
    buf: seq[uint8] = newSeq[uint8](1024 * 1024)
    f: File
    i: int = 0
    j: int = 0
    started: float = 0.0
    writeSeconds: float = 0.0
    readSeconds: float = 0.0
  result.path = path
  result.sizeMb = sizeMb
  if sizeMb < 1 or not dirExists(path):
    result.err = "the speed test needs an existing folder and at least 1 MB"
    return
  for k in 0 ..< buf.len:
    buf[k] = uint8(k mod 251)
  try:
    started = epochTime()
    f = open(tmp, fmWrite)
    try:
      while i < sizeMb:
        # A short write means the disk is full: that must fail, not look fast.
        if writeBytes(f, buf, 0, buf.len) != buf.len:
          raise newException(IOError, "the disk filled up during the speed test")
        i = i + 1
      flushFile(f)
      when defined(posix):
        discard fsync(getFileHandle(f))
    finally:
      f.close()
    writeSeconds = epochTime() - started
    started = epochTime()
    f = open(tmp, fmRead)
    try:
      while j < sizeMb:
        discard readBytes(f, buf, 0, buf.len)
        j = j + 1
    finally:
      f.close()
    readSeconds = epochTime() - started
    result.writeMBs = float(sizeMb) / max(writeSeconds, 1e-6)
    result.readMBs = float(sizeMb) / max(readSeconds, 1e-6)
    result.ok = true
  except CatchableError as e:
    result.err = "speed test failed in " & path & ": " & e.msg
  finally:
    if fileExists(tmp):
      removeFile(tmp)

proc recordSpeed*(path: string, r: SpeedResult): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "storageIo|write".} =
  ## path/r: keep the result of a speed test in the storage path (Def. 3), so the
  ## speed policy of later runs can use it. Refused for a failed test, or when the
  ## folder is not there.
  var
    pairs: seq[tuple[key, value: string]] = @[]
    file: string = path / speedFileName
    tmp: string = file & ".tmp"
  if not r.ok:
    return (false, "a failed speed test is not recorded: " & r.err)
  if not dirExists(path):
    return (false, "no folder at " & path & ", so its speed is not recorded")
  pairs = @[("geist-speed", "1"), ("writeMBs", $r.writeMBs),
    ("readMBs", $r.readMBs), ("sizeMb", $r.sizeMb)]
  writeFile(tmp, renderFile(pairs))
  moveFile(tmp, file)
  gSpeeds[absolutePath(path)] = r.writeMBs
  result = (true, "")

proc measuredSpeedOf*(path: string): float {.role: parser, tag: "storageIo|read".} =
  ## path: a storage path. Its recorded write speed in MB/s, or 0.0 when it was
  ## never measured or its file does not check out (a speed is advice, so a bad
  ## file is ignored rather than refused). The file is read once per run.
  var
    full: string = absolutePath(path)
    got: tuple[ok: bool, pairs: Table[string, string], err: string] =
      (false, initTable[string, string](), "")
  if full in gSpeeds:
    return gSpeeds[full]
  if not fileExists(path / speedFileName):
    return 0.0
  got = parseKeyFile(readFile(path / speedFileName))
  if got.ok and got.pairs.hasKey("writeMBs"):
    try:
      result = parseFloat(got.pairs["writeMBs"])
    except ValueError:
      result = 0.0
  gSpeeds[full] = result

proc floatBack(R: var seq[tuple[path: string, mbs: float]], i: int) {.
    role: helper, tag: "appApi|storageIo|read".} =
  ## R/i: move entry i toward the front while the entry before it is slower.
  ## Equal speeds never swap, so the sort that calls this one stays stable.
  var
    j: int = i
  while j > 0 and R[j - 1].mbs < R[j].mbs:
    swap(R[j - 1], R[j])
    j = j - 1

proc orderedByPolicy*(paths: seq[string], policy: StoragePolicy,
    free: Table[string, FreeSpace], needBytes: uint64,
    speeds: Table[string, float]): seq[string] {.role: parser,
    tag: "appApi|storageIo|read".} =
  ## paths/policy/free/needBytes/speeds: the storage paths in the order a write
  ## should try them. A path is left out when it has no entry in `free` (its folder
  ## is not there), or when its free space is known and smaller than needBytes.
  ## Under the speed policy the fastest comes first; ties keep the order of the list.
  var
    roomy: seq[string] = @[]
    rate: seq[tuple[path: string, mbs: float]] = @[]
    i: int = 0
  for p in paths:
    if p in free and (not free[p].ok or free[p].free >= needBytes):
      roomy.add p
  if policy == spPriority:
    return roomy
  for p in roomy:
    rate.add (path: p, mbs: (if p in speeds: speeds[p] else: 0.0))
  while i < rate.len:
    floatBack(rate, i)
    i = i + 1
  for r in rate:
    result.add r.path

proc listDrives*(): seq[string] {.role: parser, tag: "storageIo|read".} =
  ## The folder of each real disk on this machine, one per disk: the first mount
  ## point the mount table names for its device. Linux only, for now. Pseudo file
  ## systems are left out, and so are bind mounts (they share their disk's device)
  ## and mount points that are not folders. Elsewhere the result is empty, and the
  ## storage paths in the configuration are the answer.
  when defined(linux):
    const
      real = ["ext2", "ext3", "ext4", "btrfs", "xfs", "zfs", "f2fs", "vfat",
        "exfat", "ntfs", "ntfs3", "fuseblk"]
    var
      parts: seq[string] = @[]
      devices: seq[string] = @[]
      mount: string = ""
    for line in lines("/proc/mounts"):
      parts = line.split(' ')
      if parts.len < 3 or parts[2] notin real or parts[0] in devices:
        continue
      mount = parts[1].replace("\\040", " ")
      if dirExists(mount):
        devices.add parts[0]
        result.add mount
