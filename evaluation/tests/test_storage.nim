## -------------------------------------------------------------------------
## Storage tests <- storage paths, speeds, and the sidecar folders placed in them
## -------------------------------------------------------------------------
##
##   suite                          what it holds down
##   -----------------------------  ------------------------------------------------
##   "the speed test"               measured speeds are positive, and no file is left
##   "free space"                   a folder's free space is read and is consistent
##   "the order of storage paths"   priority and speed orders, ties and unknowns
##   "several roots"                a payload goes to the first usable root and reads
##                                  from any of them; an unplugged drive is never used
##   "a session over storage"       payloads go to the storage path and are swept there
##   "store folders"                two stores never share a sidecar folder name
##   "two databases in a folder"    the sweep is refused, and deletes nothing
##   "drives"                       every drive listed is a folder that exists

import std/[os, strutils, tables, unittest]

import runePragmas
import geist
import geist/folder
import geist/sidecar
import geist/storage

type
  Doc = object
    docId: int
    body: string

proc freshDir(name: string): string {.role: helper.} =
  ## name: a folder under the temp dir, emptied and created.
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc bytesOf(s: string): ByteSeq {.role: helper.} =
  ## s: text as the bytes a payload is made of.
  result = cast[ByteSeq](s)

proc countFiles(dir: string): int {.role: parser.} =
  ## dir: every file below it, counted. A missing folder holds none.
  if not dirExists(dir):
    return 0
  for _ in walkDirRec(dir):
    result = result + 1

proc cappedConfig(): GeistConfig {.role: configurator.} =
  ## A capped column narrow enough that a long body escapes to a sidecar.
  result = appConfig()
  result.columnPolicy = @[cappedColumn("body", 64'u32)]
  result.sidecarThreshold = 32'u32
  result.backup.enabled = false

suite "the speed test":
  # {.testKind: tkUnit.}
  test "a speed test measures write and read speed, and removes its file":
    var
      dir = freshDir("geist_t_storage_speed")
      got = speedTestOf(dir, 1)
    check got.ok
    check got.writeMBs > 0.0
    check got.readMBs > 0.0
    check countFiles(dir) == 0
    # Measuring records nothing: recording is a separate step, done by bench.
    check not fileExists(dir / speedFileName)

  # {.testKind: tkUnit.}
  test "a recorded speed is read back by a later run":
    var
      dir = freshDir("geist_t_storage_record")
      got = speedTestOf(dir, 1)
    check recordSpeed(dir, got).ok
    check fileExists(dir / speedFileName)
    # A later run starts with nothing remembered, and reads the file.
    gSpeeds.del(absolutePath(dir))
    check measuredSpeedOf(dir) == got.writeMBs

  # {.testKind: tkEdgeCase.}
  test "a damaged speed file counts as unmeasured, and a failed test is not recorded":
    var
      dir = freshDir("geist_t_storage_damaged")
      got = speedTestOf(dir, 1)
    check recordSpeed(dir, got).ok
    writeFile(dir / speedFileName, "writeMBs = 999\n")
    gSpeeds.del(absolutePath(dir))
    check measuredSpeedOf(dir) == 0.0
    check not recordSpeed(dir, SpeedResult(ok: false, err: "broke")).ok

  # {.testKind: tkEdgeCase.}
  test "a speed test refuses a folder that is not there, and makes none":
    var
      dir = getTempDir() / "geist_t_storage_missing"
    removeDir(dir)
    var
      got = speedTestOf(dir, 1)
    check not got.ok
    check got.err.len > 0
    check not dirExists(dir)

suite "free space":
  # {.testKind: tkUnit.}
  test "the free space of a folder is read, and free never exceeds total":
    var
      dir = freshDir("geist_t_storage_free")
      room = freeSpaceOf(dir)
    check room.ok
    check room.total > 0'u64
    check room.free <= room.total

suite "the order of storage paths":
  # {.testKind: tkUnit.}
  test "priority keeps the list order and drops a path without room":
    var
      room = initTable[string, FreeSpace]()
    room["a"] = FreeSpace(ok: true, free: 100'u64)
    room["b"] = FreeSpace(ok: true, free: 10'u64)
    room["c"] = FreeSpace(ok: true, free: 90'u64)
    # "x" has no entry: its folder is not there, so it is never used.
    check orderedByPolicy(@["a", "b", "x", "c"], spPriority, room, 50'u64,
      initTable[string, float]()) == @["a", "c"]

  # {.testKind: tkUnit.}
  test "speed puts the fastest first; ties keep the list order; unmeasured last":
    var
      room = initTable[string, FreeSpace]()
      speeds = initTable[string, float]()
    for p in ["a", "b", "c", "d"]:
      room[p] = FreeSpace(ok: true, free: 1000'u64)
    speeds["a"] = 10.0
    speeds["b"] = 50.0
    speeds["d"] = 50.0
    # "c" was never measured, so it counts as slowest.
    check orderedByPolicy(@["a", "b", "c", "d"], spSpeed, room, 1'u64,
      speeds) == @["b", "d", "a", "c"]

  # {.testKind: tkEdgeCase.}
  test "a path whose free space is unknown counts as having room":
    var
      room = initTable[string, FreeSpace]()
    room["a"] = FreeSpace(ok: false)
    check orderedByPolicy(@["a"], spPriority, room, 999999'u64,
      initTable[string, float]()) == @["a"]

suite "several roots":
  # {.testKind: tkUnit.}
  test "a payload goes to the first usable root, and reads back from any root":
    var
      base = freshDir("geist_t_storage_roots")
      first = base / "first"
      second = base / "second"
      store: SidecarStore = initSidecarRoots(@[first / "p", second / "p"], 32'u32)
      rf: Ref
      moved: string = ""
    createDir(first)
    createDir(second)
    rf = store.putSidecar(bytesOf("payload one, long enough to keep"))
    check store.storedAt(refLocator(rf)).startsWith(first)
    # Move the payload into the second root: a read still finds it there.
    moved = second / "p" / refLocator(rf)
    createDir(parentDir(moved))
    moveFile(store.storedAt(refLocator(rf)), moved)
    check store.storedAt(refLocator(rf)).startsWith(second)
    check store.getSidecar(rf).data == bytesOf("payload one, long enough to keep")

  # {.testKind: tkEdgeCase.}
  test "a root whose folder is not there is never written into":
    var
      base = freshDir("geist_t_storage_unplugged")
      here = base / "here"
      store: SidecarStore = initSidecarRoots(@[base / "not-plugged-in" / "p",
        here / "p"], 32'u32)
      rf: Ref
    createDir(here)
    rf = store.putSidecar(bytesOf("a payload long enough to matter"))
    check not dirExists(base / "not-plugged-in")
    check store.storedAt(refLocator(rf)).startsWith(here)

  # {.testKind: tkEdgeCase.}
  test "with no root that has room, a write is refused":
    var
      base = freshDir("geist_t_storage_none")
      store: SidecarStore = initSidecarRoots(@[base / "gone" / "p"], 32'u32)
    expect IOError:
      discard store.putSidecar(bytesOf("nowhere to go"))
    check not dirExists(base / "gone")

  # {.testKind: tkUnit.}
  test "under the speed policy a payload goes to the fastest measured root":
    var
      base = freshDir("geist_t_storage_speed_policy")
      slow = base / "slow"
      fast = base / "fast"
      store: SidecarStore = initSidecarRoots(@[slow / "p", fast / "p"], 32'u32,
        hkBlake3, spSpeed)
      rf: Ref
    createDir(slow)
    createDir(fast)
    check recordSpeed(slow, SpeedResult(ok: true, path: slow, sizeMb: 1,
      writeMBs: 5.0, readMBs: 5.0)).ok
    check recordSpeed(fast, SpeedResult(ok: true, path: fast, sizeMb: 1,
      writeMBs: 500.0, readMBs: 500.0)).ok
    rf = store.putSidecar(bytesOf("a payload for the fast disk"))
    check store.storedAt(refLocator(rf)).startsWith(fast)

suite "a session over storage":
  # {.testKind: tkIntegration.}
  test "payloads go to the storage path, and the sweep reclaims them there":
    var
      base = freshDir("geist_t_storage_session")
      root = base / "db"
      fast = base / "fast"
      cfg = cappedConfig()
    createDir(fast)
    cfg.storagePaths = @[fast]
    var
      db = openGeist[Doc](root, cfg)
      a = db.put(Doc(docId: 1, body: repeat("S", 4096)))
    check db.save().ok
    check countFiles(fast / storeFolderName(root)) == 1
    check countFiles(root / sidecarFolderName) == 0
    check db.delete(a)
    check db.compact().ok
    check db.save().ok
    var
      swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 1
    check countFiles(fast / storeFolderName(root)) == 0
    db.close()

suite "store folders":
  # {.testKind: tkUnit.}
  test "two stores with the same folder name get different sidecar folder names":
    var
      one = storeFolderName("/data/a/main")
      two = storeFolderName("/data/b/main")
    check one != two
    check one.startsWith("main-")
    check one.endsWith(".geist-sidecar")
    check two.startsWith("main-")

  # {.testKind: tkUnit.}
  test "a store's roots are one folder per storage path, then its own folder last":
    var
      roots = storeRootsOf("/data/a/main", @["/mnt/fast", "/mnt/big"])
    check roots.len == 3
    check roots[0].startsWith("/mnt/fast")
    check roots[1].startsWith("/mnt/big")
    check extractFilename(roots[2]) == sidecarFolderName

suite "two databases in a folder":
  # {.testKind: tkEdgeCase.}
  test "a folder holding two databases refuses the sweep, and deletes nothing":
    var
      base = freshDir("geist_t_storage_two")
      root = base / "db"
      cfg = cappedConfig()
    var
      one = openSession[Doc](root, "one", cfg, "")
    discard one.put(Doc(docId: 1, body: repeat("O", 4096)))
    check one.save().ok
    one.close()
    var
      two = openSession[Doc](root, "two", cfg, "")
    discard two.put(Doc(docId: 2, body: repeat("T", 4096)))
    check two.save().ok
    two.close()
    check databaseNamesIn(root).len == 2
    var
      again = openSession[Doc](root, "one", cfg, "")
      swept = again.sweepSidecar()
    check not swept.ok
    check swept.err.contains("more than one database")
    check countFiles(root / sidecarFolderName) == 2
    again.close()

suite "drives":
  # {.testKind: tkSmoke.}
  test "every drive listed is a folder that exists, and none is listed twice":
    var
      seen: seq[string] = @[]
    for d in listDrives():
      check dirExists(d)
      check d notin seen
      seen.add d
