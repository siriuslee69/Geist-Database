## ---------------------------------------------------------------------
## Durable <- writes that survive a crash, and the rename that publishes
## ---------------------------------------------------------------------
##
##   writeDurable(p, A)        bytes -> new file -> flush -> fsync
##   replaceDurable(p, A|s)    bytes -> p.tmp -> fsync -> rename -> fsync dir
##   syncDir(d)                make a rename itself durable
##
## Why two shapes:
##
##   a NEW file (generation N+1)     already has a name nobody reads yet,
##                                   so writing it and fsyncing is enough
##   a file replaced IN PLACE        (the manifest) can be observed while
##                                   half written, so it is staged beside
##                                   itself and renamed over
##
## `rename()` is atomic on POSIX and `MoveFileEx` is on Windows. That is the
## whole reason the generation manifest exists: three artifacts must appear
## together, and only one file is ever renamed.
##
##   write .gN+1 ---> fsync ---> verify ---> rename current ---> fsync dir
##        |              |          |             |                  |
##    still invisible    |    reject a bad     THE atomic       so the swap
##    to any reader      |    write BEFORE      step            outlives a
##                  bytes are on   publishing                   power cut
##                  the platter
##
## Without the fsync, "the bytes are in the file" only means the kernel
## agreed to remember them. A power cut before writeback loses them and
## leaves a file whose name says it is complete.

import std/os

import geistPragmas

when defined(posix):
  import std/posix
elif defined(windows):
  import std/winlean

  proc flushFileBuffers(h: Handle): WINBOOL {.importc: "FlushFileBuffers",
    stdcall, dynlib: "kernel32".}

proc syncHandle(f: File): bool {.role: dataWriter,
    metaTags: {tagStorageIo, tagWrite}.} =
  ## f: open file whose bytes are pushed from the kernel's cache to the
  ## device. Everything else in this module is bookkeeping around this call.
  when defined(posix):
    result = fsync(getFileHandle(f)) == 0
  elif defined(windows):
    result = flushFileBuffers(getOsFileHandle(f)) != 0
  else:
    result = true

proc syncDir*(dir: string): tuple[ok: bool, err: string] {.role: dataWriter,
    metaTags: {tagStorageIo, tagWrite}.} =
  ## dir: directory whose ENTRY LIST is made durable, which is what a
  ## rename actually changes. Renaming without this can leave a committed
  ## manifest pointing at a name the directory forgot.
  ##
  ## Windows has no directory handle to flush and does not need one: its
  ## metadata journal covers the rename, so this succeeds by doing nothing.
  var
    fd: cint = 0
  result = (true, "")
  when defined(posix):
    if dir.len == 0:
      return (true, "")
    fd = open(dir.cstring, O_RDONLY)
    if fd < 0:
      return (false, "cannot open directory for sync: " & dir)
    if fsync(fd) != 0:
      discard close(fd)
      return (false, "fsync failed on directory: " & dir)
    discard close(fd)

proc writeDurable*(path: string, A: openArray[uint8]): tuple[ok: bool,
    err: string] {.role: dataWriter, metaTags: {tagStorageIo, tagWrite}.} =
  ## path: destination, created or truncated.
  ## A: payload written, flushed and fsynced before this returns.
  ##
  ## Use for a file whose NAME is not yet published -- a new generation.
  ## For anything a reader may already be looking at, use `replaceDurable`.
  var
    f: File = nil
    ok: bool = false
  try:
    if parentDir(path).len > 0 and not dirExists(parentDir(path)):
      createDir(parentDir(path))
    if not open(f, path, fmWrite):
      return (false, "cannot open for writing: " & path)
    if A.len > 0:
      discard f.writeBuffer(unsafeAddr A[0], A.len)
    flushFile(f)
    ok = syncHandle(f)
    f.close()
    f = nil
    if not ok:
      return (false, "fsync failed on " & path)
    result = (true, "")
  except CatchableError as exc:
    if f != nil:
      f.close()
    result = (false, exc.msg)

proc replaceDurable*(path: string, A: openArray[uint8]): tuple[ok: bool,
    err: string] {.role: dataWriter, metaTags: {tagStorageIo, tagWrite}.} =
  ## path: file replaced ATOMICALLY -- a reader sees the old bytes or the
  ##   new ones, never a mixture, and never an empty file.
  ## A: payload.
  var
    tmp: string = ""
    written: tuple[ok: bool, err: string]
  tmp = path & ".tmp"
  written = writeDurable(tmp, A)
  if not written.ok:
    return written
  try:
    moveFile(tmp, path)
  except CatchableError as exc:
    removeFile(tmp)
    return (false, exc.msg)
  result = syncDir(parentDir(path))

proc replaceDurable*(path, s: string): tuple[ok: bool, err: string] {.
    role: dataWriter, metaTags: {tagStorageIo, tagWrite}.} =
  ## path/s: the same replacement for text -- the manifest and the lock
  ## file, both of which are one line a person may want to read.
  result = replaceDurable(path, toOpenArrayByte(s, 0, s.len - 1))
