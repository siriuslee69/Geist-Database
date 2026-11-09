## ---------------------------------------------------------------------
## Sidecar stream <- a value too large to hold, written and read in pieces
## ---------------------------------------------------------------------
##
##   var W = beginSidecar(store)
##   W.feedSidecar(chunk) ...        any number of chunks, any size
##   var r = store.finishSidecar(W)  r.reference names the bytes by their hash
##
##   var R = store.openSidecarReader(reference)
##   while not R.done:
##     piece = R.readSidecar(64 * 1024)
##   if R.failed: the bytes were not the right ones
##
## Memory stays at one piece, however large the value is.
##
## ╭─ ❧ Written under a temporary name ⚠️
##
## The name of a sidecar is the hash of its bytes, and the hash is only known at
## the end. So the bytes go to `<root>/.incoming-<random>` first, and the file
## takes its name in one rename. Nobody ever sees half a value under a real name.
##
## ╭─ ❧ When a reader finds out ⚠️
##
## The hash can only be checked once the last byte was read. A reader of a
## damaged file has already been handed pieces by then, so `failed` must be
## looked at before believing any of it. A program that cannot take bytes back
## should write them to a temporary place first.

import std/[os, sysrand]

import tyr/hashes/blake3 as tyr_blake3

import runePragmas
import ./types
import ./durable
import ./textfile
import ./crypto/hashing
import ./crypto/hashwidths
import ./sidecar

type
  SidecarWriter* {.role: truthState, tag: "sidecar|types",
      expectedCount: [0, 64], lifeCycle: lcJob.} = object
    ## One value on its way in.
    path*: string
    root*: string
    file*: File
    hasher*: Blake3Hasher
    size*: int64
    failed*: string

  SidecarReader* {.role: truthState, tag: "sidecar|types",
      expectedCount: [0, 64], lifeCycle: lcJob.} = object
    ## One value on its way out.
    file*: File
    hasher*: Blake3Hasher
    expected*: ByteSeq
    done*: bool
    failed*: bool
    err*: string
    total*: int64

proc beginSidecar*(S: SidecarStore, sizeHint: int64 = 0): SidecarWriter {.
    role: dataWriter, tag: "sidecar|appApi|storageIo|write".} =
  ## S: where it goes. sizeHint: how large it will be, when known, so that a
  ## storage path with room is chosen. Check `failed` before going on.
  var
    root: string = ""
  if S.hash != hkBlake3:
    result.failed = "streaming needs a store that hashes with BLAKE3"
    return
  root = S.writeRootFor(sizeHint)
  if root.len == 0:
    result.failed = "no storage path has room for a value of " & $sizeHint & " bytes"
    return
  result.root = root
  result.path = root / (".incoming-" & hexText(urandom(8)))
  result.hasher = initBlake3Hasher()
  createDir(root)
  if not open(result.file, result.path, fmWrite):
    result.failed = "cannot write " & result.path

proc feedSidecar*(W: var SidecarWriter, A: openArray[uint8]) {.role: dataWriter,
    tag: "sidecar|appApi|storageIo|write".} =
  ## W/A: the next piece. The first failure is kept in `failed`.
  if W.failed.len > 0 or A.len == 0:
    return
  updateBlake3(W.hasher, A)
  if W.file.writeBuffer(unsafeAddr A[0], A.len) != A.len:
    W.failed = "could not write to " & W.path
    return
  W.size = W.size + int64(A.len)

proc abortSidecar*(W: var SidecarWriter) {.role: actor,
    tag: "sidecar|appApi|storageIo|write".} =
  ## W: nothing is kept.
  if W.file != nil:
    W.file.close()
    W.file = nil
  if W.path.len > 0:
    removeFile(W.path)

proc finishSidecar*(S: var SidecarStore, W: var SidecarWriter): tuple[ok: bool,
    reference: Ref, err: string] {.role: orchestrator,
    tag: "sidecar|appApi|storageIo|write".} =
  ## S/W: flushed, synced, and given its real name. A value already there is
  ## kept as it is and this copy dropped.
  var
    hash: ByteSeq = @[]
    locator: string = ""
    target: string = ""
    done: bool = false
  if W.failed.len > 0:
    W.abortSidecar()
    return (false, Ref(), W.failed)
  flushFile(W.file)
  done = syncFile(W.file)
  W.file.close()
  W.file = nil
  if not done:
    W.abortSidecar()
    return (false, Ref(), "fsync failed on " & W.path)
  hash = finalBlake3(W.hasher, fullDigestBytes)
  locator = sidecarLocator(hash)
  result = (true, Ref(target: rtSidecar, hash: hash), "")
  if S.storedAt(locator).len > 0:
    W.abortSidecar()
    S.reused = S.reused + 1'u32
    return
  target = W.root / locator
  createDir(parentDir(target))
  moveFile(W.path, target)
  discard syncDir(parentDir(target))
  S.writes = S.writes + 1'u32
  S.bytesWritten = S.bytesWritten + uint64(W.size)

proc openSidecarReader*(s: SidecarStore, r: Ref): SidecarReader {.role: dataFetcher,
    tag: "sidecar|appApi|storageIo|read".} =
  ## s/r: the value this reference names. `failed` = true when it is not here.
  var
    full: string = ""
  result.expected = r.hash
  result.hasher = initBlake3Hasher()
  if not validRef(r) or s.hash != hkBlake3:
    result.failed = true
    result.err = "this reference cannot be read in pieces"
    result.done = true
    return
  full = s.storedAt(r.refLocator())
  if full.len == 0 or not open(result.file, full, fmRead):
    result.failed = true
    result.err = "the value is not on this machine"
    result.done = true

proc closeReader(R: var SidecarReader) {.role: actor, inline.} =
  ## R: the file closed.
  if R.file != nil:
    R.file.close()
    R.file = nil

proc readSidecar*(R: var SidecarReader, maxBytes: int): ByteSeq {.role: dataFetcher,
    tag: "sidecar|appApi|storageIo|read".} =
  ## R: the next piece, at most maxBytes. Empty and `done` at the end, and only
  ## then is `failed` the verdict on the whole value.
  var
    n: int = 0
  if R.done:
    return @[]
  result = newSeq[uint8](maxBytes)
  n = R.file.readBuffer(addr result[0], maxBytes)
  result.setLen(n)
  if n > 0:
    updateBlake3(R.hasher, result)
    R.total = R.total + int64(n)
  if n < maxBytes:
    R.done = true
    R.closeReader()
    R.failed = not constantTimeEq(finalBlake3(R.hasher, fullDigestBytes), R.expected)
    if R.failed:
      R.err = "the value failed its hash check"
