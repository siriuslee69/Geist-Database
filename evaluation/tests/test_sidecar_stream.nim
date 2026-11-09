## Sidecar stream tests <- a large value in pieces, the same as a value whole.

import std/[os, unittest]

import runePragmas
import geist/types
import geist/sidecar
import geist/sidecarstream

proc storeAt(name: string): SidecarStore {.role: helper.} =
  ## name: an empty store.
  var
    dir = getTempDir() / "geist_stream" / name
  removeDir(dir)
  createDir(dir)
  result = initSidecarStore(dir, 1024, hkBlake3)

suite "streaming":
  # {.testKind: tkProperty, covers: "feedSidecar|finishSidecar".}
  test "pieces give the same reference as the whole value":
    var
      A = newSeq[uint8](300_000)
      s = storeAt("same")
      t = storeAt("same2")
      W = beginSidecar(s, int64(A.len))
      i = 0
    for k in 0 ..< A.len: A[k] = uint8(k mod 251)
    while i < A.len:
      W.feedSidecar(A.toOpenArray(i, min(i + 7000, A.len) - 1))
      i = i + 7000
    var r = s.finishSidecar(W)
    check r.ok and r.reference.hash == t.putSidecar(A).hash
    check s.getSidecar(r.reference).data == A

  # {.testKind: tkIntegration, covers: "readSidecar".}
  test "reading in pieces gives the same bytes and a clean verdict":
    var
      A = newSeq[uint8](100_000)
      s = storeAt("read")
      r = s.putSidecar(A)
      R = s.openSidecarReader(r)
      back: seq[uint8] = @[]
    while not R.done:
      back.add(R.readSidecar(4096))
    check back == A and not R.failed

  # {.testKind: tkEdgeCase, covers: "readSidecar".}
  test "a damaged file is caught at the end":
    var
      A = newSeq[uint8](10_000)
      s = storeAt("bad")
      r = s.putSidecar(A)
      path = s.storedAt(r.refLocator())
      raw = readFile(path)
    raw[50] = chr(ord(raw[50]) xor 1)
    writeFile(path, raw)
    var R = s.openSidecarReader(r)
    while not R.done:
      discard R.readSidecar(4096)
    check R.failed

  # {.testKind: tkEdgeCase, covers: "abortSidecar".}
  test "an abandoned value leaves nothing behind":
    var
      s = storeAt("gone")
      W = beginSidecar(s)
    W.feedSidecar([1'u8, 2, 3])
    W.abortSidecar()
    for k, p in walkDir(s.roots[0]):
      check false

  # {.testKind: tkEdgeCase, covers: "finishSidecar".}
  test "a value that is already there is kept once":
    var
      s = storeAt("twice")
      W = beginSidecar(s)
    discard s.putSidecar([1'u8, 2, 3])
    W.feedSidecar([1'u8, 2, 3])
    check s.finishSidecar(W).ok
    check s.reused == 1'u32

  # {.testKind: tkEdgeCase, covers: "openSidecarReader".}
  test "a value that is not here says so":
    var s = storeAt("none")
    check s.openSidecarReader(Ref(target: rtSidecar, hash: newSeq[uint8](32))).failed
