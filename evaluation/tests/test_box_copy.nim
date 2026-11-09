## Box copy tests <- a log handed over in chunks gives the same box.

import std/[os, tables, unittest]

import runePragmas
import geist/types
import geist/boxlog
import geist/boxcopy
import geist/box

const
  T = 1000'u64

proc rulesHere(): seq[BoxRule] {.role: helper.} =
  ## One kind, large items allowed.
  var
    r = defaultBoxRule("chat")
  r.owner = boSpace
  r.read = baMembers
  r.write = baMembers
  r.maxItemBytes = 1024 * 1024
  result = @[r]

proc shelf(name: string): BoxShelf {.role: helper.} =
  ## name: an empty shelf.
  var
    dir = getTempDir() / "geist_box_copy" / name
  removeDir(dir)
  result = openShelf(dir, rulesHere()).shelf

proc follow(H, C: BoxShelf, id: string): bool {.role: orchestrator.} =
  ## H/C/id: everything H has of this box handed to C, as a mover would.
  var
    logId = 0'u64
    offset = 0'i64
    got: tuple[found: bool, box: BoxFile] = C.boxOf("chat", id)
    chunk = BoxCopyChunk()
  if got.found:
    logId = got.box.logId
    offset = got.box.size
  while true:
    chunk = H.boxLogSince("chat", id, logId, offset, 300)
    if not chunk.ok: return false
    for n in chunk.blobs:
      if not C.putBoxBlob("chat", id, n, H.boxBlobBytes("chat", id, n).bytes).ok:
        return false
    if not C.applyBoxLog("chat", id, chunk).ok: return false
    got = C.boxOf("chat", id)
    logId = got.box.logId
    offset = got.box.size
    if offset >= chunk.size: return true

suite "copying a box":
  # {.testKind: tkIntegration, covers: "boxLogSince|applyBoxLog".}
  test "a copy holds the same items, numbers, people and large values":
    var
      H = shelf("h1")
      C = shelf("c1")
      big = newSeq[uint8](boxInlineMax + 5)
      i = 0
    big[9] = 7'u8
    check H.createBox("chat", "c", "alice").ok
    check H.setBoxPeople("chat", "c", "alice", ["bob"], []).ok
    while i < 20:
      check H.putBoxItem("chat", "c", "bob", $i, textBytes("v" & $i), 0, T).ok
      i = i + 1
    check H.putBoxItem("chat", "c", "alice", "big", big, 0, T).ok
    check follow(H, C, "c")
    var f = C.fetchBoxItems("chat", "c", "bob", 0, 100, T)
    check f.items.len == 21 and f.number == 21'u64
    check f.items[0].writer == "bob" and f.items[20].data == big
    check C.usage["alice"].boxes == 1
    H.closeShelf(); C.closeShelf()

  # {.testKind: tkIntegration, covers: "boxLogSince".}
  test "only what is new travels the second time":
    var
      H = shelf("h2")
      C = shelf("c2")
    check H.createBox("chat", "c", "a").ok
    check H.putBoxItem("chat", "c", "a", "1", textBytes("x"), 0, T).ok
    check follow(H, C, "c")
    var at = C.boxOf("chat", "c").box.size
    check H.putBoxItem("chat", "c", "a", "2", textBytes("y"), 0, T).ok
    var chunk = H.boxLogSince("chat", "c", C.boxOf("chat", "c").box.logId, at)
    check chunk.offset == at and chunk.bytes.len < 200
    check C.applyBoxLog("chat", "c", chunk).ok
    check C.fetchBoxItems("chat", "c", "a", 0, 9, T).number == 2'u64
    H.closeShelf(); C.closeShelf()

  # {.testKind: tkEdgeCase, covers: "applyBoxLog".}
  test "a changed byte, or a chunk from the wrong place, changes nothing":
    var
      H = shelf("h3")
      C = shelf("c3")
    check H.createBox("chat", "c", "a").ok
    check H.putBoxItem("chat", "c", "a", "1", textBytes("x"), 0, T).ok
    check follow(H, C, "c")
    check H.putBoxItem("chat", "c", "a", "2", textBytes("y"), 0, T).ok
    var
      at = C.boxOf("chat", "c").box.size
      id = C.boxOf("chat", "c").box.logId
      good = H.boxLogSince("chat", "c", id, at)
      bad = good
    bad.bytes[^1] = bad.bytes[^1] xor 1'u8
    check not C.applyBoxLog("chat", "c", bad).ok
    bad = good
    bad.offset = at + 1
    check not C.applyBoxLog("chat", "c", bad).ok
    check C.fetchBoxItems("chat", "c", "a", 0, 9, T).number == 1'u64
    check C.applyBoxLog("chat", "c", good).ok
    H.closeShelf(); C.closeShelf()

  # {.testKind: tkRegression, covers: "boxLogSince|compactBox".}
  test "a holder that rewrote its log starts the copy over":
    var
      H = shelf("h4")
      C = shelf("c4")
      big = newSeq[uint8](40000)
      i = 0
    H.rules[0].mode = bmOverwrite
    check H.createBox("chat", "c", "a").ok
    check H.putBoxItem("chat", "c", "a", "k", big, 0, T).ok
    check follow(H, C, "c")
    var before = H.boxOf("chat", "c").box.logId
    while i < 6:
      check H.putBoxItem("chat", "c", "a", "k", big, uint64(i + 1), T).ok
      i = i + 1
    check H.boxOf("chat", "c").box.logId != before
    check follow(H, C, "c")
    check C.boxOf("chat", "c").box.logId == H.boxOf("chat", "c").box.logId
    check C.boxOf("chat", "c").box.counter == 7'u64
    H.closeShelf(); C.closeShelf()

  # {.testKind: tkUnit, covers: "listBoxes".}
  test "a listing names every box":
    var S = shelf("list")
    check S.createBox("chat", "a", "x").ok
    check S.createBox("chat", "b", "x").ok
    check S.listBoxes().len == 2
    S.closeShelf()
