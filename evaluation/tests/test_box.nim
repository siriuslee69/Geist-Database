## Box tests <- the four modes, the rules, and what a crash may do to a log.
##
##   suite         what it holds down
##   ------------  --------------------------------------------------------
##   "modes"       append, overwrite, queue, takeOnce; numbers and limits
##   "access"      who may do what, and that a refusal says nothing
##   "the log"     a crash cannot reuse a number; damage is found; rewriting
##   "large items" blobs on their own, checked, removed with their item
##   "at rest"     a key handed over seals bodies; no key, no reading
##   "signed"      labels: right key, right data, right place, right order
##   "limits"      what one owner may use
##   "many writes" one trip to the disk

import std/[os, strutils, tables, unittest]

import runePragmas
import geist/types
import geist/boxlog
import geist/box

const
  T = 1000'u64

proc rule(name: string, read, write: BoxAccess, mode: BoxMode,
    owner: BoxOwner = boAccount): BoxRule =
  ## name/read/write/mode/owner: one kind with the usual limits.
  result = defaultBoxRule(name)
  result.read = read
  result.write = write
  result.mode = mode
  result.owner = owner

proc rules(): seq[BoxRule] =
  ## The kinds these tests use.
  result = @[rule("vault", baOwner, baOwner, bmOverwrite),
    rule("mail", baOwner, baAnyone, bmQueue),
    rule("keys", baWhitelist, baOwner, bmTakeOnce),
    rule("chat", baMembers, baMembers, bmAppend, boSpace),
    rule("seen", baAnyone, baOwner, bmOverwrite)]

proc fresh(name: string, limits = BoxLimits(), key: BoxKey = nil): BoxShelf =
  ## name: an empty shelf in a temporary folder.
  var
    dir = getTempDir() / "geist_box_test" / name
  removeDir(dir)
  var got = openShelf(dir, rules(), limits, key)
  doAssert got.ok, got.err
  result = got.shelf

proc b(s: string): seq[uint8] =
  ## s: its bytes.
  result = textBytes(s)

suite "modes":
  # {.testKind: tkUnit, covers: "putBoxItem|fetchBoxItems".}
  test "append: keys are written once; items come back after a number":
    var S = fresh("append")
    check S.createBox("chat", "c1", "alice").ok
    check S.putBoxItem("chat", "c1", "alice", "a", b("1"), 0, T).number == 1'u64
    check S.putBoxItem("chat", "c1", "alice", "b", b("2"), 0, T).number == 2'u64
    check not S.putBoxItem("chat", "c1", "alice", "a", b("x"), 0, T).ok
    var f = S.fetchBoxItems("chat", "c1", "alice", 1, 10, T)
    check f.ok and f.items.len == 1 and f.items[0].data == b("2") and f.number == 2'u64
    S.closeShelf()

  # {.testKind: tkUnit, covers: "putBoxItem".}
  test "overwrite: a write names the version it replaces":
    var S = fresh("over")
    check S.createBox("vault", "alice", "alice").ok
    check S.putBoxItem("vault", "alice", "alice", "k", b("1"), 0, T).version == 1'u64
    check S.putBoxItem("vault", "alice", "alice", "k", b("2"), 1, T).version == 2'u64
    var r = S.putBoxItem("vault", "alice", "alice", "k", b("3"), 1, T)
    check not r.ok and r.err == "stale version: the newest is 2"
    check not S.putBoxItem("vault", "alice", "alice", "new", b("x"), 5, T).ok
    var f = S.fetchBoxItems("vault", "alice", "alice", 0, 10, T)
    check f.items.len == 1 and f.items[0].data == b("2")
    S.closeShelf()

  # {.testKind: tkUnit, covers: "ackBoxItems".}
  test "queue: anyone drops a letter, only the owner reads and clears it":
    var S = fresh("queue")
    check S.createBox("mail", "alice", "alice").ok
    check S.putBoxItem("mail", "alice", "bob", "m1", b("hi"), 0, T).ok
    check not S.fetchBoxItems("mail", "alice", "bob", 0, 10, T).ok
    check S.fetchBoxItems("mail", "alice", "alice", 0, 10, T).items[0].writer == "bob"
    check not S.ackBoxItems("mail", "alice", "bob", ["m1"]).ok
    check S.ackBoxItems("mail", "alice", "alice", ["m1"]).number == 1'u64
    check S.ackBoxItems("mail", "alice", "alice", ["m1"]).number == 0'u64
    check S.fetchBoxItems("mail", "alice", "alice", 0, 10, T).items.len == 0
    S.closeShelf()

  # {.testKind: tkUnit, covers: "takeBoxItem".}
  test "takeOnce: every key goes to exactly one reader":
    var S = fresh("take")
    check S.createBox("keys", "alice", "alice").ok
    check S.setBoxPeople("keys", "alice", "alice", [], ["bob", "carol"]).ok
    check S.putBoxItem("keys", "alice", "alice", "k1", b("1"), 0, T).ok
    check S.putBoxItem("keys", "alice", "alice", "k2", b("2"), 0, T).ok
    check S.takeBoxItem("keys", "alice", "bob", T).items[0].key == "k1"
    check S.takeBoxItem("keys", "alice", "carol", T).items[0].key == "k2"
    check S.takeBoxItem("keys", "alice", "bob", T).items.len == 0
    check not S.takeBoxItem("keys", "alice", "mallory", T).ok
    check not S.fetchBoxItems("keys", "alice", "bob", 0, 10, T).ok
    S.closeShelf()

  # {.testKind: tkRegression, covers: "putBoxItem|sweepBox", pins: "expired items counted against the limit for ever".}
  test "expired items do not hold a box full, and a sweep frees them":
    var S = fresh("expire")
    S.rules[1].keepMs = 100
    S.rules[1].maxItems = 2
    check S.createBox("mail", "alice", "alice").ok
    check S.putBoxItem("mail", "alice", "x", "a", b("1"), 0, T).ok
    check S.putBoxItem("mail", "alice", "x", "b", b("2"), 0, T).ok
    check not S.putBoxItem("mail", "alice", "x", "c", b("3"), 0, T).ok
    check S.fetchBoxItems("mail", "alice", "alice", 0, 10, T + 200).items.len == 0
    check S.putBoxItem("mail", "alice", "x", "c", b("3"), 0, T + 200).ok
    check S.fetchBoxItems("mail", "alice", "alice", 0, 10, T + 200).items.len == 1
    S.rules[1].maxItems = 100
    check S.putBoxItem("mail", "alice", "x", "d", b("4"), 0, T + 200).ok
    check S.sweepBox("mail", "alice", T + 400) == 2
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "putBoxItem".}
  test "size and key limits":
    var S = fresh("limit")
    S.rules[0].maxItemBytes = 3
    check S.createBox("vault", "alice", "alice").ok
    check not S.putBoxItem("vault", "alice", "alice", "k", b("1234"), 0, T).ok
    check not S.putBoxItem("vault", "alice", "alice", "", b("1"), 0, T).ok
    check not S.putBoxItem("vault", "alice", "alice", repeat('k', 257), b("1"), 0, T).ok
    S.closeShelf()

suite "access":
  # {.testKind: tkUnit, covers: "createBox".}
  test "an account box is made by that account only":
    var S = fresh("acc")
    check not S.createBox("vault", "alice", "bob").ok
    check S.createBox("vault", "alice", "alice").ok
    check S.createBox("vault", "alice", "alice").err == "the box exists already"
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "fetchBoxItems|putBoxItem".}
  test "a refusal and a missing box give the same words":
    var S = fresh("noleak")
    check S.createBox("vault", "alice", "alice").ok
    check S.fetchBoxItems("vault", "alice", "bob", 0, 1, T).err == boxRefused
    check S.fetchBoxItems("vault", "nobody", "bob", 0, 1, T).err == boxRefused
    check S.putBoxItem("nokind", "x", "bob", "k", b("x"), 0, T).err == boxRefused
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "validBoxId".}
  test "an id can never climb out of the shelf":
    var S = fresh("climb")
    check not S.createBox("chat", "../up", "a").ok
    check not S.createBox("chat", "..", "a").ok
    check not S.createBox("chat", "a/b", "a").ok
    check not S.createBox("chat", ".hidden", "a").ok
    check not S.createBox("chat", "", "a").ok
    S.closeShelf()

  # {.testKind: tkUnit, covers: "setBoxPeople".}
  test "members come and go; only the owner changes them":
    var S = fresh("people")
    check S.createBox("chat", "c", "alice").ok
    check not S.setBoxPeople("chat", "c", "bob", ["bob"], []).ok
    check not S.putBoxItem("chat", "c", "bob", "k", b("x"), 0, T).ok
    check S.setBoxPeople("chat", "c", "alice", ["bob"], []).ok
    check S.putBoxItem("chat", "c", "bob", "k", b("x"), 0, T).ok
    check S.setBoxPeople("chat", "c", "alice", [], []).ok
    check not S.fetchBoxItems("chat", "c", "bob", 0, 9, T).ok
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "mayBox".}
  test "an empty subject may do nothing":
    var S = fresh("empty")
    check not S.createBox("chat", "c", "").ok
    S.closeShelf()

proc reopen(S: BoxShelf): BoxShelf =
  ## S: closed and opened again, as after a restart.
  var
    root = S.root
    R = S.rules
    L = S.limits
    k = S.atRest
  S.closeShelf()
  var got = openShelf(root, R, L, k)
  doAssert got.ok, got.err
  result = got.shelf

proc logOf(S: BoxShelf, kind, id: string): string =
  ## S/kind/id: the path of one log.
  result = S.boxDir(kind, id) / boxLogName

suite "the log":
  # {.testKind: tkIntegration, covers: "openBoxFile".}
  test "everything comes back after a restart, numbers going on":
    var S = fresh("restart")
    check S.createBox("chat", "c", "alice").ok
    check S.setBoxPeople("chat", "c", "alice", ["bob"], []).ok
    check S.putBoxItem("chat", "c", "bob", "a", b("1"), 0, T).ok
    S = S.reopen()
    check S.putBoxItem("chat", "c", "alice", "b", b("2"), 0, T).number == 2'u64
    var f = S.fetchBoxItems("chat", "c", "bob", 0, 10, T)
    check f.items.len == 2 and f.items[0].writer == "bob"
    S.closeShelf()

  # {.testKind: tkRegression, covers: "putBoxItem|openBoxFile", pins: "item and counter saved apart reused a number".}
  test "a crash in the middle of a record reuses no number and loses no reader":
    var S = fresh("torn")
    check S.createBox("chat", "c", "alice").ok
    check S.putBoxItem("chat", "c", "alice", "a", b("one"), 0, T).number == 1'u64
    check S.putBoxItem("chat", "c", "alice", "b", b("two"), 0, T).number == 2'u64
    var
      path = S.logOf("chat", "c")
      root = S.root
      kept = rules()
    S.closeShelf()
    var whole = readFile(path)
    writeFile(path, whole[0 ..< whole.len - 5])
    var got = openShelf(root, kept)
    check got.ok
    S = got.shelf
    var f = S.fetchBoxItems("chat", "c", "alice", 0, 10, T)
    check f.items.len == 1 and f.number == 1'u64
    check S.putBoxItem("chat", "c", "alice", "b", b("again"), 0, T).number == 2'u64
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "openBoxFile|repairBox".}
  test "a changed byte is found; the box refuses, and can be repaired":
    var S = fresh("damage")
    check S.createBox("chat", "c", "alice").ok
    check S.putBoxItem("chat", "c", "alice", "a", b("one"), 0, T).ok
    check S.putBoxItem("chat", "c", "alice", "b", b("two"), 0, T).ok
    var
      path = S.logOf("chat", "c")
      dir = S.boxDir("chat", "c")
      root = S.root
      kept = rules()
    S.closeShelf()
    var whole = readFile(path)
    whole[whole.len - 20] = chr(ord(whole[whole.len - 20]) xor 1)
    writeFile(path, whole)
    gBoxDamage = @[]
    var got = openShelf(root, kept)
    S = got.shelf
    check S.fetchBoxItems("chat", "c", "alice", 0, 10, T).err == boxRefused
    check gBoxDamage.len == 1 and "damaged" in gBoxDamage[0]
    S.closeShelf()
    check repairBox(dir, "chat/c", nil).ok
    got = openShelf(root, kept)
    S = got.shelf
    check S.fetchBoxItems("chat", "c", "alice", 0, 10, T).items.len == 1
    S.closeShelf()

  # {.testKind: tkIntegration, covers: "compactBox".}
  test "a log that is mostly dead is rewritten, and numbers survive it":
    var
      S = fresh("compact")
      big = newSeq[uint8](40000)
      i = 0
    check S.createBox("vault", "alice", "alice").ok
    while i < 6:
      check S.putBoxItem("vault", "alice", "alice", "k", big, uint64(i), T).ok
      i = i + 1
    var size = getFileSize(S.logOf("vault", "alice"))
    check size < 90000
    check S.putBoxItem("vault", "alice", "alice", "n", b("x"), 0, T).number == 7'u64
    S = S.reopen()
    var f = S.fetchBoxItems("vault", "alice", "alice", 0, 10, T)
    check f.items.len == 2 and f.number == 7'u64
    check S.putBoxItem("vault", "alice", "alice", "o", b("y"), 0, T).number == 8'u64
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "openShelf".}
  test "two programs cannot hold one shelf":
    var S = fresh("lease")
    check not openShelf(S.root, rules()).ok
    S.closeShelf()

  # {.testKind: tkUnit, covers: "boxCounter".}
  test "a counter says what is newest without opening anything new":
    var S = fresh("counter")
    check S.boxCounter("chat", "none") == 0'u64
    check S.createBox("chat", "c", "alice").ok
    check S.putBoxItem("chat", "c", "alice", "a", b("1"), 0, T).ok
    check S.boxCounter("chat", "c") == 1'u64
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "boxOf".}
  test "more boxes than may stay open still all work":
    var
      dir = getTempDir() / "geist_box_test" / "lru"
      i = 0
    removeDir(dir)
    var S = openShelf(dir, rules(), maxOpen = 2).shelf
    while i < 6:
      check S.createBox("chat", "c" & $i, "a").ok
      check S.putBoxItem("chat", "c" & $i, "a", "k", b($i), 0, T).ok
      i = i + 1
    check S.open.len <= 2
    check S.fetchBoxItems("chat", "c0", "a", 0, 1, T).items[0].data == b("0")
    S.closeShelf()

suite "large items":
  # {.testKind: tkIntegration, covers: "writeBlob|readWholeItem".}
  test "a large item lies beside the log, and comes back whole":
    var
      S = fresh("blob")
      big = newSeq[uint8](boxInlineMax + 10)
    big[77] = 9'u8
    S.rules[0].maxItemBytes = 1024 * 1024
    check S.createBox("vault", "alice", "alice").ok
    check S.putBoxItem("vault", "alice", "alice", "k", big, 0, T).ok
    check fileExists(S.boxDir("vault", "alice") / boxBlobDir / "1")
    check getFileSize(S.logOf("vault", "alice")) < 1000
    S = S.reopen()
    check S.fetchBoxItems("vault", "alice", "alice", 0, 1, T).items[0].data == big
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "readWholeItem".}
  test "a changed large item is left out, and noted":
    var
      S = fresh("blobbad")
      big = newSeq[uint8](boxInlineMax + 10)
    S.rules[0].maxItemBytes = 1024 * 1024
    check S.createBox("vault", "alice", "alice").ok
    check S.putBoxItem("vault", "alice", "alice", "k", big, 0, T).ok
    var
      path = S.boxDir("vault", "alice") / boxBlobDir / "1"
      whole = readFile(path)
    whole[3] = chr(ord(whole[3]) xor 1)
    writeFile(path, whole)
    gBoxDamage = @[]
    check S.fetchBoxItems("vault", "alice", "alice", 0, 1, T).items.len == 0
    check gBoxDamage.len == 1
    S.closeShelf()

  # {.testKind: tkUnit, covers: "commitBox".}
  test "a replaced large item's old file is removed":
    var
      S = fresh("blobdrop")
      big = newSeq[uint8](boxInlineMax + 10)
    S.rules[0].maxItemBytes = 1024 * 1024
    check S.createBox("vault", "alice", "alice").ok
    check S.putBoxItem("vault", "alice", "alice", "k", big, 0, T).ok
    check S.putBoxItem("vault", "alice", "alice", "k", big, 1, T).ok
    check not fileExists(S.boxDir("vault", "alice") / boxBlobDir / "1")
    check fileExists(S.boxDir("vault", "alice") / boxBlobDir / "2")
    S.closeShelf()

suite "at rest":
  proc key(v: uint8): BoxKey =
    ## v: a test key, 32 bytes of v.
    var A = newSeq[uint8](32)
    for x in A.mitems: x = v
    result = newBoxKey(A)

  # {.testKind: tkIntegration, covers: "sealBody|openBody".}
  test "a key handed over seals bodies; the right key reads them back":
    var S = fresh("rest", key = key(7))
    check S.createBox("vault", "alice", "alice").ok
    check S.putBoxItem("vault", "alice", "alice", "k", b("visible words"), 0, T).ok
    var path = S.logOf("vault", "alice")
    S = S.reopen()
    check "visible words" notin readFile(path)
    check S.fetchBoxItems("vault", "alice", "alice", 0, 1, T).items[0].data == b("visible words")
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "openBody".}
  test "another key opens nothing":
    var
      S = fresh("restbad", key = key(7))
      root = S.root
    check S.createBox("vault", "alice", "alice").ok
    S.closeShelf()
    var got = openShelf(root, rules(), atRest = key(8))
    check got.ok
    S = got.shelf
    check S.fetchBoxItems("vault", "alice", "alice", 0, 1, T).err == boxRefused
    S.closeShelf()

suite "limits":
  # {.testKind: tkEdgeCase, covers: "createBox".}
  test "an owner cannot make more boxes than allowed":
    var S = fresh("nboxes", BoxLimits(maxBoxesPerOwner: 1))
    check S.createBox("chat", "c1", "alice").ok
    check not S.createBox("chat", "c2", "alice").ok
    check S.createBox("chat", "c3", "bob").ok
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "putBoxItem".}
  test "a letter counts against the box's owner, not its writer":
    var S = fresh("nbytes", BoxLimits(maxBytesPerOwner: 400))
    check S.createBox("mail", "alice", "alice").ok
    var r = S.putBoxItem("mail", "alice", "bob", "m", newSeq[uint8](500), 0, T)
    check not r.ok and r.err == "this owner's storage is full"
    check S.usage["alice"].bytes < 400 and not S.usage.hasKey("bob")
    S.closeShelf()

  # {.testKind: tkRegression, covers: "scanUsage".}
  test "what an owner uses is known again after a restart":
    var S = fresh("usage", BoxLimits(maxBoxesPerOwner: 1))
    check S.createBox("chat", "c1", "alice").ok
    S = S.reopen()
    check S.usage["alice"].boxes == 1
    check not S.createBox("chat", "c2", "alice").ok
    S.closeShelf()

suite "many writes":
  # {.testKind: tkUnit, covers: "flushShelf".}
  test "writes share one trip to the disk and all arrive":
    var
      S = fresh("batch")
      i = 0
    check S.createBox("chat", "c", "alice").ok
    while i < 50:
      check S.putBoxItem("chat", "c", "alice", $i, b("x"), 0, T, flush = false).ok
      i = i + 1
    check S.open["chat/c"].dirty
    check S.flushShelf().ok
    check not S.open["chat/c"].dirty
    S = S.reopen()
    check S.fetchBoxItems("chat", "c", "alice", 0, 100, T).items.len == 50
    S.closeShelf()
