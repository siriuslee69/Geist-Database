## Signed box tests <- every item carries a label signed by a key the box holds.
##
##   the right key, the right data, the right box, the right place in the chain.

import std/[os, unittest]

import runePragmas
import geist/types
import geist/textfile
import geist/boxlog
import geist/box
import tyr/signatures

const
  T = 1000'u64

proc shelf(name: string): BoxShelf {.role: helper.} =
  ## name: an empty shelf with one signed kind.
  var
    dir = getTempDir() / "geist_box_signed" / name
    r = defaultBoxRule("archive")
  r.signed = true
  removeDir(dir)
  result = openShelf(dir, [r]).shelf

proc trustFor(kp: SigKeypair): TrustTable {.role: helper.} =
  ## kp: the one key the box believes.
  result = TrustTable(keys: @[TrustedKey(signer: "alice", algorithm: "dilithium65",
    publicKey: kp.public)])

proc labelOf(data: seq[uint8], kp: SigKeypair, prev: string, id: string = "alice",
    signer: string = "alice"): string {.role: helper.} =
  ## data/kp/prev/id/signer: a label the way the owner's program makes one.
  var
    f = boxEntryFields("archive", id, signer, data, prev, 5)
    sig = sign(dilithium65, textBytes(noteSignedText(f)), kp.secret)
  result = renderNote(f, "dilithium65:" & hexText(sig))

suite "signed boxes":
  setup:
    var
      kp = keypair(dilithium65)
      other = keypair(dilithium65)
      data = textBytes("sealed bytes")

  # {.testKind: tkIntegration, covers: "putBoxItem|labelError".}
  test "a good label is taken, and the chain moves on":
    var S = shelf("good")
    check S.createBox("archive", "alice", "alice", trustFor(kp)).ok
    var r = S.putBoxItem("archive", "alice", "alice", "a", data, 0, T,
      labelOf(data, kp, boxZeroHead))
    check r.ok and r.chainHead != boxZeroHead
    check S.putBoxItem("archive", "alice", "alice", "b", data, 0, T,
      labelOf(data, kp, r.chainHead)).ok
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "labelError".}
  test "an old head is refused, and the answer names the new one":
    var S = shelf("stale")
    check S.createBox("archive", "alice", "alice", trustFor(kp)).ok
    var r = S.putBoxItem("archive", "alice", "alice", "a", data, 0, T,
      labelOf(data, kp, boxZeroHead))
    var again = S.putBoxItem("archive", "alice", "alice", "b", data, 0, T,
      labelOf(data, kp, boxZeroHead))
    check not again.ok and again.err == "stale head: the newest is " & r.chainHead
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "labelError".}
  test "another key, other data, another box or no label is refused":
    var S = shelf("bad")
    check S.createBox("archive", "alice", "alice", trustFor(kp)).ok
    check not S.putBoxItem("archive", "alice", "alice", "a", data, 0, T,
      labelOf(data, other, boxZeroHead)).ok
    check not S.putBoxItem("archive", "alice", "alice", "a", textBytes("other"), 0, T,
      labelOf(data, kp, boxZeroHead)).ok
    check not S.putBoxItem("archive", "alice", "alice", "a", data, 0, T,
      labelOf(data, kp, boxZeroHead, "bob")).ok
    check not S.putBoxItem("archive", "alice", "alice", "a", data, 0, T, "").ok
    check S.fetchBoxItems("archive", "alice", "alice", 0, 9, T).items.len == 0
    S.closeShelf()

  # {.testKind: tkRegression, covers: "applyFrame".}
  test "the keys and the chain come back after a restart":
    var
      S = shelf("back")
      root = S.root
      R = S.rules
    check S.createBox("archive", "alice", "alice", trustFor(kp)).ok
    var r = S.putBoxItem("archive", "alice", "alice", "a", data, 0, T,
      labelOf(data, kp, boxZeroHead))
    S.closeShelf()
    S = openShelf(root, R).shelf
    check S.putBoxItem("archive", "alice", "alice", "b", data, 0, T,
      labelOf(data, kp, r.chainHead)).ok
    var f = S.fetchBoxItems("archive", "alice", "alice", 0, 9, T)
    check f.items.len == 2 and f.items[0].label.len > 0
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "createBox".}
  test "a signed box needs a key from the start":
    var S = shelf("nokey")
    check not S.createBox("archive", "alice", "alice").ok
    S.closeShelf()

  # {.testKind: tkEdgeCase, covers: "boxRuleError".}
  test "only an append box can be a chain":
    var r = defaultBoxRule("x")
    r.signed = true
    r.mode = bmQueue
    check boxRuleError(r).len > 0
