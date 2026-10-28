## The key folder's symmetric keys, and the words that rebuild them.
##
## What matters most: words rebuild EXACTLY the same key, and a typo is
## refused rather than turned into a different key. Pairs and peer pins
## are tested in Nebel-DecentralizedDB (test_identity_folder.nim).

import runePragmas
import std/[os, unittest]

import geist/keyfolder
import geist/words

proc scratch(name: string): string {.role: helper.} =
  ## name: an empty folder below the temp dir.
  result = getTempDir() / "geist_keyfolder_test" / name
  removeDir(result)

suite "words":
  # {.testKind: tkUnit.}
  test "BIP-39 vectors: all zero and all one bytes":
    var
      z: seq[uint8] = newSeq[uint8](16)
      f: seq[uint8] = newSeq[uint8](32)
      i: int = 0
    while i < f.len:
      f[i] = 0xff
      i = i + 1
    check toWords(z) == "abandon abandon abandon abandon abandon abandon " &
      "abandon abandon abandon abandon abandon about"
    check toWords(f) == "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo " &
      "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
    check fromWords(toWords(f)).bytes == f

  # {.testKind: tkEdgeCase.}
  test "a wrong word, a wrong count and an unknown word are refused":
    check not fromWords("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo").ok
    check not fromWords("abandon about").ok
    check not fromWords("abandon abandon abandon abandon abandon abandon " &
      "abandon abandon abandon abandon abandon geist").ok

suite "key folder":
  # {.testKind: tkIntegration.}
  test "a symmetric key travels as words":
    var
      a: KeyFolder = openKeyFolder(scratch("a"), "pw-a")
      b: KeyFolder = openKeyFolder(scratch("b"), "pw-b")
      e: KeyEntry = KeyEntry()
    check a.newSymmetric("backup").ok
    check a.listKeys().len == 1
    e = a.findKey("backup").entry
    check e.kind == kkSymmetric
    check b.importWords("backup", kkSymmetric, a.secretWords(e).words).ok
    check b.secretWords(e).words == a.secretWords(e).words

  # {.testKind: tkEdgeCase.}
  test "a pair is refused here: nebel imports pairs":
    var
      a: KeyFolder = openKeyFolder(scratch("p"), "pw")
    check not a.importWords("server", kkPair, "x").ok

  # {.testKind: tkEdgeCase.}
  test "a wrong password cannot read the secret words":
    var
      a: KeyFolder = openKeyFolder(scratch("e"), "right")
      w: KeyFolder = openKeyFolder(scratch("e"), "wrong")
    check a.newSymmetric("k").ok
    check not w.secretWords(w.findKey("k").entry).ok
