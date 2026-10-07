## The key folder and its words: pairs, symmetric keys, peers.
##
## What matters most: words rebuild EXACTLY the same key, a typo is
## refused rather than turned into a different key, and a pin whose
## fingerprint does not match the words read out is never trusted.

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
  test "a pair and a symmetric key travel as words":
    var
      a: KeyFolder = openKeyFolder(scratch("a"), "pw-a")
      b: KeyFolder = openKeyFolder(scratch("b"), "pw-b")
      e: KeyEntry = KeyEntry()
    check a.newPair("server").ok
    check a.newSymmetric("backup").ok
    check a.listKeys().len == 2
    e = a.findKey("1").entry
    check e.kind == kkPair
    check b.importWords("server", kkPair, a.secretWords(e).words).ok
    check readFile(a.pairPinPath("server")) == readFile(b.pairPinPath("server"))
    e = a.findKey("backup").entry
    check b.importWords("backup", kkSymmetric, a.secretWords(e).words).ok
    check b.secretWords(e).words == a.secretWords(e).words

  # {.testKind: tkEdgeCase.}
  test "trust checks the fingerprint words":
    var
      a: KeyFolder = openKeyFolder(scratch("c"), "pw")
      b: KeyFolder = openKeyFolder(scratch("d"), "pw")
      fp: string = ""
    check a.newPair("server").ok
    fp = a.publicWords(a.findKey("server").entry).words
    check not b.trustPin("bad", a.pairPinPath("server"),
      toWords(newSeq[uint8](16))).ok
    check b.trustPin("server", a.pairPinPath("server"), fp).ok
    check b.findKey("server").entry.kind == kkPeer

  # {.testKind: tkEdgeCase.}
  test "a wrong password cannot read the secret words":
    var
      a: KeyFolder = openKeyFolder(scratch("e"), "right")
      w: KeyFolder = openKeyFolder(scratch("e"), "wrong")
    check a.newSymmetric("k").ok
    check not w.secretWords(w.findKey("k").entry).ok
