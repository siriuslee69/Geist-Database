## Sealing bytes and objects in memory, by key and by password.
##
## The promises: what goes in comes out; the wrong key, the wrong context,
## a changed byte and a blob of another kind are all refused -- with one
## answer, never with garbage; the same object sealed twice never looks
## the same; an object of another type is refused by name.

import std/[strutils, tables, unittest]

import runePragmas
import geist

type
  Entry = object
    site: string
    user: string
    secret: string
    tags: seq[string]
    extra: Table[string, string]
    uses: int
    score: float

  Other = object
    site: int

proc sampleEntry(): Entry {.role: configurator.} =
  ## An entry using every kind of field sealObject has to carry.
  result = Entry(site: "mail.example", user: "alice", secret: "pw",
    tags: @["work", "mail"], uses: 7, score: 0.25)
  result.extra["recovery"] = "codes"

proc bytesOf(s: string): seq[uint8] {.role: parser.} =
  ## s: its bytes.
  for c in s:
    result.add uint8(c)

suite "bytes with a key":
  # {.testKind: tkUnit, covers: "sealWithKey, openWithKey".}
  test "what goes in comes out":
    var
      key: Secret = newSealKey()
      sealed: SealedBlob = sealWithKey(key, bytesOf("hello"), bytesOf("ctx"))
      opened: SealedBlob = default(SealedBlob)
    check sealed.ok
    opened = openWithKey(key, sealed.data, bytesOf("ctx"))
    check opened.ok
    check opened.data == bytesOf("hello")

  # {.testKind: tkEdgeCase, covers: "openWithKey".}
  test "wrong key, wrong context and a changed byte are one refusal":
    var
      key: Secret = newSealKey()
      other: Secret = newSealKey()
      sealed: SealedBlob = sealWithKey(key, bytesOf("hello"), bytesOf("a"))
      tampered: seq[uint8] = @[]
    check not openWithKey(other, sealed.data, bytesOf("a")).ok
    check not openWithKey(key, sealed.data, bytesOf("b")).ok
    tampered = sealed.data
    tampered[^1] = tampered[^1] xor 1'u8
    check not openWithKey(key, tampered, bytesOf("a")).ok
    check openWithKey(other, sealed.data, bytesOf("a")).err ==
      openWithKey(key, tampered, bytesOf("a")).err

  # {.testKind: tkProperty, covers: "sealWithKey".}
  test "the same bytes sealed twice never look alike":
    var
      key: Secret = newSealKey()
    check sealWithKey(key, bytesOf("same")).data !=
      sealWithKey(key, bytesOf("same")).data

  # {.testKind: tkEdgeCase, covers: "openWithKey, openWithPassword".}
  test "a blob of the other kind, or too short, is refused by its shape":
    var
      key: Secret = newSealKey()
      byPassword: SealedBlob = sealWithPassword("long enough pw", bytesOf("x"))
    check openWithKey(key, byPassword.data).err.contains("wrong magic")
    check openWithKey(key, @[1'u8, 2]).err.contains("too short")
    check not openWithKey(key, bytesOf("GSK1") & @[200'u8, 1, 2]).ok

  # {.testKind: tkEdgeCase, covers: "sealWithKey".}
  test "a key shorter than 16 bytes is refused":
    var
      weak: Secret = initSecret(@[1'u8, 2, 3])
    check not sealWithKey(weak, bytesOf("x")).ok

suite "objects":
  # {.testKind: tkUnit, covers: "sealObject, openObject".}
  test "every kind of field survives, lists and tables included":
    var
      key: Secret = newSealKey()
      sealed: SealedBlob = sealObject(sampleEntry(), key, "vault/alice")
      opened: tuple[ok: bool, value: Entry, err: string] =
        (false, default(Entry), "")
    check sealed.ok
    opened = openObject[Entry](sealed.data, key, "vault/alice")
    check opened.ok
    check opened.value == sampleEntry()

  # {.testKind: tkEdgeCase, covers: "openObject".}
  test "an object sealed for one record does not open for another":
    var
      key: Secret = newSealKey()
      sealed: SealedBlob = sealObject(sampleEntry(), key, "vault/alice")
    check not openObject[Entry](sealed.data, key, "vault/bob").ok

  # {.testKind: tkEdgeCase, covers: "openObject".}
  test "an object of another type is refused by name":
    var
      key: Secret = newSealKey()
      sealed: SealedBlob = sealObject(sampleEntry(), key)
      wrong: tuple[ok: bool, value: Other, err: string] =
        (false, default(Other), "")
    wrong = openObject[Other](sealed.data, key)
    check not wrong.ok
    check wrong.err.contains("site")

  # {.testKind: tkUnit, covers: "sealObjectWithPassword, openObjectWithPassword".}
  test "by password":
    var
      sealed: SealedBlob = sealObjectWithPassword(sampleEntry(),
        "a long passphrase")
    check sealed.ok
    check openObjectWithPassword[Entry](sealed.data,
      "a long passphrase").value == sampleEntry()
    check not openObjectWithPassword[Entry](sealed.data, "wrong one").ok
