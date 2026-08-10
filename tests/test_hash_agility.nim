## Algorithm selection: hash family, digest width, and the one combiner
## that is deliberately refused.

import std/[os, unittest]

import ../src/geist
import ../src/geist/crypto/hashing
import ../src/geist/crypto/mac
import ../src/geist/crypto/batch

type
  Note = object
    id*: int
    title*: string

suite "hash agility":

  test "every family produces both documented widths":
    for k in [hkBlake3, hkSha3, hkGimli]:
      check geistHash(k, cast[ByteSeq]("abc"), shortDigestBytes).len == 16
      check geistHash(k, cast[ByteSeq]("abc"), fullDigestBytes).len == 32

  test "families disagree, so a break in one is not a break in another":
    var a = geistHash(hkBlake3, cast[ByteSeq]("abc"), fullDigestBytes)
    var b = geistHash(hkSha3, cast[ByteSeq]("abc"), fullDigestBytes)
    var c = geistHash(hkGimli, cast[ByteSeq]("abc"), fullDigestBytes)
    check a != b
    check b != c
    check a != c

  test "hashing is deterministic across calls":
    check geistHash(hkSha3, cast[ByteSeq]("x"), 32) ==
      geistHash(hkSha3, cast[ByteSeq]("x"), 32)

  test "only the two documented widths validate":
    check validDigestBytes(16)
    check validDigestBytes(32)
    check not validDigestBytes(20)
    check not validDigestBytes(0)
    check not validDigestBytes(64)

  test "a narrowed MAC still verifies at its own width":
    var key = initSecret(newSeq[uint8](32))
    var msg = cast[ByteSeq]("payload")
    var aad = cast[ByteSeq]("position")
    var t16 = authTag(mkCombined, key, msg, aad, shortDigestBytes)
    check t16.len == 16
    check verifyTag(mkCombined, key, msg, aad, t16)
    var t32 = authTag(mkCombined, key, msg, aad, fullDigestBytes)
    check t32.len == 32
    check verifyTag(mkCombined, key, msg, aad, t32)
    # A tag of the wrong width must not verify by prefix.
    check not verifyTag(mkCombined, key, msg, aad, t32[0 ..< 16])

  test "an empty tag is rejected rather than trivially accepted":
    var key = initSecret(newSeq[uint8](32))
    check not verifyTag(mkBlake3, key, cast[ByteSeq]("m"),
      cast[ByteSeq]("a"), @[])

  test "the tree hash travels with the data, not with the caller":
    # A ledger entry records its own tree hash so a database written under
    # one configuration stays verifiable after the configuration changes.
    var e = LedgerEntry(cipher: ckChaCha20, mac: mkBlake3, treeHash: hkSha3,
      keyRef: 5'u64, groupId: 1'u16, batchIndex: 2'u32, epoch: 9'u64,
      root: newSeq[uint8](32))
    var buf = encodeLedgerEntry(e)
    var o = 0
    var back = decodeLedgerEntry(buf, o)
    check back.treeHash == hkSha3
    check back.cipher == ckChaCha20
    check back.keyRef == 5'u64
    check back.epoch == 9'u64

  test "config rejects a width that would weaken a guarantee":
    var c = appConfig()
    c.contentHashBytes = 20'u8
    check not validateGeistConfig(c).ok
    # A 16-byte Merkle digest puts a birthday attack at 2^64, so the tree
    # width is not a free choice even though the content width is.
    c = appConfig()
    c.treeHashBytes = uint8(shortDigestBytes)
    check not validateGeistConfig(c).ok

  test "presets carry the documented algorithm defaults":
    check appConfig().contentHashBytes == uint8(shortDigestBytes)
    check secureAppConfig().contentHashBytes == uint8(fullDigestBytes)
    # A hash-linked record should not depend on one hash family.
    check ledgerConfig().treeHash == hkSha3
    check ledgerConfig().chainHash == hkSha3
    check ledgerConfig().contentHash == hkSha3
    # Gimli is the default: fastest of the three on row-sized messages,
    # which is where a MAC pass is felt on a constrained part.
    check iotConfig().mac == mkGimli
    check appConfig().mac == mkGimli
    # Assurance presets opt into two independent primitives explicitly,
    # accepting the measured 2.15x.
    check secureAppConfig().mac == mkCombined
    check archiveConfig().mac == mkCombined

  test "a database written with SHA3 throughout reopens and reads":
    var root = getTempDir() / "geist_t_sha3"
    removeDir(root)
    var c = ledgerConfig()
    var s = openSession[Note](root, "main", c, "pw-sha3")
    s.put Note(id: 1, title: "chained")
    s.put Note(id: 2, title: "second")
    check s.save().ok
    s.close()
    var re = openSession[Note](root, "main", c, "pw-sha3")
    check re.entryCount() == 2'u32
    check re.get[:Note](1'u32).title == "second"
    re.close()
    removeDir(root)

  test "sidecar verification uses the configured family":
    var root = getTempDir() / "geist_t_sccfg"
    removeDir(root)
    var store = initSidecarStore(root, 8'u32, hkSha3)
    var payload = cast[ByteSeq]("a payload well past the threshold")
    var r = store.putSidecar(payload)
    check r.target == rtSidecar
    check r.hash.len == fullDigestBytes
    var got = store.getSidecar(r)
    check got.ok
    check got.data == payload
    # The path is derived from the hash, so a corrupted digest cannot even
    # locate a file, let alone pass verification.
    var bad = r
    bad.hash[0] = bad.hash[0] xor 0xFF'u8
    check not store.getSidecar(bad).ok
    removeDir(root)
