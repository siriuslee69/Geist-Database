## Masks and the Query/Reply wire codec.
import std/[bitops, strutils, unittest]
import geist/network
import bifrost_exchange_protocols as bfx except ByteSeq

suite "masks":
  # {.testKind: tkUnit.}
  test "every tier validates against Bifrost's own tier checker":
    var L = geistLayout()
    for t in GeistTier:
      check tierOf(L, t).tierId == uint32(ord(t)) + 1'u32

  # {.testKind: tkUnit.}
  test "the layout declares all six slot families":
    var L = geistLayout()
    check L.kems.length == 8'u8
    check L.signatures.length == 4'u8
    check L.ciphers.length == 2'u8
    check L.macs.length == 2'u8
    check L.hashes.length == 2'u8
    check L.kdfs.length == 2'u8

  # {.testKind: tkUnit.}
  test "KEM breadth grows monotonically with tier":
    var
      prev = 0
      bits = 0
      m: bfx.AmeTierMasks = default(bfx.AmeTierMasks)
    for t in GeistTier:
      m = tierMasks(t)
      bits = countSetBits(m.kem)
      check bits >= prev
      prev = bits

  # {.testKind: tkUnit.}
  test "tiers 0..3 use only the small KEM slots":
    # Slots 4..7 hold the large keys (FrodoKEM-1344, HQC-5); the lower tiers
    # must stay inside one 65507 B frame.
    for t in [gtTelemetry, gtUserData, gtStandard, gtSecret]:
      check (tierMasks(t).kem and 0x0F'u8) == 0'u8

  # {.testKind: tkRegression, covers: "geistKemSlots", pins: "Frodo slot once derived mismatched secrets".}
  test "every declared KEM slot agrees on a secret through Bifrost":
    ## Keypair, seal and open each slot exactly as a handshake would. An
    ## older pinned stack gave the two sides different Frodo secrets.
    var
      S = geistKemSlots()
      a: bfx.AmeKemAlgorithm = bfx.akaX25519
      kp: bfx.AmeKemKeypair = default(bfx.AmeKemKeypair)
      c: bfx.AmeKemCipher = default(bfx.AmeKemCipher)
      i: int = 0
    while i < int(S.length):
      a = S[i]
      kp = bfx.ameKemKeypair(a)
      c = bfx.sealAmeKem(a, kp.publicKey)
      check bfx.openAmeKem(a, c, kp.secretKey) == c.sharedSecret
      i = i + 1

  # {.testKind: tkUnit.}
  test "no declared KEM slot is Classic McEliece":
    ## Replaced 2026-10-16 after the Goppa-code key-recovery papers.
    var
      S = geistKemSlots()
      i: int = 0
    while i < int(S.length):
      check bfx.ameKemName(S[i]).find("McEliece") < 0
      i = i + 1

  # {.testKind: tkUnit.}
  test "every tier signs with at least one algorithm":
    for t in GeistTier:
      check tierMasks(t).signature != 0'u8

  # {.testKind: tkUnit.}
  test "the default trigger policy validates":
    check defaultTriggerPolicy().validateTriggerPolicy().ok

  # {.testKind: tkEdgeCase.}
  test "a zero-threshold automatic trigger is rejected":
    var p = defaultTriggerPolicy()
    p.rows[gtSecret] = TierTrigger(kind: tkTransferred, threshold: 0'u64)
    check not p.validateTriggerPolicy().ok

  # {.testKind: tkEdgeCase.}
  test "non-monotonic thresholds are rejected":
    var p = defaultTriggerPolicy()
    p.rows[gtArchive] = TierTrigger(kind: tkTransferred, threshold: 1'u64)
    check not p.validateTriggerPolicy().ok

suite "transport codec":
  # {.testKind: tkUnit.}
  test "a Query round-trips, including predicates and payload":
    var q = Query(op: qoFind, collection: "notes",
      where: @[Predicate(field: "title", text: "x", isText: true),
               Predicate(field: "score", num: -12, isText: false)],
      limit: 25, cursor: 7, subscriptionId: "s", payload: @[9'u8, 8])
    check decodeQuery(encodeQuery(q)) == q

  # {.testKind: tkUnit.}
  test "a Reply round-trips rows and schema":
    var r = Reply(ok: true, matched: 2, cursor: 4,
      schema: schemaFor[Predicate](),
      rows: @[Row(schemaId: 1, data: @[1'u8, 2]),
              Row(schemaId: 1, data: @[3'u8, 4])])
    var back = decodeReply(encodeReply(r))
    check back.ok and back.matched == 2'u32 and back.rows.len == 2
    check back.schema.slots.len == r.schema.slots.len

  # {.testKind: tkEdgeCase.}
  test "subscribe and poll are ordinary ops, not a second protocol":
    check decodeQuery(encodeQuery(Query(op: qoSubscribe,
      subscriptionId: "a"))).op == qoSubscribe
    check decodeQuery(encodeQuery(Query(op: qoPoll,
      subscriptionId: "a"))).op == qoPoll
