## ---------------------------------------------------------------------
## Masks <- the ONLY thing Geist defines about the AME/DAC transport
## ---------------------------------------------------------------------
##
## Bifrost owns the transport completely: framing, packaging, replay
## defence, the KEM handshake, identity certificates, session state and
## tier transitions. Geist contributes exactly two things:
##
##   1. the SUITE LAYOUT  -- which algorithms occupy which slots
##   2. the TIER MASKS    -- which slots are active at each tier
##
## Everything else is a Bifrost call. Nothing in this file re-implements
## a primitive; it selects them.
##
##   tier 0  telemetry   1 KEM, 1 signature      one DAC frame
##   tier 1  userdata    1 KEM, 2 signatures      one DAC frame
##   tier 2  standard    2 KEMs, 2 signatures     one DAC frame, default
##   tier 3  secret      3 KEMs, 3 signatures     one DAC frame
##   tier 4  archive     5 KEMs, 3 signatures     needs package transfer
##   tier 5  recovery    6 KEMs, 3 signatures     needs package transfer
##
## Masks are MSB-first over the declared slot order, which is why the slot
## lists below are ordered strongest-first: bit 7 is slot 0.
##
## Tier 5 deliberately stops short of Frodo1344Aes. The pinned Bifrost/Tyr
## Frodo backend derives mismatched sender and receiver secrets, so Geist
## fails closed rather than silently substituting an algorithm.

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas

type
  GeistTier* {.role: configurator, tag: "ame|config|cryptoBoundary|networkSurface|types".} = enum
    gtTelemetry = 0'u8,
    gtUserData,
    gtStandard,
    gtSecret,
    gtArchive,
    gtRecovery

  TriggerKind* {.role: configurator, tag: "ame|config|networkSurface|types".} = enum
    ## When a session should climb to the next tier.
    tkManual,        ## only an explicit control call moves the tier
    tkTransferred,   ## after N mebibytes of committed application plaintext
    tkElapsed,       ## after N milliseconds of session lifetime
    tkDisabled       ## this tier is never entered automatically

  TierTrigger* {.role: configurator, tag: "ame|config|networkSurface|types".} = object
    kind*: TriggerKind
    threshold*: uint64

  TriggerPolicy* {.role: configurator, tag: "ame|config|networkSurface|types".} = object
    ## One trigger row per tier. The starting tier retires its own row and
    ## every row below it, so a session never "escalates" downwards.
    startTier*: GeistTier
    rows*: array[GeistTier, TierTrigger]

proc geistKemSlots*(): bfx.AmeKemAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## Masks are MSB-first, so bit 7 selects slot 0.
  ##
  ## Slots 0..3 are FRAME-SIZED: Kyber1024 (1568 B), NTRU-HPS4096821
  ## (1230 B), FireSaber (1312 B) and Saber (992 B) public keys all fit a
  ## client hello inside one 65507-byte DAC frame. Slots 4..7 are the
  ## code-based KEMs, whose public keys run to roughly 1.3 MB and therefore
  ## require DAC package transfer rather than a single frame.
  ##
  ## That split is why McEliece appears only from gtArchive upward: putting
  ## it at slot 0 would force every handshake at every tier through package
  ## transfer, including a telemetry sensor's.
  ##
  ## Families are deliberately mixed -- lattice (Kyber), NTRU and
  ## code-based (McEliece) are structurally distinct, so a break in one
  ## does not collapse a whole tier.
  result = bfx.initAmeKemAlgorithms([
    bfx.akaKyber1024,
    bfx.akaNtruHps4096821,
    bfx.akaFireSaber,
    bfx.akaSaber,
    bfx.akaMcEliece8192,
    bfx.akaMcEliece6960,
    bfx.akaKyber768,
    bfx.akaNtruHps2048677])

proc geistSignatureSlots*(): bfx.AmeSignatureAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## Ordered strongest-first. Ed25519 sits last so it is present at every
  ## tier as a fast classical check alongside the post-quantum stacks;
  ## SPHINCS+ is hash-based and survives a lattice break outright.
  result = bfx.initAmeSignatureAlgorithms([
    bfx.asaSphincsShake128f,
    bfx.asaDilithium87,
    bfx.asaFalcon1024,
    bfx.asaEd25519])

proc geistCipherSlots*(): bfx.AmeCipherAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## Matches the at-rest cascade: XChaCha20 and AES-CTR are both seekable.
  result = bfx.initAmeCipherAlgorithms([bfx.acaXChaCha20, bfx.acaAesCtr])

proc geistMacSlots*(): bfx.AmeMacAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## BLAKE3 and Gimli, the same pair combined at rest.
  result = bfx.initAmeMacAlgorithms([bfx.amaBlake3, bfx.amaGimli])

proc geistHashSlots*(): bfx.AmeHashAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## Distinct constructions: BLAKE3 is a tree, SHA3 a sponge.
  result = bfx.initAmeHashAlgorithms([bfx.ahaBlake3, bfx.ahaSha3])

proc geistKdfSlots*(): bfx.AmeKdfAlgorithms {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## BLAKE3 for speed, Gimli XOF as an independent fallback.
  result = bfx.initAmeKdfAlgorithms([bfx.akfaBlake3, bfx.akfaGimliXof])

proc geistLayout*(): bfx.AmeSuiteLayout {.role: configurator,
    tag: "ame|cryptoBoundary|networkSurface".} =
  ## The complete Geist suite layout. `defaultAmeLayout` is deliberately
  ## NOT used: it fixes the signature slots to Ed25519 + Falcon512, and the
  ## signature stack is one of the things Geist wants to choose per tier.
  result = bfx.initAmeSuiteLayout(geistKemSlots(), geistCipherSlots(),
    geistMacSlots(), geistHashSlots(), geistSignatureSlots(), geistKdfSlots())

proc tierMasks*(t: GeistTier): bfx.AmeTierMasks {.role: configurator,
    tag: "ame|config|cryptoBoundary|networkSurface".} =
  ## t: tier whose slot selection is returned, MSB-first over the layout.
  ## KEM bits widen fastest because a KEM break is the one failure that
  ## retroactively exposes recorded traffic.
  case t
  of gtTelemetry:
    result = bfx.initAmeTierMasks(0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8,
      0x10'u8, 0x80'u8)
  of gtUserData:
    result = bfx.initAmeTierMasks(0x80'u8, 0x80'u8, 0x80'u8, 0x80'u8,
      0x90'u8, 0x80'u8)
  of gtStandard:
    result = bfx.initAmeTierMasks(0xC0'u8, 0xC0'u8, 0xC0'u8, 0xC0'u8,
      0x90'u8, 0xC0'u8)
  of gtSecret:
    result = bfx.initAmeTierMasks(0xE0'u8, 0xC0'u8, 0xC0'u8, 0xC0'u8,
      0xB0'u8, 0xC0'u8)
  of gtArchive:
    result = bfx.initAmeTierMasks(0xF8'u8, 0xC0'u8, 0xC0'u8, 0xC0'u8,
      0xF0'u8, 0xC0'u8)
  of gtRecovery:
    result = bfx.initAmeTierMasks(0xFC'u8, 0xC0'u8, 0xC0'u8, 0xC0'u8,
      0xF0'u8, 0xC0'u8)

proc tierOf*(L: bfx.AmeSuiteLayout, t: GeistTier): bfx.AmeMaskTier {.
    role: configurator, tag: "ame|cryptoBoundary|networkSurface".} =
  ## L: the Geist suite layout.
  ## t: tier resolved to a validated Bifrost mask tier.
  result = bfx.initAmeMaskTier(L, uint32(ord(t)) + 1'u32, tierMasks(t))

proc defaultTriggerPolicy*(): TriggerPolicy {.role: configurator,
    tag: "ame|config|networkSurface".} =
  ## Standard start, climbing on transferred volume. Thresholds are in
  ## mebibytes for tkTransferred and milliseconds for tkElapsed.
  result.startTier = gtStandard
  result.rows[gtTelemetry] = TierTrigger(kind: tkDisabled, threshold: 0'u64)
  result.rows[gtUserData] = TierTrigger(kind: tkDisabled, threshold: 0'u64)
  result.rows[gtStandard] = TierTrigger(kind: tkManual, threshold: 0'u64)
  result.rows[gtSecret] = TierTrigger(kind: tkTransferred, threshold: 64'u64)
  result.rows[gtArchive] = TierTrigger(kind: tkTransferred, threshold: 1024'u64)
  result.rows[gtRecovery] = TierTrigger(kind: tkManual, threshold: 0'u64)

proc validateTriggerPolicy*(p: TriggerPolicy): tuple[ok: bool, err: string] {.
    role: sanitizer, tag: "ame|config|networkSurface|read".} =
  ## p: policy checked for monotonic thresholds and a usable start tier.
  var
    t: GeistTier = gtTelemetry
    last: uint64 = 0'u64
  while true:
    if t > p.startTier and p.rows[t].kind == tkTransferred and
        p.rows[t].threshold <= last:
      return (false, "trigger thresholds must increase with tier: " & $t)
    if t > p.startTier and p.rows[t].kind == tkTransferred:
      last = p.rows[t].threshold
    if p.rows[t].kind in {tkTransferred, tkElapsed} and
        p.rows[t].threshold == 0'u64:
      return (false, $t & " uses an automatic trigger with a zero threshold")
    if t == gtRecovery:
      break
    t = succ(t)
  result = (true, "")

proc supportedTierPath*(p: TriggerPolicy): bfx.AmeTierPath {.
    role: configurator, tag: "ame|cryptoBoundary|networkSurface".} =
  ## p: policy whose reachable tiers become the advertised path. Tiers at
  ## or below the start tier are retired, so a peer cannot negotiate the
  ## session down to a weaker suite than the operator configured.
  var
    L: bfx.AmeSuiteLayout = default(bfx.AmeSuiteLayout)
    tiers: seq[bfx.AmeMaskTier] = @[]
    t: GeistTier = p.startTier
  L = geistLayout()
  while true:
    if p.rows[t].kind != tkDisabled or t == p.startTier:
      tiers.add tierOf(L, t)
    if t == gtRecovery:
      break
    t = succ(t)
  result = bfx.initAmeTierPath(L, tiers)
