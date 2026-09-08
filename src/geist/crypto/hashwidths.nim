## ---------------------------------------------------------------------
## Hash widths <- the leaf module: algorithm names and digest sizes
## ---------------------------------------------------------------------
##
## Deliberately import-free. `types` needs the widths to size a `Ref`, and
## `hashing` needs `types` for `Secret` -- so the constants live here,
## below both, and neither module has to know about the other.
##
## `crypto/hashing` re-exports everything here, so ordinary callers import
## that one and never name this module.

import geistPragmas

const
  fullDigestBytes* = 32
    ## Width required wherever collisions matter: content addressing in the
    ## own-file tier, Merkle leaves and nodes, journal chain links, and the
    ## index change detector.
  shortDigestBytes* = 16
    ## Verification-only width. Sound where the address is explicit (the
    ## packed tier), because only second-preimage resistance is needed and
    ## 16 bytes puts that at 2^128 rather than 2^64.

type
  HashKind* {.role: truthState, metaTags: {tagAppApi, tagCryptoBoundary,
      tagTypes}.} = enum
    ## Structurally independent families, so a break in one construction
    ## does not imply a break in another: BLAKE3 is a tree, SHA3 a sponge,
    ## Gimli a lightweight permutation sponge.
    ##
    ## There is deliberately no XOR-combined member. `MacKind` has one
    ## because XOR is a sound PRF combiner and unforgeability is a PRF
    ## property. Collision resistance does not combine that way -- there is
    ## no collision-resistance combiner shorter than concatenation -- so an
    ## XOR of two hashes carries no collision proof and must never address
    ## content, build a Merkle leaf, or link a journal row.
    hkBlake3, hkSha3, hkGimli

proc hashName*(k: HashKind): string {.role: helper,
    metaTags: {tagCryptoBoundary, tagFormatting}.} =
  ## k: hash family rendered for config output and error messages.
  case k
  of hkBlake3: result = "blake3"
  of hkSha3: result = "sha3"
  of hkGimli: result = "gimli"

proc parseHashKind*(s: string): tuple[ok: bool, kind: HashKind,
    err: string] {.role: parser,
    metaTags: {tagConfig, tagCryptoBoundary, tagParsing}.} =
  ## s: algorithm name from a config file or command line.
  case s
  of "blake3", "b3": result = (true, hkBlake3, "")
  of "sha3": result = (true, hkSha3, "")
  of "gimli": result = (true, hkGimli, "")
  else:
    result = (false, hkBlake3,
      "unknown hash '" & s & "'; expected blake3, sha3 or gimli")

proc validDigestBytes*(n: int): bool {.role: sanitizer, inline,
    metaTags: {tagConfig, tagCryptoBoundary, tagRead}.} =
  ## n: candidate digest width. Only the two documented widths are legal;
  ## an arbitrary truncation would silently weaken a guarantee nobody
  ## re-derived at the call site.
  result = n == shortDigestBytes or n == fullDigestBytes

proc constantTimeEq*(a, b: openArray[uint8]): bool {.role: sanitizer,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## a/b: byte strings compared without an early exit, so a caller cannot
  ## time its way to a matching prefix.
  var
    diff: uint8 = 0'u8
    i: int = 0
  if a.len != b.len:
    return false
  while i < a.len:
    diff = diff or (a[i] xor b[i])
    i = i + 1
  result = diff == 0'u8
