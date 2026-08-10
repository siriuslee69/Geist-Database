## ---------------------------------------------------------------------
## Secret <- move-only, self-zeroing key material
## ---------------------------------------------------------------------
##
##   initSecret -> use / derive -> (scope ends) -> volatile clear
##                      `-> clone() is the ONLY way to duplicate
##
## `data` is not exported, `=copy` is a compile error, and `$` never
## reveals bytes. Duplicating key material therefore requires an explicit
## `clone()` at a reviewable call site.
##
## Zeroization uses volatile stores, per the Tyr convention: plain
## `zeroMem` on a dying buffer is a dead store the optimiser may remove.

import std/volatile

import ../analysis_pragmas

type
  Secret* {.role: truthState, metaTags: {tagCryptoBoundary, tagTypes}.} = object
    data: seq[uint8]

proc volatileClear*(A: var openArray[uint8]) {.role: helper,
    metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## A: buffer overwritten with zeroes through volatile stores.
  var
    i: int = 0
    p: ptr UncheckedArray[uint8] = nil
  if A.len == 0:
    return
  p = cast[ptr UncheckedArray[uint8]](addr A[0])
  while i < A.len:
    volatileStore(addr p[i], 0'u8)
    i = i + 1

proc `=destroy`*(s: Secret) =
  ## s: expiring secret whose bytes are cleared before the memory is freed.
  if s.data.len > 0:
    volatileClear(cast[ptr UncheckedArray[uint8]](
      unsafeAddr s.data[0]).toOpenArray(0, s.data.len - 1))

proc `=copy`*(dst: var Secret, src: Secret) {.error:
  "Secret is move-only: call clone() so every duplication is explicit".}

proc initSecret*(A: openArray[uint8]): Secret {.role: helper,
    metaTags: {tagCryptoBoundary}.} =
  ## A: raw key bytes taken into owned, self-clearing storage.
  result.data = @A

proc len*(s: Secret): int {.role: parser, inline,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s: secret whose byte length is returned.
  result = s.data.len

proc use*(s: Secret): lent seq[uint8] {.role: parser, inline,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s: secret borrowed for one cryptographic call. Does not copy.
  result = s.data

proc clone*(s: Secret): Secret {.role: helper,
    metaTags: {tagCryptoBoundary}.} =
  ## s: secret being deliberately duplicated. The only legal copy path.
  result.data = s.data

proc `$`*(s: Secret): string {.role: helper,
    metaTags: {tagCryptoBoundary, tagFormatting}.} =
  ## s: secret rendered for logs without revealing any byte.
  result = "Secret(" & $s.data.len & "B)"
