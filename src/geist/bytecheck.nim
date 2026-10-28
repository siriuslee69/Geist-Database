## ---------------------------------------------------------------------
## Bytecheck <- is this file's buffer the shape it claims to be?
## ---------------------------------------------------------------------
##
##   bytes from disk --> schemaFrom / checkSchemaBytes --> "" ?
##                                                          |
##                       yes: decodeSchema  <---------------+
##                       no:  refuse, with the complaint
##
## The decoders in `format.nim` trust every length they read, because the
## bytes they are meant for are the bytes their own encoders wrote. A
## damaged file is not that: a flipped bit can claim a four-gigabyte string
## in a ten-byte buffer. Decoding that reads past the end.
##
## So every buffer read from a file is WALKED first, here, with every length
## checked against what is actually there and every enum byte checked
## against its enum. Only a buffer that walks cleanly to its last byte is
## handed to a decoder. Nothing here allocates what a length claims.
##
## The same primitives are exported for `geist_sync` (wire_check.nim), which
## walks the bytes a peer sends with them. The wire layouts themselves live
## there, not here.
##
## Def. 1: a TEXT is `u32 n | n bytes` (see `format.addText`).
## Def. 2: a COUNT is a `u32` saying how many items follow. A count is
## never trusted as a size: the loop stops at the first item that does
## not fit, so a count of four billion costs one failed check.

import runePragmas
import var_invariants
import ./types
import ./format

proc take*(A: openArray[uint8], o: var int, k: int): bool {.role: sanitizer,
    inline, tag: "codecBoundary|read",
    needs: o >= 0,
    gives: not result or o <= A.len.} =
  ## A/o: buffer and cursor; k: bytes to step over.
  ## True and advanced when all k are there; false and unmoved otherwise.
  if k < 0 or o + k > A.len:
    return false
  o = o + k
  result = true

proc takeText*(A: openArray[uint8], o: var int): bool {.role: sanitizer,
    tag: "codecBoundary|read".} =
  ## A/o: step over one text (Def. 1), or return false.
  if o + 4 > A.len:
    return false
  result = take(A, o, 4 + int(A.getU32(o)))

proc takeCount*(A: openArray[uint8], o: var int): tuple[ok: bool, n: int] {.
    role: sanitizer, tag: "codecBoundary|read".} =
  ## A/o: read one count (Def. 2) and step past it.
  if o + 4 > A.len:
    return (false, 0)
  result = (true, int(A.getU32(o)))
  o = o + 4

type
  ItemStep = proc (A: openArray[uint8], o: var int): bool {.nimcall.}
    ## Steps over ONE item of a list and says whether it was all there:
    ## `takeText`, `takePredicate`, `takeRow`.

proc takeEach*(A: openArray[uint8], o: var int, n: int,
    item: ItemStep): bool {.role: sanitizer, tag: "codecBoundary|read".} =
  ## A/o/n: step over n items back to back, or return false.
  ## item: how one item is laid out.
  ##
  ## Stops at the first item that does not fit, so a count of four billion
  ## (Def. 2) costs one failed step, not four billion.
  var
    i: int = 0
  while i < n:
    if not item(A, o):
      return false
    i = i + 1
  result = true

proc enumByteOk*(b: uint8, highest: int): bool {.role: sanitizer, inline,
    tag: "codecBoundary|read".} =
  ## b/highest: does this byte name a value of an enum whose last value
  ## is `highest`?
  result = int(b) <= highest

## ---------------------------- schema --------------------------------

proc takeSlots(A: openArray[uint8], o: var int, n: int): string {.
    role: sanitizer, tag: "codecBoundary|read".} =
  ## A/o/n: step over n slot records, 9 bytes each:
  ##
  ##   | u16 nameId | u8 kind | u8 column | u8 onOverflow | u32 width |
  var
    i: int = 0
  while i < n:
    if o + 9 > A.len:
      return "schema: slot " & $i & " runs past the end"
    if not enumByteOk(A[o + 2], ord(high(SlotKind))):
      return "schema: slot " & $i & " has an unknown kind " & $A[o + 2]
    if not enumByteOk(A[o + 3], ord(high(ColumnKind))):
      return "schema: slot " & $i & " has an unknown column " & $A[o + 3]
    if not enumByteOk(A[o + 4], ord(high(OverflowPolicy))):
      return "schema: slot " & $i & " has an unknown overflow " & $A[o + 4]
    o = o + 9
    i = i + 1
  result = ""

proc checkSchemaBytes*(A: openArray[uint8], o: var int): string {.
    role: sanitizer, tag: "codecBoundary|read".} =
  ## A/o: a schema block starting at o (the layout `encodeSchema` writes);
  ## o ends just past it. Returns the complaint, "" when it is sound.
  ##
  ##   text typeName | count n | n texts (field names) | u8 autoCollapse
  ##   | count m | m slots | count k | k pairs of texts (aliases)
  var
    c: tuple[ok: bool, n: int] = (false, 0)
  if not takeText(A, o):
    return "schema: the type name runs past the end"
  c = takeCount(A, o)
  if not c.ok or not takeEach(A, o, c.n, takeText):
    return "schema: the field names run past the end"
  if not take(A, o, 1):
    return "schema: the autoCollapse byte is missing"
  c = takeCount(A, o)
  if not c.ok:
    return "schema: the slot count is missing"
  result = takeSlots(A, o, c.n)
  if result.len > 0:
    return
  c = takeCount(A, o)
  if not c.ok or not takeEach(A, o, 2 * c.n, takeText):
    return "schema: the aliases run past the end"
  result = ""

## ---------------------------- from a file ---------------------------

proc schemaFrom*(A: openArray[uint8], o: var int, where: string): Schema {.
    role: sanitizer, tag: "codecBoundary|read|storageIo".} =
  ## A/o: a schema block read from a FILE, starting at o; o ends past it.
  ## where: the file, for the message.
  ##
  ## The same walk a peer's bytes get, for the same reason: a damaged file
  ## is as untrusted as a hostile peer. A bad block raises IOError -- which
  ## the reader of a file already has to expect -- rather than reading past
  ## the end of the buffer.
  var
    probe: int = o
    complaint: string = checkSchemaBytes(A, probe)
  if complaint.len > 0:
    raise newException(IOError, where & ": " & complaint)
  result = decodeSchema(A, o)
