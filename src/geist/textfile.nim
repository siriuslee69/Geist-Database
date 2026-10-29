## ---------------------------------------------------------------------
## Textfile <- the small hashed text files Geist keeps beside its data
## ---------------------------------------------------------------------
##
## Folder files (geist.version, geist.permissions) and store parameter files
## (<name>.params) and sidecar locator files (<hash>.locator) share one format:
##
##   key = value          one per line; '#' lines and blank lines are ignored
##   ...
##   digest = <hex>      BLAKE3 of every line above it; it must be the LAST line
##
## A file whose digest does not match was changed or damaged. Readers refuse it.
## Writers render the body first and then append its digest.

import std/[strutils, tables]

import runePragmas
import ./types
import ./crypto/hashing

proc hexText*(A: openArray[uint8]): string {.role: helper, tag: "formatting|read".} =
  ## A: bytes rendered as lowercase hex.
  const digits = "0123456789abcdef"
  var
    i: int = 0
  result = newString(A.len * 2)
  while i < A.len:
    result[i * 2] = digits[int(A[i] shr 4)]
    result[i * 2 + 1] = digits[int(A[i] and 0x0F'u8)]
    i = i + 1

proc digestOf*(body: string): string {.role: helper, tag: "cryptoBoundary|read".} =
  ## body: the text a file carries above its digest line. Its hash, in hex.
  var
    bytes: ByteSeq = cast[ByteSeq](body)
  result = hexText(geistHash(hkBlake3, bytes, 32))

proc renderFile*(pairs: seq[tuple[key, value: string]]): string {.
    role: helper, tag: "formatting|write".} =
  ## pairs: the key/value lines, in order. Returns the file text, digest last.
  var
    body: string = ""
  for p in pairs:
    body.add p.key & " = " & p.value & "\n"
  result = body & "digest = " & digestOf(body) & "\n"

proc parseKeyFile*(text: string): tuple[ok: bool, pairs: Table[string, string],
    err: string] {.role: parser, tag: "formatting|read".} =
  ## text: a folder or params file. The digest must be the last line and must
  ## match the lines above it. Returns the key/value pairs, or why not.
  var
    lines: seq[string] = text.splitLines()
    body: string = ""
    stated: string = ""
    i: int = 0
    eq: int = -1
    key: string = ""
    value: string = ""
  result.pairs = initTable[string, string]()
  while lines.len > 0 and lines[^1].strip().len == 0:
    lines.setLen(lines.len - 1)
  if lines.len == 0:
    result.err = "the file is empty"
    return
  if not lines[^1].startsWith("digest = "):
    result.err = "the file does not end with a digest line"
    return
  stated = lines[^1]["digest = ".len .. ^1].strip()
  while i < lines.len - 1:
    body.add lines[i] & "\n"
    i = i + 1
  if digestOf(body) != stated:
    result.err = "the digest does not match the file: it was changed or damaged"
    return
  for line in lines[0 .. ^2]:
    eq = line.find(" = ")
    if line.strip().len == 0 or line.startsWith("#"):
      continue
    if eq <= 0:
      result.err = "a line is not 'key = value': " & line
      return
    key = line[0 ..< eq].strip()
    value = line[eq + 3 .. ^1].strip().strip(chars = {'"'})
    result.pairs[key] = value
  result.ok = true


proc digitValue(c: char): int {.role: parser, tag: "formatting|read".} =
  ## c: one hex digit. -1 when it is not one.
  case c
  of '0' .. '9': result = ord(c) - ord('0')
  of 'a' .. 'f': result = ord(c) - ord('a') + 10
  of 'A' .. 'F': result = ord(c) - ord('A') + 10
  else: result = -1

proc unhexText*(s: string): ByteSeq {.role: parser, tag: "formatting|read".} =
  ## s: hex text, two digits a byte. Empty when the length is odd or a digit is not
  ## hex, and the caller treats an empty result as a refusal.
  var
    i: int = 0
    hi: int = 0
    lo: int = 0
  if s.len == 0 or s.len mod 2 != 0:
    return @[]
  result = newSeq[uint8](s.len div 2)
  while i < result.len:
    hi = digitValue(s[2 * i])
    lo = digitValue(s[2 * i + 1])
    if hi < 0 or lo < 0:
      return @[]
    result[i] = uint8(hi * 16 + lo)
    i = i + 1
