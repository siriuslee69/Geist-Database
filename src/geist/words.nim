## ---------------------------------------------------------------------
## Words <- key bytes written as English words a person can type
## ---------------------------------------------------------------------
##
## A 32-byte key is hard to read aloud and easy to mistype. Written as
## words from a fixed list of 2048, it becomes 24 words that a person can
## copy onto paper and type into another Geist.
##
##   32 bytes = 256 bits  +  8 check bits  =  264 bits  =  24 words of 11 bits
##   16 bytes = 128 bits  +  4 check bits  =  132 bits  =  12 words of 11 bits
##
##   bits:  [ key bits ................................ | check bits ]
##           \_ 11 _/\_ 11 _/ ...                          \_ last word
##           word 1   word 2                               (partly check)
##
## "Check bits" are the first bits of the SHA-256 of the key. A typo in
## one word changes the key, the key no longer matches its check bits,
## and `fromWords` refuses it instead of silently making a wrong key.
##
## The list and the rule are BIP-39 (the standard behind most wallet
## "recovery phrases"), so other tools read the same words the same way.
## The list is `words_en.txt` beside this file, SHA-256
## 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
##
##   toWords([0x00 * 16])   ->  "abandon abandon ... abandon about"
##   fromWords(that)        ->  ok, [0x00 * 16]

import std/[strutils, tables]

import tyr

import runePragmas

const
  wordText = staticRead("words_en.txt")
  wordBits = 11

proc loadWords(): seq[string] {.role: parser, tag: "words".} =
  ## The 2048 words, in list order. Index in this list = 11-bit value.
  result = wordText.strip().splitLines()

const
  wordList*: seq[string] = loadWords()

var
  wordIndex {.threadvar.}: Table[string, int]

proc indexOfWord(w: string): int {.role: parser, tag: "words".} =
  ## w: one lower-case word -> its position in the list, or -1.
  var
    i: int = 0
  if wordIndex.len == 0:
    while i < wordList.len:
      wordIndex[wordList[i]] = i
      i = i + 1
  result = wordIndex.getOrDefault(w, -1)

proc bitAt(A: openArray[uint8], i: int): int {.role: helper, inline,
    tag: "words".} =
  ## A/i: bit i of A, counting from the top bit of the first byte.
  result = int((A[i shr 3] shr (7 - (i and 7))) and 1'u8)

proc toWords*(A: openArray[uint8]): string {.role: helper,
    tag: "formatting|words".} =
  ## A: 16, 20, 24, 28 or 32 key bytes -> words separated by one space.
  var
    bits: seq[uint8] = @A
    digest: Sha256Digest = sha256Hash(A)
    total: int = 0
    i: int = 0
    v: int = 0
  if A.len < 16 or A.len > 32 or A.len mod 4 != 0:
    raise newException(ValueError, "words need 16..32 bytes in steps of 4")
  bits.add digest[0]
  total = A.len * 8 + A.len div 4
  while i < total:
    v = (v shl 1) or bitAt(bits, i)
    i = i + 1
    if i mod wordBits == 0:
      if result.len > 0:
        result.add ' '
      result.add wordList[v]
      v = 0

proc fromWords*(text: string): tuple[ok: bool, bytes: seq[uint8],
    err: string] {.role: parser, tag: "parsing|words".} =
  ## text: words separated by spaces, any case -> the key bytes, or why not.
  var
    W: seq[string] = text.toLowerAscii().splitWhitespace()
    bits: seq[uint8] = @[]
    n: int = 0
    i: int = 0
    j: int = 0
    v: int = 0
    digest: Sha256Digest = default(Sha256Digest)
  if W.len notin [12, 15, 18, 21, 24]:
    return (false, @[], "expected 12, 15, 18, 21 or 24 words, got " & $W.len)
  bits = newSeq[uint8]((W.len * wordBits + 7) div 8)
  while i < W.len:
    v = indexOfWord(W[i])
    if v < 0:
      return (false, @[], "word " & $(i + 1) & " ('" & W[i] &
        "') is not in the list")
    j = 0
    while j < wordBits:
      if ((v shr (wordBits - 1 - j)) and 1) == 1:
        n = i * wordBits + j
        bits[n shr 3] = bits[n shr 3] or (1'u8 shl (7 - (n and 7)))
      j = j + 1
    i = i + 1
  n = W.len * wordBits * 32 div 33 div 8
  result.bytes = bits[0 ..< n]
  digest = sha256Hash(result.bytes)
  i = 0
  while i < n div 4:
    if bitAt(bits, n * 8 + i) != bitAt(digest, i):
      return (false, @[], "the words do not check out: one is mistyped or " &
        "they are in the wrong order")
    i = i + 1
  result.ok = true
