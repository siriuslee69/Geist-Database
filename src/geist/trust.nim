## ---------------------------------------------------------------------
## Trust <- which signatures Geist believes, and the signed notes it reads
## ---------------------------------------------------------------------
##
## A trusted keys file says which public keys belong to which signer:
##
##   # signer      algorithm     public key (hex)
##   phone         dilithium87   9f3a...
##   phone         ed25519       7c10...
##
## Default place: <config>/geist/trusted.keys. `[default] trustedKeys` moves it.
## A missing file trusts nobody.
##
## A NOTE is a small text file that a program leaves beside a payload (sidecar.nim,
## leaveNote). It is a list of fields, and an optional signature:
##
##   geist-note = 1
##   hash = ab12...            the payload it stands for
##   signer = phone            who signed the note
##   ...                       any other fields the program wants
##   sig = dilithium87:3c..,ed25519:9e..
##   digest = ...              BLAKE3 of the lines above it
##
## The signature covers the note's SIGNED TEXT: every field except `sig`, sorted by
## name and rendered as above. Geist does not read the fields' meaning; it only
## checks the hash, the signer and the signature.
##
##   Def. 1 (trusted)  every trusted key of the note's signer has a part in `sig`,
##                     and every part verifies over the signed text.
##   Def. 2 (unsigned) the note has no signature, or its signer is named by no
##                     trusted key.
##   Def. 3 (bad)      a part that does not verify, a part for an algorithm the
##                     signer has no trusted key for, or a trusted signer with a
##                     part missing. A bad note is refused whatever the policy says.
##   Def. 4 (none)     no note at all: the payload is asked for by hash alone.

import std/[algorithm, os, strutils, tables]

import runePragmas
import ./types
import ./textfile
import tyr/signatures

const
  sigAlgorithmNames*: array[7, string] = ["ed25519", "dilithium44",
    "dilithium65", "dilithium87", "falcon512", "falcon1024", "sphincsshake128f"]
    ## The names a trusted key file and a note's `sig` use. nebel maps its own
    ## algorithm names onto these.
  noteMarker*: string = "geist-note"
  trustFileName*: string = "trusted.keys"

type
  NoteTrust* {.role: truthState, tag: "cryptoBoundary|types".} = enum
    ## How much a note's signature is worth (Def. 1 to Def. 4).
    ntNone, ntUnsigned, ntSigned, ntBad

  TrustedKey* {.role: truthState, tag: "cryptoBoundary|types".} = object
    signer*: string
    algorithm*: string
    publicKey*: ByteSeq

  TrustTable* {.role: truthState, tag: "cryptoBoundary|types".} = object
    keys*: seq[TrustedKey]

  SidecarNote* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## hash: the payload the note stands for. sig: the signature field, "" if none.
    ## fields: every field except `sig`, sorted by name. Includes geist-note, hash
    ##   and signer, so the signed text is rebuilt from them alone.
    hash*: ByteSeq
    sig*: string
    fields*: seq[tuple[key, value: string]]

## ╭⟢ trusted keys

proc defaultTrustPath*(): string {.role: helper, tag: "config|storageIo".} =
  ## The trusted keys file a program uses when none is named.
  result = getConfigDir() / "geist" / trustFileName

proc knownAlgorithm*(name: string): bool {.role: parser, tag: "cryptoBoundary".} =
  ## name: a signature algorithm this build can verify.
  result = name in sigAlgorithmNames

proc parseTrustFile*(text: string): tuple[ok: bool, table: TrustTable,
    err: string] {.role: parser, tag: "cryptoBoundary|read".} =
  ## text: a trusted keys file. Refused on the first line that is not understood, so a
  ## typo can never quietly trust less (or more) than was meant.
  var
    fields: seq[string] = @[]
    key: ByteSeq = @[]
    n: int = 0
  for raw in text.splitLines():
    n = n + 1
    if raw.strip().len == 0 or raw.strip().startsWith("#"):
      continue
    fields = raw.splitWhitespace()
    if fields.len != 3:
      result.err = "trusted keys, line " & $n & ": write signer, algorithm and key"
      return
    if not knownAlgorithm(fields[1]):
      result.err = "trusted keys, line " & $n & ": unknown algorithm '" &
        fields[1] & "'"
      return
    key = unhexText(fields[2])
    if key.len == 0:
      result.err = "trusted keys, line " & $n & ": the key is not hex"
      return
    result.table.keys.add TrustedKey(signer: fields[0], algorithm: fields[1],
      publicKey: key)
  result.ok = true

proc loadTrustFile*(path: string): tuple[ok: bool, table: TrustTable,
    err: string] {.role: parser, tag: "cryptoBoundary|storageIo|read".} =
  ## path: the trusted keys file; "" means the default place. A missing file is an
  ## empty table, which trusts nobody: that is not an error, only a fact.
  var
    where: string = if path.len > 0: path else: defaultTrustPath()
  if not fileExists(where):
    result.ok = true
    return
  result = parseTrustFile(readFile(where))
  if not result.ok:
    result.err = where & ": " & result.err

proc keysOf*(table: TrustTable, signer: string): seq[TrustedKey] {.role: parser.} =
  ## table/signer: every trusted key that belongs to `signer`.
  for k in table.keys:
    if k.signer == signer:
      result.add k

## ╭⟢ signatures

proc verifyWith*(algorithm: string, msg, sig, publicKey: ByteSeq): bool {.
    role: parser, tag: "cryptoBoundary".} =
  ## algorithm/msg/sig/publicKey: one signature, checked by Tyr. An algorithm this
  ## build cannot check verifies as false.
  case algorithm
  of "ed25519":
    result = ed25519TyrVerify(msg, sig, publicKey)
  of "dilithium44":
    result = verify(dilithium44, msg, sig, publicKey)
  of "dilithium65":
    result = verify(dilithium65, msg, sig, publicKey)
  of "dilithium87":
    result = verify(dilithium87, msg, sig, publicKey)
  of "falcon512":
    result = verify(falcon512, msg, sig, publicKey)
  of "falcon1024":
    result = verify(falcon1024, msg, sig, publicKey)
  of "sphincsshake128f":
    result = verify(sphincsShake128fSimple, msg, sig, publicKey)
  else:
    result = false

## ╭⟢ notes

proc sortedFields(fields: seq[tuple[key, value: string]]): seq[tuple[key, value: string]] {.
    role: helper.} =
  ## fields: the same fields, in name order. Signer and verifier must agree on it.
  result = fields
  result.sort(proc (a, b: tuple[key, value: string]): int = cmp(a.key, b.key))

proc noteFields*(hash: ByteSeq, body: seq[tuple[key, value: string]]): seq[tuple[
    key, value: string]] {.role: helper, tag: "cryptoBoundary".} =
  ## hash/body: a new note's fields: the marker and the hash, then what the program
  ## wants to say. `sig` is added later, by whoever signs.
  result = @[(key: noteMarker, value: "1"), (key: "hash", value: hexText(hash))]
  for f in body:
    result.add f

proc noteSignedText*(fields: seq[tuple[key, value: string]]): string {.role: helper,
    tag: "cryptoBoundary".} =
  ## fields: a note's fields, without `sig`. The text a signature covers.
  var
    body: seq[tuple[key, value: string]] = @[]
  for f in sortedFields(fields):
    if f.key != "sig":
      body.add f
  result = renderFile(body)

proc renderNote*(fields: seq[tuple[key, value: string]], sig: string): string {.
    role: helper, tag: "cryptoBoundary".} =
  ## fields/sig: the note as the file kept beside the payload. `sig` may be "".
  var
    all: seq[tuple[key, value: string]] = @[]
  for f in sortedFields(fields):
    if f.key != "sig":
      all.add f
  if sig.len > 0:
    all.add (key: "sig", value: sig)
  result = renderFile(all)

proc parseNote*(text: string): tuple[ok: bool, note: SidecarNote, err: string] {.
    role: parser, tag: "cryptoBoundary|read".} =
  ## text: a note file. Refused when the digest does not match, the marker is not
  ## there, or the hash is not a full hash: a note that cannot be trusted names
  ## nothing.
  var
    got: tuple[ok: bool, pairs: Table[string, string], err: string] =
      parseKeyFile(text)
  if not got.ok:
    result.err = got.err
    return
  if got.pairs.getOrDefault(noteMarker, "") != "1":
    result.err = "not a note this build reads (no " & noteMarker & " = 1)"
    return
  if not got.pairs.hasKey("hash"):
    result.err = "a note must say its hash"
    return
  result.note.hash = unhexText(got.pairs["hash"])
  if result.note.hash.len != fullDigestBytes:
    result.err = "a note's hash is not a full hash"
    return
  result.note.sig = got.pairs.getOrDefault("sig", "")
  for key, value in got.pairs.pairs:
    if key != "sig":
      result.note.fields.add (key: key, value: value)
  result.note.fields = sortedFields(result.note.fields)
  result.ok = true

proc noteValue*(note: SidecarNote, key: string): string {.role: parser.} =
  ## note/key: the value of one field, "" when the note does not have it.
  for f in note.fields:
    if f.key == key:
      return f.value
  result = ""

proc parseParts(sig: string): seq[tuple[algorithm, hex: string]] {.role: parser.} =
  ## sig: "alg:hex,alg:hex". A part without a colon is kept, and fails later.
  var
    at: int = 0
  for part in sig.split(','):
    at = part.find(':')
    if at < 0:
      result.add (algorithm: "", hex: part)
    else:
      result.add (algorithm: part[0 ..< at], hex: part[at + 1 .. ^1])

proc trustOf*(note: SidecarNote, table: TrustTable): NoteTrust {.role: parser,
    tag: "cryptoBoundary|read".} =
  ## note/table: how much this note's signature is worth (Def. 1 to Def. 3). A note with
  ## nothing in it at all is ntNone; that is decided by the caller, which has no note.
  var
    signer: string = noteValue(note, "signer")
    trusted: seq[TrustedKey] = keysOf(table, signer)
    parts: seq[tuple[algorithm, hex: string]] = @[]
    msg: ByteSeq = @[]
    key: TrustedKey = TrustedKey()
    found: bool = false
  if note.sig.len == 0 or trusted.len == 0:
    return ntUnsigned
  parts = parseParts(note.sig)
  if parts.len != trusted.len:
    return ntBad
  msg = textBytes(noteSignedText(note.fields))
  for p in parts:
    found = false
    for k in trusted:
      if k.algorithm == p.algorithm:
        key = k
        found = true
    if not found:
      return ntBad
    if not verifyWith(p.algorithm, msg, unhexText(p.hex), key.publicKey):
      return ntBad
  result = ntSigned
