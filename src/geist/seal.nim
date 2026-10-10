## ---------------------------------------------------------------------
## Seal <- one object encrypted in memory; the bytes are yours to keep
## ---------------------------------------------------------------------
##
##   object --sealObject(key)--> bytes   write them anywhere: a file, a
##                                       column in someone else's database,
##                                       a message, a cookie
##   bytes  --openObject(key)--> object  or the reason not: wrong key,
##                                       altered bytes, another type
##
## A Geist STORE seals rows for you. This is for everything that is not a
## store: a password entry kept by another program, a game save, one
## record inside a message.
##
## How an object becomes bytes, step by step:
##
##   Login(site: "mail", uses: 3)
##     | toNode (./doc)              every field, by name
##     v
##   {"site":"mail","uses":3}        JSON text, as bytes
##     | sealWithKey (./secrets)     keystream + tag, fresh nonce
##     v
##   | GSK1 | 24 | nonce | t | tag | sealed JSON |
##
## JSON rather than the store's packed rows, on purpose: the objects people
## seal carry lists and tables (tags on a password, items in a save), which
## a packed row cannot hold, and a field added to the type later simply
## keeps its default when an older blob is opened.
##
## Limits worth knowing: an integer above 2^63 does not survive the JSON
## step, and a field whose type `toNode` does not know will not compile.

import std/json

import runePragmas
import ./types
import ./secret
import ./secrets
import ./doc

proc objectBytes[T](x: T): ByteSeq {.role: truthBuilder,
    tag: "codecBoundary|cryptoBoundary".} =
  ## x: the object as compact JSON bytes -- what gets sealed.
  result = textBytes($toNode(x))

proc objectFrom[T](opened: SealedBlob): tuple[ok: bool, value: T,
    err: string] {.role: parser, tag: "codecBoundary|cryptoBoundary".} =
  ## opened: the result of an open. Its bytes back into a T, starting from
  ## T's defaults, so a field the blob does not mention keeps its default.
  ## A field of the WRONG type is an error, not a silent default: it means
  ## this blob was sealed from a different type.
  var
    parsed: tuple[ok: bool, node: JsonNode, err: string] =
      (false, newJObject(), "")
    report: DocReport = DocReport(ok: true)
  if not opened.ok:
    return (false, default(T), opened.err)
  parsed = parseDoc(bytesText(opened.data), dfJson)
  if not parsed.ok:
    return (false, default(T), "the sealed bytes are not an object: " &
      parsed.err)
  result.value = default(T)
  fromNode(parsed.node, result.value, "", report)
  if report.mistyped.len > 0:
    return (false, default(T), "sealed from a different type; these " &
      "fields do not fit: " & $report.mistyped)
  result.ok = true

proc sealObject*[T](x: T, key: Secret, aad: string = ""): SealedBlob {.
    role: encryptor, tag: "appApi|cryptoBoundary|write".} =
  ## x: the object to protect.
  ## key: from `newSealKey`, or `deriveKey` done once for many objects.
  ## aad: context the blob is bound to but does not hide -- "vault/alice".
  ##   The same text is needed to open it, which stops a blob copied into
  ##   another record from opening there.
  result = sealWithKey(key, objectBytes(x), textBytes(aad))

proc openObject*[T](blob: openArray[uint8], key: Secret,
    aad: string = ""): tuple[ok: bool, value: T, err: string] {.
    role: decryptor, tag: "appApi|cryptoBoundary|read".} =
  ## blob/key/aad: the reverse of `sealObject`, into a T.
  result = objectFrom[T](openWithKey(key, blob, textBytes(aad)))

proc sealObjectWithPassword*[T](x: T, password: string,
    aad: string = ""): SealedBlob {.role: encryptor,
    tag: "appApi|cryptoBoundary|write".} =
  ## x/password/aad: one object sealed by a password.
  ##
  ## Pays the full Argon2 cost on every call, by design -- right for one
  ## object now and then. For many, derive a key once with `deriveKey` and
  ## call `sealObject`.
  result = sealWithPassword(password, objectBytes(x), textBytes(aad))

proc openObjectWithPassword*[T](blob: openArray[uint8], password: string,
    aad: string = ""): tuple[ok: bool, value: T, err: string] {.
    role: decryptor, tag: "appApi|cryptoBoundary|read".} =
  ## blob/password/aad: the reverse of `sealObjectWithPassword`.
  result = objectFrom[T](openWithPassword(password, blob, textBytes(aad)))
