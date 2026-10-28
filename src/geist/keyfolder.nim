## ---------------------------------------------------------------------
## Key folder <- the symmetric keys this Geist seals data with
## ---------------------------------------------------------------------
##
## A symmetric key is 32 random bytes that two sides share, used to seal
## data both sides must open. `geist export --seal-key NAME` uses one.
## A symmetric key needs no file at all: its 24 words ARE the key.
##
## The same folder also holds signing pairs and trusted peer pins. Those
## need Bifrost, so they are handled by nebel (identity_folder.nim),
## which writes into this folder layout. This module still LISTS and DROPS
## them by name, because listing and dropping are only file operations:
##
##   kind       what it is                          handled by
##   ---------  ----------------------------------  ---------------------------
##   symmetric  32 random bytes both sides share    geist (this file)
##   pair       a signing key pair                  nebel
##   peer       someone else's pin, trusted here    nebel
##
## On disk:
##
##   <dir>/
##   ├── pairs/<name>.id          pair   (nebel)
##   ├── pairs/<name>.pin         pair   (nebel)
##   ├── peers/<name>.pin         peer   (nebel)
##   └── secret/sym.<name>.key    symmetric key, sealed with the password

import std/[algorithm, os, strutils]

import tyr

import runePragmas
import ./keystore
import ./secret
import ./words

const
  pairDir = "pairs"
  secretDir = "secret"
  peerDir = "peers"
  pairPrefix* = "pair."
  symPrefix = "sym."
  seedBytes = 32

type
  KeyKind* {.role: configurator, tag: "cryptoBoundary|types".} = enum
    kkPair, kkSymmetric, kkPeer

  KeyFile* {.role: configurator, tag: "storageIo|types".} = enum
    ## Which file of a key: a pair's sealed secret half, a pair's pin,
    ## or a trusted peer's pin.
    kfPairSecret, kfPairPin, kfPeerPin

  KeyEntry* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## One line of `listKeys`.
    name*: string
    kind*: KeyKind

  KeyFolder* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## dir: the folder above. store: where seeds and symmetric keys are
    ## sealed. password: seals the secret halves of pairs as well.
    dir*: string
    password*: string
    store*: Keystore

proc kindName*(k: KeyKind): string {.role: helper, tag: "formatting".} =
  ## k: the word shown in a listing.
  case k
  of kkPair: result = "pair"
  of kkSymmetric: result = "symmetric"
  of kkPeer: result = "peer"

proc openKeyFolder*(dir, password: string): KeyFolder {.role: configurator,
    tag: "cryptoBoundary|lifecycle".} =
  ## dir: the key folder, created on first write.
  ## password: seals every secret in it. Listing works with any password.
  result.dir = dir
  result.password = password
  result.store = openKeystore(dir / secretDir, password)

proc keyFile*(f: KeyFolder, name: string, w: KeyFile): string {.role: helper,
    tag: "storageIo".} =
  ## f/name: one key. w: which of its files -> where that file lives.
  case w
  of kfPairSecret: result = f.dir / pairDir / name & ".id"
  of kfPairPin: result = f.dir / pairDir / name & ".pin"
  of kfPeerPin: result = f.dir / peerDir / name & ".pin"

proc namesIn(dir, ext: string): seq[string] {.role: parser,
    tag: "read|storageIo".} =
  ## dir/ext: the file names in dir ending in ext, without the ending.
  var
    t: string = ""
  if not dirExists(dir):
    return @[]
  for kind, path in walkDir(dir):
    t = path.extractFilename()
    if t.endsWith(ext):
      result.add t[0 ..< t.len - ext.len]
  result.sort()

proc listKeys*(f: KeyFolder): seq[KeyEntry] {.role: parser,
    tag: "appApi|cryptoBoundary|read".} =
  ## f: every key, pairs first, then symmetric keys, then peers.
  ## Needs no password: only file names are read.
  for n in namesIn(f.dir / pairDir, ".pin"):
    result.add KeyEntry(name: n, kind: kkPair)
  for n in namesIn(f.dir / secretDir, keystoreSuffix):
    if n.startsWith(symPrefix):
      result.add KeyEntry(name: n[symPrefix.len .. ^1], kind: kkSymmetric)
  for n in namesIn(f.dir / peerDir, ".pin"):
    result.add KeyEntry(name: n, kind: kkPeer)

proc findKey*(f: KeyFolder, nameOrNumber: string): tuple[ok: bool,
    entry: KeyEntry, err: string] {.role: parser,
    tag: "appApi|parsing".} =
  ## nameOrNumber: a name, or the number `listKeys` printed before it (1..).
  ## A name found in two kinds is refused: say the number instead.
  var
    L: seq[KeyEntry] = f.listKeys()
    n: int = 0
    hits: int = 0
  if nameOrNumber.len > 0 and nameOrNumber.allCharsInSet(Digits):
    n = parseInt(nameOrNumber)
    if n < 1 or n > L.len:
      return (false, KeyEntry(), "there is no key number " & nameOrNumber)
    return (true, L[n - 1], "")
  for e in L:
    if e.name == nameOrNumber:
      result.entry = e
      hits = hits + 1
  if hits == 0:
    return (false, KeyEntry(), "no key called '" & nameOrNumber & "'")
  if hits > 1:
    return (false, KeyEntry(), "'" & nameOrNumber & "' names more than " &
      "one key; use its number from `geist keys list`")
  result.ok = true

proc taken*(f: KeyFolder, name: string, k: KeyKind): string {.role: sanitizer,
    tag: "parsing".} =
  ## f/name/k: why this name cannot be used for a new key, or "".
  var
    err: string = checkName(name)
  if err.len > 0:
    return err
  for e in f.listKeys():
    if e.name == name and e.kind == k:
      return "a " & kindName(k) & " key called '" & name &
        "' already exists; drop it first or pick another name"
  if f.password.len == 0 and k != kkPeer:
    return "a password is needed: the key is sealed with it"
  result = ""

proc newSymmetric*(S: var KeyFolder, name: string): tuple[ok: bool,
    err: string] {.role: orchestrator, tag: "appApi|cryptoBoundary|write".} =
  ## S/name: 32 fresh random bytes, sealed.
  var
    err: string = S.taken(name, kkSymmetric)
  if err.len > 0:
    return (false, err)
  result = S.store.put(symPrefix & name, cryptoRandomBytes(seedBytes))

proc importWords*(S: var KeyFolder, name: string, k: KeyKind,
    text: string): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|parsing|write".} =
  ## S/name: where the key goes. k: only kkSymmetric; a pair is rebuilt by
  ## nebel, which knows how to grow one.
  ## text: the 24 words `secretWords` printed on the other machine.
  var
    err: string = S.taken(name, k)
    got: tuple[ok: bool, bytes: seq[uint8], err: string] = (false, @[], "")
  if err.len > 0:
    return (false, err)
  if k != kkSymmetric:
    return (false, "only a symmetric key is imported here; pairs and " &
      "peers are handled by nebel")
  got = fromWords(text)
  if not got.ok:
    return (false, got.err)
  if got.bytes.len != seedBytes:
    return (false, "a key is 24 words; these were " &
      $(text.splitWhitespace().len))
  result = S.store.put(symPrefix & name, got.bytes)


proc dropKey*(S: var KeyFolder, e: KeyEntry): tuple[ok: bool, err: string] {.
    role: actor, tag: "appApi|cryptoBoundary|delete".} =
  ## S/e: forget one key and every file it has.
  try:
    case e.kind
    of kkPair:
      removeFile(S.keyFile(e.name, kfPairSecret))
      removeFile(S.keyFile(e.name, kfPairPin))
      result = S.store.drop(pairPrefix & e.name)
    of kkSymmetric:
      result = S.store.drop(symPrefix & e.name)
    of kkPeer:
      removeFile(S.keyFile(e.name, kfPeerPin))
      result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc secretWords*(f: KeyFolder, e: KeyEntry): tuple[ok: bool, words: string,
    err: string] {.role: decryptor, tag: "appApi|cryptoBoundary|read".} =
  ## f/e: the 24 words that rebuild this key. SECRET: whoever reads them
  ## owns the key. A peer has no secret here and gets an error.
  var
    got: KeyResult = KeyResult()
  case e.kind
  of kkPair: got = f.store.get(pairPrefix & e.name)
  of kkSymmetric: got = f.store.get(symPrefix & e.name)
  of kkPeer:
    return (false, "", "a peer's secret half is theirs, not ours")
  if not got.ok:
    return (false, "", got.err)
  result = (true, toWords(got.value.use()), "")

proc symmetricKey*(f: KeyFolder, name: string): KeyResult {.role: decryptor,
    tag: "appApi|cryptoBoundary|read".} =
  ## f/name: the 32 bytes of the symmetric key `name` (or its number in
  ## `listKeys`), to seal with -- `geist export --seal-key name` uses it.
  var
    found: tuple[ok: bool, entry: KeyEntry, err: string] = f.findKey(name)
  if not found.ok:
    return KeyResult(err: found.err)
  if found.entry.kind != kkSymmetric:
    return KeyResult(err: "'" & name & "' is a " &
      kindName(found.entry.kind) & " key, not a symmetric one")
  result = f.store.get(symPrefix & found.entry.name)
