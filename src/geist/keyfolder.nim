## ---------------------------------------------------------------------
## Key folder <- every key this Geist owns or trusts, in one place
## ---------------------------------------------------------------------
##
## Three kinds of key live here:
##
##   kind       what it is                          used for
##   ---------  ----------------------------------  ---------------------------
##   pair       a signing key pair: a secret half   signing the first Bifrost
##              that never leaves, a public half    message; telling a server
##              (the "pin") handed to peers         apart from an impostor
##   symmetric  32 random bytes both sides share    sealing data both sides
##                                                  must open
##   peer       someone else's pin, trusted here    checking who is on the
##                                                  other end
##
## On disk:
##
##   <dir>/
##   ├── pairs/<name>.id     pair: secret keys, sealed with the password
##   ├── pairs/<name>.pin    pair: public keys        <- hand this to peers
##   ├── secret/pair.<name>.key   the 32-byte seed the pair grew from
##   ├── secret/sym.<name>.key    a symmetric key
##   └── peers/<name>.pin    a trusted peer's pin
##
## WHY A PAIR HAS A SEED. Every key of a pair is grown from ONE 32-byte
## seed: slot i gets BLAKE3(key = seed, "geist pair slot " & i), cut to
## the 32 or 48 bytes that slot's key maker takes. The seed
## written as 24 words therefore rebuilds the whole pair on another
## machine -- a backup, or the same server identity on a second box. The
## seed is as secret as the pair itself.
##
## WHY A PIN IS NOT WORDS. A pin holds four post-quantum public keys,
## about 5 KB. That would be thousands of words. So the pin travels as a
## FILE (it is public, any channel will do), and its 12-word FINGERPRINT
## travels by a channel you trust (read aloud, on paper). `trust` refuses
## a pin whose fingerprint does not match the words given.
##
##   server                                   client
##   ------                                   ------
##   keys new-pair server
##   keys show server   -> 12 words  ~~~~~~>  (read aloud)
##   pairs/server.pin   ---- any channel --->  keys trust server
##                                               --pin server.pin
##                                               --words "<12 words>"
##
## A symmetric key needs no file at all: its 24 words ARE the key.

import std/[algorithm, os, strutils]

import bifrost_exchange_protocols as bfx except ByteSeq
import tyr

import runePragmas
import ./identity
import ./keystore
import ./masks
import ./secret
import ./words

const
  pairDir = "pairs"
  secretDir = "secret"
  peerDir = "peers"
  pairPrefix = "pair."
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

proc slotSeedBytes(a: bfx.AmeSignatureAlgorithm): int {.role: helper,
    tag: "cryptoBoundary".} =
  ## a: one signature slot -> how many seed bytes its key generator takes.
  case a
  of bfx.asaSphincsShake128f, bfx.asaFalcon512, bfx.asaFalcon1024: result = 48
  else: result = 32

proc pairFromSeed*(subject: string, seed: openArray[uint8]): bfx.AmeIdentityKey {.
    role: truthBuilder, tag: "cryptoBoundary".} =
  ## subject: the pair's name. seed: 32 bytes -> the same pair every time.
  var
    slots: bfx.AmeSignatureAlgorithms = geistSignatureSlots()
    S: seq[bfx.ByteSeq] = @[]
    i: int = 0
  while i < int(slots.length):
    S.add blake3KeyedHash(seed, cast[seq[byte]]("geist pair slot " & $i),
      slotSeedBytes(slots.algorithms[i]))
    i = i + 1
  result = bfx.initAmeIdentityKey(subject, slots, S)

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

proc taken(f: KeyFolder, name: string, k: KeyKind): string {.role: sanitizer,
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

proc savePair(S: var KeyFolder, name: string,
    seed: openArray[uint8]): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "cryptoBoundary|storageIo|write".} =
  ## S/name/seed: grow the pair, then write seed, secret half and pin.
  var
    k: bfx.AmeIdentityKey = pairFromSeed(name, seed)
  result = S.store.put(pairPrefix & name, seed)
  if not result.ok:
    return
  result = saveIdentity(S.keyFile(name, kfPairSecret), S.password, k)
  if not result.ok:
    return
  result = savePin(S.keyFile(name, kfPairPin), pinOf(k))

proc newPair*(S: var KeyFolder, name: string): tuple[ok: bool,
    err: string] {.role: orchestrator, tag: "appApi|cryptoBoundary|write".} =
  ## S/name: a fresh signing pair from 32 random bytes.
  var
    err: string = S.taken(name, kkPair)
  if err.len > 0:
    return (false, err)
  result = S.savePair(name, cryptoRandomBytes(seedBytes))

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
  ## S/name: where the key goes. k: kkPair or kkSymmetric.
  ## text: the 24 words `secretWords` printed on the other machine.
  ## A pair is rebuilt under `name`, which becomes its subject, so give it
  ## the same name it had there if peers already trust its pin.
  var
    err: string = S.taken(name, k)
    got: tuple[ok: bool, bytes: seq[uint8], err: string] = (false, @[], "")
  if err.len > 0:
    return (false, err)
  got = fromWords(text)
  if not got.ok:
    return (false, got.err)
  if got.bytes.len != seedBytes:
    return (false, "a key is 24 words; these were " &
      $(text.splitWhitespace().len))
  case k
  of kkPair: result = S.savePair(name, got.bytes)
  of kkSymmetric: result = S.store.put(symPrefix & name, got.bytes)
  of kkPeer: result = (false, "a peer is trusted from its pin file")

proc trustPin*(S: var KeyFolder, name, pinPath, fingerprint: string): tuple[
    ok: bool, err: string] {.role: orchestrator,
    tag: "appApi|cryptoBoundary|networkSurface|write".} =
  ## S/name: the peer's name here. pinPath: its .pin file.
  ## fingerprint: the 12 words the peer read out, or "" to skip the check
  ## (only when the file itself came over a channel you trust).
  var
    err: string = S.taken(name, kkPeer)
    pin: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string] =
      (false, bfx.AmePinnedPeerIdentity(), "")
  if err.len > 0:
    return (false, err)
  pin = loadPin(pinPath)
  if not pin.ok:
    return (false, pin.err)
  if fingerprint.len > 0 and
      fingerprint.toLowerAscii().splitWhitespace().join(" ") !=
      toWords(pinFingerprint(pin.pin)):
    return (false, "the pin's fingerprint does not match the words: " &
      "this is not the pin that was read out. NOT trusted")
  result = savePin(S.keyFile(name, kfPeerPin), pin.pin)

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

proc publicWords*(f: KeyFolder, e: KeyEntry): tuple[ok: bool, words: string,
    err: string] {.role: parser, tag: "appApi|cryptoBoundary|read".} =
  ## f/e: the 12 fingerprint words of a pair's or peer's pin. Safe to show
  ## anyone. A symmetric key has no public side and gets an error.
  var
    pin: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string] =
      (false, bfx.AmePinnedPeerIdentity(), "")
  case e.kind
  of kkPair: pin = loadPin(f.keyFile(e.name, kfPairPin))
  of kkPeer: pin = loadPin(f.keyFile(e.name, kfPeerPin))
  of kkSymmetric:
    return (false, "", "a symmetric key has no public side")
  if not pin.ok:
    return (false, "", pin.err)
  result = (true, toWords(pinFingerprint(pin.pin)), "")

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
