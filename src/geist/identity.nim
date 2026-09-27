## ---------------------------------------------------------------------
## Identity <- persisting a signing identity and exchanging pins
## ---------------------------------------------------------------------
##
##   geist keygen --identity node.key --pin node.pin
##
##   node.key   subject + public keys + SEALED secret keys   (never shared)
##   node.pin   subject + public keys only                   (hand to peers)
##
## Pinned trust means each side must already know the other's public keys.
## An identity generated fresh on every run cannot be pinned by anyone,
## which is why these files exist: without them the handshake correctly
## refuses to connect, and that refusal looks like a bug.
##
##   client                        daemon
##   ------                        ------
##   --identity client.key         --identity daemon.key
##   --peer-pin daemon.pin   <---- daemon.pin
##   client.pin              ----> --trust client.pin
##
## Bifrost serialises certificates but not identity KEYS (a certificate
## deliberately carries no secret half), so the on-disk form is defined
## here. Secret keys are sealed with the same Argon2id + cascade the key
## file uses; the pin file is public and only integrity-checked.

import std/[os, strutils]

import bifrost_exchange_protocols as bfx except ByteSeq
import tyr

import runePragmas
import ./types
import ./format
import ./crypto/cipher
import ./crypto/mac

const
  identityMagic* = "GEID\x01"
  pinMagic* = "GEPIN\x01"
  argonPasses = 3
  argonMemoryKiB = 65536
  argonLanes = 4

proc encodeSigningKeys(A: seq[bfx.AmeIdentitySigningKey]): ByteSeq {.
    role: encryptor, tag: "codecBoundary|networkSurface".} =
  ## A: public signing keys serialised in slot order.
  var
    i: int = 0
  result.addU32(uint32(A.len))
  while i < A.len:
    result.add uint8(ord(A[i].algorithm))
    result.addU32(uint32(A[i].publicKey.len))
    result.addBytes(A[i].publicKey)
    i = i + 1

proc decodeSigningKeys(A: openArray[uint8],
    o: var int): seq[bfx.AmeIdentitySigningKey] {.role: parser,
    tag: "codecBoundary|networkSurface".} =
  ## A/o: buffer and cursor advanced past the signing key list.
  var
    n: int = 0
    i: int = 0
    m: int = 0
    k: bfx.AmeIdentitySigningKey = default(bfx.AmeIdentitySigningKey)
  n = int(A.getU32(o)); o = o + 4
  while i < n:
    k = bfx.AmeIdentitySigningKey()
    k.algorithm = bfx.AmeSignatureAlgorithm(A[o]); o = o + 1
    m = int(A.getU32(o)); o = o + 4
    k.publicKey = @(A[o ..< o + m])
    o = o + m
    result.add k
    i = i + 1

proc pinOf*(k: bfx.AmeIdentityKey): bfx.AmePinnedPeerIdentity {.
    role: helper, tag: "cryptoBoundary|networkSurface".} =
  ## k: identity whose public half becomes a shareable pin.
  result = bfx.pinnedPeerIdentity(k)

proc savePin*(path: string, p: bfx.AmePinnedPeerIdentity): tuple[ok: bool,
    err: string] {.role: dataWriter,
    tag: "networkSurface|storageIo|write".} =
  ## path: destination for the public pin.
  ## p: subject and public signing keys. Nothing here is secret; the file
  ## carries a trailing hash so a corrupted pin fails loudly rather than
  ## silently trusting the wrong key material.
  var
    buf: ByteSeq = @[]
  buf = @(cast[ByteSeq](pinMagic))
  buf.addText(p.subject)
  buf.addBytes(encodeSigningKeys(p.signingKeys))
  buf.addBytes(blake3TyrHash(buf, 32))
  try:
    if parentDir(path).len > 0 and not dirExists(parentDir(path)):
      createDir(parentDir(path))
    writeFile(path, cast[string](buf))
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc loadPin*(path: string): tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity,
    err: string] {.role: dataFetcher,
    tag: "networkSurface|read|storageIo".} =
  ## path: pin file produced by `savePin`.
  var
    raw: ByteSeq = @[]
    o: int = 0
    i: int = 0
    check: ByteSeq = @[]
  if not fileExists(path):
    return (false, bfx.AmePinnedPeerIdentity(), "no pin file at " & path)
  raw = cast[ByteSeq](readFile(path))
  if raw.len < pinMagic.len + 32:
    return (false, bfx.AmePinnedPeerIdentity(), "pin file is truncated")
  while i < pinMagic.len:
    if raw[i] != uint8(pinMagic[i]):
      return (false, bfx.AmePinnedPeerIdentity(), "not a Geist pin file")
    i = i + 1
  check = @(blake3TyrHash(raw[0 ..< raw.len - 32], 32))
  i = 0
  while i < 32:
    if check[i] != raw[raw.len - 32 + i]:
      return (false, bfx.AmePinnedPeerIdentity(),
        "pin file failed its integrity check: " & path)
    i = i + 1
  o = pinMagic.len
  result.pin.subject = raw.readText(o)
  result.pin.signingKeys = decodeSigningKeys(raw, o)
  result.ok = true

proc saveIdentity*(path, password: string,
    k: bfx.AmeIdentityKey): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "cryptoBoundary|networkSurface|storageIo|write".} =
  ## path: destination for the private identity.
  ## password: credential whose Argon2id output seals the secret keys.
  ## k: identity to persist. Public halves are stored in clear so a pin can
  ## be re-derived without the password; only the secret keys are sealed.
  var
    salt: ByteSeq = @[]
    fileKey: Secret = default(Secret)
    strm: StreamKeys = default(StreamKeys)
    plain: ByteSeq = @[]
    sealedSecrets: ByteSeq = @[]
    publicPart: ByteSeq = @[]
    tag: ByteSeq = @[]
    buf: ByteSeq = @[]
    i: int = 0
  if password.len == 0:
    return (false, "an identity file needs a password to seal its secret keys")
  salt = @(cryptoRandomBytes(16))
  fileKey = initSecret(argon2idTyrHash(cast[seq[byte]](password), salt,
    argonPasses, argonMemoryKiB, argonLanes, 32))
  strm = deriveStreamKeys(fileKey, salt)
  plain.addU32(uint32(k.secretKeys.len))
  while i < k.secretKeys.len:
    plain.addU32(uint32(k.secretKeys[i].len))
    plain.addBytes(k.secretKeys[i])
    i = i + 1
  sealedSecrets = applyKeystream(ckCascade, strm, 0'u64, plain)
  publicPart.addText(k.subject)
  publicPart.addBytes(encodeSigningKeys(k.signingKeys))
  tag = authTag(mkCombined, fileKey, publicPart & sealedSecrets, salt)
  buf = @(cast[ByteSeq](identityMagic))
  buf.addU32(uint32(salt.len));           buf.addBytes(salt)
  buf.addU32(uint32(publicPart.len));     buf.addBytes(publicPart)
  buf.addU32(uint32(sealedSecrets.len));  buf.addBytes(sealedSecrets)
  buf.addU32(uint32(tag.len));            buf.addBytes(tag)
  try:
    if parentDir(path).len > 0 and not dirExists(parentDir(path)):
      createDir(parentDir(path))
    writeFile(path, cast[string](buf))
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc loadIdentity*(path, password: string): tuple[ok: bool,
    key: bfx.AmeIdentityKey, err: string] {.role: dataFetcher,
    tag: "cryptoBoundary|networkSurface|read|storageIo".} =
  ## path: identity file produced by `saveIdentity`.
  ## password: credential; a wrong one fails the tag check, not the parse.
  var
    raw: ByteSeq = @[]
    o: int = 0
    n: int = 0
    i: int = 0
    salt: ByteSeq = @[]
    publicPart: ByteSeq = @[]
    sealedSecrets: ByteSeq = @[]
    tag: ByteSeq = @[]
    fileKey: Secret = default(Secret)
    strm: StreamKeys = default(StreamKeys)
    plain: ByteSeq = @[]
    po: int = 0
    m: int = 0
  if not fileExists(path):
    return (false, bfx.AmeIdentityKey(), "no identity file at " & path)
  raw = cast[ByteSeq](readFile(path))
  if raw.len < identityMagic.len:
    return (false, bfx.AmeIdentityKey(), "identity file is truncated")
  while i < identityMagic.len:
    if raw[i] != uint8(identityMagic[i]):
      return (false, bfx.AmeIdentityKey(), "not a Geist identity file")
    i = i + 1
  o = identityMagic.len
  n = int(raw.getU32(o)); o = o + 4
  salt = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  publicPart = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  sealedSecrets = raw[o ..< o + n]; o = o + n
  n = int(raw.getU32(o)); o = o + 4
  tag = raw[o ..< o + n]
  fileKey = initSecret(argon2idTyrHash(cast[seq[byte]](password), salt,
    argonPasses, argonMemoryKiB, argonLanes, 32))
  if not verifyTag(mkCombined, fileKey, publicPart & sealedSecrets, salt, tag):
    return (false, bfx.AmeIdentityKey(),
      "identity file rejected: wrong password or tampering")
  result.key.subject = publicPart.readText(po)
  result.key.signingKeys = decodeSigningKeys(publicPart, po)
  strm = deriveStreamKeys(fileKey, salt)
  plain = applyKeystream(ckCascade, strm, 0'u64, sealedSecrets)
  n = int(plain.getU32(0))
  po = 4
  i = 0
  while i < n:
    m = int(plain.getU32(po)); po = po + 4
    result.key.secretKeys.add plain[po ..< po + m]
    po = po + m
    i = i + 1
  result.ok = true

proc loadOrCreateIdentity*(path, password, subject: string,
    slots: bfx.AmeSignatureAlgorithms): tuple[ok: bool,
    key: bfx.AmeIdentityKey, created: bool, err: string] {.
    role: orchestrator, tag: "cryptoBoundary|networkSurface|orchestrator|storageIo".} =
  ## path/password/subject/slots: identity file, credential, local name and
  ## the signature slots the Geist tier masks can select.
  ## An existing file that will not open is an error, never a reason to
  ## mint a new identity: silently rotating a pinned key would break every
  ## peer that trusts it.
  var
    loaded: tuple[ok: bool, key: bfx.AmeIdentityKey, err: string] =
      (false, default(bfx.AmeIdentityKey), "")
    written: tuple[ok: bool, err: string] = (false, "")
  if fileExists(path):
    loaded = loadIdentity(path, password)
    return (loaded.ok, loaded.key, false, loaded.err)
  result.key = bfx.initAmeIdentityKey(subject, slots)
  written = saveIdentity(path, password, result.key)
  if not written.ok:
    return (false, bfx.AmeIdentityKey(), false, written.err)
  result.ok = true
  result.created = true

proc describePin*(p: bfx.AmePinnedPeerIdentity): string {.role: helper,
    tag: "formatting|networkSurface|status".} =
  ## p: pin rendered for operator confirmation. Shows a short fingerprint
  ## per slot so two sides can compare out of band.
  const
    H = "0123456789abcdef"
  var
    i: int = 0
    j: int = 0
    digest: seq[byte] = @[]
    line: string = ""
  result = "subject: " & p.subject & "\n"
  while i < p.signingKeys.len:
    digest = blake3TyrHash(p.signingKeys[i].publicKey, 8)
    line = ""
    j = 0
    while j < digest.len:
      line.add H[int(uint8(digest[j]) shr 4)]
      line.add H[int(uint8(digest[j]) and 0x0F'u8)]
      j = j + 1
    result.add "  " & alignLeft($p.signingKeys[i].algorithm, 26) & line & "\n"
    i = i + 1
