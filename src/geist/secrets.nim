## ---------------------------------------------------------------------
## Secrets <- the only crypto an application should ever need
## ---------------------------------------------------------------------
##
##   a person types a password
##        |
##        +-- storing it in a user database   -> hashPassword / verifyPassword
##        +-- unlocking a local store         -> deriveKey
##        +-- sealing something that is not
##            a Geist store                   -> sealWithPassword / open...
##
## WHY THIS EXISTS. Fjord and Eris both imported `tyr_crypto` directly and
## both were about to grow their own idea of how a password becomes a key.
## Two applications with two answers to that is two chances to pick the
## wrong Argon2 parameters, forget a salt, or compare a hash with `==`.
##
## So there is one answer, it lives here, and an application imports
## `geist` and nothing else. Tyr is still what does the work -- this
## module invents no cryptography whatsoever. It chooses parameters,
## fixes an encoding, and refuses the three mistakes below.
##
## THE THREE MISTAKES THIS MODULE MAKES IMPOSSIBLE:
##
##   a password compared with `==`      -> `verifyPassword` is the only
##                                         comparison, and it is constant
##                                         time
##   one salt for every user            -> the salt is generated inside
##                                         `hashPassword`; a caller cannot
##                                         supply one
##   parameters that can never be raised -> they are stored IN the hash,
##                                         so raising them later leaves
##                                         every existing login working
##
## WHAT A PASSWORD HASH LOOKS LIKE. A single line of text, so it fits in
## a packed row as an ordinary field:
##
##   geist$argon2id$v=1$m=65536,t=3,p=4$<salt>$<hash>
##
## Self-describing on purpose. The verifier reads the cost out of the
## string rather than assuming today's, which is what lets a server raise
## the cost in a year without locking anybody out -- and `needsRehash`
## says who to upgrade on their next successful sign-in.
##
## AUTHENTICATION AND ENCRYPTION USE DIFFERENT DERIVATIONS. The key that
## unlocks someone's local store must never equal the value a server
## holds to check their password, or a stolen user database would decrypt
## every mailbox in it. `deriveKey` and `hashPassword` therefore mix in
## different domain separators, and the separation is a property of this
## module rather than a convention every caller has to remember.

import std/[base64, strutils]

import tyr

import runePragmas
import ./types
import ./secret
import ./crypto/cipher
import ./crypto/mac

const
  passwordScheme* = "geist$argon2id$v=1"
    ## The prefix every stored hash carries. Versioned so a future change
    ## of algorithm is a new prefix rather than a silent reinterpretation
    ## of the old bytes.

  defaultPasswordPasses* = 3'u32
  defaultPasswordMemoryKiB* = 65_536'u32
  defaultPasswordLanes* = 4'u32
    ## Argon2id cost for a stored password: three passes over 64 MiB
    ## across four lanes. Roughly a tenth of a second on a modern core,
    ## which is the usual trade -- slow enough to make a stolen database
    ## expensive to attack, fast enough that a login does not feel broken.
    ##
    ## Raise them by changing these constants. Existing hashes keep their
    ## own parameters and keep verifying; `needsRehash` finds them.

  passwordSaltBytes* = 16
  passwordHashBytes* = 32
    ## 128 bits of salt and 256 of output. The salt only has to be unique,
    ## not secret.

  minPasswordBytes* = 1
  maxPasswordBytes* = 4096
    ## An empty password is refused because it is almost always a bug --
    ## an unset field rather than a decision. The ceiling stops a
    ## megabyte-long "password" turning a login into a denial of service,
    ## since the KDF must run before anything can be rejected.

  keyDomainStorage* = "geist:storage:v1"
  keyDomainAuth* = "geist:auth:v1"
    ## Domain separators. See the module note: the key that decrypts a
    ## store must never equal the value a server stores to check the same
    ## password.

type
  PasswordParams* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## The cost one particular hash was made with, read back out of it.
    passes*: uint32
    memoryKiB*: uint32
    lanes*: uint32

  PasswordRecord* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## A stored hash, taken apart. `encoded` is the line that goes in the
    ## database; the rest is what `verifyPassword` needs to recompute it.
    ok*: bool
    encoded*: string
    params*: PasswordParams
    salt*: ByteSeq
    hash*: ByteSeq
    err*: string

  SealedBlob* {.role: truthState, tag: "cryptoBoundary|types".} = object
    ## Something sealed with a password: the salt it was derived with, the
    ## ciphertext, and the tag that proves both.
    ##
    ## Kept as a type rather than a bare string so a caller cannot lose
    ## the salt, which is the one part that looks discardable and is not.
    ok*: bool
    data*: ByteSeq
    err*: string

proc defaultPasswordParams*(): PasswordParams {.role: configurator, stage: stDone,
    tag: "cryptoBoundary".} =
  ## Today's cost, for a password being hashed now.
  result.passes = defaultPasswordPasses
  result.memoryKiB = defaultPasswordMemoryKiB
  result.lanes = defaultPasswordLanes

proc checkPassword*(password: string): string {.role: sanitizer,
    tag: "cryptoBoundary".} =
  ## password: refused with a reason, or "" when it is usable.
  ##
  ## This is not a strength policy and deliberately does not try to be.
  ## It is the bounds check that keeps the KDF from being handed
  ## something it should never run on.
  if password.len < minPasswordBytes:
    return "a password must not be empty"
  if password.len > maxPasswordBytes:
    return "a password longer than " & $maxPasswordBytes &
      " bytes is refused, because the derivation has to run before it " &
      "can be rejected"
  result = ""

proc randomSalt*(n: int = passwordSaltBytes): ByteSeq {.role: helper,
    tag: "cryptoBoundary".} =
  ## n: fresh bytes from the platform generator.
  ##
  ## Exported because a caller sealing several things at once may want to
  ## make one salt per item, and because a test needs to be able to name
  ## the size. Nothing here ever reuses one.
  result = @(cryptoRandomBytes(n))

proc encodeSalt*(salt: openArray[uint8]): string {.role: helper,
    tag: "cryptoBoundary|formatting".} =
  ## salt: as text, so it can live in a packed row beside a password hash.
  ##
  ## One encoding for the whole codebase. A salt written as hex in one
  ## place and base64 in another is a key that derives differently
  ## depending on which module last touched the record.
  result = encode(salt)

proc decodeSalt*(s: string): ByteSeq {.role: parser,
    tag: "cryptoBoundary|parsing".} =
  ## s: back to bytes. An unreadable value comes back EMPTY rather than
  ## raising, and an empty salt derives a key that will simply not open
  ## anything -- which is the correct outcome for a corrupted record, and
  ## a much better one than a crash in a sign-in path.
  try:
    result = cast[ByteSeq](decode(s))
  except CatchableError:
    result = @[]

proc kdf(password: string, salt: openArray[uint8], domain: string,
    p: PasswordParams, outLen: int): ByteSeq {.role: encryptor,
    tag: "cryptoBoundary".} =
  ## password/salt/domain/p/outLen: the one call into Tyr.
  ##
  ## The domain is mixed into the SALT rather than the password, so two
  ## uses of one password with one salt still derive different values and
  ## neither derivation can be turned into the other by anything a caller
  ## passes in.
  var
    mixed: ByteSeq = @(cast[seq[byte]](domain)) & @salt
  result = argon2idTyrHash(cast[seq[byte]](password), mixed,
    int(p.passes), int(p.memoryKiB), int(p.lanes), outLen)

proc encodeParams(p: PasswordParams): string {.role: helper,
    tag: "cryptoBoundary|formatting".} =
  ## p: the `m=..,t=..,p=..` field of an encoded hash.
  result = "m=" & $p.memoryKiB & ",t=" & $p.passes & ",p=" & $p.lanes

proc decodeParams(s: string): tuple[ok: bool, p: PasswordParams] {.
    role: parser, tag: "cryptoBoundary|parsing".} =
  ## s: `m=..,t=..,p=..`, or a failure. Nothing raises: this text came out
  ## of a database that a person may have edited.
  var
    parts: seq[string] = s.split(',')
    i: int = 0
    kv: seq[string] = @[]
    seenM: bool = false
    seenT: bool = false
    seenP: bool = false
  while i < parts.len:
    kv = parts[i].split('=')
    if kv.len != 2:
      return (false, PasswordParams())
    try:
      case kv[0].strip()
      of "m": result.p.memoryKiB = uint32(parseUInt(kv[1].strip())); seenM = true
      of "t": result.p.passes = uint32(parseUInt(kv[1].strip())); seenT = true
      of "p": result.p.lanes = uint32(parseUInt(kv[1].strip())); seenP = true
      else: return (false, PasswordParams())
    except ValueError:
      return (false, PasswordParams())
    i = i + 1
  if not (seenM and seenT and seenP):
    return (false, PasswordParams())
  if result.p.memoryKiB == 0'u32 or result.p.passes == 0'u32 or
      result.p.lanes == 0'u32:
    # A zero would make the derivation instant, which is the one shape of
    # corrupted record that must not be treated as a valid cheap hash.
    return (false, PasswordParams())
  result.ok = true

proc hashPassword*(password: string,
    p: PasswordParams = defaultPasswordParams()): PasswordRecord {.
    role: encryptor, tag: "cryptoBoundary|write".} =
  ## password: what the person typed.
  ## p: the cost. The default is today's; passing an older one is only
  ##   useful to a test.
  ##
  ## Returns the line to store. THE SALT IS GENERATED HERE and cannot be
  ## supplied, because a caller-provided salt is how every user in a
  ## database ends up sharing one.
  var
    bad: string = checkPassword(password)
  if bad.len > 0:
    return PasswordRecord(err: bad)
  result.params = p
  result.salt = randomSalt()
  result.hash = kdf(password, result.salt, keyDomainAuth, p,
    passwordHashBytes)
  result.encoded = passwordScheme & "$" & encodeParams(p) & "$" &
    encode(result.salt) & "$" & encode(result.hash)
  result.ok = true

proc parsePasswordHash*(encoded: string): PasswordRecord {.role: parser,
    tag: "cryptoBoundary|parsing".} =
  ## encoded: a stored line, taken apart.
  ##
  ## Nothing raises. This string comes out of a database and may have
  ## been truncated, hand-edited or written by a different version, and a
  ## login path that threw on a malformed record would take the server
  ## down for one bad row.
  var
    parts: seq[string] = encoded.split('$')
    p: tuple[ok: bool, p: PasswordParams] = (false, default(PasswordParams))
  result.encoded = encoded
  # geist $ argon2id $ v=1 $ params $ salt $ hash
  if parts.len != 6:
    result.err = "not a Geist password hash"
    return
  if parts[0] & "$" & parts[1] & "$" & parts[2] != passwordScheme:
    result.err = "unknown password scheme: " & parts[0] & "$" & parts[1] &
      "$" & parts[2]
    return
  p = decodeParams(parts[3])
  if not p.ok:
    result.err = "unreadable cost parameters: " & parts[3]
    return
  result.params = p.p
  try:
    result.salt = cast[ByteSeq](decode(parts[4]))
    result.hash = cast[ByteSeq](decode(parts[5]))
  except CatchableError:
    result.err = "salt or hash is not base64"
    return
  if result.salt.len == 0 or result.hash.len == 0:
    result.err = "salt or hash is empty"
    return
  result.ok = true

proc verifyPassword*(password, encoded: string): bool {.role: sanitizer,
    tag: "cryptoBoundary|read".} =
  ## password: what was typed now.
  ## encoded: what the database holds.
  ##
  ## CONSTANT TIME, and the only comparison in the codebase that should
  ## ever be made against a stored hash. A `==` on the encoded strings
  ## leaks the length of the shared prefix, which is enough to recover a
  ## hash a byte at a time given enough attempts.
  ##
  ## A malformed record verifies as FALSE rather than raising. It is not
  ## a valid credential, and refusing to sign anybody in because one row
  ## is corrupt would turn a bad row into an outage.
  ##
  ## The cost comes from the RECORD, not from today's constants, so a
  ## password hashed cheaply years ago still verifies.
  var
    got: ByteSeq = @[]
    rec: PasswordRecord = parsePasswordHash(encoded)
  if not rec.ok:
    return false
  if checkPassword(password).len > 0:
    return false
  got = kdf(password, rec.salt, keyDomainAuth, rec.params, rec.hash.len)
  result = constantTimeEq(got, rec.hash)

proc needsRehash*(encoded: string,
    p: PasswordParams = defaultPasswordParams()): bool {.role: parser,
    tag: "cryptoBoundary|status".} =
  ## encoded: a stored hash.
  ## p: the cost this server would use today.
  ##
  ## True when the record is weaker than current policy, or unreadable.
  ## The moment to act on it is immediately after a SUCCESSFUL verify --
  ## that is the only time the plaintext password is in hand, and doing it
  ## then upgrades a user silently instead of asking them to change
  ## anything.
  var
    rec: PasswordRecord = parsePasswordHash(encoded)
  if not rec.ok:
    return true
  result = rec.params.memoryKiB < p.memoryKiB or
    rec.params.passes < p.passes or
    rec.params.lanes < p.lanes or
    rec.hash.len < passwordHashBytes

## ---------------------------- storage keys --------------------------

proc deriveKey*(password: string, salt: openArray[uint8],
    p: PasswordParams = defaultPasswordParams()): Secret {.role: encryptor,
    tag: "cryptoBoundary|keyLifecycle".} =
  ## password/salt: what unlocks a local store.
  ## p: the cost. Match whatever the store was sealed with.
  ##
  ## A DIFFERENT DOMAIN from `hashPassword`, which is the point: a server
  ## that is breached hands out authentication material, and that material
  ## must not decrypt anybody's mailbox. See the module note.
  ##
  ## Returns a move-only `Secret`, so key material cannot be copied by
  ## accident -- duplicating it is an explicit `clone()` at a call site
  ## somebody can review.
  result = initSecret(kdf(password, salt, keyDomainStorage, p,
    passwordHashBytes))

## ---------------------------- sealed blobs --------------------------
##
## Two ways to seal bytes that are not a Geist store, one layout for both:
##
##   | magic 4 | u8 n | n bytes: salt or nonce | u8 t | t bytes: tag | sealed |
##
##   magic   who made it         the n bytes         the key is
##   ------  ------------------  ------------------  ----------------------
##   GSB1    sealWithPassword    salt (16)           Argon2(password, salt)
##   GSK1    sealWithKey         nonce (24)          the caller's key
##
## Both then do the same two steps: a keystream derived from (key, salt or
## nonce) turns the bytes unreadable, and a tag over the result, the salt
## and the caller's `aad` proves nothing was changed. The salt or nonce is
## fresh per blob, so the same bytes sealed twice never look alike.

const
  sealMagic = "GSB1"
    ## Four bytes at the front of a password-sealed blob, so a file that
    ## is not one is refused by its shape rather than by a failed tag.
  keySealMagic = "GSK1"
    ## The same for a blob sealed with a key.
  sealKeyBytes* = 32
    ## The size `newSealKey` makes. `sealWithKey` refuses anything under 16.
  sealNonceBytes = 24

proc frameBlob(magic: string, salt, tag, sealed: openArray[uint8]): ByteSeq {.
    role: dataWriter, tag: "cryptoBoundary|write".} =
  ## magic/salt/tag/sealed: the four parts, laid out as the section note
  ## draws them.
  result = @[]
  for c in magic:
    result.add uint8(c)
  result.add uint8(salt.len)
  result.add salt
  result.add uint8(tag.len)
  result.add tag
  result.add sealed

proc hasMagic(magic: string, blob: openArray[uint8]): bool {.role: parser,
    inline, tag: "cryptoBoundary|read".} =
  ## magic/blob: does the blob start with these four letters?
  var
    i: int = 0
  while i < magic.len:
    if i >= blob.len or blob[i] != uint8(magic[i]):
      return false
    i = i + 1
  result = true

proc splitBlob(magic: string, blob: openArray[uint8]): tuple[ok: bool,
    salt: ByteSeq, tag: ByteSeq, sealed: ByteSeq, err: string] {.
    role: sanitizer, tag: "cryptoBoundary|read".} =
  ## magic/blob: the parts of a blob made by `frameBlob`, or why it is not
  ## one. Every length is checked before it is used.
  var
    o: int = magic.len
    n: int = 0
  if blob.len < magic.len + 2:
    return (false, @[], @[], @[], "not a sealed blob: too short")
  if not hasMagic(magic, blob):
    return (false, @[], @[], @[], "not a sealed blob: wrong magic")
  n = int(blob[o]); o = o + 1
  if o + n >= blob.len:
    return (false, @[], @[], @[], "not a sealed blob: truncated salt")
  result.salt = @(blob[o ..< o + n]); o = o + n
  n = int(blob[o]); o = o + 1
  if o + n > blob.len:
    return (false, @[], @[], @[], "not a sealed blob: truncated tag")
  result.tag = @(blob[o ..< o + n]); o = o + n
  result.sealed = @(blob[o ..< blob.len])
  result.ok = true

proc sealUnder(key: Secret, salt: openArray[uint8], plain: openArray[uint8],
    aad: openArray[uint8], magic: string): SealedBlob {.role: encryptor,
    tag: "cryptoBoundary|write".} =
  ## key/salt: what the keystream and the tag are derived from.
  ## plain/aad/magic: the bytes, their context, and which kind of blob.
  var
    stream: StreamKeys = deriveStreamKeys(key, salt)
    sealed: ByteSeq = applyKeystream(ckCascade, stream, 0'u64, plain)
    tag: ByteSeq = authTag(mkCombined, key, sealed, @salt & @aad)
  result.data = frameBlob(magic, salt, tag, sealed)
  result.ok = true

proc openUnder(key: Secret, salt, tag, sealed: openArray[uint8],
    aad: openArray[uint8], refusal: string): SealedBlob {.role: decryptor,
    tag: "cryptoBoundary|read".} =
  ## key/salt/tag/sealed/aad: the reverse of `sealUnder`, checked first.
  ## refusal: what to say when the tag does not match.
  ##
  ## A WRONG KEY AND A TAMPERED BLOB ARE THE SAME ANSWER, and that is
  ## deliberate: telling them apart tells an attacker which of the two they
  ## achieved.
  var
    stream: StreamKeys = default(StreamKeys)
  if not verifyTag(mkCombined, key, sealed, @salt & @aad, tag):
    return SealedBlob(err: refusal)
  stream = deriveStreamKeys(key, salt)
  result.data = applyKeystream(ckCascade, stream, 0'u64, sealed)
  result.ok = true

proc sealWithPassword*(password: string, plain: openArray[uint8],
    aad: openArray[uint8] = [], p: PasswordParams = defaultPasswordParams()):
    SealedBlob {.role: encryptor,
    tag: "cryptoBoundary|write".} =
  ## password: what will be needed to open it.
  ## plain: the bytes to protect.
  ## aad: context bound to the ciphertext but not hidden -- a filename, an
  ##   account. Changing it makes the blob refuse to open, which is how a
  ##   blob is stopped from being moved somewhere it does not belong.
  ## p: the cost.
  ##
  ## For the things a Geist store is the wrong shape for: a token cache, a
  ## session file, an export. A store is still the right answer for rows.
  ##
  ## The salt travels IN the blob. A caller who had to keep it beside the
  ## ciphertext would eventually lose one of the two.
  var
    bad: string = checkPassword(password)
    salt: ByteSeq = @[]
  if bad.len > 0:
    return SealedBlob(err: bad)
  salt = randomSalt()
  result = sealUnder(deriveKey(password, salt, p), salt, plain, aad,
    sealMagic)

proc openWithPassword*(password: string, blob: openArray[uint8],
    aad: openArray[uint8] = [], p: PasswordParams = defaultPasswordParams()):
    SealedBlob {.role: decryptor,
    tag: "cryptoBoundary|read".} =
  ## password/blob/aad/p: the reverse of `sealWithPassword`.
  var
    parts: tuple[ok: bool, salt: ByteSeq, tag: ByteSeq, sealed: ByteSeq,
      err: string] = splitBlob(sealMagic, blob)
  if not parts.ok:
    return SealedBlob(err: parts.err)
  result = openUnder(deriveKey(password, parts.salt, p), parts.salt,
    parts.tag, parts.sealed, aad,
    "wrong password, or the sealed data has been altered")

proc newSealKey*(): Secret {.role: configurator,
    tag: "cryptoBoundary|keyLifecycle".} =
  ## A fresh random key for `sealWithKey`, `sealBytes` and `sealObject`.
  ##
  ## Keep it where keys belong -- the OS keystore (`geist/keystore`) or a
  ## key file only its owner can read. Lose it and what it sealed is gone:
  ## there is no password to fall back on.
  result = initSecret(randomSalt(sealKeyBytes))

proc sealWithKey*(key: Secret, plain: openArray[uint8],
    aad: openArray[uint8] = []): SealedBlob {.role: encryptor,
    tag: "cryptoBoundary|write".} =
  ## key: from `newSealKey`, or `deriveKey` done ONCE for many blobs.
  ## plain/aad: as for `sealWithPassword`.
  ##
  ## The fast path. `sealWithPassword` pays Argon2 on every call, which is
  ## right for one blob and wrong for ten thousand; here the costly step
  ## happened once, when the key was made. A fresh 24-byte nonce per blob
  ## keeps every keystream different.
  if key.len < 16:
    return SealedBlob(err: "a sealing key must be at least 16 bytes")
  result = sealUnder(key, randomSalt(sealNonceBytes), plain, aad,
    keySealMagic)

proc openWithKey*(key: Secret, blob: openArray[uint8],
    aad: openArray[uint8] = []): SealedBlob {.role: decryptor,
    tag: "cryptoBoundary|read".} =
  ## key/blob/aad: the reverse of `sealWithKey`.
  var
    parts: tuple[ok: bool, salt: ByteSeq, tag: ByteSeq, sealed: ByteSeq,
      err: string] = splitBlob(keySealMagic, blob)
  if not parts.ok:
    return SealedBlob(err: parts.err)
  result = openUnder(key, parts.salt, parts.tag, parts.sealed, aad,
    "wrong key, or the sealed data has been altered")
