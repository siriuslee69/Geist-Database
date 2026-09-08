## ---------------------------------------------------------------------
## Keystore <- where a key actually lives, per platform
## ---------------------------------------------------------------------
##
##   openKeystore(dir)  ->  put / get / drop / status
##                            |
##      +---------------------+---------------------+
##      |                     |                     |
##   ksFile               ksAndroid              ksMemory
##   Argon2id-sealed       Android Keystore       never written
##   file, portable        holds the wrapping     for tests and
##   everywhere            key in hardware        one-shot sessions
##
## A password manager on a phone has a problem a desktop does not: the
## master key has to survive being backgrounded, and the only place on
## Android where a key is genuinely protected is the Keystore, which
## never hands the key material back at all. It wraps and unwraps on
## your behalf inside hardware you cannot read.
##
## So this is not "a file, but on Android": the two providers have
## different shapes and the API is the intersection of what both can
## honestly do.
##
##   put(name, secret)      store it; ask nothing about how
##   get(name)              take it back, or say why not
##   drop(name)             forget it
##   status(name)           absent / present / INVALIDATED / unavailable
##
## `ksInvalidated` IS THE POINT OF THE FOURTH CASE. When a phone's owner
## adds a fingerprint, Android permanently destroys keys bound to
## biometrics. The bytes are gone and no password recovers them. Without
## a distinct status that surfaces as a decrypt failure, and a password
## manager that reports "wrong password" to someone whose password is
## right will have them typing it for an hour.
##
## WHAT IS AND IS NOT IMPLEMENTED HERE. `ksFile` and `ksMemory` are
## complete and tested. `ksAndroid` is a JNI SEAM: the Nim side, the
## status mapping and the fallback are here, and the calls resolve
## against a companion class the app ships (see `androidBridgeClass`).
## On a build with no Android runtime the provider REFUSES rather than
## pretending, and `openKeystore` falls back to `ksFile` and says so in
## `provider` -- an app that wants to warn "your keys are not in
## hardware" has to be able to find that out, so it is a value and not a
## silent decision.
##
## NOTHING HERE INVENTS CRYPTOGRAPHY. The file provider seals with the
## same Argon2id-derived key file the database uses (`keys.nim`), because
## a second, slightly different key-sealing path is how one of them ends
## up wrong.

import std/[os, strutils, tables]

import geistPragmas
import ./secret
import ./keys
import ./types

const
  androidBridgeClass* = "com/siriuslee/geist/GeistKeystore"
    ## The companion class an Android app must ship for `ksAndroid` to
    ## work. Named here rather than in the app so three apps cannot each
    ## pick a different one; see docs/keystore.md for its four methods.
  keystoreSuffix* = ".key"
    ## What a file-provider entry is called on disk, under the keystore
    ## directory. One file per name so dropping one cannot disturb another.
  maxSecretBytes* = 64 * 1024
    ## The largest thing this will store. A keystore holds keys; something
    ## larger is data, and data belongs in the database.

type
  KeyProvider* {.role: configurator, metaTags: {tagConfig, tagCryptoBoundary,
      tagTypes}.} = enum
    ## Where the bytes end up.
    ##
    ##   kpFile     an Argon2id-sealed file. Portable, and the default
    ##              everywhere the platform offers nothing better.
    ##   kpAndroid  the Android Keystore wraps the entry; the raw key
    ##              never exists outside hardware.
    ##   kpMemory   this process only. Nothing is written and nothing
    ##              survives, which is what a test wants and what a
    ##              one-shot session may prefer.
    kpFile, kpAndroid, kpMemory

  KeyStatus* {.role: truthState, metaTags: {tagCryptoBoundary, tagStatus,
      tagTypes}.} = enum
    ## What is known about one name.
    ##
    ##   ksAbsent       never stored, or dropped
    ##   ksPresent      there, and retrievable
    ##   ksInvalidated  there, and PERMANENTLY unreadable. The platform
    ##                  destroyed the wrapping key -- on Android, because
    ##                  the biometric enrolment changed. Re-enrolling does
    ##                  not bring it back; the entry must be re-created
    ##                  from whatever the user can still supply.
    ##   ksUnavailable  the provider is not usable right now: device
    ##                  locked, hardware busy, no runtime. TRY AGAIN is a
    ##                  reasonable response, which is what separates this
    ##                  from ksInvalidated.
    ksAbsent, ksPresent, ksInvalidated, ksUnavailable

  Keystore* {.role: truthState, metaTags: {tagCryptoBoundary, tagTypes}.} =
      object
    ## One place keys are kept.
    ##
    ## `provider` is what is ACTUALLY in use, which may not be what was
    ## asked for -- see `requested`. An app that cares (and a password
    ## manager does) compares the two and tells its user.
    provider*: KeyProvider
    requested*: KeyProvider
    dir*: string
    password*: string
    note*: string
    held: Table[string, seq[uint8]]

  KeyResult* {.role: truthState, metaTags: {tagCryptoBoundary, tagStatus,
      tagTypes}.} = object
    ## The answer to a `get`, with the reason when there is not one.
    ok*: bool
    status*: KeyStatus
    value*: Secret
    err*: string

proc describeProvider*(p: KeyProvider): string {.role: helper,
    metaTags: {tagCryptoBoundary, tagStatus}.} =
  ## p: one line an application can show a person.
  case p
  of kpFile:
    result = "a password-sealed file on this device"
  of kpAndroid:
    result = "the Android Keystore (the key never leaves hardware)"
  of kpMemory:
    result = "memory only -- nothing is saved and nothing survives a restart"

proc describeStatus*(s: KeyStatus): string {.role: helper,
    metaTags: {tagCryptoBoundary, tagStatus}.} =
  ## s: one line an application can show a person.
  case s
  of ksAbsent: result = "not stored"
  of ksPresent: result = "stored"
  of ksInvalidated:
    result = "permanently unreadable: the device destroyed the key that " &
      "protected it, usually because the screen lock or fingerprints " &
      "changed. It has to be set up again."
  of ksUnavailable:
    result = "temporarily unavailable: unlock the device and try again"

## ---------------------------- the android seam ----------------------

when defined(android):
  ## The JNI half. Declared, not guessed: each of these maps to one method
  ## of `androidBridgeClass`, and the app is what provides that class.
  ##
  ## Kept behind `when defined(android)` so a desktop build compiles no
  ## JNI at all -- and so this file's shape is obvious to someone reading
  ## it on a desktop, which is where it will be read.
  proc geistAndroidAvailable(): bool {.importc: "geist_android_ks_available",
    cdecl.}
  proc geistAndroidPut(name: cstring, data: ptr uint8,
    len: cint): cint {.importc: "geist_android_ks_put", cdecl.}
  proc geistAndroidGet(name: cstring, outBuf: ptr uint8,
    cap: cint): cint {.importc: "geist_android_ks_get", cdecl.}
  proc geistAndroidDrop(name: cstring): cint {.
    importc: "geist_android_ks_drop", cdecl.}
  proc geistAndroidStatus(name: cstring): cint {.
    importc: "geist_android_ks_status", cdecl.}

proc androidUsable*(): bool {.role: parser,
    metaTags: {tagCryptoBoundary, tagCompat}.} =
  ## Is the Android Keystore reachable from this process?
  ##
  ## False everywhere except an Android build whose app has loaded the
  ## companion class. This is a QUESTION and not an assumption: an app
  ## installed on a device with no hardware-backed keystore gets the same
  ## false, and falls back the same way.
  when defined(android):
    result = geistAndroidAvailable()
  else:
    result = false

## ---------------------------- opening -------------------------------

proc openKeystore*(dir: string, password: string = "",
    want: KeyProvider = kpFile): Keystore {.role: configurator,
    metaTags: {tagAppApi, tagCryptoBoundary, tagLifecycle}.} =
  ## dir: where a file provider keeps its entries. Created on first write.
  ## password: required by kpFile; ignored by the others, which do not
  ##   have anything for it to protect.
  ## want: the provider to use IF it is available.
  ##
  ## Never fails. A request for `kpAndroid` on a device that cannot
  ## provide it comes back as `kpFile` with `note` saying so, because the
  ## alternative -- refusing to open -- turns "your keys are less
  ## protected than you asked for" into "the app does not start".
  result.requested = want
  result.provider = want
  result.dir = dir
  result.password = password
  result.held = initTable[string, seq[uint8]]()
  if want == kpAndroid and not androidUsable():
    result.provider = kpFile
    result.note = "the Android Keystore is not available on this device; " &
      "falling back to " & describeProvider(kpFile)

proc downgraded*(k: Keystore): bool {.role: parser, inline,
    metaTags: {tagCryptoBoundary, tagStatus}.} =
  ## k: did this keystore end up weaker than it was asked to be?
  ##
  ## The thing a password manager shows a warning for. It is a single
  ## comparison so that no app has to reason about provider availability
  ## to know whether to worry.
  result = k.provider != k.requested

## ---------------------------- the file provider ---------------------

proc pathFor(k: Keystore, name: string): string {.role: helper,
    metaTags: {tagCryptoBoundary}.} =
  ## k/name: where the file provider keeps one entry.
  result = k.dir / name & keystoreSuffix

proc checkName*(name: string): string {.role: sanitizer,
    metaTags: {tagCryptoBoundary, tagParsing}.} =
  ## name: the complaint, empty when there is none.
  ##
  ## A name becomes a path segment, so `..` and separators are refused
  ## outright. Nothing else about this module would stop a caller from
  ## naming a key `../../.ssh/id_ed25519`.
  var
    i: int = 0
  if name.len == 0:
    return "a key needs a name"
  if name.len > 128:
    return "key name is longer than 128 bytes"
  if name.contains("..") or name.contains("/") or name.contains("\\"):
    return "key name '" & name & "' contains a path separator"
  while i < name.len:
    if not (name[i] in {'a' .. 'z', 'A' .. 'Z', '0' .. '9', '-', '_', '.'}):
      return "key name '" & name & "' has an illegal character at " & $i
    i = i + 1
  result = ""

proc putFile(k: Keystore, name: string, value: openArray[uint8]): tuple[
    ok: bool, err: string] {.role: encryptor,
    metaTags: {tagCryptoBoundary, tagStorageIo, tagWrite}.} =
  ## k/name/value: sealed with the same key file the database uses.
  ##
  ## One KeySet per entry: dropping one key must not require rewriting
  ## the others, and a corrupt entry must not take the rest with it.
  var
    K: KeySet = newKeySet()
  if k.password.len == 0:
    return (false, "a file keystore needs a password; without one the " &
      "entry would be sealed with nothing")
  try:
    createDir(k.dir)
  except CatchableError as exc:
    return (false, exc.msg)
  # The secret IS the key file's master. A KeySet seals exactly one root
  # secret under an Argon2id-derived key, which is what an entry needs;
  # the ledger records beside it stay empty because nothing derives from
  # this one.
  discard K.allocKeyRef(name)
  K.master = initSecret(value)
  result = writeKeyFile(k.pathFor(name), k.password, K)

proc getFile(k: Keystore, name: string): KeyResult {.role: decryptor,
    metaTags: {tagCryptoBoundary, tagRead, tagStorageIo}.} =
  ## k/name: unsealed, or the reason it was not.
  ##
  ## A file that is THERE and will not open is reported as a failure with
  ## the reason, never as absent. "You never stored this" and "your
  ## password is wrong" are different things to be told.
  var
    read: tuple[ok: bool, keys: KeySet, err: string]
  if not fileExists(k.pathFor(name)):
    result.status = ksAbsent
    result.err = "no key called '" & name & "'"
    return
  read = readKeyFile(k.pathFor(name), k.password)
  if not read.ok:
    result.status = ksPresent
    result.err = read.err
    return
  if read.keys.master.len == 0:
    result.status = ksPresent
    result.err = "key file for '" & name & "' held no material"
    return
  result.ok = true
  result.status = ksPresent
  result.value = read.keys.master.clone()

## ---------------------------- the api -------------------------------

proc put*(S: var Keystore, name: string,
    value: openArray[uint8]): tuple[ok: bool, err: string] {.
    role: dataWriter, metaTags: {tagAppApi, tagCryptoBoundary, tagWrite}.} =
  ## S/name/value: store one secret under one name, replacing any before.
  var
    err: string = checkName(name)
    rc: cint = 0
  if err.len > 0:
    return (false, err)
  if value.len == 0:
    return (false, "refusing to store an empty secret for '" & name & "'")
  if value.len > maxSecretBytes:
    return (false, "'" & name & "' is " & $value.len & " bytes; the limit " &
      "is " & $maxSecretBytes & ". A keystore holds keys, not data")
  case S.provider
  of kpMemory:
    S.held[name] = @value
    result = (true, "")
  of kpFile:
    result = S.putFile(name, value)
  of kpAndroid:
    when defined(android):
      rc = geistAndroidPut(name.cstring, cast[ptr uint8](unsafeAddr value[0]),
        cint(value.len))
      result = (rc == 0, (if rc == 0: "" else:
        "the Android Keystore refused to store '" & name & "' (code " &
        $rc & ")"))
    else:
      result = (false, "this build has no Android Keystore")

proc get*(s: Keystore, name: string): KeyResult {.role: dataFetcher,
    metaTags: {tagAppApi, tagCryptoBoundary, tagRead}.} =
  ## s/name: the secret, or why not.
  ##
  ## Check `status` before `err` when showing a person anything:
  ## `ksInvalidated` is not a mistake they can correct by trying again.
  var
    err: string = checkName(name)
    buf: seq[uint8] = @[]
    n: cint = 0
  if err.len > 0:
    result.err = err
    return
  case s.provider
  of kpMemory:
    if not s.held.hasKey(name):
      result.status = ksAbsent
      result.err = "no key called '" & name & "'"
      return
    result.ok = true
    result.status = ksPresent
    result.value = initSecret(s.held[name])
  of kpFile:
    result = s.getFile(name)
  of kpAndroid:
    when defined(android):
      buf = newSeq[uint8](maxSecretBytes)
      n = geistAndroidGet(name.cstring, addr buf[0], cint(buf.len))
      if n < 0:
        result.status = KeyStatus(-n)
        result.err = describeStatus(result.status)
        return
      buf.setLen(int(n))
      result.ok = true
      result.status = ksPresent
      result.value = initSecret(buf)
    else:
      result.status = ksUnavailable
      result.err = "this build has no Android Keystore"

proc drop*(S: var Keystore, name: string): tuple[ok: bool, err: string] {.
    role: stateController, metaTags: {tagAppApi, tagCryptoBoundary,
    tagDelete}.} =
  ## S/name: forget one secret. Dropping something that is not there is a
  ## SUCCESS -- the caller asked for it to be gone and it is gone.
  var
    err: string = checkName(name)
    rc: cint = 0
  if err.len > 0:
    return (false, err)
  case S.provider
  of kpMemory:
    S.held.del(name)
    result = (true, "")
  of kpFile:
    try:
      removeFile(S.pathFor(name))
      result = (true, "")
    except CatchableError as exc:
      result = (false, exc.msg)
  of kpAndroid:
    when defined(android):
      rc = geistAndroidDrop(name.cstring)
      result = (rc == 0, (if rc == 0: "" else: "code " & $rc))
    else:
      result = (false, "this build has no Android Keystore")

proc status*(s: Keystore, name: string): KeyStatus {.role: parser,
    metaTags: {tagAppApi, tagCryptoBoundary, tagStatus}.} =
  ## s/name: what is known about this entry, without unsealing it.
  ##
  ## Cheap on purpose: a startup path that wants to know whether to show
  ## an unlock screen or a setup screen should not have to run Argon2id
  ## to find out.
  var
    rc: cint = 0
  if checkName(name).len > 0:
    return ksAbsent
  case s.provider
  of kpMemory:
    result = if s.held.hasKey(name): ksPresent else: ksAbsent
  of kpFile:
    result = if fileExists(s.pathFor(name)): ksPresent else: ksAbsent
  of kpAndroid:
    when defined(android):
      rc = geistAndroidStatus(name.cstring)
      result = if rc >= 0 and rc <= ord(high(KeyStatus)): KeyStatus(rc)
               else: ksUnavailable
    else:
      result = ksUnavailable

proc names*(s: Keystore): seq[string] {.role: parser,
    metaTags: {tagAppApi, tagCryptoBoundary, tagRead}.} =
  ## s: every name this keystore holds.
  ##
  ## The Android provider does not answer this: its entries are enumerable
  ## only through the platform's own alias list, and an app that needs the
  ## list should keep it beside the keys rather than ask the hardware.
  var
    t: string = ""
  result = @[]
  case s.provider
  of kpMemory:
    for key in s.held.keys:
      result.add key
  of kpFile:
    if not dirExists(s.dir):
      return
    for kind, path in walkDir(s.dir):
      t = path.extractFilename()
      if t.endsWith(keystoreSuffix):
        result.add t[0 ..< t.len - keystoreSuffix.len]
  of kpAndroid:
    discard

proc closeKeystore*(S: var Keystore) {.role: stateController,
    metaTags: {tagCryptoBoundary, tagLifecycle}.} =
  ## S: forget everything held in memory. The file and Android providers
  ## have nothing to close; the memory one has everything.
  for key in S.held.keys:
    volatileClear(S.held[key])
  S.held.clear()
