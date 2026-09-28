## ---------------------------------------------------------------------
## Geist Seal <- encrypt an object in memory, store the bytes yourself
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/geist_seal.nim
##
## A Geist STORE encrypts rows for you. This is for everything that is not
## a store: one object in a message, a token in a cookie, a record you keep
## in somebody else's database, a file you write with your own code.
##
##   object --sealObject(key)--> bytes   (write them anywhere)
##   bytes  --openObject(key)--> object  (or why not: wrong key, altered,
##                                         a different type)
##
## Two ways to hold the key:
##
##   newSealKey()            random, 32 bytes. Keep it in the OS keystore
##                           (geist/keystore) or a key file.
##   deriveKey(password,     from something a person types. Slow on
##     salt)                 purpose (Argon2); derive ONCE, seal many.
##
## sealObjectWithPassword does both steps per object -- simplest, and right
## for one object now and then; wrong for ten thousand, because every call
## pays the Argon2 cost again.

import runePragmas
import geist

type
  Login = object
    site: string
    user: string
    password: string
    uses: int

proc sampleLogin(): Login {.role: configurator.} =
  ## One record worth protecting.
  result = Login(site: "mail.example", user: "alice",
    password: "correct horse", uses: 3)

when isMainModule:
  var
    key: Secret = newSealKey()
    item: Login = sampleLogin()
    sealed: SealedBlob = default(SealedBlob)
    opened: tuple[ok: bool, value: Login, err: string] =
      (false, default(Login), "")
    wrong: tuple[ok: bool, value: Login, err: string] =
      (false, default(Login), "")
    byPassword: SealedBlob = default(SealedBlob)

  ## ── 1. Seal with a key: the bytes are yours to put anywhere ──
  ##
  ## `aad` is context bound to the ciphertext but not hidden. Sealed for
  ## "vault/alice", the blob refuses to open as anything else -- so it
  ## cannot be copied into bob's record and read there.
  sealed = sealObject(item, key, aad = "vault/alice")
  doAssert sealed.ok, sealed.err
  echo "sealed ", sealed.data.len, " bytes (no field readable in them)"

  ## ── 2. Open it again ──
  opened = openObject[Login](sealed.data, key, aad = "vault/alice")
  doAssert opened.ok, opened.err
  echo "opened: ", opened.value.user, "@", opened.value.site,
    " uses=", opened.value.uses

  ## ── 3. The wrong context is refused, not decrypted into garbage ──
  wrong = openObject[Login](sealed.data, key, aad = "vault/bob")
  echo "as vault/bob: ", (if wrong.ok: "OPENED (bug)" else: wrong.err)

  ## ── 4. One-off, by password ──
  byPassword = sealObjectWithPassword(item, "a long passphrase here")
  doAssert byPassword.ok, byPassword.err
  opened = openObjectWithPassword[Login](byPassword.data,
    "a long passphrase here")
  doAssert opened.ok, opened.err
  echo "by password: ", opened.value.password.len, "-character password ",
    "came back intact"
