## ---------------------------------------------------------------------
## Users <- a sign-in database, so no application writes one twice
## ---------------------------------------------------------------------
##
##   openUsers(home, "fjord")   ->  db/fjord/users
##        |
##        +-- createUser(name, password)
##        +-- authenticate(name, password)   -> ok / why not
##        +-- setPassword, disable, delete
##
## Fjord and Eris both need exactly this and neither should invent it. A
## user table is one of those things that looks like ten lines and is not:
## the ten lines are easy and the ones that matter are the ones about what
## a FAILED sign-in is allowed to reveal.
##
## THE RULES THAT ARE NOT OBVIOUS, and are the reason this is shared:
##
## AN UNKNOWN USER AND A WRONG PASSWORD LOOK THE SAME. Both come back as
## `arWrong` with one message. Distinguishing them turns the sign-in form
## into a tool for discovering who has an account -- and the two paths
## must also take the same TIME, so an unknown name still runs a
## derivation against a dummy hash before failing.
##
## A DISABLED ACCOUNT IS DIFFERENT, and is told apart on purpose. Someone
## whose account was suspended needs to know that rather than being told
## their password is wrong for ever. It is only revealed AFTER the
## password verifies, so it cannot be used to enumerate accounts either.
##
## THE PASSWORD IS NEVER STORED, and neither is anything derived from it
## with the storage domain. `UserRecord.password` holds what
## `hashPassword` produced -- an Argon2id output with its own salt and its
## own cost, useless for decrypting anything. See `secrets.nim` for why
## those are deliberately different derivations.
##
## REHASHING HAPPENS ON SUCCESSFUL SIGN-IN, which is the only moment the
## plaintext exists. `authenticate` reports it; `signIn` does it. An
## application that raises its cost gets its users upgraded as they return
## rather than by asking anybody to do anything.

import std/[algorithm, os, strutils, times]

import ../analysis_pragmas
import ./types
import ./config
import ./layout
import ./secret
import ./secrets
import ./session

const
  usersTarget* = "users"
    ## Where an application's sign-in database lives, under its own app
    ## directory: `db/<app>/users`. One per app and per instance, because
    ## a staging deployment must not share production's accounts.

  maxUserNameBytes* = 64
    ## A name longer than this is refused. It has to fit a row comfortably
    ## and appear in a log line without wrapping.

type
  AuthResult* {.role: truthState, metaTags: {tagCryptoBoundary, tagStatus,
      tagTypes}.} = enum
    ## What a sign-in attempt was.
    ##
    ##   arOk        the password is right and the account is usable
    ##   arWrong     no such user, OR the wrong password. ONE answer on
    ##               purpose -- see the module note
    ##   arDisabled  right password, account suspended
    ##   arRefused   the request itself was malformed
    arOk, arWrong, arDisabled, arRefused

  UserRecord* {.role: truthState, metaTags: {tagCryptoBoundary,
      tagTypes}.} = object
    ## One account.
    ##
    ## `password` is the ENCODED hash from `hashPassword`, not a password
    ## and not a key. `salt` is a separate per-user value for deriving
    ## that user's STORAGE key -- kept here so a client can unlock its
    ## local store with the same password after signing in, without the
    ## server ever holding anything that could do the unlocking.
    name*: string
    displayName*: string
    password*: string
    salt*: string
    createdAt*: int64
    updatedAt*: int64
    lastSeenAt*: int64
    disabled*: bool
    role*: string

  AuthOutcome* {.role: truthState, metaTags: {tagCryptoBoundary, tagStatus,
      tagTypes}.} = object
    ## The answer, and what to do about it.
    ##
    ## `rehash` is true when the stored hash is weaker than current policy
    ## and the caller is holding a plaintext that verified -- the one
    ## moment an upgrade is possible.
    result*: AuthResult
    reason*: string
    rehash*: bool
    user*: UserRecord

  UserStore* {.role: truthState, metaTags: {tagCryptoBoundary, tagTypes}.} =
      object
    ## An open sign-in database.
    ##
    ## Filled in place like every other store handle, because `Session`
    ## owns a move-only `Secret` and cannot be copied out of a tuple.
    session*: Session
    app*: string
    instance*: string
    root*: string
    open*: bool

  UserResult* {.role: truthState, metaTags: {tagStatus, tagTypes}.} = object
    ok*: bool
    err*: string

proc userOk(): UserResult {.role: helper, inline,
    metaTags: {tagCryptoBoundary}.} =
  result.ok = true

proc userErr(err: string): UserResult {.role: helper, inline,
    metaTags: {tagCryptoBoundary}.} =
  result.err = err

proc checkUserName*(name: string): string {.role: sanitizer,
    metaTags: {tagCryptoBoundary}.} =
  ## name: refused with a reason, or "" when it is usable.
  ##
  ## A user name is not a path segment here -- users live in ROWS, not in
  ## directories -- but it is still bounded and restricted, because it
  ## ends up in log lines, in address targets and in whatever an
  ## application does with it next.
  var
    i: int = 0
  if name.len == 0:
    return "a user name must not be empty"
  if name.len > maxUserNameBytes:
    return "a user name longer than " & $maxUserNameBytes & " bytes"
  while i < name.len:
    if not (name[i] in {'a' .. 'z', '0' .. '9', '-', '_', '.', '@'}):
      return "a user name may only hold a-z, 0-9, '-', '_', '.' and '@'; '" &
        name & "' does not"
    i = i + 1
  result = ""

proc openUsers*(S: var UserStore, h: GeistHome, app: string,
    c: GeistConfig, password: string = "", readOnly: bool = false,
    instance: string = ""): UserResult {.role: orchestrator,
    metaTags: {tagCryptoBoundary, tagStorageIo}.} =
  ## S: the store handle, filled in place.
  ## h: this machine's one Geist folder.
  ## app: which application's users -- `fjord`, `eris`.
  ## c: the Geist configuration. `secureAppConfig()` and an at-rest
  ##   password are the right choice for a server: the hashes inside are
  ##   already useless for decryption, but the NAMES are not, and a
  ##   plaintext user table is a membership list.
  ## password: the at-rest secret for the store itself. NOT any user's.
  ## readOnly/instance: as everywhere else.
  var
    root: string = h.appDir(app, instance) / usersTarget
  if app.len == 0:
    return userErr("a user store needs an app name")
  try:
    createDir(root)
  except CatchableError as exc:
    return userErr(root & ": " & exc.msg)
  # `openSession` rather than `openGeist`, which lives in the door module
  # that imports this one. Same call underneath -- `openGeist` only splits
  # a path into a directory and a stem, and this one is already a
  # directory.
  S.session = openSession[UserRecord](root, "main", c, password, readOnly)
  S.app = app
  S.instance = instance
  S.root = root
  S.open = true
  result = userOk()

proc saveUsers*(S: var UserStore): UserResult {.role: dataWriter,
    metaTags: {tagCryptoBoundary, tagStorageIo, tagWrite}.} =
  ## S: publish a new generation.
  var
    t: tuple[ok: bool, err: string]
  if not S.open:
    return userErr("user store is not open")
  t = S.session.save()
  result = UserResult(ok: t.ok, err: t.err)

proc closeUsers*(S: var UserStore): UserResult {.role: stateController,
    metaTags: {tagCryptoBoundary, tagLifecycle, tagStorageIo}.} =
  ## S: save what is pending and release the lease.
  if not S.open:
    return userOk()
  S.session.close()
  S.open = false
  result = userOk()

proc userRowFor*(s: UserStore, name: string): tuple[found: bool, id: RowId] {.
    role: parser, metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s/name: where a user sits, or that they do not.
  var
    ids: seq[RowId] = @[]
  if not s.open:
    return (false, 0'u64)
  ids = s.session.findIds("name", name.toLowerAscii())
  if ids.len == 0:
    return (false, 0'u64)
  result = (true, ids[0])

proc getUser*(s: UserStore, name: string): tuple[found: bool,
    value: UserRecord] {.role: dataFetcher,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s/name: one account, or that there is none.
  ##
  ## Returns the record INCLUDING the encoded hash, because the caller is
  ## the server that owns it. Nothing here ever sends one anywhere.
  var
    at: tuple[found: bool, id: RowId] = s.userRowFor(name)
  if not at.found:
    return (false, UserRecord())
  result = s.session.byId[:UserRecord](at.id)

proc userExists*(s: UserStore, name: string): bool {.role: parser,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s/name: is there such an account?
  result = s.getUser(name).found

proc createUser*(S: var UserStore, name, password: string,
    displayName: string = "", userRole: string = ""): UserResult {.
    role: dataWriter, metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## S: the user store, open for writing.
  ## name: the account name, lower-cased on the way in.
  ## password: what the person chose. Hashed here and never stored.
  ## displayName/userRole: whatever the application wants them to mean.
  ##
  ## Refuses a name that already exists rather than replacing it. An
  ## overwrite would be an account takeover spelled as a typo.
  var
    who: string = name.toLowerAscii()
    bad: string = checkUserName(who)
    hashed: PasswordRecord
    r: UserRecord
  if not S.open:
    return userErr("user store is not open")
  # Checked AFTER lower-casing, or `Alice` would be refused for holding a
  # character the stored form never contains.
  if bad.len > 0:
    return userErr(bad)
  if S.userExists(who):
    return userErr("there is already an account called " & who)
  hashed = hashPassword(password)
  if not hashed.ok:
    return userErr(hashed.err)
  r.name = who
  r.displayName = (if displayName.len > 0: displayName else: who)
  r.password = hashed.encoded
  # A per-user salt for deriving THAT user's storage key. Generated here
  # so it exists from the first moment and never has to be invented
  # later by whichever component happens to need it first.
  r.salt = encodeSalt(randomSalt())
  r.createdAt = getTime().toUnix()
  r.updatedAt = r.createdAt
  r.role = userRole
  discard S.session.put(r)
  result = userOk()

proc setPassword*(S: var UserStore, name, password: string): UserResult {.
    role: dataWriter, metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## S/name/password: replace the stored hash.
  ##
  ## THE STORAGE SALT IS NOT ROTATED. Changing a password must not make
  ## the person's existing local stores unopenable -- the salt is what
  ## ties the new password to the same derived key, and rotating it here
  ## would silently destroy data on every device they own.
  var
    at: tuple[found: bool, id: RowId]
    got: tuple[found: bool, value: UserRecord]
    hashed: PasswordRecord
  if not S.open:
    return userErr("user store is not open")
  at = S.userRowFor(name)
  if not at.found:
    return userErr("no account called " & name.toLowerAscii())
  got = S.session.byId[:UserRecord](at.id)
  if not got.found:
    return userErr("no account called " & name.toLowerAscii())
  hashed = hashPassword(password)
  if not hashed.ok:
    return userErr(hashed.err)
  got.value.password = hashed.encoded
  got.value.updatedAt = getTime().toUnix()
  S.session.set(at.id, got.value)
  result = userOk()

proc setDisabled*(S: var UserStore, name: string,
    disabled: bool): UserResult {.role: dataWriter,
    metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## S/name/disabled: suspend or restore an account without deleting it.
  var
    at: tuple[found: bool, id: RowId]
    got: tuple[found: bool, value: UserRecord]
  if not S.open:
    return userErr("user store is not open")
  at = S.userRowFor(name)
  if not at.found:
    return userErr("no account called " & name.toLowerAscii())
  got = S.session.byId[:UserRecord](at.id)
  if not got.found:
    return userErr("no account called " & name.toLowerAscii())
  got.value.disabled = disabled
  got.value.updatedAt = getTime().toUnix()
  S.session.set(at.id, got.value)
  result = userOk()

proc deleteUser*(S: var UserStore, name: string): UserResult {.
    role: dataWriter, metaTags: {tagCryptoBoundary, tagDelete, tagWrite}.} =
  ## S/name: a tombstone, so the removal can reach a mirror.
  var
    at: tuple[found: bool, id: RowId]
  if not S.open:
    return userErr("user store is not open")
  at = S.userRowFor(name)
  if not at.found:
    return userOk()
  S.session.delete(at.id)
  result = userOk()

proc userNames*(s: UserStore): seq[string] {.role: parser,
    metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s: every account, sorted.
  var
    i: uint32 = 0
    total: uint32 = 0
    one: UserRecord
  result = @[]
  if not s.open:
    return @[]
  total = s.session.entryCount()
  while i < total:
    one = s.session.get[:UserRecord](i)
    i = i + 1'u32
    if one.name.len > 0:
      result.add one.name
  result.sort()

## ---------------------------- signing in ----------------------------

const
  dummyHash = "geist$argon2id$v=1$m=65536,t=3,p=4$" &
    "AAAAAAAAAAAAAAAAAAAAAA==$" &
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ## A well-formed hash that no password matches, at the DEFAULT cost.
    ##
    ## Verified against when the account does not exist, so an unknown
    ## name costs the same time as a known one. Without it, a sign-in form
    ## answers "no such user" in a millisecond and "wrong password" in a
    ## tenth of a second, and anyone can read an account list off the
    ## clock.

proc authenticate*(s: UserStore, name, password: string): AuthOutcome {.
    role: sanitizer, metaTags: {tagCryptoBoundary, tagRead}.} =
  ## s: the user store.
  ## name/password: what was typed.
  ##
  ## Does NOT write, so it is safe on a read-only replica and safe to call
  ## from anywhere. `signIn` is the writing version.
  ##
  ## An unknown user and a wrong password are ONE answer in one time. See
  ## the module note for why that matters more than the better error
  ## message it costs.
  var
    got: tuple[found: bool, value: UserRecord]
  if not s.open:
    return AuthOutcome(result: arRefused, reason: "user store is not open")
  # Lower-cased before the check for the same reason as `createUser`:
  # someone who typed their name with a capital is not making a malformed
  # request.
  if checkUserName(name.toLowerAscii()).len > 0 or
      checkPassword(password).len > 0:
    # Malformed, and still charged a derivation: refusing instantly would
    # separate "impossible name" from "wrong password" on the clock.
    discard verifyPassword((if password.len > 0: password else: "x"),
      dummyHash)
    return AuthOutcome(result: arWrong,
      reason: "that user name and password do not match an account")
  got = s.getUser(name)
  if not got.found:
    discard verifyPassword(password, dummyHash)
    return AuthOutcome(result: arWrong,
      reason: "that user name and password do not match an account")
  if not verifyPassword(password, got.value.password):
    return AuthOutcome(result: arWrong,
      reason: "that user name and password do not match an account")
  # The password is right. Only now is it safe to say more: a disabled
  # account revealed before this point would be an account oracle.
  if got.value.disabled:
    return AuthOutcome(result: arDisabled, user: got.value,
      reason: "that account is disabled")
  result = AuthOutcome(result: arOk, user: got.value,
    rehash: needsRehash(got.value.password))

proc signIn*(S: var UserStore, name, password: string): AuthOutcome {.
    role: orchestrator, metaTags: {tagCryptoBoundary, tagWrite}.} =
  ## S: the user store, open for writing.
  ## name/password: what was typed.
  ##
  ## `authenticate`, plus the two things that need a write: the rehash and
  ## `lastSeenAt`.
  ##
  ## THE REHASH HAPPENS HERE because this is the only moment the plaintext
  ## exists. A server that raised its Argon2 cost gets its users upgraded
  ## as they come back, without asking anyone to change anything.
  var
    at: tuple[found: bool, id: RowId]
    got: tuple[found: bool, value: UserRecord]
  result = S.authenticate(name, password)
  if result.result != arOk:
    return
  at = S.userRowFor(name)
  if not at.found:
    return
  got = S.session.byId[:UserRecord](at.id)
  if not got.found:
    return
  got.value.lastSeenAt = getTime().toUnix()
  if result.rehash:
    var hashed = hashPassword(password)
    if hashed.ok:
      got.value.password = hashed.encoded
      got.value.updatedAt = got.value.lastSeenAt
  S.session.set(at.id, got.value)
  result.user = got.value

proc storageKeyFor*(u: UserRecord, password: string): Secret {.
    role: encryptor, metaTags: {tagCryptoBoundary, tagKeyLifecycle}.} =
  ## u: the record, for its per-user salt.
  ## password: the same password they signed in with.
  ##
  ## The key that unlocks THAT user's local stores. Derived in the storage
  ## domain, so it is not the value the server holds -- a stolen user
  ## table cannot open anything, which is the property `secrets.nim`
  ## exists to guarantee.
  ##
  ## The caller must have verified the password first. This function
  ## cannot: it is given a record and a string and has no way to tell
  ## whether the string was checked.
  result = deriveKey(password, decodeSalt(u.salt))

proc describeAuth*(o: AuthOutcome): string {.role: helper,
    metaTags: {tagCryptoBoundary, tagStatus}.} =
  ## o: one line for a log.
  ##
  ## Deliberately says nothing a log reader could use to enumerate
  ## accounts, because logs are read by more people than databases are.
  case o.result
  of arOk: result = "signed in"
  of arWrong: result = "sign-in refused"
  of arDisabled: result = "sign-in refused: account disabled"
  of arRefused: result = "sign-in refused: " & o.reason
