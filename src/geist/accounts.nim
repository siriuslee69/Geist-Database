## ---------------------------------------------------------------------
## Accounts <- who somebody is: a name, public keys, a login check
## ---------------------------------------------------------------------
##
##   account   a name, a random id, the keys of its devices
##   id        32 hex characters. Boxes list ids, not names, so a box means the
##             same on every machine and a name can change.
##   key id    names one device's public key. Made by the caller.
##
## The password never comes here. The caller hands over a hash that only proves
## knowledge of it, and bytes this module never looks into:
##
##   stored per account      what it is for
##   ----------------------  -------------------------------------------------
##   authHash                compared at login, in constant time
##   settings                how the device makes its keys from the password
##   sealedMaster            the master key, sealed; opens only on a device
##
## Def. 1 (decoys): for a name that does not exist, `accountIdOf` still answers,
##   with an id made from a secret of this store and the name. The same name
##   always gets the same answer, so nobody can list accounts by asking.
## Def. 2 (login): a known and an unknown name take the same path and give the
##   same answer.
##
## Everything is one log (./boxlog): an account changes in one record, so a
## crash leaves the old state or the new one, never half.

import std/[json, os, strutils, sysrand, tables]

import runePragmas
import ./types
import ./lease
import ./durable
import ./textfile
import ./crypto/hashing
import ./crypto/hashwidths
import ./boxtypes
import ./boxlog

const
  accountMaxDevices* = 8
  accountNameMax* = 64
  accountsBox = "accounts/all"
  decoyFile = "decoy.key"
  accountIdBytes = 16

type
  AccountRow* {.role: truthState, tag: "accounts|types",
      expectedCount: [0, -1], lifeCycle: lcForever.} = object
    ## One account.
    id*: string
    name*: string
    authHash*: ByteSeq
    settings*: ByteSeq
    sealedMaster*: ByteSeq
    keys*: seq[string]
    createdMs*: uint64
    disabled*: bool

  Accounts* {.role: truthState, tag: "accounts|types",
      expectedCount: 1, lifeCycle: lcForever.} = ref object
    ## Every account of one store.
    lease*: Lease
    log*: BoxFile
    byName*: Table[string, AccountRow]
    nameOfId*: Table[string, string]
    nameOfKey*: Table[string, string]
    decoySecret*: ByteSeq

  AccountLogin* {.role: preparedData, tag: "accounts|types".} = object
    ## What a successful login gives.
    ok*: bool
    id*: string
    settings*: ByteSeq
    sealedMaster*: ByteSeq

proc validAccountName*(s: string): bool {.role: sanitizer, tag: "accounts".} =
  ## s: 1 to 64 lower-case letters, digits, '-', '_', '.'; never '.' first.
  result = s.len > 0 and s.len <= accountNameMax and s[0] != '.' and
    s.allCharsInSet({'a'..'z', '0'..'9', '-', '_', '.'})

proc rowJson(R: AccountRow): string {.role: dataWriter.} =
  ## R: as text, for the log.
  result = $(%*{"id": R.id, "name": R.name, "auth": hexText(R.authHash),
    "settings": hexText(R.settings), "master": hexText(R.sealedMaster),
    "keys": R.keys, "at": $R.createdMs, "off": R.disabled})

proc rowOf(s: string): AccountRow {.role: parser.} =
  ## s: as `rowJson` wrote it. Raises when malformed.
  var
    n: JsonNode = parseJson(s)
  result = AccountRow(id: n["id"].getStr(), name: n["name"].getStr(),
    authHash: unhexText(n["auth"].getStr()), settings: unhexText(n["settings"].getStr()),
    sealedMaster: unhexText(n["master"].getStr()),
    createdMs: parseBiggestUInt(n["at"].getStr()), disabled: n["off"].getBool())
  for k in n["keys"].items:
    result.keys.add(k.getStr())

proc remember(A: Accounts, R: AccountRow) {.role: truthBuilder.} =
  ## A/R: this row is the newest; every map follows it.
  if A.byName.hasKey(R.name):
    for old in A.byName[R.name].keys:
      A.nameOfKey.del(old)
  A.byName[R.name] = R
  A.nameOfId[R.id] = R.name
  for k in R.keys:
    A.nameOfKey[k] = R.name

proc loadDecoySecret(dir: string): ByteSeq {.role: dataFetcher.} =
  ## dir: the secret of Def. 1, made once.
  var
    path: string = dir / decoyFile
    done: tuple[ok: bool, err: string] = (false, "")
  if fileExists(path):
    return cast[ByteSeq](readFile(path))
  result = urandom(fullDigestBytes)
  done = writeDurable(path, result)
  if not done.ok:
    raise newException(IOError, done.err)

proc replayRows(A: Accounts) {.role: truthBuilder.} =
  ## A: every row read back from the log.
  var
    got: tuple[ok: bool, item: BoxItem] = (false, BoxItem())
  for key, slot in A.log.index.pairs:
    got = readWholeItem(A.log, slot)
    if not got.ok:
      raise newException(IOError, "the account " & key & " is damaged")
    A.remember(rowOf(textOfBytes(got.item.data)))

proc openAccounts*(dir: string, atRest: BoxKey = nil): tuple[ok: bool,
    accounts: Accounts, err: string] {.role: orchestrator,
    tag: "accounts|appApi|storageIo".} =
  ## dir: the folder. atRest: seals the rows, nil for none. One program at a time.
  var
    got: tuple[ok: bool, lease: Lease, err: string] = (false, Lease(), "")
    made: tuple[ok: bool, err: string] = (false, "")
    A: Accounts = nil
  try:
    createDir(dir)
    got = acquireLease(dir)
    if not got.ok:
      return (false, nil, got.err)
    A = Accounts(lease: got.lease, decoySecret: loadDecoySecret(dir),
      log: makeBoxFile(dir, accountsBox, atRest),
      byName: initTable[string, AccountRow](), nameOfId: initTable[string, string](),
      nameOfKey: initTable[string, string]())
    if fileExists(dir / boxLogName):
      made = openBoxFile(A.log)
    else:
      made = createBoxFile(A.log, BoxHead(kind: "accounts", id: "all", owner: "system"))
    if not made.ok:
      return (false, nil, made.err)
    A.replayRows()
    result = (true, A, "")
  except CatchableError as e:
    result = (false, nil, e.msg)

proc closeAccounts*(A: Accounts) {.role: actor, tag: "accounts|appApi|storageIo".} =
  ## A: the log closed, the lease given back.
  closeBoxFile(A.log)
  releaseLease(A.lease)

proc saveRow(A: Accounts, R: AccountRow, nowMs: uint64): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "accounts|storageIo|write".} =
  ## A/R/nowMs: the newest state of one account, durably.
  var
    item: BoxItem = BoxItem(key: R.name, number: A.log.counter + 1'u64, version: 1'u64,
      writer: "system", atMs: nowMs, data: textBytes(rowJson(R)))
  try:
    appendFrame(A.log, brItem, encodeItem(item))
    result = syncBox(A.log)
    if result.ok:
      A.remember(R)
    if result.ok and A.log.needsCompacting():
      result = compactBox(A.log)
  except CatchableError as e:
    result = (false, e.msg)

proc decoyId(A: Accounts, name: string): string {.role: helper.} =
  ## A/name: Def. 1.
  result = hexText(geistHash(hkBlake3, A.decoySecret & textBytes("id:" & name),
    accountIdBytes))

proc accountIdOf*(A: Accounts, name: string): string {.role: parser,
    tag: "accounts|appApi".} =
  ## A/name: the id of this account, or a decoy (Def. 1).
  if A.byName.hasKey(name):
    return A.byName[name].id
  result = A.decoyId(name)

proc accountOfKey*(A: Accounts, keyId: string): string {.role: parser,
    tag: "accounts|appApi".} =
  ## A/keyId: the id of the account this device key belongs to, or "".
  var
    n: string = A.nameOfKey.getOrDefault(keyId)
  if n.len > 0 and not A.byName[n].disabled:
    result = A.byName[n].id

proc accountSettings*(A: Accounts, name: string): tuple[found: bool, settings: ByteSeq] {.
    role: parser, tag: "accounts|appApi".} =
  ## A/name: how this account's device makes its keys. found = false: the caller
  ## must answer with made-up settings, and can make them from `decoySecret`.
  if A.byName.hasKey(name):
    result = (true, A.byName[name].settings)

proc createAccount*(A: Accounts, name: string, authHash, settings,
    sealedMaster: openArray[uint8], keyId: string, nowMs: uint64): tuple[ok: bool,
    id: string, err: string] {.role: actor, tag: "accounts|appApi|storageIo|write".} =
  ## A/name: the new account. authHash/settings/sealedMaster: see the top.
  ## keyId: its first device. nowMs: the clock.
  var
    R: AccountRow = AccountRow()
    done: tuple[ok: bool, err: string] = (false, "")
  if not validAccountName(name):
    return (false, "", "a name is 1 to 64 of a-z, 0-9, - _ .")
  if authHash.len != fullDigestBytes or keyId.len == 0:
    return (false, "", "an account needs a login hash and a device key")
  if A.byName.hasKey(name):
    return (false, "", "that name is taken")
  if A.nameOfKey.hasKey(keyId):
    return (false, "", "this device key already belongs to an account")
  R = AccountRow(id: hexText(urandom(accountIdBytes)), name: name, authHash: @authHash,
    settings: @settings, sealedMaster: @sealedMaster, keys: @[keyId], createdMs: nowMs)
  done = A.saveRow(R, nowMs)
  if not done.ok:
    return (false, "", done.err)
  result = (true, R.id, "")

proc checkAccountLogin*(A: Accounts, name: string, authHash: openArray[uint8]): AccountLogin {.
    role: parser, tag: "accounts|appApi|cryptoBoundary".} =
  ## A/name/authHash: Def. 2. ok = false for an unknown name, a wrong hash, or a
  ## disabled account, and nothing tells them apart.
  var
    known: bool = A.byName.hasKey(name)
    R: AccountRow = if known: A.byName[name] else: AccountRow(authHash: A.decoySecret)
  if constantTimeEq(R.authHash, authHash) and known and not R.disabled:
    result = AccountLogin(ok: true, id: R.id, settings: R.settings,
      sealedMaster: R.sealedMaster)

proc addAccountKey*(A: Accounts, name: string, authHash: openArray[uint8],
    keyId: string, nowMs: uint64): AccountLogin {.role: actor,
    tag: "accounts|appApi|storageIo|write".} =
  ## A/name/authHash: a login. keyId: this device, which joins the account.
  ## Refused when the login fails, the key belongs to another account, or the
  ## account already has `accountMaxDevices`. A key that is already here is fine.
  var
    R: AccountRow = AccountRow()
  result = A.checkAccountLogin(name, authHash)
  if not result.ok or keyId.len == 0:
    return AccountLogin()
  R = A.byName[name]
  if keyId in R.keys:
    return
  if A.nameOfKey.hasKey(keyId) or R.keys.len >= accountMaxDevices:
    return AccountLogin()
  R.keys.add(keyId)
  if not A.saveRow(R, nowMs).ok:
    return AccountLogin()

proc removeAccountKey*(A: Accounts, id, keyId: string, nowMs: uint64): bool {.
    role: actor, tag: "accounts|appApi|storageIo|write".} =
  ## A/id/keyId: this device is no longer part of the account. False when it was
  ## not, or when it is the last one (an account with no device is locked out).
  var
    n: string = A.nameOfId.getOrDefault(id)
    R: AccountRow = AccountRow()
  if n.len == 0:
    return false
  R = A.byName[n]
  if keyId notin R.keys or R.keys.len <= 1:
    return false
  A.nameOfKey.del(keyId)
  R.keys.delete(R.keys.find(keyId))
  result = A.saveRow(R, nowMs).ok

proc changeAccountPassword*(A: Accounts, id: string, authHash, settings,
    sealedMaster: openArray[uint8], nowMs: uint64): bool {.role: actor,
    tag: "accounts|appApi|storageIo|write".} =
  ## A/id: whose. authHash/settings/sealedMaster: all three replaced in one
  ## record, so a crash leaves the old password working or the new one.
  var
    n: string = A.nameOfId.getOrDefault(id)
    R: AccountRow = AccountRow()
  if n.len == 0 or authHash.len != fullDigestBytes:
    return false
  R = A.byName[n]
  R.authHash = @authHash
  R.settings = @settings
  R.sealedMaster = @sealedMaster
  result = A.saveRow(R, nowMs).ok
