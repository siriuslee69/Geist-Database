## ---------------------------------------------------------------------
## Blind <- a store that keeps sealed entries for one owner and cannot read them
## ---------------------------------------------------------------------
##
##   owner's program                          this module
##   -------------------------------          ------------------------------
##   seals data, hashes the sealed bytes
##   signs a LABEL (entryFields)     ----->   append: checks stamp, hash, chain,
##                                            limits; shelves the blob
##   signs a REQUEST (fetchFields)   ----->   fetch: checks stamp and clock;
##                                            returns (label, blob) in time order
##
## The design, with the picture and the reasons, is docs/BLIND_STORE.md. Geist
## holds no key for a blob. It checks signatures only, with the public keys in
## <name>.owner, using the signed notes of trust.nim.
##
## Files, beside each other in one folder:
##
##   <name>.owner        who owns the store: its id, signer name, public keys
##   <name>.ge1st...     the index: one row per entry (BlindRow)
##   <name>.blobs/       the blobs, each named by its own hash (a sidecar folder)
##
## Def. 1 (stale head)  an entry whose `prev` is not the newest entry's hash.
## Def. 2 (refusal)     every refusal returns ok = false and says why in `err`.
##                      Nothing is written before every check has passed.

import std/[algorithm, os, strutils, tables, times]
import std/sysrand

import runePragmas
import ./types
import ./config
import ./collection
import ./sidecar
import ./trust
import ./textfile
import ./crypto/hashing
import ./crypto/hashwidths

const
  blindOwnerSuffix*: string = ".owner"
  blindBlobsSuffix*: string = ".blobs"
  ownerMarker*: string = "geist-owner"
  kindEntry*: string = "entry"
  kindFetch*: string = "fetch"
  zeroHead*: string = "0000000000000000000000000000000000000000000000000000000000000000"
    ## The `prev` of the first entry: 64 zeros, a hash nothing has.
  fetchWindowMs*: int64 = 300_000
    ## A request is refused when its `askedAt` is further than this from our clock.
  skewWarnMs*: int64 = 600_000
    ## An entry whose `sentAt` is further than this from our clock is kept, with a warning.

type
  BlindLimits* {.role: configurator, tag: "blind|config|types".} = object
    ## Soft numbers only warn, hard numbers refuse (Def. 10 and 11 of the design). 0 = no limit.
    warnBlobBytes*: int64
    maxBlobBytes*: int64
    warnStoreBytes*: int64
    maxStoreBytes*: int64
    warnEntries*: int64
    maxEntries*: int64

  BlindOwner* {.role: configurator, tag: "blind|cryptoBoundary|types".} = object
    ## signer: the name written in every label. keys: one or more public keys; with
    ## several, every one must sign (trust.nim, Def. 1).
    signer*: string
    keys*: seq[TrustedKey]

  BlindRow* {.role: truthState, tag: "blind|db|types",
    expectedCount: [0, 1000000], lifeCycle: lcSession.} = object
    ## One entry in the index. The blob itself is a file named `hash`.
    seqNo*: int
    receivedAt*: int
    sentAt*: int
    hash*: string
    size*: int
    note*: string

  BlindStore* {.role: truthState, tag: "blind|db|types",
    expectedCount: [0, 1000], lifeCycle: lcSession.} = object
    dir*: string
    name*: string
    id*: string
    signer*: string
    owner*: TrustTable
    rows*: Collection[BlindRow]
    blobs*: SidecarStore
    limits*: BlindLimits
    head*: string
    lastReceived*: int64
    nextSeq*: int64
    totalBytes*: int64
    entryCount*: int64
    readOnly*: bool

  BlindResult* {.role: truthState, tag: "blind|types".} = object
    ## ok: it worked. err: why not. seqNo/receivedAt: where an appended entry landed.
    ## warnings: soft limits passed, or a far clock; they never stop the call.
    ok*: bool
    err*: string
    seqNo*: int64
    receivedAt*: int64
    warnings*: seq[string]

  BlindEntry* {.role: preparedData, tag: "blind|types".} = object
    ## What fetch hands back, unchanged: the signed label and the blob.
    seqNo*: int64
    receivedAt*: int64
    sentAt*: int64
    hash*: string
    note*: string
    blob*: ByteSeq

  FetchResult* {.role: truthState, tag: "blind|types".} = object
    ok*: bool
    err*: string
    entries*: seq[BlindEntry]

  Fields* = seq[tuple[key, value: string]]

proc defaultBlindLimits*(): BlindLimits {.role: configurator, stage: stDone,
    tag: "blind|config".} =
  ## The start values of docs/BLIND_STORE.md section 7. An app changes them.
  result.warnBlobBytes = 1_048_576
  result.maxBlobBytes = 8_388_608
  result.warnStoreBytes = 268_435_456
  result.maxStoreBytes = 1_073_741_824
  result.warnEntries = 100_000
  result.maxEntries = 1_000_000

proc nowMs*(): int64 {.role: helper, tag: "blind|time".} =
  ## Our clock in milliseconds since 1970.
  result = int64(epochTime() * 1000.0)

proc refuse(why: string): BlindResult {.role: helper, inline, tag: "blind".} =
  ## why: the reason, as the result of a call that stopped.
  result.err = why

## ╭⟢ the owner file

proc ownerPath*(dir, name: string): string {.role: helper, tag: "blind|storageIo".} =
  ## dir/name: where the owner file of this store lies.
  result = dir / (name & blindOwnerSuffix)

proc renderOwner(id, signer: string, keys: seq[TrustedKey]): string {.
    role: helper, tag: "blind|cryptoBoundary".} =
  ## id/signer/keys: the text of an owner file (key = value lines and a digest).
  var
    pairs: Fields = @[(key: ownerMarker, value: "1"), (key: "store", value: id),
      (key: "signer", value: signer), (key: "keys", value: $keys.len)]
    i: int = 0
  while i < keys.len:
    pairs.add (key: "key" & $i, value: keys[i].algorithm & ":" & hexText(keys[i].publicKey))
    i = i + 1
  result = renderFile(pairs)

proc ownerKey(pairs: Table[string, string], i: int, signer: string): TrustedKey {.
    role: parser, tag: "blind|cryptoBoundary".} =
  ## pairs/i/signer: key number i of an owner file. algorithm stays empty if it is bad.
  var
    v: string = pairs.getOrDefault("key" & $i, "")
    at: int = v.find(':')
  if at < 0:
    return
  result.signer = signer
  result.algorithm = v[0 ..< at]
  result.publicKey = unhexText(v[at + 1 .. ^1])

proc parseOwner(text: string): tuple[ok: bool, id, signer: string,
    table: TrustTable, err: string] {.role: parser, tag: "blind|cryptoBoundary|read".} =
  ## text: an owner file. Refused when the digest is wrong, the marker or the id is
  ## missing, or one key is not "algorithm:hex" of a known algorithm.
  var
    got: tuple[ok: bool, pairs: Table[string, string], err: string] = parseKeyFile(text)
    n: int = 0
    i: int = 0
    k: TrustedKey = TrustedKey()
  if not got.ok:
    result.err = got.err
    return
  if got.pairs.getOrDefault(ownerMarker, "") != "1":
    result.err = "not an owner file (no " & ownerMarker & " = 1)"
    return
  result.id = got.pairs.getOrDefault("store", "")
  result.signer = got.pairs.getOrDefault("signer", "")
  n = parseInt(got.pairs.getOrDefault("keys", "0"))
  if result.id.len != 2 * fullDigestBytes or result.signer.len == 0 or n < 1:
    result.err = "the owner file names no store id, no signer or no key"
    return
  while i < n:
    k = ownerKey(got.pairs, i, result.signer)
    if not knownAlgorithm(k.algorithm) or k.publicKey.len == 0:
      result.err = "owner key " & $i & " is not 'algorithm:hex' of a known algorithm"
      return
    result.table.keys.add k
    i = i + 1
  result.ok = true

## ╭⟢ the text an owner signs

proc entryFields*(storeId, signer: string, blob: ByteSeq, prev: string,
    sentAt: int64): Fields {.role: helper, tag: "blind|cryptoBoundary".} =
  ## storeId/signer: the store and its owner's name. blob: the SEALED bytes.
  ## prev: the head the owner last saw (zeroHead for the first entry).
  ## sentAt: the owner's clock, milliseconds.
  ## The owner signs `noteSignedText(fields)` and ships `renderNote(fields, sig)`.
  result = noteFields(geistHash(hkBlake3, blob, fullDigestBytes), @[
    (key: "kind", value: kindEntry), (key: "prev", value: prev),
    (key: "sentAt", value: $sentAt), (key: "signer", value: signer),
    (key: "store", value: storeId)])

proc fetchFields*(storeId, signer: string, sinceMs, untilMs: int64, limit: int,
    askedAt: int64): Fields {.role: helper, tag: "blind|cryptoBoundary".} =
  ## sinceMs/untilMs: the range of receivedAt (until 0 = open end). limit: most rows.
  ## askedAt: the owner's clock; the request dies after fetchWindowMs.
  result = @[(key: noteMarker, value: "1"), (key: "kind", value: kindFetch),
    (key: "signer", value: signer), (key: "store", value: storeId),
    (key: "since", value: $sinceMs), (key: "until", value: $untilMs),
    (key: "limit", value: $limit), (key: "askedAt", value: $askedAt)]

## ╭⟢ checking a signed text

proc checkSigned(S: BlindStore, text, kind: string): tuple[ok: bool,
    note: SidecarNote, err: string] {.role: parser,
    tag: "blind|cryptoBoundary|read".} =
  ## S: the store. text: a label or a request. kind: the one it must be.
  ## One wording covers a wrong signer, a wrong store and a bad signature, so the
  ## answer never tells a stranger whether the store holds anything.
  var
    got: tuple[ok: bool, note: SidecarNote, err: string] =
      parseNote(text, needHash = (kind == kindEntry))
  if not got.ok:
    result.err = "unreadable: " & got.err
    return
  result.note = got.note
  if noteValue(got.note, "kind") != kind or noteValue(got.note, "store") != S.id:
    result.err = "this is not " & kind & " text for this store"
    return
  if trustOf(got.note, S.owner) != ntSigned:
    result.err = "the signature does not belong to this store's owner"
    return
  result.ok = true

proc headOf(note: SidecarNote): string {.role: helper, tag: "blind|cryptoBoundary".} =
  ## note: a label. The hash of its signed text; the next entry names it as `prev`.
  result = hexText(geistHash(hkBlake3, textBytes(noteSignedText(note.fields)),
    fullDigestBytes))

## ╭⟢ making and opening a store

proc newStoreId(): string {.role: helper, tag: "blind|cryptoBoundary".} =
  ## 32 random bytes as hex. Written into every signed text of the store.
  result = hexText(urandom(fullDigestBytes))

proc rowsInOrder(S: BlindStore): seq[BlindRow] {.role: parser, tag: "blind|db|read".} =
  ## S: every index row, oldest first.
  result = S.rows.toSeq()
  result.sort(proc (a, b: BlindRow): int = cmp(a.seqNo, b.seqNo))

proc loadState(S: var BlindStore): string {.role: truthBuilder,
    tag: "blind|db|read".} =
  ## S: rebuilds head, counters and clock from the index. Returns "" or why not.
  var
    R: seq[BlindRow] = rowsInOrder(S)
    got: tuple[ok: bool, note: SidecarNote, err: string] = (false, SidecarNote(), "")
  S.head = zeroHead
  S.lastReceived = 0
  S.nextSeq = 0
  S.totalBytes = 0
  S.entryCount = int64(R.len)
  for r in R:
    S.totalBytes = S.totalBytes + int64(r.size)
    S.lastReceived = max(S.lastReceived, int64(r.receivedAt))
    S.nextSeq = int64(r.seqNo) + 1
  if R.len == 0:
    return ""
  got = parseNote(R[^1].note)
  if not got.ok:
    return "the newest entry's label cannot be read: " & got.err
  S.head = headOf(got.note)

proc openBlind*(S: var BlindStore, dir, name: string,
    limits: BlindLimits = defaultBlindLimits(),
    readOnly: bool = false): BlindResult {.role: orchestrator,
    tag: "blind|db|storageIo".} =
  ## dir/name: the folder and the store's name.
  ## limits: soft and hard numbers (defaultBlindLimits).
  ## readOnly: follow without the write lease; append is then refused.
  var
    owner: tuple[ok: bool, id, signer: string, table: TrustTable, err: string] =
      (false, "", "", TrustTable(), "")
    why: string = ""
  when not sidecarsCompiled:
    return refuse("a blind store keeps its blobs as sidecar files; build with " &
      "-d:sidecars (the default configs set it)")
  if not fileExists(ownerPath(dir, name)):
    return refuse("no owner file " & ownerPath(dir, name) & ": make the store with createBlind")
  owner = parseOwner(readFile(ownerPath(dir, name)))
  if not owner.ok:
    return refuse(ownerPath(dir, name) & ": " & owner.err)
  S = default(BlindStore)
  S.dir = dir
  S.name = name
  S.id = owner.id
  S.signer = owner.signer
  S.owner = owner.table
  S.limits = limits
  S.readOnly = readOnly
  try:
    S.rows = openCollection[BlindRow](dir, name, appConfig(), "", true, readOnly)
  except CatchableError as e:
    return refuse("the index cannot be opened: " & e.msg)
  S.blobs = initSidecarStore(dir / (name & blindBlobsSuffix))
  why = loadState(S)
  if why.len > 0:
    return refuse(why)
  result.ok = true

proc createBlind*(S: var BlindStore, dir, name: string, owner: BlindOwner,
    limits: BlindLimits = defaultBlindLimits()): BlindResult {.
    role: orchestrator, tag: "blind|cryptoBoundary|storageIo|write".} =
  ## dir/name: the folder and the new store's name.
  ## owner: signer name and public keys. Whoever calls this has decided the owner may
  ##   have a store; Geist adds no gate (the app does, see the design, section 8).
  ## Refused when the store exists, the owner has no key, or a key's algorithm is unknown.
  var
    tmp: string = ownerPath(dir, name) & ".tmp"
  if fileExists(ownerPath(dir, name)):
    return refuse("the store " & name & " already has an owner file")
  if owner.signer.len == 0 or owner.keys.len == 0:
    return refuse("an owner needs a signer name and at least one key")
  for k in owner.keys:
    if not knownAlgorithm(k.algorithm) or k.publicKey.len == 0:
      return refuse("owner key algorithm '" & k.algorithm & "' is not one this build checks")
  try:
    createDir(dir)
    writeFile(tmp, renderOwner(newStoreId(), owner.signer, owner.keys))
    moveFile(tmp, ownerPath(dir, name))
  except CatchableError as e:
    return refuse("the owner file cannot be written: " & e.msg)
  result = openBlind(S, dir, name, limits)

## ╭⟢ handing in an entry (the limits it checks, then the checks, then the write)

proc pct(a, b: int64): int {.role: math, tag: "blind".} =
  ## a/b: a as whole percent of b (b > 0).
  result = int((a * 100) div b)

proc overLimits(S: BlindStore, n: int64): tuple[err: string, warnings: seq[string]] {.
    role: parser, tag: "blind".} =
  ## S/n: may a blob of n bytes be added? Hard limits give `err`, soft ones `warnings`.
  var
    L: BlindLimits = S.limits
    total: int64 = S.totalBytes + n
    count: int64 = S.entryCount + 1
  if L.maxBlobBytes > 0 and n > L.maxBlobBytes:
    result.err = "the blob is " & $n & " bytes, over the hard limit maxBlobBytes (" &
      $L.maxBlobBytes & ")"
    return
  if L.maxStoreBytes > 0 and total > L.maxStoreBytes:
    result.err = "the store would hold " & $total & " bytes, over the hard limit " &
      "maxStoreBytes (" & $L.maxStoreBytes & ")"
    return
  if L.maxEntries > 0 and count > L.maxEntries:
    result.err = "the store would hold " & $count & " entries, over the hard limit " &
      "maxEntries (" & $L.maxEntries & ")"
    return
  if L.warnBlobBytes > 0 and n > L.warnBlobBytes:
    result.warnings.add "blob of " & $n & " bytes is over warnBlobBytes (" &
      $L.warnBlobBytes & ")"
  if L.warnStoreBytes > 0 and total > L.warnStoreBytes:
    result.warnings.add "store " & S.name & " is at " & $pct(total, L.warnStoreBytes) &
      "% of warnStoreBytes (" & $total & " of " & $L.warnStoreBytes & " bytes)"
  if L.warnEntries > 0 and count > L.warnEntries:
    result.warnings.add "store " & S.name & " holds " & $count &
      " entries, over warnEntries (" & $L.warnEntries & ")"


proc checkEntry(S: BlindStore, text: string, blob: ByteSeq): tuple[ok: bool,
    note: SidecarNote, sentAt: int64, err: string] {.role: parser,
    tag: "blind|cryptoBoundary|read".} =
  ## S/text/blob: every check of section 5 that needs no limit and no write, in the
  ## order the design lists them. Stops at the first failure.
  var
    got: tuple[ok: bool, note: SidecarNote, err: string] = checkSigned(S, text, kindEntry)
  if not got.ok:
    result.err = got.err
    return
  result.note = got.note
  if hexText(geistHash(hkBlake3, blob, fullDigestBytes)) != hexText(got.note.hash):
    result.err = "the blob does not match the hash in its label"
    return
  if noteValue(got.note, "prev") != S.head:
    result.err = "stale head: the label follows " & noteValue(got.note, "prev") &
      " but the store ends at " & S.head & "; fetch the newest entry and sign again"
    return
  try:
    result.sentAt = parseBiggestInt(noteValue(got.note, "sentAt"))
  except ValueError:
    result.err = "the label's sentAt is not a number"
    return
  result.ok = true

proc writeEntry(S: var BlindStore, text: string, blob: ByteSeq, note: SidecarNote,
    sentAt, now: int64): BlindResult {.role: dataWriter,
    tag: "blind|db|storageIo|write".} =
  ## Blob file first, then the index row, then the head. A crash between them leaves a
  ## file nobody names, never a row naming a missing file.
  var
    stored: Ref = Ref()
    row: BlindRow = BlindRow()
  try:
    stored = S.blobs.putSidecar(blob)
    row = BlindRow(seqNo: int(S.nextSeq), receivedAt: int(max(now, S.lastReceived)),
      sentAt: int(sentAt), hash: hexText(note.hash), size: blob.len, note: text)
    S.rows.add row
  except CatchableError as e:
    return refuse("the entry cannot be written: " & e.msg)
  if hexText(stored.hash) != row.hash:
    return refuse("the blob file got a different name than its hash; entry not kept")
  S.head = headOf(note)
  S.lastReceived = int64(row.receivedAt)
  S.nextSeq = S.nextSeq + 1
  S.totalBytes = S.totalBytes + int64(blob.len)
  S.entryCount = S.entryCount + 1
  result.ok = true
  result.seqNo = int64(row.seqNo)
  result.receivedAt = int64(row.receivedAt)

proc append*(S: var BlindStore, entryText: string, blob: ByteSeq,
    now: int64 = nowMs()): BlindResult {.role: actor,
    tag: "blind|cryptoBoundary|db|write".} =
  ## S: the store. entryText: the label, signed by the owner. blob: the sealed bytes.
  ## now: our clock (a parameter so a test can set it).
  ## Writes nothing unless every check passes. `warnings` carries soft limits and a
  ## sentAt far from our clock.
  var
    checked: tuple[ok: bool, note: SidecarNote, sentAt: int64, err: string] =
      (false, SidecarNote(), 0'i64, "")
    lim: tuple[err: string, warnings: seq[string]] = (err: "", warnings: @[])
  if S.readOnly:
    return refuse("the store is open read-only")
  checked = checkEntry(S, entryText, blob)
  if not checked.ok:
    return refuse(checked.err)
  lim = overLimits(S, int64(blob.len))
  if lim.err.len > 0:
    return refuse(lim.err)
  result = writeEntry(S, entryText, blob, checked.note, checked.sentAt, now)
  result.warnings = lim.warnings
  if result.ok and abs(checked.sentAt - result.receivedAt) > skewWarnMs:
    result.warnings.add "sentAt differs from our clock by " &
      $(abs(checked.sentAt - result.receivedAt) div 1000) & " s"

## ╭⟢ asking for entries back

proc readRange(note: SidecarNote): tuple[ok: bool, since, until, asked: int64,
    limit: int] {.role: parser, tag: "blind|read".} =
  ## note: a checked request. The numbers it carries; not ok when one is not a number.
  try:
    result.since = parseBiggestInt(noteValue(note, "since"))
    result.until = parseBiggestInt(noteValue(note, "until"))
    result.asked = parseBiggestInt(noteValue(note, "askedAt"))
    result.limit = parseInt(noteValue(note, "limit"))
    result.ok = true
  except ValueError:
    result.ok = false

proc entryOf(S: BlindStore, r: BlindRow): tuple[ok: bool, entry: BlindEntry,
    err: string] {.role: dataFetcher, tag: "blind|storageIo|read".} =
  ## r: one index row -> its entry with the blob read back and re-verified by hash.
  var
    got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    ref0: Ref = Ref(target: rtSidecar, hash: unhexText(r.hash))
  got = S.blobs.getSidecar(ref0)
  if not got.ok:
    result.err = "entry " & $r.seqNo & ": " & got.err
    return
  result.entry = BlindEntry(seqNo: int64(r.seqNo), receivedAt: int64(r.receivedAt),
    sentAt: int64(r.sentAt), hash: r.hash, note: r.note, blob: got.data)
  result.ok = true

proc fetch*(S: BlindStore, requestText: string, byteBudget: int = 0,
    now: int64 = nowMs()): FetchResult {.role: actor,
    tag: "blind|cryptoBoundary|db|read".} =
  ## S: the store. requestText: a request signed by the owner (fetchFields).
  ## byteBudget: stop once the blobs total this many bytes; the first entry always
  ##   comes, so one big blob cannot stall a reader. 0 = no budget.
  ## now: our clock.
  ## Entries come in index order, those with since <= receivedAt (< until, if given).
  var
    checked: tuple[ok: bool, note: SidecarNote, err: string] =
      checkSigned(S, requestText, kindFetch)
    q: tuple[ok: bool, since, until, asked: int64, limit: int] =
      (false, 0'i64, 0'i64, 0'i64, 0)
    one: tuple[ok: bool, entry: BlindEntry, err: string] = (false, BlindEntry(), "")
    used: int = 0
  if not checked.ok:
    result.err = checked.err
    return
  q = readRange(checked.note)
  if not q.ok or q.limit < 1:
    result.err = "the request's since, until, askedAt or limit is not usable"
    return
  if abs(now - q.asked) > fetchWindowMs:
    result.err = "the request is " & $(abs(now - q.asked) div 1000) &
      " s away from our clock; the window is " & $(fetchWindowMs div 1000) & " s"
    return
  for r in rowsInOrder(S):
    if int64(r.receivedAt) < q.since or (q.until > 0 and int64(r.receivedAt) >= q.until):
      continue
    if result.entries.len >= q.limit or (byteBudget > 0 and result.entries.len > 0 and
        used >= byteBudget):
      break
    one = entryOf(S, r)
    if not one.ok:
      result.entries = @[]
      result.err = one.err
      return
    used = used + one.entry.blob.len
    result.entries.add one.entry
  result.ok = true

proc closeBlind*(S: var BlindStore) {.role: actor, tag: "blind|db|storageIo".} =
  ## S: saves and releases the index.
  S.rows.close()
