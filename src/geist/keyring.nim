## ---------------------------------------------------------------------
## Keyrings <- several sealed stores, one password each, opened one by one
## ---------------------------------------------------------------------
##
## A keyring set splits one body of data into parts that open separately.
## Each part (a RING) is an ordinary sealed Geist store with its own key
## file, so its own password and its own master secret:
##
##   root/
##     rings              public list: one ring name per line, in order
##     stage1/            a sealed store  (main.ge1st.gN, main.keys.gN, ...)
##     stage2/            another one, under a different password
##     ...
##
##   openKeyrings(root)          every ring CLOSED: names only, no rows
##   unlock(K, "stage2", pw)     that ring's rows become readable
##   upsert / remove             only on unlocked rings
##   save(K)                     rewrites ONLY the rings that changed
##
## Why separate stores and not one store with several keys. A store with
## text columns seals whole rows (crypto/column.nim, the packed path), so a
## key per column group cannot split one row between two secrets. Separate
## stores can, and they need nothing new in the sealing code: every ring
## is sealed, verified, generation-swapped and backed up exactly like any
## other Geist store.
##
## What the split buys. A ring that was never unlocked is never read and
## never written. Saving with only the first two passwords leaves rings
## three and four byte-for-byte as they were:
##
##   unlocked   stage1  stage2            locked   stage3  stage4
##   changed    yes     no                         --      --
##   on save    written untouched                  untouched (never opened)
##
## Rows are deliberately plain: an id, a kind, and a body the caller
## owns. How a caller spreads one record over several rings (Avalon puts
## each card's stage-N fields in ring N) is the caller's business.
##
## Example:
##
##   var K = createKeyrings("vault", ["stage1", "stage2"], ["pw1", "pw1|pw2"])
##   K.upsert("stage1", RingRow(rowKey: "card-7", kind: "accounts", body: "{}"))
##   discard K.save()
##   K.close()
##
##   K = openKeyrings("vault")
##   discard K.unlock("stage1", "pw1")      # stage2 stays closed
##   echo K.rows("stage1").len

import std/[os, strutils]

import runePragmas
import ./types
import ./config
import ./keys
import ./sessionopen
import ./sessioncore
import ./store

const
  ringListName* = "rings"
    ## The public list of ring names. It names rings; it holds no secret.
  rowMapName* = "rowmap"
    ## Per ring, written on each save: which visible row (by rowKey) sits at
    ## which position of the sealed file. Public, like the ledger: it reveals
    ## the rowKeys and row count, never content. It is what lets `sealedRow`
    ## hand out a LOCKED ring's sealed bytes without any key.

type
  RingRow* {.role: preparedData, expectedCount: [0, 100000],
      lifeCycle: lcSession.} = object
    ## rowKey: the caller's own id for the thing (unique within a ring).
    ## kind: the caller's grouping, e.g. a collection name.
    ## body: the caller's payload; Geist never looks inside it.
    rowKey*: string
    kind*: string
    body*: string

  Ring* {.role: truthState, expectedCount: [0, 16], lifeCycle: lcSession.} = object
    ## One sealed store. `session` is only meaningful while `open`.
    name*: string
    open*: bool
    dirty*: bool
    session*: Session

  Keyrings* {.role: truthState, expectedCount: [0, 8], lifeCycle: lcSession.} = object
    ## root: the folder holding the ring list and one folder per ring.
    ## config: the preset every ring is opened with.
    root*: string
    config*: GeistConfig
    rings*: seq[Ring]

proc ringIndex*(K: Keyrings, name: string): int {.role: parser,
    tag: "keyring|read".} =
  ## K/name: position of the ring called `name`, or -1.
  var
    i: int = 0
  result = -1
  while i < K.rings.len:
    if K.rings[i].name == name:
      return i
    i = i + 1

proc requireOpen(K: Keyrings, name: string): int {.role: parser,
    tag: "keyring|read".} =
  ## K/name: index of an UNLOCKED ring; anything else is a caller error.
  result = K.ringIndex(name)
  if result < 0:
    raise newException(KeyError, "no ring called " & name)
  if not K.rings[result].open:
    raise newException(ValueError, "ring " & name & " is locked")

proc validName(name: string): bool {.role: parser, inline, tag: "keyring".} =
  ## name: a ring name doubles as a folder name, so it stays plain.
  result = name.len > 0 and name.allCharsInSet({'a'..'z', 'A'..'Z', '0'..'9', '_', '-'})

proc ringNames*(root: string): seq[string] {.role: dataFetcher,
    tag: "keyring|read|storageIo".} =
  ## root: keyring folder. Empty when it has no ring list.
  var
    path: string = root / ringListName
  if not fileExists(path):
    return @[]
  for line in readFile(path).splitLines():
    if line.strip().len > 0:
      result.add line.strip()

proc openKeyrings*(root: string, c: GeistConfig = secureAppConfig()): Keyrings {.
    role: orchestrator, tag: "appApi|keyring|read".} =
  ## root: keyring folder made by `createKeyrings`.
  ## c: preset the rings were created with.
  ## Every ring starts LOCKED; nothing secret is read here.
  var
    names: seq[string] = ringNames(root)
  if names.len == 0:
    raise newException(IOError, "no keyring set at " & root)
  result.root = root
  result.config = c
  for n in names:
    result.rings.add Ring(name: n)

proc unlock*(K: var Keyrings, name, password: string): tuple[ok: bool,
    err: string] {.role: decryptor, tag: "appApi|cryptoBoundary|keyring|read".} =
  ## K/name: the ring to open. Already open is fine and changes nothing.
  ## password: that ring's own password. A wrong one leaves it locked and
  ## says so; it never creates a fresh, empty ring in its place.
  var
    i: int = K.ringIndex(name)
  if i < 0:
    return (false, "no ring called " & name)
  if K.rings[i].open:
    return (true, "")
  if not fileExists(K.root / name / manifestName):
    return (false, "ring " & name & " has no data: the set is damaged")
  try:
    K.rings[i].session = openSession[RingRow](K.root / name, "main", K.config, password)
  except IOError, ValueError:
    return (false, "ring " & name & ": " & getCurrentExceptionMsg())
  K.rings[i].open = true
  K.rings[i].dirty = false
  result = (true, "")

proc createKeyrings*(root: string, names, passwords: openArray[string],
    c: GeistConfig = secureAppConfig()): Keyrings {.role: orchestrator,
    tag: "appApi|cryptoBoundary|keyring|write".} =
  ## root: a folder that does not hold a keyring set yet.
  ## names/passwords: one password per ring, in the same order.
  ## Every ring is written once, empty, so its key file exists and a later
  ## wrong password is told apart from "never created". All end UNLOCKED.
  var
    i: int = 0
    saved: tuple[ok: bool, err: string] = (false, "")
  if names.len == 0 or names.len != passwords.len:
    raise newException(ValueError, "one password per ring is required")
  if ringNames(root).len > 0:
    raise newException(IOError, "a keyring set already exists at " & root)
  createDir(root)
  result.root = root
  result.config = c
  while i < names.len:
    if not validName(names[i]) or result.ringIndex(names[i]) >= 0:
      raise newException(ValueError, "ring names must be unique letters, digits, _ or -: " & names[i])
    if passwords[i].len == 0:
      raise newException(ValueError, "ring " & names[i] & " needs a password")
    result.rings.add Ring(name: names[i], open: true,
      session: openSession[RingRow](root / names[i], "main", c, passwords[i]))
    saved = result.rings[i].session.save()
    if not saved.ok:
      raise newException(IOError, saved.err)
    i = i + 1
  # The list is written LAST: a set whose creation failed half way has no
  # list, so it is never mistaken for a usable one.
  writeFile(root / ringListName, names.join("\n") & "\n")

proc rows*(K: Keyrings, name: string): seq[RingRow] {.role: parser,
    tag: "appApi|keyring|read".} =
  ## K/name: every visible row of an unlocked ring.
  var
    i: int = K.requireOpen(name)
    j: uint32 = 0'u32
    n: uint32 = K.rings[i].session.entryCount()
  while j < n:
    result.add get[RingRow](K.rings[i].session, j)
    j = j + 1'u32

proc upsert*(K: var Keyrings, name: string, r: RingRow) {.role: actor,
    tag: "appApi|keyring|write".} =
  ## K/name: an unlocked ring. r: replaces the row with the same rowKey,
  ## or is added when there is none.
  var
    i: int = K.requireOpen(name)
    ids: seq[RowId] = K.rings[i].session.findIds("rowKey", r.rowKey)
  if r.rowKey.len == 0:
    raise newException(ValueError, "a ring row needs a rowKey")
  if ids.len > 0:
    discard K.rings[i].session.set(ids[0], r)
  else:
    discard K.rings[i].session.put(r)
  K.rings[i].dirty = true

proc remove*(K: var Keyrings, name, rowKey: string): bool {.role: actor,
    tag: "appApi|keyring|write", discardable.} =
  ## K/name: an unlocked ring. rowKey: the row to drop. False when absent.
  var
    i: int = K.requireOpen(name)
  for id in K.rings[i].session.findIds("rowKey", rowKey):
    result = K.rings[i].session.delete(id) or result
  if result:
    K.rings[i].dirty = true

proc replaceAll*(K: var Keyrings, name: string, R: openArray[RingRow]) {.
    role: actor, tag: "appApi|keyring|write".} =
  ## K/name: an unlocked ring. R: its complete new contents. Rows whose
  ## rowKey is not in R are removed; the rest are upserted. A row that is
  ## unchanged is left alone, so saving an untouched ring writes nothing.
  var
    keep: seq[string] = @[]
    old: seq[RingRow] = K.rows(name)
  for r in R:
    keep.add r.rowKey
  for o in old:
    if o.rowKey notin keep:
      K.remove(name, o.rowKey)
  for r in R:
    if r notin old:
      K.upsert(name, r)

proc changePassword*(K: var Keyrings, name, password: string) {.role: actor,
    tag: "appApi|cryptoBoundary|keyring|write".} =
  ## K/name: an unlocked ring. password: sealed into its key file on the
  ## next save; the master secret and every row stay as they are.
  var
    i: int = K.requireOpen(name)
  if password.len == 0:
    raise newException(ValueError, "a ring password cannot be empty")
  K.rings[i].session.password = password
  K.rings[i].dirty = true

proc writeRowMap(K: Keyrings, i: int) {.role: dataWriter,
    tag: "keyring|storageIo|write".} =
  ## K/i: an open ring just saved. Its row map: the generation on the first
  ## line, then one "rowKey<TAB>position" line per visible row.
  template S: untyped = K.rings[i].session
  var
    t: string = $S.generation & "\n"
    j: uint32 = 0'u32
  while j < S.entryCount():
    t.add get[RingRow](S, j).rowKey & "\t" & $S.livePosition(j) & "\n"
    j = j + 1'u32
  writeFile(K.root / K.rings[i].name / rowMapName, t)

proc sealedRow*(K: Keyrings, name, rowKey: string): seq[uint8] {.role: dataFetcher,
    tag: "appApi|keyring|read|storageIo".} =
  ## K/name/rowKey: the SEALED bytes of one row, read without any key, so a
  ## locked ring can show what is stored for a row without opening it.
  ## Empty when the ring has no such row, or its map is from another
  ## generation than the live file.
  var
    dir: string = K.root / name
    lines: seq[string] = @[]
    parts: seq[string] = @[]
    pos: int = -1
    idx: tuple[ok: bool, f: GeistFile, err: string] = (false, default(GeistFile), "")
    at: int = -1
    C: ClusterBuild = default(ClusterBuild)
  if not fileExists(dir / rowMapName):
    return @[]
  lines = readFile(dir / rowMapName).splitLines()
  if lines.len == 0 or lines[0] != $liveGeneration(dir):
    return @[]
  for line in lines[1 .. ^1]:
    parts = line.split('\t')
    if parts.len == 2 and parts[0] == rowKey:
      pos = parseInt(parts[1])
  idx = readIndex(generationPaths(dir, "main", liveGeneration(dir)).dataPath)
  if pos < 0 or not idx.ok:
    return @[]
  at = idx.f.findIndex(crEntry)
  if at < 0:
    return @[]
  C = readCluster(generationPaths(dir, "main", liveGeneration(dir)).dataPath, idx.f.index[at])
  if pos + 1 >= C.rowOffsets.len or int(C.rowOffsets[pos + 1]) > C.rows.len:
    return @[]
  result = C.rows[int(C.rowOffsets[pos]) ..< int(C.rowOffsets[pos + 1])]

proc save*(K: var Keyrings): tuple[ok: bool, err: string] {.role: orchestrator,
    tag: "appApi|keyring|storageIo|write".} =
  ## K: writes every unlocked ring that changed, and only those. A ring
  ## whose old versions outnumber its live rows is compacted first, so
  ## edits do not grow the file without end.
  var
    i: int = 0
    r: tuple[ok: bool, err: string] = (true, "")
  result = (true, "")
  while i < K.rings.len:
    if K.rings[i].open and K.rings[i].dirty:
      if K.rings[i].session.logCount() > 2'u32 * K.rings[i].session.entryCount():
        discard K.rings[i].session.compact()
      r = K.rings[i].session.save()
      if not r.ok:
        return (false, "ring " & K.rings[i].name & ": " & r.err)
      K.writeRowMap(i)
      K.rings[i].dirty = false
    i = i + 1

proc lock*(K: var Keyrings, name: string) {.role: actor,
    tag: "appApi|keyring|lifecycle".} =
  ## K/name: forget an unlocked ring's rows and key. Unsaved changes are
  ## DISCARDED -- call `save` first to keep them.
  var
    i: int = K.ringIndex(name)
  if i < 0 or not K.rings[i].open:
    return
  K.rings[i].session.dirty = false
  K.rings[i].session.close()
  K.rings[i].open = false
  K.rings[i].dirty = false

proc close*(K: var Keyrings) {.role: actor, tag: "appApi|keyring|lifecycle".} =
  ## K: locks every ring. Unsaved changes are discarded, as for `lock`.
  var
    i: int = 0
  while i < K.rings.len:
    K.lock(K.rings[i].name)
    i = i + 1
