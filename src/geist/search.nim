## ---------------------------------------------------------------------------
## Search <- Geist stores and files, searched through Null-QueryAPIs
## ---------------------------------------------------------------------------
##
## Geist keeps rows in its own binary format (a GE1ST file per generation,
## see format.nim). This module puts those rows behind the Null interface, so
## one predicate can search a store, a text file, a JSON-lines file, or a frame
## file.
##
##   what                          how it is read
##   ---------------------------   -----------------------------------------------
##   plain store, untyped          openStore / openStoreFor: the live rows are found
##                                 once from the identity columns (livePositions),
##                                 then read from disk by position. A value that
##                                 sits in a sidecar follows FollowSidecars (Def. 4)
##   plain store, typed (a T)      typedSeekSource[T]: the same, one T per row. A T
##                                 holds every value, so sidecars are always read
##   sealed store (needs T)       sealedSource[T]: a typed session, opened with
##                                 the password, reads rows from memory
##   text, JSON lines, frames      openFileSource: the Null sources for files
##
## A sealed store cannot be read without its type. Its columns are grouped by
## the schema, so an untyped open reads the wrong bytes. That is why sealed
## stores take a T, and plain stores do not.
##
## Def. 1 (untyped row): a row read with the schema the file carries. Each slot
##   becomes one named field; the slot kind picks the value kind. The identity
##   columns (__rowId, __flags) are not fields: they name a row inside its own
##   store, and say nothing about what the row holds.
## Def. 2 (typed row): a row read into a Nim object T; each object field becomes
##   one named field, by its type.
## Def. 3 (live row): the newest version of a row that has not been removed. The
##   log keeps every older version and every removal (a tombstone). A search sees
##   only live rows, in the order a session presents them, so a plain store and a
##   session give the same answer.
## Def. 4 (sidecar value): a capped column (config.nim, cappedColumn) that is too
##   wide for its value keeps a reference in the row, and the value itself is in
##   <store>/.geist-sidecar/. An own-file reference column (slot kind "ref") is
##   always one. FollowSidecars says how a search reads such a value:
##     fsNever       the reference text is searched ("<sidecar ...>"), so a
##                   predicate on the value does not match its content
##     fsWhenNamed   the value is read for the fields the query names (default)
##     fsAlways      the value is read for every field
##   A payload that cannot be read (missing, or its hash does not match) is shown
##   as "<sidecar: reason>". No predicate matches that text by accident.
##
## Slot kinds that cannot be read without a key are shown, not hidden:
##   sealed field  -> the text "<sealed>"
##   reference     -> the text "<ref>"
## A predicate on either does not match a value it cannot see.

import std/[os, strutils, tables]

import runePragmas
import null_query_apis as nq
import ./types
import ./keys
import ./seek
import ./dynamic
import ./config
import ./row
import ./sidecar
import ./sessionopen
import ./sessioncore
import ./rowid
import ./store
import ./settings
import ./folder

const
  storeBaseName*: string = "main"
    ## The stem Geist gives a store folder unless a caller asks otherwise.

type
  FollowSidecars* {.role: configurator, tag: "appApi|config|types".} = enum
    ## How a search reads a value that a row keeps in a sidecar (Def. 4).
    fsNever,      ## the reference text is searched; the value is not read
    fsWhenNamed,  ## the value is read for the fields the query names
    fsAlways      ## the value is read for every field

  SessionHolder {.role: truthState.} = ref object
    ## The session, behind a reference, so the source's closures can share it.
    db: Session

proc followFromWord*(word: string): FollowSidecars {.role: parser,
    tag: "appApi|config|read".} =
  ## word: "never", "named" or "always", as written in `[default] follow` or on a
  ## command line. Any other word means "named", the default.
  case word
  of "never":
    result = fsNever
  of "always":
    result = fsAlways
  else:
    result = fsWhenNamed

proc defaultFollow*(): FollowSidecars {.role: configurator, tag: "appApi|config|read".} =
  ## The run-time default for how search reads sidecar values: `[default] follow`
  ## in configs/default.toml, "named" when the file does not say. A caller who
  ## passes `follow` explicitly always wins over this default.
  result = followFromWord(geistDefaults().follow)

proc queryFields*(q: nq.NullQuery): seq[string] {.role: parser,
    tag: "appApi|read".} =
  ## q: one search. The fields its predicates name, in order. "*" means every
  ## field, and a predicate that names it makes every sidecar value read.
  for p in q.predicates:
    result.add p.field

proc wantsSidecar*(follow: FollowSidecars, name: string,
    named: seq[string]): bool {.role: parser, tag: "appApi|read".} =
  ## follow/name/named: whether the sidecar value of the field `name` is read.
  case follow
  of fsNever:
    result = false
  of fsAlways:
    result = true
  of fsWhenNamed:
    result = name in named or "*" in named

proc sidecarOf*(dir: string, cfg: GeistConfig): SidecarStore {.role: configurator,
    tag: "sidecar|storageIo".} =
  ## dir/cfg: a store folder and the configuration it was written with. The
  ## content-hash family is not kept in the file, so a reader must be given it,
  ## or every payload fails its hash check. The storage paths come from cfg too,
  ## so the same folders are searched that a writer placed payloads in. The trusted
  ## keys and the unsafe-retrieval policy come from cfg as well.
  result = initSidecarRoots(storeRootsOf(dir, cfg.storagePaths), cfg.sidecarThreshold,
    cfg.contentHash, cfg.storagePolicy)
  result.applyTrust(cfg.trustedKeys, cfg.trustUnsigned)

proc isReferenced*(schema: Schema, data: seq[uint8], offsets: seq[int],
    slot: int): bool {.role: parser, tag: "sidecar|read".} =
  ## schema/data/offsets/slot: true when the slot's value lives in a sidecar
  ## (Def. 4): a capped column that took the escape, or an own-file reference.
  if offsets[slot] < 0:
    return false
  if schema.isExternal(data, offsets, slot):
    return true
  if schema.slots[slot].kind == skRef:
    result = decodeRef(schema.rawAt(data, offsets, slot)).target == rtSidecar

proc sidecarValue*(schema: Schema, data: seq[uint8], offsets: seq[int], slot: int,
    store: SidecarStore): nq.NullValue {.role: dataFetcher,
    tag: "sidecar|storageIo|read".} =
  ## schema/data/offsets/slot/store: the value of one slot, read through its
  ## reference (Def. 4). A payload that cannot be read is shown as its reason.
  var
    got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
  got = store.getSidecar(decodeRef(schema.rawAt(data, offsets, slot)))
  if not got.ok:
    result = nq.nullText("<sidecar: " & got.err & ">")
  elif schema.slots[slot].kind == skBytes:
    result = nq.nullBytes(got.data)
  else:
    result = nq.nullText(cast[string](got.data))

proc slotValue*(kind: SlotKind, text: string): nq.NullValue {.role: helper.} =
  ## kind/text: one rendered slot and how it is stored. An integer or a float
  ## is parsed back to a number, so a range predicate works on it.
  case kind
  of skNull:
    result = nq.NullValue(kind: nq.nkNull)
  of skInt:
    try:
      result = nq.nullInt(parseBiggestInt(text))
    except ValueError:
      result = nq.nullText(text)
  of skFloat:
    try:
      result = nq.nullFloat(parseFloat(text))
    except ValueError:
      result = nq.nullText(text)
  of skText, skBytes:
    result = nq.nullText(text)
  of skSealed:
    result = nq.nullText("<sealed>")
  of skRef:
    result = nq.nullText("<ref>")

proc rowObjectFollowing*(schema: Schema, data: seq[uint8], number: int,
    store: SidecarStore, follow: FollowSidecars,
    named: seq[string]): nq.NullObject {.role: helper, tag: "sidecar|read".} =
  ## schema/data/number/store/follow/named: one untyped row (Def. 1) as a Null
  ## object. The identity columns are skipped. A value that sits in a sidecar
  ## (Def. 4) is read through its reference when `follow` and `named` ask for
  ## it; otherwise the field shows the reference text.
  var
    texts: seq[string] = renderRow(schema, data)
    offsets: seq[int] = @[]
    first: int = 0
    name: string = ""
    value: nq.NullValue = nq.NullValue()
  if schema.hasIdentity():
    first = identityColumnCount
  if follow != fsNever:
    offsets = fieldOffsets(schema, data)
  result.number = number
  for j in first ..< schema.slots.len:
    name = nameOf(schema, schema.slots[j].nameId)
    if follow != fsNever and wantsSidecar(follow, name, named) and
        isReferenced(schema, data, offsets, j):
      value = sidecarValue(schema, data, offsets, j, store)
    else:
      value = slotValue(schema.slots[j].kind, texts[j])
    result.fields.add nq.NullField(name: name, value: value)

proc rowObject*(schema: Schema, data: seq[uint8], number: int): nq.NullObject {.
    role: helper.} =
  ## schema/data/number: one untyped row as a Null object, with every sidecar
  ## value left as its reference text (fsNever).
  result = rowObjectFollowing(schema, data, number, SidecarStore(), fsNever, @[])

proc typedValue*[V](x: V): nq.NullValue {.role: helper.} =
  ## x: one field of a typed row, as the value kind its type maps to.
  when V is bool:
    result = nq.nullBool(x)
  elif V is SomeInteger:
    result = nq.nullInt(int64(x))
  elif V is SomeFloat:
    result = nq.nullFloat(float64(x))
  elif V is string:
    result = nq.nullText(x)
  elif V is seq[uint8]:
    result = nq.nullBytes(x)
  elif compiles($x):
    result = nq.nullText($x)
  else:
    result = nq.nullText("")

proc toNullObject*[T: object](x: T, number: int): nq.NullObject {.role: helper.} =
  ## x/number: one typed row (Def. 2) as a Null object, one field per object field.
  result.number = number
  for fieldName, fieldValue in x.fieldPairs:
    result.fields.add nq.NullField(name: $fieldName, value: typedValue(fieldValue))

proc refuseSealed(path: string): tuple[ok: bool, src: nq.NullSource, err: string] {.
    role: helper.} =
  ## The answer for a sealed data file that an untyped or seek open was given.
  result = (false, nil, "the store at " & path & " is sealed: search it with " &
    "sealedSource[T] and its password")

proc livePositions*(h: SeekHandle): seq[uint32] {.role: dataFetcher,
    tag: "storageIo|read".} =
  ## h: an open plain store. The log positions of its live rows (Def. 3), in the
  ## order a session presents them. Reads the two identity columns once, never
  ## the row payloads. A store without identity columns has no updates and no
  ## removals, so every row is live.
  var
    idx: LiveIndex = initLiveIndex()
    ids: seq[uint64] = @[]
    flags: seq[uint64] = @[]
    at: uint32 = 0'u32
    i: int = 0
  if not h.schema.hasIdentity():
    while i < int(h.rowCount):
      result.add uint32(i)
      i = i + 1
    return
  ids = h.seekFixedColumn(0)
  flags = h.seekFixedColumn(1)
  while i < ids.len:
    idx.noteRow(ids[i], flags[i], uint32(i))
    i = i + 1
  i = 0
  while i < idx.order.len:
    at = idx.newest[idx.order[i]]
    if not flags[int(at)].isTombstone():
      result.add at
    i = i + 1

proc sidecarStoreOf*(path: string, cfg: GeistConfig): SidecarStore {.role: configurator,
    tag: "sidecar|storageIo".} =
  ## path: a live data file of a plain store. Its store folder holds the sidecar.
  result = sidecarOf(parentDir(path), cfg)

proc seekSource*(path: string, follow: FollowSidecars = defaultFollow(),
    cfg: GeistConfig = appConfig(), named: seq[string] = @[]): nq.NullOpen {.
    role: orchestrator, tag: "storageIo|read".} =
  ## path: a data file of a plain store. Only its live rows are shown (Def. 3),
  ## read from disk in whatever ranges the search asks for. Sidecar values are
  ## read as `follow` and `named` say (Def. 4), with the store's configuration
  ## `cfg`. A sealed file is refused, with the reason.
  var opened = openSeek(path)
  if not opened.ok:
    return (false, nil, opened.err)
  if looksSealed(opened.h):
    return refuseSealed(path)
  var
    h = opened.h
    live: seq[uint32] = h.livePositions()
    store: SidecarStore = sidecarStoreOf(path, cfg)
  result = nq.openRecords(path, live.len, proc (first, n: int): seq[nq.NullObject] =
    for k in 0 ..< n:
      result.add rowObjectFollowing(h.schema, h.seekRow(live[first + k]).data,
        first + k, store, follow, named))

proc openStore*(dir: string, follow: FollowSidecars = defaultFollow(),
    cfg: GeistConfig = appConfig(), named: seq[string] = @[]): nq.NullOpen {.
    role: orchestrator, tag: "storageIo|read".} =
  ## dir: a plain Geist store folder. Opens its live data file for streaming.
  ## Never takes the write lease: a search must not block a running writer.
  ## The default follows every sidecar, because a source does not know the
  ## query it will be given. searchStore asks for the fields a query names.
  var
    path: string = liveDataPath(dir, storeBaseName)
    folderCheck: FolderCheck = default(FolderCheck)
    paramsLoaded: ParamsLoad = default(ParamsLoad)
    readCfg: GeistConfig = cfg
  if not fileExists(path):
    return (false, nil, "no store at " & dir)
  # Fail closed, as an open of a session does: a folder that does not validate is
  # not read. The store's own parameters decide how its values are checked.
  folderCheck = checkFolder(dir, forWrite = false)
  if not folderCheck.ok:
    return (false, nil, folderCheck.err)
  paramsLoaded = loadParams(dir, storeBaseName)
  if not paramsLoaded.ok:
    return (false, nil, paramsLoaded.err)
  if paramsLoaded.found:
    readCfg = applyParams(cfg, paramsLoaded.params)
  result = seekSource(path, follow, readCfg, named)

proc openStoreFor*(dir: string, q: nq.NullQuery, follow: FollowSidecars = defaultFollow(),
    cfg: GeistConfig = appConfig()): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir/q: a plain store opened for one query. With fsWhenNamed, a sidecar value
  ## is read for the fields the query names, so a predicate sees its real text.
  result = openStore(dir, follow, cfg, queryFields(q))

proc typedSeekSource*[T: object](path: string, cfg: GeistConfig = appConfig()): nq.NullOpen {.
    role: orchestrator, tag: "storageIo|read".} =
  ## path: a data file of a plain store whose rows are a T. Rows are read one at
  ## a time from disk. A T holds every value, so sidecar values are read in full
  ## here. A payload that is missing or damaged stops the search with its reason
  ## (an untyped source shows that reason in the row instead).
  var opened = openSeek(path)
  if not opened.ok:
    return (false, nil, opened.err)
  if looksSealed(opened.h):
    return refuseSealed(path)
  var
    h = opened.h
    live: seq[uint32] = h.livePositions()
    store: SidecarStore = sidecarStoreOf(path, cfg)
  result = nq.openRecords(path, live.len, proc (first, n: int): seq[nq.NullObject] =
    for k in 0 ..< n:
      result.add toNullObject(seekObject[T](h, live[first + k], store), first + k))

proc sealedSource*[T: object](dir: string, password: string,
    cfg: GeistConfig = appConfig()): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir/password/cfg: a sealed store folder, opened read-only as a T with its
  ## password and the configuration it was written with. The rows are read from
  ## memory (Geist does not yet stream a sealed file). Closing the source closes
  ## the session. The session reads sidecar values in full, so `follow` does not
  ## apply to a sealed store.
  var
    db: Session = default(Session)
  try:
    db = openSession[T](dir, storeBaseName, cfg, password, true)
  except CatchableError as e:
    return (false, nil, e.msg)
  var
    holder = SessionHolder(db: move(db))
    count = int(holder.db.entryCount())
    readFn: proc (first, n: int): seq[nq.NullObject] {.closure.} = nil
  readFn = proc (first, n: int): seq[nq.NullObject] =
    for i in first ..< first + n:
      result.add toNullObject(objectAt[T](holder.db.entries, holder.db.livePosition(uint32(i))), i)
  result = nq.openRecords(dir, count, readFn)
  if result.ok:
    result.src.closeFn = proc () = close(holder.db)

proc searchStore*(dir: string, q: nq.NullQuery, capacity: int = 0,
    follow: FollowSidecars = defaultFollow(), cfg: GeistConfig = appConfig()): tuple[
    ok: bool, res: nq.NullResult, err: string] {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir/q/capacity/follow/cfg: search one plain store. capacity 0 reads everything
  ## at once; a positive capacity streams through a ring of that many rows. The
  ## sidecar values are read as `follow` says (Def. 4); the default reads the
  ## values of the fields that q names.
  var opened = openStoreFor(dir, q, follow, cfg)
  if not opened.ok:
    return (false, nq.NullResult(), opened.err)
  if capacity > 0:
    result.res = nq.nullSearchStream(@[opened.src], q, capacity)
  else:
    result.res = nq.nullSearchAll(@[opened.src], q)
  nq.close(opened.src)
  result.ok = true

proc searchSealed*[T: object](dir: string, password: string, q: nq.NullQuery,
    cfg: GeistConfig = appConfig(), capacity: int = 0): tuple[ok: bool,
    res: nq.NullResult, err: string] {.role: orchestrator, tag: "storageIo|read".} =
  ## dir/password/q/cfg/capacity: search one sealed store as a T. See sealedSource.
  var opened = sealedSource[T](dir, password, cfg)
  if not opened.ok:
    return (false, nq.NullResult(), opened.err)
  if capacity > 0:
    result.res = nq.nullSearchStream(@[opened.src], q, capacity)
  else:
    result.res = nq.nullSearchAll(@[opened.src], q)
  nq.close(opened.src)
  result.ok = true

proc openFileSource*(kind: string, files: seq[string]): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## kind/files: a file or several files of one kind: "lines", "jsonl" or
  ## "frames". Geist searches these the same way it searches its own stores.
  case kind
  of "lines": result = nq.openLines(files)
  of "jsonl": result = nq.openJsonLines(files)
  of "frames": result = nq.openBlobs(files)
  else: result = (false, nil, "unknown file kind '" & kind & "'; use lines, jsonl or frames")
