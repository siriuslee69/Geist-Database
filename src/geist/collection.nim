## ---------------------------------------------------------------------
## Collection <- the ergonomic path: a typed handle over one object kind
## ---------------------------------------------------------------------
##
##   var notes = openCollection[Note]("data", "notes")
##   notes.add Note(id: 1, title: "hello")
##   for n in notes.items:  echo n.title
##   echo notes[0].title
##   notes.close()
##
## This is to Geist what `to(T)` / `%*` are to std/json: the object type is
## the schema, declaration order is the field order, and no mapping is
## written by hand. `std/json` reaches an object through `parseJson` then
## `to`; Geist reaches it through `schemaFor[T]` then `fromRow[T]`, both
## generated at compile time by `fieldPairs`.
##
## The difference from `Session` is scope, not power. `Session` exposes the
## whole database -- meta, journal, subscriptions, backup, key lifecycle.
## `Collection` exposes ONE object kind with the operations an application
## actually reaches for, so the common case reads like a `seq[T]` and the
## uncommon case is still there under `.session`.
##
## Encryption is a constructor argument, not a different API. The same
## calls work sealed or plain; only `openCollection` differs.

import std/[os, times]

import ../analysis_pragmas
import ./types
import ./config
import ./session

export types
export config
export session

type
  Collection*[T] {.role: truthState, metaTags: {tagAppApi, tagDb,
      tagTypes}.} = object
    ## A typed view of one object kind. `session` stays public because
    ## narrowing the surface must never mean losing access to it.
    session*: Session

proc openCollection*[T: object](baseDir, name: string,
    c: GeistConfig = appConfig(), password: string = "",
    autoSave: bool = true, readOnly: bool = false): Collection[T] {.
    role: orchestrator,
    metaTags: {tagAppApi, tagDb, tagOrchestrator, tagStorageIo}.} =
  ## baseDir: store root.
  ## name: database stem, e.g. "notes".
  ## c: configuration; a preset or a caller-composed value.
  ## password: required when the configuration selects a cipher.
  ## readOnly: follow without taking the write lease. A second instance of
  ##   the same application opens read-only by itself when the first still
  ##   holds it, so passing this is only necessary for a deliberate reader.
  ## autoSave: flush on every mutation. Convenient and safe by default;
  ##   turn it off for a bulk import and call `save` once at the end, which
  ##   is roughly two orders of magnitude faster for large batches.
  ##
  ## autoSave is not a second scheduling mechanism -- it SELECTS one. It
  ## sets the session's `writeMode`, so a collection and a session opened
  ## the same way behave the same way, and there is one place to look for
  ## when a write reaches disk. A configuration that already asked for
  ## something specific (`iot`'s interval, `stream`'s volatility) keeps it:
  ## only the default is overridden.
  var
    cfg: GeistConfig
  cfg = normalizeGeistConfig(c)
  if cfg.writeMode == wmManual:
    cfg.writeMode = if autoSave: wmOnChange else: wmManual
  result.session = openSession[T](baseDir, name, cfg, password, readOnly)

proc openEncryptedCollection*[T: object](baseDir, name,
    password: string, c: GeistConfig = secureAppConfig(),
    autoSave: bool = true): Collection[T] {.role: orchestrator,
    metaTags: {tagAppApi, tagCryptoBoundary, tagDb, tagOrchestrator}.} =
  ## baseDir/name/password: as above, with the password required rather
  ## than optional. Exists so that "encrypted" is a spelling difference at
  ## the call site instead of a configuration detail a caller can forget.
  if password.len == 0:
    raise newException(ValueError,
      "openEncryptedCollection needs a non-empty password")
  if c.cipher == ckNone:
    raise newException(ValueError,
      "openEncryptedCollection was given a configuration with no cipher (" &
      c.name & "); use openCollection for plaintext storage")
  result = openCollection[T](baseDir, name, c, password, autoSave)

proc len*[T](C: Collection[T]): int {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection whose stored object count is returned.
  result = int(C.session.entryCount())

proc add*[T](C: var Collection[T], x: T): RowId {.role: dataWriter,
    metaTags: {tagAppApi, tagDb, tagWrite}, discardable.} =
  ## C: collection receiving one object.
  ## x: value appended; its ID is returned -- the name to use later with
  ## `[]=`, `delete` or `byId`. Whether it reaches disk now is the
  ## session's write policy, not a decision made here.
  result = C.session.put(x)

proc add*[T](C: var Collection[T], A: openArray[T]): seq[RowId] {.
    role: dataWriter, metaTags: {tagAppApi, tagDb, tagWrite}, discardable.} =
  ## C/A: collection and objects appended in order.
  ## Flushes ONCE at the end rather than per element, so a bulk add costs
  ## one file write instead of `A.len` of them.
  result = C.session.put(A)

proc `[]=`*[T](C: var Collection[T], id: RowId, x: T) {.role: dataWriter,
    metaTags: {tagAppApi, tagDb, tagWrite}.} =
  ## C/id/x: replace one row BY NAME.
  ##
  ##   notes[id] = Note(title: "corrected")
  ##
  ## Raises on an unknown id rather than creating a row: the assignment
  ## says "change the one I mean", so inventing one would be the wrong
  ## answer to a typo. Use `add` to create.
  if not C.session.set(id, x):
    raise newException(KeyError, "no row with id " & $id)

proc setRow*[T](C: var Collection[T], id: RowId, x: T): bool {.
    role: dataWriter, metaTags: {tagAppApi, tagDb, tagWrite}, discardable.} =
  ## C/id/x: the same replacement, REPORTING an unknown id instead of
  ## raising -- for a caller that is checking rather than asserting.
  result = C.session.set(id, x)

proc delete*[T](C: var Collection[T], id: RowId): bool {.role: dataWriter,
    metaTags: {tagAppApi, tagDb, tagDelete, tagWrite}, discardable.} =
  ## C/id: remove one row. False when there was nothing there to remove.
  ## The row leaves the collection at once; its space comes back at
  ## `compact`.
  result = C.session.delete(id)

proc byId*[T](C: Collection[T], id: RowId): tuple[found: bool, value: T] {.
    role: parser, metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/id: the current version of one row, or `found = false` when it is
  ## not there any more.
  result = byId[T](C.session, id)

proc contains*[T](C: Collection[T], id: RowId): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/id: `id in notes`, for the check that needs no value.
  result = C.byId(id).found

proc ids*[T](C: Collection[T]): seq[RowId] {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: the id of every visible row, in view order.
  result = C.session.rowIds()

proc idAt*[T](C: Collection[T], i: int): RowId {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: the id of the i-th visible row -- what turns a position from
  ## `pairs` into something that can be changed afterwards.
  result = C.session.idAt(uint32(i))

proc compact*[T](C: var Collection[T]): tuple[ok: bool, removed: uint32,
    err: string] {.role: orchestrator, metaTags: {tagAppApi, tagDb, tagWrite},
    discardable.} =
  ## C: collection whose superseded versions and tombstones are reclaimed.
  ## Nothing visible changes; the file gets smaller.
  result = C.session.compact()

proc sweepSidecar*[T](C: var Collection[T]): tuple[ok: bool, removed: int,
    bytes: uint64, err: string] {.role: orchestrator,
    metaTags: {tagAppApi, tagDb, tagSidecar, tagWrite}, discardable.} =
  ## C: collection whose orphaned sidecar payloads are deleted.
  ##
  ## Run it after `compact`: a value referenced by a superseded version
  ## still in the log is not orphaned, it is history.
  result = C.session.sweepSidecar()

proc autoSaves*[T](C: Collection[T]): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection reporting whether a mutation reaches disk by itself.
  ## True for the interval mode too: it flushes without being asked, just
  ## not on every write.
  result = C.session.config.writeMode in {wmOnChange, wmInterval}

proc `[]`*[T](C: Collection[T], i: int): T {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C/i: collection and index. Addressing is arithmetic, not a scan.
  if i < 0 or i >= C.len:
    raise newException(IndexDefect,
      "index " & $i & " is out of range for a collection of " & $C.len)
  result = C.session.get[:T](uint32(i))

iterator items*[T](C: Collection[T]): T {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection iterated in stored order.
  var
    i: uint32 = 0'u32
  while i < C.session.entryCount():
    yield C.session.get[:T](i)
    i = i + 1'u32

iterator pairs*[T](C: Collection[T]): tuple[index: int, value: T] {.
    role: parser, metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection iterated with indices, for callers that need to address
  ## a row again afterwards.
  var
    i: uint32 = 0'u32
  while i < C.session.entryCount():
    yield (int(i), C.session.get[:T](i))
    i = i + 1'u32

proc find*[T](C: Collection[T], field, value: string): seq[T] {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection to search.
  ## field/value: exact text match on one field.
  result = C.session.find[:T](field, value)

proc toSeq*[T](C: Collection[T]): seq[T] {.role: parser,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: whole collection materialised. Named explicitly rather than offered
  ## as an implicit conversion, because for a large database this is the
  ## expensive call and it should look like one.
  for x in C.items:
    result.add x

proc save*[T](C: var Collection[T]): tuple[ok: bool, err: string] {.
    role: orchestrator, metaTags: {tagAppApi, tagDb, tagWrite}.} =
  ## C: collection flushed to its artifact set.
  result = C.session.save()

proc close*[T](C: var Collection[T]) {.role: stateController,
    metaTags: {tagAppApi, tagDb, tagLifecycle}.} =
  ## C: collection persisted if dirty, then cleared.
  C.session.close()

proc checkpoint*[T](C: var Collection[T],
    message: string = "checkpoint"): uint32 {.role: stateController,
    metaTags: {tagAppApi, tagDb, tagWrite}, discardable.} =
  ## C/message: hash-chained journal entry, when the configuration keeps
  ## history.
  result = C.session.checkpoint(message)

proc schema*[T](C: Collection[T]): Schema {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead}.} =
  ## C: collection whose stored schema is returned -- the one read back
  ## from the file, which may differ from `schemaFor[T]()` if the file was
  ## written by an older version of the type.
  result = C.session.entries.schema

proc isEncrypted*[T](C: Collection[T]): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagCryptoBoundary, tagDb, tagRead}.} =
  ## C: collection reporting whether its rows are sealed at rest.
  result = C.session.encrypted

proc isWritable*[T](C: Collection[T]): bool {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead, tagStatus}.} =
  ## C: collection reporting whether `add` will be accepted.
  ## False when another process holds the write lease -- ask BEFORE offering
  ## the user an edit button, rather than after catching the exception.
  result = not C.session.readOnly

proc blockedBy*[T](C: Collection[T]): string {.role: parser, inline,
    metaTags: {tagAppApi, tagDb, tagRead, tagStatus}.} =
  ## C: collection naming who holds the write lease, empty when nobody does.
  ## Show this: "held by pid 4711 on thinkpad" is something a person can act
  ## on, and "read-only" is not.
  result = C.session.leaseHolder

proc artifacts*[T](C: Collection[T]): seq[string] {.role: parser, inline,
    metaTags: {tagAppApi, tagBackup, tagDb, tagRead}.} =
  ## C: the file set that must move together. Copying the data file alone
  ## produces an unrecoverable database when encryption is on.
  result = C.session.artifactSet()
