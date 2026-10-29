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
##   plain store, untyped          openStore: the live data file is opened with
##                                 the seek handle and rows are read from disk in
##                                 the ranges the search asks for
##   plain store, typed (a T)      typedSeekSource[T]: the same, one T per row
##   sealed store (needs T)       sealedSource[T]: a typed session, opened with
##                                 the password, reads rows from memory
##   text, JSON lines, frames      openFileSource: the Null sources for files
##
## A sealed store cannot be read without its type. Its columns are grouped by
## the schema, so an untyped open reads the wrong bytes. That is why sealed
## stores take a T, and plain stores do not.
##
## Def. 1 (untyped row): a row read with the schema the file carries. Each slot
##   becomes one named field; the slot kind picks the value kind.
## Def. 2 (typed row): a row read into a Nim object T; each object field becomes
##   one named field, by its type.
##
## Slot kinds that cannot be read without a key are shown, not hidden:
##   sealed field  -> the text "<sealed>"
##   reference     -> the text "<ref>"
## A predicate on either does not match a value it cannot see.

import std/[os, strutils]

import runePragmas
import null_query_apis as nq
import ./types
import ./keys
import ./seek
import ./dynamic
import ./config
import ./sessionopen
import ./sessioncore
import ./store

const
  storeBaseName*: string = "main"
    ## The stem Geist gives a store folder unless a caller asks otherwise.

type
  SessionHolder {.role: truthState.} = ref object
    ## The session, behind a reference, so the source's closures can share it.
    db: Session

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

proc rowObject*(schema: Schema, data: seq[uint8], number: int): nq.NullObject {.
    role: helper.} =
  ## schema/data/number: one untyped row (Def. 1) as a Null object.
  var
    texts: seq[string] = renderRow(schema, data)
  result.number = number
  for j in 0 ..< schema.slots.len:
    result.fields.add nq.NullField(name: nameOf(schema, schema.slots[j].nameId),
      value: slotValue(schema.slots[j].kind, texts[j]))

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

proc seekSource*(path: string): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## path: a data file of a plain store. Rows are read from disk, in whatever
  ## ranges the search asks for. A sealed file is refused, with the reason.
  var opened = openSeek(path)
  if not opened.ok:
    return (false, nil, opened.err)
  if looksSealed(opened.h):
    return refuseSealed(path)
  var h = opened.h
  result = nq.openRecords(path, int(h.rowCount), proc (first, n: int): seq[nq.NullObject] =
    var rows = h.seekRange(uint32(first), uint32(n))
    for k in 0 ..< rows.len:
      result.add rowObject(h.schema, rows[k].data, first + k))

proc openStore*(dir: string): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir: a plain Geist store folder. Opens its live data file for streaming.
  ## Never takes the write lease: a search must not block a running writer.
  var path = liveDataPath(dir, storeBaseName)
  if not fileExists(path):
    return (false, nil, "no store at " & dir)
  result = seekSource(path)

proc typedSeekSource*[T: object](path: string): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## path: a data file of a plain store whose rows are a T. Rows are read one at
  ## a time from disk, as the search asks for them.
  var opened = openSeek(path)
  if not opened.ok:
    return (false, nil, opened.err)
  if looksSealed(opened.h):
    return refuseSealed(path)
  var h = opened.h
  result = nq.openRecords(path, int(h.rowCount), proc (first, n: int): seq[nq.NullObject] =
    for i in first ..< first + n:
      result.add toNullObject(seekObject[T](h, uint32(i)), i))

proc sealedSource*[T: object](dir: string, password: string,
    cfg: GeistConfig = appConfig()): nq.NullOpen {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir/password/cfg: a sealed store folder, opened read-only as a T with its
  ## password and the configuration it was written with. The rows are read from
  ## memory (Geist does not yet stream a sealed file). Closing the source closes
  ## the session.
  var
    db: Session = default(Session)
  try:
    db = openSession[T](dir, storeBaseName, cfg, password, true)
  except CatchableError as e:
    return (false, nil, e.msg)
  var
    holder = SessionHolder(db: move(db))
    count = int(holder.db.entryCount())
    readFn: proc (first, n: int): seq[nq.NullObject] {.closure.}
  readFn = proc (first, n: int): seq[nq.NullObject] =
    for i in first ..< first + n:
      result.add toNullObject(objectAt[T](holder.db.entries, holder.db.livePosition(uint32(i))), i)
  result = nq.openRecords(dir, count, readFn)
  if result.ok:
    result.src.closeFn = proc () = close(holder.db)

proc searchStore*(dir: string, q: nq.NullQuery, capacity: int = 0): tuple[ok: bool,
    res: nq.NullResult, err: string] {.role: orchestrator, tag: "storageIo|read".} =
  ## dir/q/capacity: search one plain store. capacity 0 reads everything at once;
  ## a positive capacity streams through a ring of that many rows.
  var opened = openStore(dir)
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
