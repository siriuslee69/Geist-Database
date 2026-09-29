## ---------------------------------------------------------------------
## Session view <- the live rows printed, and the column-first search copy
## ---------------------------------------------------------------------
##
## What a person sees (show, visibleRow) and the transposed copy a
## search reads instead of every row (syncTransposed, transposedView).
##
## Part of the Session; see ./session for how the parts fit.


import runePragmas
import ./types
import ./rowid
import ./store
import ./config
import ./show
import ./transpose
import ./sessioncore

## ------------------------------ showing -----------------------------
##
## `echo db` on a store of any size. The rows that will not be printed are
## never decoded: `show` asks the style which positions it needs, fetches
## exactly those, and hands them over already selected. Printing twenty
## lines of a million-row store costs twenty rows.

proc visibleRow*(s: Session, i: uint32): Row {.role: parser, inline,
    tag: "appApi|db|read".} =
  ## s/i: the i-th VISIBLE row -- superseded versions and tombstones are
  ## in the log, not in the list a person asked for.
  result = s.entries.rowAt(s.livePosition(i))

proc shownSlice(s: Session, limit: int): tuple[rows: seq[Row], at: seq[int],
    gapAfter: int] {.role: dataFetcher, tag: "db|read".} =
  ## s/limit: the head and tail this style will print, and nothing else.
  var
    n: int = int(s.entryCount())
    k: tuple[head, tail: int, elided: bool] = shownCount(n, limit)
  for i in shownIndexes(n, limit):
    result.rows.add s.visibleRow(uint32(i))
    result.at.add i
  result.gapAfter = if k.elided: k.head - 1 else: -1

proc show*(s: Session,
    style: ShowStyle = defaultShowStyle()): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## s/style: the visible rows as an aligned table, elided by default.
  var
    slice: tuple[rows: seq[Row], at: seq[int], gapAfter: int] = (@[], @[], 0)
  slice = s.shownSlice(style.maxRows)
  result = showSelection(s.entries.schema, slice.rows, slice.at,
    int(s.entryCount()), slice.gapAfter, style)

proc showTransposed*(s: Session,
    style: ShowStyle = defaultShowStyle()): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## s/style: the same rows with the axes swapped -- one line per field.
  var
    swapped: ShowStyle = style
    slice: tuple[rows: seq[Row], at: seq[int], gapAfter: int] = (@[], @[], 0)
  swapped.maxRows = style.maxColumns
  swapped.maxColumns = style.maxRows
  slice = s.shownSlice(swapped.maxRows)
  result = showSelection(s.entries.schema, slice.rows, slice.at,
    int(s.entryCount()), slice.gapAfter, swapped, transposed = true)

proc `$`*(s: Session): string {.role: helper,
    tag: "appApi|db|formatting|read".} =
  ## `echo db`, with the default style. A Session that printed its object
  ## fields instead would print a key set and a lease, which is both
  ## useless and the last thing anyone wants in a log.
  result = s.show()

## ---------------------------- fast search ---------------------------
##
## The column-first copy, and the two questions an operator has about it:
## is it current, and rebuild it now. The copy itself lives in
## transpose.nim; what belongs here is WHEN it is written, which only a
## session that just published a generation can know.


proc syncTransposed*(S: var Session): tuple[ok: bool, err: string] {.
    role: orchestrator, tag: "appApi|db|storageIo|write".} =
  ## S: rebuild the column copy from what is on disk NOW, whatever the
  ## configured mode says.
  ##
  ## This is the manual half of `tmManual`: write the store when you like,
  ## bring the search copy up to date when it suits. It refuses on an
  ## unsaved session rather than writing a copy of rows the store does not
  ## have yet -- the copy would then be the newer of the two, which is the
  ## one state the freshness check cannot express.
  if S.config.transpose == tmNone:
    return (false, "this database is configured with transpose = tmNone")
  if S.dirty:
    return (false, "there are unsaved rows; save first, or the column " &
      "copy would hold rows the store does not")
  result = S.writeTransposedNow(S.generation)

proc transposeState*(S: Session): TransposeStatus {.role: parser,
    tag: "appApi|db|read|status".} =
  ## S: which of the two copies is ahead, read from the files themselves.
  result = transposeState(S.baseDir, S.baseName)

proc transposedView*(S: Session): tuple[ok: bool, t: TransposedFile,
    err: string] {.role: parser, tag: "appApi|db|read".} =
  ## S: the column copy, opened for reading, IF it matches the live
  ## generation. A stale copy is refused rather than silently searched:
  ## the answer would be yesterday's rows, which is worse than a slow
  ## answer today.
  var
    state: TransposeStatus = S.transposeState()
  if state.state != tsCurrent:
    return (false, TransposedFile(),
      "column copy is " & describeTransposeState(state.state, state.live,
        state.built))
  result = openTransposed(state.path)

proc visibleIndexOf*(s: Session, logPosition: uint32): int {.role: parser,
    tag: "appApi|db|read".} =
  ## s/logPosition: where a row of the LOG appears in the visible list, or
  ## -1 when it does not appear at all.
  ##
  ## The inverse of `livePosition`, and the question anything that searched
  ## the log has to ask before it reports a hit: the log holds superseded
  ## versions and tombstones, and neither is an answer. Walking the live
  ## list costs one pass over a seq of positions -- no row is decoded, so
  ## it stays cheap next to the search that produced the hit.
  var
    i: int = 0
  if not s.hasIdentity():
    return (if logPosition < s.entries.rowCount: int(logPosition) else: -1)
  while i < s.live.live.len:
    if s.live.live[i] == logPosition:
      return i
    i = i + 1
  result = -1
