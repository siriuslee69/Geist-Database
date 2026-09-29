## ---------------------------------------------------------------------
## Show <- rows as a table a person can read
## ---------------------------------------------------------------------
##
##   echo db.show()               the rows, elided like a matrix
##   echo db.showTransposed()     the same rows with the axes swapped
##
## Rendering a row used to live in the CLI, which meant a library user
## with a Session in hand had to write their own aligned columns or shell
## out to `geist list`. It is the same job whether the answer goes to a
## terminal, a log, or a test failure message.
##
## ELISION IS THE DEFAULT, and it is why this module has a style object at
## all. `echo` on a 500,000-row store is not a printout, it is an
## accident. So a big table is shown the way a big matrix is written --
## the corners, with the middle marked:
##
##   @    __rowId               noteId  ...  title   body
##   ---------------------------------------------------------
##   0    11831573047125475329  1       ...  first   hello
##   1    11831573047125475330  2       ...  second  world
##   ...  ...                   ...     ...  ...     ...
##   99   11831573047125475428  100     ...  last    row
##
##   100 rows x 7 columns (showing 20 x 6)
##
## The elided rows are never rendered -- not rendered and then dropped.
## Showing part of a huge table costs the size of the part. A caller with
## the whole store still in a seq gets that for free; a caller who can
## fetch by position (a Session) uses `showSelection` and never touches
## the middle at all.
##
## `everything()` turns elision off for a caller who means it.

import std/[strutils, json]

import runePragmas
import ./types
import ./dynamic

const
  ellipsis* = "..."
    ## What stands in for the part left out. Three dots rather than a
    ## Unicode character: this goes into terminals, log files and test
    ## output, and one of those will be the one that cannot render it.

type
  ShowStyle* {.role: configurator, tag: "cli|config|formatting|types".} = object
    ## maxRows/maxColumns: how many to SHOW, not how many exist. Zero on
    ##   either means no limit, which is what `everything()` sets.
    ## maxCellWidth: one long body would otherwise set the width of its
    ##   whole column and turn every other line into padding.
    ## positions: show the `@` column -- the short name a person types
    ##   back, as opposed to the id another machine would use.
    ## footer: the "N rows x M columns" line. Worth keeping: without it an
    ##   elided table looks like a complete small one.
    maxRows*: int
    maxColumns*: int
    maxCellWidth*: int
    positions*: bool
    footer*: bool

proc defaultShowStyle*(): ShowStyle {.role: configurator, stage: stDone,
    tag: "cli|formatting".} =
  ## Corners of the table, sized for a terminal rather than a file.
  result.maxRows = 20
  result.maxColumns = 10
  result.maxCellWidth = 42
  result.positions = true
  result.footer = true

proc everything*(): ShowStyle {.role: configurator,
    tag: "cli|formatting".} =
  ## No elision. For a caller who knows how big the table is and wants all
  ## of it: a test fixture, a small store, a redirect into a file.
  result = defaultShowStyle()
  result.maxRows = 0
  result.maxColumns = 0
  result.footer = false

## ------------------------- what to leave out ------------------------

proc shownCount*(n, limit: int): tuple[head, tail: int, elided: bool] {.
    role: parser, tag: "formatting".} =
  ## n/limit: how many of `n` items to take from each end.
  ##
  ## The head gets the odd one when the limit is odd, because the first
  ## rows are the ones a reader looks at first. Public because a caller
  ## that fetches rows by position needs to know WHICH ones to fetch
  ## before it can hand them over -- see `showSelection`.
  if limit <= 0 or n <= limit:
    return (n, 0, false)
  result.head = (limit + 1) div 2
  result.tail = limit div 2
  result.elided = true

proc shownIndexes*(n, limit: int): seq[int] {.role: parser,
    tag: "formatting".} =
  ## n/limit: the indexes actually shown, in order.
  ##
  ## One list, used for both directions, so rows and columns cannot drift
  ## into eliding by different rules.
  var
    k: tuple[head, tail: int, elided: bool] = shownCount(n, limit)
    i: int = 0
  while i < k.head:
    result.add i
    i = i + 1
  i = n - k.tail
  while i < n:
    result.add i
    i = i + 1

## ----------------------------- rendering ----------------------------

proc clip(s: string, width: int): string {.role: helper,
    tag: "formatting".} =
  ## s/width: a cell cut to fit, with the cut made visible.
  if width <= 0 or s.len <= width:
    return s
  if width <= ellipsis.len:
    return s[0 ..< width]
  result = s[0 ..< width - ellipsis.len] & ellipsis

proc gapRow(n: int): seq[string] {.role: helper,
    tag: "formatting".} =
  ## n: a line of nothing but the mark that says something was left out.
  for i in 0 ..< n:
    result.add ellipsis

proc lineOf(rendered: seq[string], cols: seq[int], width: int): seq[string] {.
    role: parser, tag: "formatting".} =
  ## rendered/cols/width: one row's cells, as the columns ask for them --
  ## an elided column (-1) as the ellipsis, a long cell clipped.
  for j in cols:
    if j < 0:
      result.add ellipsis
    elif j < rendered.len:
      result.add clip(rendered[j], width)
    else:
      result.add ""

proc cellsOf(s: Schema, R: openArray[Row], cols: seq[int],
    gapAfter: int, width: int): seq[seq[string]] {.role: parser,
    tag: "formatting|read".} =
  ## s/R: schema and the rows to render -- ALL of them; the caller has
  ##   already decided which those are.
  ## cols: column indexes to show, -1 marking an elided column.
  ## gapAfter: index in R after which the elided-rows line goes, or -1.
  var
    i: int = 0
  while i < R.len:
    result.add lineOf(renderRow(s, R[i].data), cols, width)
    if i == gapAfter:
      result.add gapRow(cols.len)
    i = i + 1

proc columnAxis(s: Schema, style: ShowStyle): seq[int] {.role: parser,
    tag: "formatting".} =
  ## s/style: column indexes to show, with -1 where the gap goes.
  var
    k: tuple[head, tail: int, elided: bool] = shownCount(s.slots.len,
      style.maxColumns)
    kept: seq[int] = shownIndexes(s.slots.len, style.maxColumns)
  result = kept
  if k.elided:
    result = kept[0 ..< k.head] & @[-1] & kept[k.head .. ^1]

proc headings(s: Schema, cols: seq[int]): seq[string] {.role: parser,
    tag: "formatting".} =
  ## s/cols: column names in shown order, the gap named too.
  for j in cols:
    if j < 0:
      result.add ellipsis
    else:
      result.add s.nameOf(s.slots[j].nameId)

proc laid(head: openArray[string], body: seq[seq[string]],
    lead: openArray[string], leadHead: string): string {.role: helper,
    tag: "formatting|write".} =
  ## head: column titles.
  ## body: one seq of cells per line, each as long as `head`.
  ## lead: an optional first cell per body line -- the `@` column, or a
  ##   field name in the transposed view. Empty when there is none.
  ## leadHead: what that first column is called.
  ##
  ## Widths come from the DATA, not from a fixed number: with ids running
  ## to twenty digits a fixed width turns every table into a ragged mess.
  var
    widths: seq[int] = @[]
    leadWidth: int = 0
    line: string = ""
    i: int = 0
    j: int = 0
  for h in head:
    widths.add h.len
  while i < body.len:
    j = 0
    while j < body[i].len and j < widths.len:
      widths[j] = max(widths[j], body[i][j].len)
      j = j + 1
    i = i + 1
  if lead.len > 0:
    leadWidth = leadHead.len
    for t in lead:
      leadWidth = max(leadWidth, t.len)
  line = if lead.len > 0: alignLeft(leadHead, leadWidth + 2) else: ""
  j = 0
  while j < head.len:
    line.add alignLeft(head[j], widths[j] + 2)
    j = j + 1
  line = line.strip(leading = false)
  result = line & "\n" & repeat('-', max(1, line.len)) & "\n"
  i = 0
  while i < body.len:
    line = if i < lead.len: alignLeft(lead[i], leadWidth + 2) else: ""
    j = 0
    while j < body[i].len and j < widths.len:
      line.add alignLeft(body[i][j], widths[j] + 2)
      j = j + 1
    result.add line.strip(leading = false) & "\n"
    i = i + 1

proc footerLine(rows, cols, shownRows, shownCols: int): string {.role: helper,
    tag: "formatting|status".} =
  ## The line that stops an elided table from looking like a complete one.
  result = "\n" & $rows & " row" & (if rows == 1: "" else: "s") & " x " &
    $cols & " column" & (if cols == 1: "" else: "s")
  if shownRows < rows or shownCols < cols:
    result.add " (showing " & $shownRows & " x " & $shownCols & ")"
  result.add "\n"

proc leadColumn(at: openArray[int], count, gapAfter: int,
    withPositions: bool): seq[string] {.role: helper,
    tag: "formatting".} =
  ## at/count/gapAfter: the `@` column for the rows being shown, with the
  ## gap marked in the same place the body marks it.
  var
    i: int = 0
  if not withPositions or at.len == 0:
    return @[]
  while i < count:
    result.add (if i < at.len: $at[i] else: "")
    if i == gapAfter:
      result.add ellipsis
    i = i + 1

proc showSelection*(s: Schema, R: openArray[Row], at: openArray[int],
    totalRows, gapAfter: int, style: ShowStyle = defaultShowStyle(),
    transposed: bool = false): string {.role: helper,
    tag: "appApi|cli|formatting|read".} =
  ## s: the schema every row belongs to.
  ## R: exactly the rows to render, in display order.
  ## at: their positions in the visible list, for the `@` column.
  ## totalRows: how many there really are, for the footer.
  ## gapAfter: index in R after which to print the elided-rows line, or -1
  ##   when R is everything.
  ##
  ## The entry point for a caller that can fetch a row by position and
  ## would rather not read the middle of a million-row store to print
  ## twenty lines of it. Callers holding the rows already want `showTable`.
  var
    cols: seq[int] = columnAxis(s, style)
    cells: seq[seq[string]] = @[]
    lead: seq[string] = @[]
    head: seq[string] = @[]
    grid: seq[seq[string]] = @[]
    shownCols: int = 0
    i: int = 0
    j: int = 0
  if s.slots.len == 0:
    return "(no columns)\n"
  for c in cols:
    if c >= 0:
      shownCols = shownCols + 1
  cells = cellsOf(s, R, cols, gapAfter, style.maxCellWidth)
  if not transposed:
    result = laid(headings(s, cols), cells,
      leadColumn(at, R.len, gapAfter, style.positions), "@")
    if style.footer:
      result.add footerLine(totalRows, s.slots.len, R.len, shownCols)
    return
  # Transposed: one line per FIELD, one column per row. The cells are the
  # same, read down instead of across.
  #
  # The headings come from `leadColumn` for the same reason the `@` column
  # does: it is the one place that knows where the gap sits, and a second
  # copy of that arithmetic is a second chance to be off by one.
  for t in leadColumn(at, R.len, gapAfter, true):
    head.add (if t == ellipsis: t else: "@" & t)
  j = 0
  while j < cols.len:
    var line: seq[string] = @[]
    i = 0
    while i < cells.len:
      line.add cells[i][j]
      i = i + 1
    grid.add line
    lead.add (if cols[j] < 0: ellipsis
              else: s.nameOf(s.slots[cols[j]].nameId))
    j = j + 1
  result = laid(head, grid, lead, "field")
  if style.footer:
    result.add footerLine(totalRows, s.slots.len, R.len, shownCols)

proc showTable*(s: Schema, R: openArray[Row],
    style: ShowStyle = defaultShowStyle(),
    at: openArray[int] = []): string {.role: helper,
    tag: "appApi|cli|formatting|read".} =
  ## s/R: schema and the rows to show. Rows are self-contained, so nothing
  ##   else is needed to render one.
  ## style: how much of it to show. The default elides; see `everything()`.
  ## at: each row's position in the visible list, shown as the `@` column.
  ##   Pass nothing and the column is left out, which is right for a result
  ##   set whose positions are not the ones `list` would print.
  var
    k: tuple[head, tail: int, elided: bool] = shownCount(R.len,
      style.maxRows)
    keptRows: seq[Row] = @[]
    keptAt: seq[int] = @[]
    i: int = 0
  for idx in shownIndexes(R.len, style.maxRows):
    keptRows.add R[idx]
    keptAt.add (if idx < at.len: at[idx] else: idx)
  result = showSelection(s, keptRows, (if at.len > 0: keptAt else: @[]),
    R.len, (if k.elided: k.head - 1 else: -1), style)

proc showTransposed*(s: Schema, R: openArray[Row],
    style: ShowStyle = defaultShowStyle(),
    at: openArray[int] = []): string {.role: helper,
    tag: "appApi|cli|formatting|read".} =
  ## s/R/style/at: the same table with the axes swapped -- one line per
  ## FIELD, one column per row.
  ##
  ## This is how a store written column-first reads (see transpose.nim),
  ## and it is also the shape that fits a terminal when the schema is wide
  ## and the answer is short: five fields of two rows is five short lines
  ## rather than two lines nothing can align.
  ##
  ## Both axes still elide; only which limit governs which changes, since
  ## rows now run across the page.
  var
    swapped: ShowStyle = style
    k: tuple[head, tail: int, elided: bool] = (0, 0, false)
    keptRows: seq[Row] = @[]
    keptAt: seq[int] = @[]
  swapped.maxRows = style.maxColumns
  swapped.maxColumns = style.maxRows
  k = shownCount(R.len, swapped.maxRows)
  for idx in shownIndexes(R.len, swapped.maxRows):
    keptRows.add R[idx]
    keptAt.add (if idx < at.len: at[idx] else: idx)
  result = showSelection(s, keptRows, keptAt, R.len,
    (if k.elided: k.head - 1 else: -1), swapped, transposed = true)

proc jsonObjectOf(s: Schema, cells: seq[string]): string {.role: helper,
    tag: "formatting".} =
  ## s/cells: one row as `{"field": "value", ...}`, every value a string.
  ## `escapeJson` escapes what JSON requires -- quotes, backslashes AND
  ## control characters; a cell holding a newline used to produce output
  ## no JSON reader would accept.
  var
    j: int = 0
  result = "{"
  while j < cells.len and j < s.slots.len:
    result.add (if j > 0: ", " else: "") &
      escapeJson(s.nameOf(s.slots[j].nameId)) & ": " & escapeJson(cells[j])
    j = j + 1
  result.add "}"

proc showJson*(s: Schema, R: openArray[Row]): string {.role: helper,
    tag: "appApi|cli|formatting|write".} =
  ## s/R: the same rows as machine-readable output.
  ##
  ## No elision here, ever: a JSON array that quietly dropped its middle
  ## would be read by a program, and a program cannot see the dots.
  var
    i: int = 0
    line: string = ""
  result = "[\n"
  while i < R.len:
    line = "  " & jsonObjectOf(s, renderRow(s, R[i].data))
    if i < R.len - 1:
      line.add ","
    result.add line & "\n"
    i = i + 1
  result.add "]\n"
