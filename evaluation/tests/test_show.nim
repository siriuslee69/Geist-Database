## Printing a table, including one too big to print.
##
## The rule under test is that a large table is shown the way a large
## matrix is written -- corners, with the middle marked -- and that the
## elided part is never rendered at all. A renderer that produced the
## right picture by building every cell and dropping most of them would
## pass a visual check and still make `echo db` unusable.

import std/[os, strutils, unittest]

import geist

type
  Note = object
    noteId: int
    title: string
    body: string

  Wide = object
    a, b, c, d, e, f, g, h, i, j, k, l: int

proc freshRoot(name: string): string =
  result = "build/test-show-" & name
  removeDir(result)

suite "a small table prints whole":

  test "every row and column is there, with the @ column":
    var db = openGeist[Note](freshRoot("small"), appConfig())
    for i in 1 .. 3:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var text = db.show()
    check text.count('\n') == 3 + 2 + 2   # header, rule, rows, blank, footer
    check "@" in text
    check "__rowId" in text
    check "t1" in text and "t2" in text and "t3" in text
    check "3 rows x 5 columns" in text
    check "showing" notin text            # nothing was left out
    db.close()

  test "an empty database still prints its columns":
    var
      db = openGeist[Note](freshRoot("empty"), appConfig())
      text = db.show()
    check "title" in text
    check "0 rows x 5 columns" in text
    db.close()

suite "a big table is elided like a matrix":

  test "the corners are kept and the middle is marked":
    var db = openGeist[Note](freshRoot("rows"), appConfig())
    for i in 1 .. 100:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var text = db.show()
    check "t1" in text                 # head
    check "t100" in text               # tail
    check "t50" notin text             # middle
    check "..." in text
    check "100 rows x 5 columns (showing 20 x 5)" in text
    # Header, rule, 20 rows, one gap line, blank, footer.
    check text.count('\n') == 2 + 20 + 1 + 2
    db.close()

  test "the head keeps the odd row when the limit is odd":
    var db = openGeist[Note](freshRoot("odd"), appConfig())
    for i in 1 .. 50:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var style = defaultShowStyle()
    style.maxRows = 5
    var text = db.show(style)
    check "t1" in text and "t2" in text and "t3" in text    # three from the head
    check "t49" in text and "t50" in text                  # two from the tail
    # " t4 " with spaces: "t4" alone is a substring of "t49", which IS shown.
    check " t4 " notin text
    db.close()

  test "columns elide too, in the same shape":
    var db = openGeist[Wide](freshRoot("wide"), appConfig())
    for i in 1 .. 3:
      db.put(Wide(a: i, l: i * 99))
    var text = db.show()
    check "__rowId" in text            # first columns
    check "l" in text                  # last column
    check " f " notin text             # a middle column's heading
    check "14 rows x 14 columns" notin text
    check "3 rows x 14 columns (showing 3 x 10)" in text
    db.close()

  test "everything() turns eliding off":
    var db = openGeist[Note](freshRoot("all"), appConfig())
    for i in 1 .. 40:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var text = db.show(everything())
    check "t20" in text
    check "..." notin text
    check text.count('\n') == 2 + 40
    db.close()

  test "a long cell is cut, and says it was":
    var db = openGeist[Note](freshRoot("long"), appConfig())
    db.put(Note(noteId: 1, title: "x".repeat(200), body: "b"))
    var text = db.show()
    check "..." in text
    # 42 wide by default, so no line runs away with the table.
    for line in text.splitLines():
      check line.len < 120
    db.close()

suite "transposed printing":

  test "fields go down the side and rows across the top":
    var db = openGeist[Note](freshRoot("t"), appConfig())
    for i in 1 .. 3:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var
      text = db.showTransposed()
      lines = text.splitLines()
    check lines[0].startsWith("field")
    check "@0" in lines[0] and "@2" in lines[0]
    # One line per field: id, flags, noteId, title, body.
    check lines[2].startsWith("__rowId")
    check lines[4].startsWith("noteId")
    check lines[5].startsWith("title")
    check "t1" in lines[5] and "t3" in lines[5]
    db.close()

  test "the axes swap which limit governs which":
    var db = openGeist[Note](freshRoot("tbig"), appConfig())
    for i in 1 .. 100:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var text = db.showTransposed()
    # 10 rows across (maxColumns), all 5 fields down.
    check "@0" in text and "@99" in text
    check "@50" notin text
    check "..." in text
    check "100 rows x 5 columns (showing 10 x 5)" in text
    db.close()

suite "machine output is never elided":

  test "json carries every row, dots or no dots":
    var db = openGeist[Note](freshRoot("json"), appConfig())
    for i in 1 .. 30:
      db.put(Note(noteId: i, title: "t" & $i, body: "b" & $i))
    var rows: seq[Row] = @[]
    for i in 0'u32 ..< db.entryCount():
      rows.add db.visibleRow(i)
    var text = showJson(db.entries.schema, rows)
    check text.count("__rowId") == 30
    check "t15" in text
    check "..." notin text
    db.close()

  test "a quote in a value does not break the json":
    var db = openGeist[Note](freshRoot("quote"), appConfig())
    db.put(Note(noteId: 1, title: "say \"hi\"", body: "back\\slash"))
    var text = showJson(db.entries.schema, @[db.visibleRow(0'u32)])
    check "\\\"hi\\\"" in text
    check "back\\\\slash" in text
    db.close()
