## ---------------------------------------------------------------------
## Geist Tables <- a database as a JSON or TOML file, and back
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/geist_tables.nim
##
##   db  --exportTable("notes.toml")-->  one [[rows]] block per row
##   db  --exportTable(.., shColumns)->  one list per column (transposed)
##   db  --exportTable(.., sealed)--->   chosen columns encrypted, as hex
##                                       or as \u00HH escapes
##   file --importTable--------------->  the rows back, same ids
##
## From the shell, the same thing:
##   geist --path data/notes export notes.toml
##   geist --path data/notes export notes.json --transposed
##   geist --path data/notes export notes.toml --seal body \
##         --seal-password-file pw.txt --binary escaped
##   geist --path data/copy  import notes.toml --seal-password-file pw.txt

import std/[os, strutils]

import runePragmas
import geist

type
  Note = object
    title: string
    body: string
    stars: int

when isMainModule:
  var
    dir: string = getTempDir() / "geist_tables_example"
    db: Session = default(Session)
    copy: Session = default(Session)
    style: TableTextStyle = defaultTableTextStyle()
    key: Secret = newSealKey()

  removeDir(dir)
  db = openSession[Note](dir / "notes", "main", defaultGeistConfig(), "")
  discard db.put(Note(title: "groceries", body: "milk, eggs", stars: 2))
  discard db.put(Note(title: "diary", body: "dear diary ...", stars: 5))

  ## ── 1. One block per row, TOML ──
  doAssert db.exportTable(dir / "notes.toml").ok
  echo "--- rows, TOML (the end of it)"
  echo readFile(dir / "notes.toml").splitLines()[^9 .. ^1].join("\n")

  ## ── 2. Transposed: one list per column, JSON ──
  style.shape = shColumns
  doAssert db.exportTable(dir / "notes.json", style).ok
  echo "--- columns, JSON (the end of it)"
  echo readFile(dir / "notes.json").splitLines()[^9 .. ^1].join("\n")

  ## ── 3. `body` sealed with a key, written with escapes ──
  style.shape = shRows
  style.binary = bfEscaped
  style.sealed = @["body"]
  doAssert db.exportTable(dir / "sealed.toml", style, key).ok
  echo "--- body sealed: the diary is not in the file: ",
    "dear diary" notin readFile(dir / "sealed.toml")

  ## ── 4. Back into a new database; the key opens it ──
  copy = openSession[Note](dir / "copy", "main", defaultGeistConfig(), "")
  echo "--- import: ", copy.importTable(dir / "sealed.toml", key)
  echo copy.byId[:Note](copy.idAt(1)).value
  echo "--- without the key: ", copy.importTable(dir / "sealed.toml").err

  db.close()
  copy.close()
