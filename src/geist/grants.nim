## -------------------------------------------------------------------------
## Grants <- who may read or write which address, from its OWN table
## -------------------------------------------------------------------------
##
## An AccessRight says WHAT a subject may do. This module says WHERE: which
## address it may do it to. The table is one Geist store, kept apart from the
## data it protects.
##
## Def. 1 (grant): subject + prefix + rights. "fjord" below is an address
##   prefix: it covers `fjord`, `fjord/mail`, `fjord/mail/alice/inbox`, ...
##   but never `fjordish`. Prefixes count whole path parts.
## Def. 2 (the decision): the most specific grant that covers an address
##   decides. A longer prefix beats a shorter one. There are NO deny rules.
## Def. 3 (default): with no grant covering an address, the subject has no
##   rights there. Nothing is readable until someone grants it.
##
##   grants                              rights at address
##   ----------------------------------  ------------------------------------
##   phone  fjord            read        phone -> fjord/mail/alice   read
##   phone  fjord/mail/alice write       phone -> fjord/mail/alice   read+write
##   phone  fjord/mail/bob   read        phone -> fjord/mail/bob     read
##                                       phone -> fjordish           (none)
##                                       eris  -> fjord/mail/alice   (none)
##
## The table is written as text, one grant per line, so an operator can read
## and check it without a tool:
##
##   phone	fjord/mail/alice	read,write
##   nas	fjord	read
##
## Subjects are exact names. There is no wildcard subject: a grant to "everyone"
## would be a grant nobody decided.

import std/[os, strutils]

import runePragmas
import ./types
import ./access
import ./config
import ./session
import ./layout
import ./rowid
import ./store
import ./row

export access

const
  grantsRowKey* = "grants"
  grantSeparator = '\t'

type
  GrantRow* {.role: truthState.} = object
    ## One grant, as the operator wrote it.
    subject*: string
    prefix*: string
    rights*: set[AccessRight]

  GrantTable* {.role: truthState.} = object
    ## Every grant. Searched in memory; saved as one row.
    grants*: seq[GrantRow]

  GrantsStoreRow* {.role: truthState.} = object
    ## The one row the store holds.
    key*: string
    body*: string

proc validName(s: string): bool {.role: sanitizer.} =
  ## s: a subject name or an address prefix. Letters, digits and . _ - / only, no
  ## empty parts, no "..", no leading or trailing slash.
  var
    i: int = 0
  if s.len == 0 or s.startsWith("/") or s.endsWith("/") or s.contains(".."):
    return false
  while i < s.len:
    if s[i] notin {'a'..'z', 'A'..'Z', '0'..'9', '.', '_', '-', '/'}:
      return false
    if s[i] == '/' and i + 1 < s.len and s[i + 1] == '/':
      return false
    i = i + 1
  result = true

proc rightsText(R: set[AccessRight]): string {.role: helper.} =
  ## R: the rights as the table writes them, "read,write" or "none".
  var
    parts: seq[string] = @[]
  if prRead in R: parts.add "read"
  if prWrite in R: parts.add "write"
  if prAdmin in R: parts.add "admin"
  result = if parts.len == 0: "none" else: parts.join(",")

proc parseRights(s: string): tuple[ok: bool, rights: set[AccessRight]] {.
    role: sanitizer.} =
  ## s: "read,write", "admin", or "none". Anything else is not ok.
  var
    part: string = ""
  if s == "none":
    return (true, {})
  for raw in s.split(','):
    part = raw.strip()
    case part
    of "read": result.rights.incl prRead
    of "write": result.rights.incl prWrite
    of "admin": result.rights.incl prAdmin
    else: return (false, {})
  result.ok = result.rights.len > 0

proc normalPath*(address: string): string {.role: helper.} =
  ## address: `geist://fjord/mail/alice/inbox?ttl=4`, or a bare path. Returns
  ## `fjord/mail/alice/inbox`: the scheme, the query and any trailing slash are
  ## dropped, so the same place always compares the same way.
  var
    s: string = address
    q: int = 0
  if s.startsWith("geist://"):
    s = s["geist://".len .. ^1]
  q = s.find('?')
  if q >= 0:
    s = s[0 ..< q]
  result = s.strip(chars = {'/'})

proc covers(prefix, path: string): bool {.role: parser.} =
  ## prefix/path: true when `prefix` names `path` or one of its parents.
  result = path == prefix or path.startsWith(prefix & "/")

proc grantIndex(T: GrantTable, subject, prefix: string): int {.role: parser.} =
  ## T/subject/prefix: the index of that exact grant, or -1.
  var
    i: int = 0
  result = -1
  while i < T.grants.len:
    if T.grants[i].subject == subject and T.grants[i].prefix == prefix:
      return i
    i = i + 1

proc grant*(T: var GrantTable, subject, prefix: string,
    rights: set[AccessRight]): tuple[ok: bool, err: string] {.role: actor.} =
  ## T/subject/prefix/rights: the grant for one subject at one prefix. An empty
  ## set removes the grant. A failed change leaves the table as it was.
  var
    i: int = -1
  if not validName(subject):
    return (false, "subject '" & subject & "' has characters a name may not have")
  if not validName(prefix):
    return (false, "prefix '" & prefix & "' is not an address path")
  i = grantIndex(T, subject, prefix)
  if i >= 0 and rights.len == 0:
    T.grants.delete(i)
  if i >= 0 and rights.len > 0:
    T.grants[i].rights = rights
  if i < 0 and rights.len > 0:
    T.grants.add GrantRow(subject: subject, prefix: prefix, rights: rights)
  result = (true, "")

proc coveringGrant(T: GrantTable, subject, path: string): int {.role: parser.} =
  ## T/subject/path: the index of the most specific grant covering `path`, or -1.
  var
    bestLen: int = -1
    i: int = 0
  result = -1
  while i < T.grants.len:
    if T.grants[i].subject == subject and covers(T.grants[i].prefix, path) and
        T.grants[i].prefix.len > bestLen:
      bestLen = T.grants[i].prefix.len
      result = i
    i = i + 1

proc rightsAt*(T: GrantTable, subject, address: string): set[AccessRight] {.
    role: parser.} =
  ## T/subject/address: the rights `subject` has at `address`. Def. 2: the most
  ## specific covering grant decides; none covering means no rights (Def. 3).
  var
    i: int = coveringGrant(T, subject, normalPath(address))
  if i >= 0:
    result = T.grants[i].rights

proc allows*(T: GrantTable, subject, address: string,
    right: AccessRight): bool {.role: parser.} =
  ## T/subject/address/right: true when that one right is held there.
  result = right in rightsAt(T, subject, address)

proc encodeGrants*(T: GrantTable): string {.role: helper.} =
  ## T: the table as text, one grant per line, in the order it was made.
  var
    lines: seq[string] = @[]
  for g in T.grants:
    lines.add g.subject & $grantSeparator & g.prefix & $grantSeparator &
      rightsText(g.rights)
  result = lines.join("\n")

proc decodeGrants*(text: string): tuple[ok: bool, table: GrantTable,
    err: string] {.role: sanitizer.} =
  ## text: a table written by encodeGrants. A line that is not three fields, or
  ## whose names or rights do not parse, refuses the whole table: a half-read
  ## table would grant less than the operator wrote.
  var
    parts: seq[string] = @[]
    rights: tuple[ok: bool, rights: set[AccessRight]] = (false, {})
    lineNo: int = 0
  for line in text.splitLines():
    lineNo = lineNo + 1
    if line.len == 0:
      continue
    parts = line.split(grantSeparator)
    if parts.len != 3:
      return (false, GrantTable(), "line " & $lineNo & " has " &
        $parts.len & " fields; a grant has 3")
    if not validName(parts[0]) or not validName(parts[1]):
      return (false, GrantTable(), "line " & $lineNo & " has a bad name")
    rights = parseRights(parts[2])
    if not rights.ok:
      return (false, GrantTable(), "line " & $lineNo & " has bad rights '" &
        parts[2] & "'")
    result.table.grants.add GrantRow(subject: parts[0], prefix: parts[1],
      rights: rights.rights)
  result.ok = true

proc saveGrants*(dir: string, T: GrantTable): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "storageIo|write".} =
  ## dir/T: the folder of the table, and the table to keep. The whole table is
  ## one row, so a save is all-or-nothing.
  var
    db: Session = openSession[GrantsStoreRow](dir, "main", appConfig(), "")
    row: GrantsStoreRow = GrantsStoreRow(key: grantsRowKey, body: encodeGrants(T))
    ids: seq[RowId] = db.findIds("key", grantsRowKey)
    saved: tuple[ok: bool, err: string] = (false, "")
  try:
    if ids.len > 0:
      discard db.set(ids[0], row)
    else:
      discard db.put(row)
    saved = db.save()
    result = (saved.ok, saved.err)
  except CatchableError as e:
    result = (false, e.msg)
  db.close()

proc loadGrants*(dir: string): tuple[ok: bool, found: bool, table: GrantTable,
    err: string] {.role: parser, tag: "storageIo|read".} =
  ## dir: the folder of the table. found false when nothing was ever saved there:
  ## the table is then empty, so nothing is granted.
  var
    db: Session = default(Session)
    rows: seq[GrantsStoreRow] = @[]
    got: tuple[ok: bool, table: GrantTable, err: string] = (false, GrantTable(), "")
  result.ok = true
  if not dirExists(dir):
    return
  try:
    db = openSession[GrantsStoreRow](dir, "main", appConfig(), "")
    rows = find[GrantsStoreRow](db, "key", grantsRowKey)
    db.close()
  except CatchableError as e:
    return (false, false, GrantTable(), e.msg)
  if rows.len == 0:
    return
  got = decodeGrants(rows[0].body)
  if not got.ok:
    return (false, false, GrantTable(), "saved grants are damaged: " & got.err)
  result.found = true
  result.table = got.table

proc grantsDir*(h: GeistHome): string {.role: helper.} =
  ## h: the folder of the grant table, under db/.
  result = h.dbDir() / "grants"
