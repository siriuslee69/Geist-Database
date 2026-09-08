## ---------------------------------------------------------------------
## Reconcile <- a hand-edited settings table against a real roster
## ---------------------------------------------------------------------
##
##   what the FILE says     what the SERVER says        what happens
##   ------------------     --------------------        ------------
##   [friend.alice]         alice                       matched, applied
##   [friend.alcie]         -                           ORPHAN, kept, idle
##   -                      bob                         added, defaults
##
## The case this exists for: someone opens `userconfig.toml`, adds a rule
## for a friend, and mistypes the name. The name they typed is not in the
## friend list, so nothing can apply their rule. Three things could happen
## next and only one of them is acceptable:
##
##   crash                 loses the whole config over one typo
##   delete the stray      destroys what they were in the middle of writing
##   KEEP IT, IDLE         it stays, it does nothing, and it is reported
##
## So an unknown NAME is not an error. That is the opposite of the rule for
## an unknown KEY -- `doc.nim` refuses `prot = "udp"` because a key is part
## of the schema and a misspelt one is dead weight nothing will ever read.
## A name is not part of the schema. It is data, it arrives from a server
## that this machine does not control, and the friend called `alcie` may
## genuinely exist tomorrow.
##
##   unknown KEY   -> reported as a problem     (doc.nim)
##   unknown NAME  -> kept as an orphan         (this module)
##
## AND THE ROSTER NAME GETS ITS ENTRY. `bob` is in the friend list with no
## section, so a section is appended with every option at its default. The
## file after a save lists every friend the account actually has, which is
## what makes it editable without looking anything up.
##
## AN ORPHAN IS NEVER SILENT. `suggest` finds the nearest roster name by
## edit distance, so a report can say `alcie -> did you mean alice?` rather
## than leaving someone to compare two lists by eye.
##
## This is generic over the settings type and knows nothing about friends:
## Eris reconciles friends, servers, rooms and roles with it, Fjord
## reconciles accounts and mailboxes, and the rule is the same each time.

import std/[algorithm, editdistance, sequtils, strutils, tables]

import geistPragmas

const
  suggestMaxDistance* = 3
    ## How far a roster name may be from an orphan and still be offered as
    ## what the person meant. Three edits on a short name is already a
    ## stretch; beyond it the suggestion is noise, and a wrong suggestion
    ## is worse than none because it invites a second wrong edit.
  suggestMinLength* = 3
    ## Names shorter than this get no suggestion. Every two-letter name is
    ## within three edits of every other one.

type
  RosterEntry* {.role: truthState, metaTags: {tagConfig, tagStatus,
      tagTypes}.} = object
    ## One name the reconciliation had something to say about.
    ##
    ## `nearest` is filled for orphans only, and is empty when nothing was
    ## close enough to be worth naming.
    name*: string
    nearest*: string

  RosterReport* {.role: truthState, metaTags: {tagConfig, tagStatus,
      tagTypes}.} = object
    ## What the file and the roster disagreed about.
    ##
    ##   matched  in both; these are the settings that actually apply
    ##   added    on the roster, absent from the file; defaults written
    ##   orphan   in the file, not on the roster; kept and never applied
    matched*: seq[string]
    added*: seq[string]
    orphan*: seq[RosterEntry]

proc changed*(r: RosterReport): bool {.role: parser, inline,
    metaTags: {tagConfig, tagStatus}.} =
  ## r: did reconciling alter the table? Only then is a rewrite worth it.
  result = r.added.len > 0

proc describe*(r: RosterReport, what: string = "entry"): string {.role: helper,
    metaTags: {tagConfig, tagDocs, tagStatus}.} =
  ## r/what: lines to show a person, or nothing when there is nothing to
  ## say. `what` names the thing being reconciled -- "friend", "room" --
  ## so one report reads correctly wherever it is used.
  var
    L: seq[string] = @[]
    i: int = 0
    t: string = ""
  if r.added.len > 0:
    L.add "added " & $r.added.len & " " & what & "(s) with default settings: " &
      r.added.join(", ")
  while i < r.orphan.len:
    t = r.orphan[i].name & " is configured but is not a known " & what
    if r.orphan[i].nearest.len > 0:
      t = t & "; did you mean " & r.orphan[i].nearest & "?"
    L.add t
    i = i + 1
  result = L.join("\n")

proc suggest*(name: string, roster: openArray[string]): string {.role: parser,
    metaTags: {tagConfig, tagParsing}.} =
  ## name: an orphan.
  ## roster: the names that do exist.
  ##
  ## The closest roster name within `suggestMaxDistance`, or nothing. Ties
  ## go to the first on the roster, which is stable because the roster
  ## arrives in a fixed order.
  var
    i: int = 0
    d: int = 0
    best: int = suggestMaxDistance + 1
    t: string = ""
  if name.len < suggestMinLength:
    return ""
  while i < roster.len:
    d = editDistance(name.toLowerAscii(), roster[i].toLowerAscii())
    if d < best:
      best = d
      t = roster[i]
    i = i + 1
  if best > suggestMaxDistance:
    return ""
  result = t

proc reconcile*[T](S: var OrderedTable[string, T], roster: openArray[string],
    fallback: T): RosterReport {.role: truthBuilder,
    metaTags: {tagAppApi, tagConfig, tagSync}.} =
  ## S: the settings table as the file had it, mutated in place.
  ## roster: the names that really exist, in the order they should appear.
  ## fallback: what a name with no section gets.
  ##
  ## After this call `S` holds every roster name plus every orphan, and
  ## nothing has been deleted. Order is: what the file already had, in the
  ## order it had it, then the new names in roster order -- so a save
  ## produces a diff that only grows.
  var
    i: int = 0
    seen: Table[string, bool] = initTable[string, bool]()
  while i < roster.len:
    seen[roster[i]] = true
    i = i + 1
  for name in S.keys:
    if seen.hasKey(name):
      result.matched.add name
    else:
      result.orphan.add RosterEntry(name: name, nearest: suggest(name, roster))
  i = 0
  while i < roster.len:
    if not S.hasKey(roster[i]):
      S[roster[i]] = fallback
      result.added.add roster[i]
    i = i + 1

proc applied*[T](s: OrderedTable[string, T],
    roster: openArray[string]): OrderedTable[string, T] {.role: parser,
    metaTags: {tagAppApi, tagConfig}.} =
  ## s/roster: only the entries that name something real.
  ##
  ## What the application should ACT on. `reconcile` keeps orphans in the
  ## table so they survive the next save; this is the view with them
  ## removed, so no code path can accidentally apply a rule for a friend
  ## who does not exist.
  var
    i: int = 0
  result = initOrderedTable[string, T]()
  while i < roster.len:
    if s.hasKey(roster[i]):
      result[roster[i]] = s[roster[i]]
    i = i + 1

proc settingsFor*[T](s: OrderedTable[string, T], name: string,
    fallback: T): T {.role: parser, metaTags: {tagAppApi, tagConfig}.} =
  ## s/name/fallback: one entry, or the defaults.
  ##
  ## The read a caller makes per message, per notification, per render.
  ## It never fails and it never inserts: a name that is not there is a
  ## name whose settings are the defaults, and reconciliation is what
  ## decides whether it should be there at all.
  result = fallback
  if s.hasKey(name):
    result = s[name]

proc rosterOf*[T](s: OrderedTable[string, T]): seq[string] {.role: parser,
    metaTags: {tagConfig}.} =
  ## s: the names in the table, in file order.
  result = toSeq(s.keys)

proc sortedRoster*(names: openArray[string]): seq[string] {.role: helper,
    metaTags: {tagConfig}.} =
  ## names: a roster in a stable order, duplicates removed.
  ##
  ## A roster arriving from a server may be in whatever order the server
  ## kept it in, and that order can change between two syncs. Sorting once
  ## here is what stops a settings file from reshuffling its sections
  ## every time it is written.
  result = @[]
  var
    i: int = 0
    t: seq[string] = @[]
  t = @names
  t.sort()
  while i < t.len:
    if i == 0 or t[i] != t[i - 1]:
      result.add t[i]
    i = i + 1
