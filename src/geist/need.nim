## ---------------------------------------------------------------------
## Need <- what this database is missing, asked for and applied
## ---------------------------------------------------------------------
##
##   connectGeist -> needRemote(S, link, remote) -> rows applied, cursor kept
##
## The mirror of `answer.nim`. That module is what a node says when it is
## ASKED; this one is what a node does when it wants what it does not yet
## have. Both live in the library for the same reason: an application
## embedding Geist should be able to replicate from a peer without
## reimplementing what `qoSync` means, and without shelling out to the CLI.
##
## Named for the question it asks -- "what do I need from you?" -- and not
## `follow`, which in this codebase already means watching a local file
## move (`followStore`). Two different things called the same thing is one
## thing too many.
##
## WHAT MAKES THIS A REPLICATION AND NOT A COPY. `qoSync` answers with rows
## of the peer's LOG -- superseded versions and tombstones included -- and
## every row carries its own identity. Applying them in order reproduces
## the peer's operations rather than a snapshot of its results, so a row
## that started on desktop A keeps A's id no matter how many desktops it
## travels through. That is what makes a chain work:
##
##   A --sync--> B --sync--> C        C ends up with A's row, under A's id
##
## B is not a special "relay": it is an ordinary node that needs from one
## peer and is needed from by another. Nothing here knows the chain length.
##
## THE CURSOR IS A LOG POSITION and belongs to the asking side, so it is kept
## here, next to the database it describes, one entry per peer. It survives
## restarts because catching up from zero every time would re-read a peer's
## whole log to discover it already had all of it.
##
## THE EPOCH IS WHAT MAKES THAT SAFE. A log position only means something
## against the log it was counted in, and compaction rewrites the log. So
## the peer's epoch is stored beside the cursor: when it changes, the
## position is discarded rather than trusted, and the catch-up starts from
## zero. Re-applying rows already held is harmless -- `applyRow` skips a
## version it already has -- so a rewind costs bandwidth, never duplicates.

import std/[os, strutils]

import runePragmas
import ./types
import ./durable
import ./address
import ./link
import ./session
import ./transport

const
  needCursorFile* = ".geist-cursors"
    ## Where this side keeps its place in each peer's log, in the store root
    ## beside the artifact set. Hidden and dot-prefixed like the lease and the
    ## sidecar folder, because it is bookkeeping rather than data.

  needRoundLimit* = 4096
    ## Most `qoSync` calls one `needRemote` will make before returning.
    ## A peer being written to faster than this side reads would otherwise
    ## keep a catch-up running for ever; stopping leaves a valid cursor and
    ## the next call resumes from it.

type
  NeedCursor* {.role: truthState, tag: "sync|types".} = object
    ## remote: the peer's address, exactly as it was dialled. Two names for
    ##   one host are two cursors, which is correct: nothing here can prove
    ##   they are the same database, and the epoch check catches it if they
    ##   are not.
    ## epoch: the peer's log epoch when this position was counted.
    ## cursor: how many rows of that log this side has applied.
    remote*: string
    epoch*: uint64
    cursor*: uint64

  NeedOutcome* {.role: truthState, tag: "status|sync|types".} = tuple
    ## What one catch-up did. Named because three procs return it and a
    ## six-field tuple written out three times is three chances to reorder
    ## two of the fields.
    ok: bool
    applied: int
    rounds: int
    cursor: uint64
    rewound: bool
    err: string

  SyncRound* {.role: truthBuilder, tag: "networkSurface|sync|types".} = proc (cursor: uint64, limit: uint32): tuple[ok: bool,
        reply: Reply, err: string] {.closure.}
    ## One `qoSync` request, however it happens to travel.
    ##
    ## `ok` false means the EXCHANGE failed. A reply that arrived saying
    ## no is `ok` true with `reply.ok` false -- the same distinction
    ## `link.ask` draws, and for the same reason: only one of the two is
    ## worth retrying elsewhere.

proc cursorPath*(baseDir: string): string {.role: parser, inline,
    tag: "storageIo|sync".} =
  ## baseDir: store root whose peer positions are named.
  result = baseDir / needCursorFile

proc parseCursorLine(line: string): tuple[ok: bool, c: NeedCursor] {.
    role: parser, tag: "parsing|sync".} =
  ## line: one `<remote> <epoch> <cursor>` record.
  ##
  ## A malformed line is DROPPED rather than raised on. This file is a
  ## cache of positions: the worst a lost line can do is make one peer be
  ## re-read from zero, and refusing to open the database because a
  ## bookkeeping file was truncated would be a far worse trade.
  var
    parts: seq[string] = @[]
  parts = line.strip().split('\t')
  if parts.len != 3 or parts[0].len == 0:
    return (false, NeedCursor())
  try:
    result.c = NeedCursor(remote: parts[0],
      epoch: parseBiggestUInt(parts[1]), cursor: parseBiggestUInt(parts[2]))
    result.ok = true
  except ValueError:
    result = (false, NeedCursor())

proc loadCursors*(baseDir: string): seq[NeedCursor] {.role: parser,
    tag: "read|storageIo|sync".} =
  ## baseDir: store root. An absent file means nothing has been needed from
  ## any peer yet, which is not an error -- it is the first run.
  var
    one: tuple[ok: bool, c: NeedCursor] = (false, default(NeedCursor))
  if not fileExists(cursorPath(baseDir)):
    return @[]
  for line in lines(cursorPath(baseDir)):
    if line.strip().len == 0:
      continue
    one = parseCursorLine(line)
    if one.ok:
      result.add one.c

proc saveCursors*(baseDir: string,
    C: openArray[NeedCursor]): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "storageIo|sync|write".} =
  ## baseDir: store root.
  ## C: every known position, written as one atomic replacement.
  ##
  ## Replaced rather than appended so a reader never sees half a table, and
  ## durably so a crash cannot leave a position AHEAD of the rows actually
  ## applied. Behind is recoverable -- the peer re-sends and the apply is
  ## idempotent -- ahead would silently skip rows for ever.
  var
    text: string = ""
    i: int = 0
  while i < C.len:
    text = text & C[i].remote & '\t' & $C[i].epoch & '\t' & $C[i].cursor & '\n'
    i = i + 1
  result = replaceDurable(cursorPath(baseDir), text)

proc indexOfRemote(C: openArray[NeedCursor], remote: string): int {.
    role: parser, tag: "sync".} =
  ## C: known positions.
  ## remote: peer looked for; -1 when this side has never needed from it.
  var
    i: int = 0
  result = -1
  while i < C.len:
    if C[i].remote == remote:
      return i
    i = i + 1

proc cursorFor*(C: openArray[NeedCursor], remote: string): NeedCursor {.
    role: parser, tag: "sync".} =
  ## C/remote: this side's position in one peer's log, or a zero position
  ## when there is none, which is what "send me everything" looks like.
  var
    at: int = indexOfRemote(C, remote)
  result = if at < 0: NeedCursor(remote: remote) else: C[at]

proc noteCursor*(C: var seq[NeedCursor], c: NeedCursor) {.
    role: actor, tag: "sync".} =
  ## C: the table updated in place.
  ## c: the new position for `c.remote`, replacing any older one.
  var
    at: int = indexOfRemote(C, c.remote)
  if at < 0:
    C.add c
  else:
    C[at] = c

proc needLoop(S: var Session, remote: string, limit: uint32,
    maxRounds: int, round: SyncRound): NeedOutcome {.role: orchestrator,
    tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the LOCAL database, open for writing, that the peer's rows land in.
  ## remote: the name this peer's cursor is filed under.
  ## limit: rows per request.
  ## maxRounds: cap on requests, so a peer written to faster than it is read
  ##   cannot hold this call open indefinitely.
  ## round: how to ask for ONE batch. The only thing that differs between
  ##   a direct link and a routed one, which is why it is the only thing
  ##   passed in -- the cursor rules, the epoch rules and the save order
  ##   below are identical for both and exist once.
  ##
  ## Returns what happened rather than printing it, because the CLI is not
  ## the only caller. `rewound` says the peer's epoch had changed and the
  ## stored position was discarded -- worth reporting, since it explains a
  ## catch-up that re-read a whole log.
  ##
  ## The cursor is SAVED AFTER the rows are, every round. A crash between
  ## two rounds therefore leaves a position that is behind the data, and
  ## the next call re-applies a batch it already had -- which `applyRow`
  ## ignores. The other order would lose rows.
  var
    table: seq[NeedCursor] = @[]
    here: NeedCursor = default(NeedCursor)
    answer: tuple[ok: bool, reply: Reply, err: string] =
      (false, default(Reply), "")
    stored: tuple[ok: bool, applied: int, err: string] = (false, 0, "")
    saved: tuple[ok: bool, err: string] = (false, "")
  if S.readOnly:
    return (false, 0, 0, 0'u64, false, S.writeRefusal())
  table = loadCursors(S.baseDir)
  here = cursorFor(table, remote)
  while result.rounds < maxRounds:
    answer = round(here.cursor, limit)
    if not answer.ok:
      return (false, result.applied, result.rounds, here.cursor,
        result.rewound, answer.err)
    if not answer.reply.ok:
      return (false, result.applied, result.rounds, here.cursor,
        result.rewound, answer.reply.err)
    # The epoch is checked on the ANSWER, not once before the loop: a peer
    # that compacts midway through a long catch-up has to be noticed then,
    # or the rest of this run would count positions in a log that no longer
    # exists.
    if here.cursor > 0'u64 and answer.reply.epoch != here.epoch:
      here.cursor = 0'u64
      here.epoch = answer.reply.epoch
      result.rewound = true
      continue
    here.epoch = answer.reply.epoch
    # A database that has never held a row has no schema of its own, and
    # every reply carries the sender's. Adopting it is what lets a desktop
    # join a chain by naming a peer and nothing else -- otherwise the
    # operator would have to retype the field list on every machine and
    # keep the copies in step by hand. A database that DOES have a schema
    # keeps it, and a row that does not fit is refused by `applyRow`.
    if S.entries.schema.slots.len == 0 and answer.reply.schema.slots.len > 0:
      S.entries.schema = answer.reply.schema
    if answer.reply.rows.len == 0:
      # Caught up. Still record the position: the epoch may have been
      # learned this round, and a peer that never sends again should not be
      # re-asked from zero after a restart.
      break
    stored = S.applyRows(answer.reply.rows)
    if not stored.ok:
      return (false, result.applied, result.rounds, here.cursor,
        result.rewound, stored.err)
    saved = S.save()
    if not saved.ok:
      return (false, result.applied, result.rounds, here.cursor,
        result.rewound, "rows applied but not saved: " & saved.err)
    result.applied = result.applied + stored.applied
    here.cursor = answer.reply.cursor
    result.rounds = result.rounds + 1
    noteCursor(table, here)
    saved = saveCursors(S.baseDir, table)
    if not saved.ok:
      return (false, result.applied, result.rounds, here.cursor,
        result.rewound, saved.err)
  noteCursor(table, here)
  saved = saveCursors(S.baseDir, table)
  if not saved.ok:
    return (false, result.applied, result.rounds, here.cursor,
      result.rewound, saved.err)
  result.cursor = here.cursor
  result.ok = true

proc needRemote*(S: var Session, link: var GeistLink, remote: string,
    limit: uint32 = 256'u32,
    maxRounds: int = needRoundLimit): NeedOutcome {.role: orchestrator,
    tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the LOCAL database, open for writing.
  ## link: an OPEN link to the peer, dialled directly.
  ## remote: the peer's address, used as the name its cursor is filed under.
  ## limit/maxRounds: as for `needLoop`.
  ##
  ## The direct case: one link, one database at the other end, no router
  ## in between. `link` is taken by `ptr` for the closure because Nim will
  ## not let a `var` parameter be captured -- the closure does not outlive
  ## this call, which is what makes that safe.
  var
    dialled: ptr GeistLink = addr link
  result = needLoop(S, remote, limit, maxRounds,
    proc (cursor: uint64, lim: uint32): tuple[ok: bool, reply: Reply,
        err: string] =
      dialled[].syncRemote(cursor, lim))

proc needVia*(S: var Session, client: var GeistClient, address: string,
    limit: uint32 = 256'u32,
    maxRounds: int = needRoundLimit): NeedOutcome {.role: orchestrator,
    tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the LOCAL database, open for writing.
  ## client: a routed client, which picks the hop and fails over.
  ## address: what to catch up WITH -- `geist://fjord/mail/alice/inbox`.
  ## limit/maxRounds: as for `needLoop`.
  ##
  ## The routed twin of `needRemote`, and the one an application usually
  ## wants. A client syncing its mailbox does not know or care which VPS
  ## daemon answers today; it names the mailbox and `ask` finds a hop.
  ##
  ## THE CURSOR IS FILED UNDER THE DESTINATION, NOT THE HOP. That is the
  ## whole reason this is not just "needRemote with a different link": a
  ## fallback daemon taking over must not look like a new peer whose log
  ## has to be read from zero. Both hops serve the same store, so both
  ## produce the same `destinationKey` and continue the same position --
  ## and if they turn out NOT to be the same log, the epoch check catches
  ## it and rewinds, which is exactly what it is there for.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string] =
      (false, default(GeistAddress), "")
    dialled: ptr GeistClient = addr client
    named: string = ""
  parsed = parseAddress(address)
  if not parsed.ok:
    return (false, 0, 0, 0'u64, false,
      "address " & address & ": " & parsed.err)
  named = parsed.a.destinationKey()
  result = needLoop(S, named, limit, maxRounds,
    proc (cursor: uint64, lim: uint32): tuple[ok: bool, reply: Reply,
        err: string] =
      var
        got: AskResult = default(AskResult)
      got = dialled[].ask(Query(op: qoSync, collection: address,
        cursor: cursor, limit: lim))
      result = (got.ok, got.reply, got.err))
