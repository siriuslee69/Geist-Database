## ---------------------------------------------------------------------
## Offer <- what a peer is missing FROM here, sent and remembered
## ---------------------------------------------------------------------
##
##   need.nim    "what do I need from you?"    pull, their log, my cursor
##   offer.nim   "here is what you lack"       push, my log, my cursor
##
## The mirror of `need.nim`, and the half a CLIENT cannot do without.
##
## Replication in Geist is pull-shaped: a node needs from a peer and the
## peer answers. That works whenever both ends can dial each other. A
## phone cannot be dialled -- it is behind a carrier NAT, it is asleep, it
## has a different address every hour -- so a server can never pull from
## it. If the phone does not push, the three messages someone wrote on a
## train never leave the train.
##
##   phone                          server
##   -----                          ------
##   needVia   <-- rows -----------  (the server's mail)
##   offerVia  --- rows ----------->  (what was written offline)
##
## Both calls, and the two together are a two-way sync. Neither is enough
## alone, and nothing else is required.
##
## WHY NOT JUST `pushRemote`. That exists, and it sends rows. What it does
## not do is remember which ones it already sent, so a caller either
## re-sends its whole log every time -- fine at ten rows, ruinous at ten
## thousand -- or keeps the position itself, which is the code every
## application was about to write again.
##
## THE CURSOR HERE COUNTS MY OWN LOG, which is the one difference from
## `need.nim` that matters. `need` remembers how much of the PEER's log
## this side has taken; `offer` remembers how much of THIS side's log the
## peer has been given. They are different numbers about different logs
## and they live in different files, because one file with both would make
## a stale entry mean two contradictory things.
##
## THE EPOCH IS MINE TOO. Compaction rewrites this node's log, so a
## position counted in the old one now points somewhere else. Storing the
## local epoch beside the cursor means a compaction rewinds the offer to
## zero and re-sends -- which `applyRow` on the far side deduplicates, so
## the cost is bandwidth and never a duplicate message.
##
## THE DESTINATION MUST ALREADY KNOW ITS SCHEMA. This is the one way a
## push is not the mirror of a pull. A `qoSync` REPLY carries the sender's
## schema, so a follower with an empty database adopts it and a chain can
## be joined by naming a peer and nothing else. A `qoPut` carries rows and
## nothing else, so there is nowhere for a schema to ride along -- and a
## store that has never held a row refuses every row that arrives, with a
## complaint about trailing bytes that no column accounts for.
##
## In practice this costs nothing, because the destination is an
## application server that opened its store from a record type it compiled
## against: `openGeist[StoredMessage]` knows the shape before the first
## row appears. It is documented here because the failure reads like a
## corruption and is not one.
##
## RE-SENDING IS SAFE AND IS THE DESIGN. Every row carries its identity,
## so an offer that arrives twice is applied twice to the same effect. The
## cursor is saved AFTER the peer confirms, so a crash mid-offer re-sends
## rather than skips.

import std/[os, strutils]

import runePragmas
import ./types
import ./address
import ./answer
import ./durable
import ./link
import ./session
import ./transport

const
  offerCursorFile* = ".geist-offers"
    ## Where this side records how much of its own log each peer has been
    ## given. Beside `.geist-cursors` and deliberately not inside it: see
    ## the module note on why one file for both would be wrong.

  offerRoundLimit* = 4096
    ## Most batches one `offerVia` will send before returning. A node
    ## written to faster than it can push would otherwise never finish;
    ## stopping leaves a valid position and the next call resumes.

type
  OfferCursor* {.role: truthState, tag: "sync|types".} = object
    ## remote: the destination, keyed the way everything else keys a
    ##   destination -- see `destinationKey`. A fallback daemon serving the
    ##   same store must continue this position rather than start a fresh
    ##   one, or a takeover would re-send the whole log.
    ## epoch: THIS node's log epoch when the position was counted.
    ## cursor: how many of this node's rows the peer has been given.
    remote*: string
    epoch*: uint64
    cursor*: uint64

  OfferRound* {.role: truthBuilder, tag: "sync|types".} = proc (
      R: seq[Row]): tuple[ok: bool, reply: Reply, err: string]
    ## Delivers ONE batch and says how the other side answered. See
    ## `offerLoop` for why it is the only part that varies.

  OfferOutcome* {.role: truthState, tag: "status|sync|types".} = tuple
    ## What one push did. `rewound` says this node's own log had been
    ## rewritten and the position was discarded -- which explains a run
    ## that re-sent everything.
    ok: bool
    sent: int
    rounds: int
    cursor: uint64
    rewound: bool
    err: string

proc offerPath*(baseDir: string): string {.role: parser, inline,
    tag: "storageIo|sync".} =
  ## baseDir: store root whose outbound positions are named.
  result = baseDir / offerCursorFile

proc parseOfferLine(line: string): tuple[ok: bool, c: OfferCursor] {.
    role: parser, tag: "parsing|sync".} =
  ## line: one `<remote> <epoch> <cursor>` record.
  ##
  ## A malformed line is DROPPED, not raised on, for the same reason as in
  ## `need.nim`: this is a cache of positions, and the worst a lost line
  ## can do is re-send to one peer. Refusing to open a mailbox because a
  ## bookkeeping file was truncated would be the far worse trade.
  var
    parts: seq[string] = @[]
  parts = line.strip().split('\t')
  if parts.len != 3 or parts[0].len == 0:
    return (false, OfferCursor())
  try:
    result.c = OfferCursor(remote: parts[0],
      epoch: parseBiggestUInt(parts[1]), cursor: parseBiggestUInt(parts[2]))
    result.ok = true
  except ValueError:
    result = (false, OfferCursor())

proc loadOffers*(baseDir: string): seq[OfferCursor] {.role: parser,
    tag: "read|storageIo|sync".} =
  ## baseDir: store root. No file means nothing has been offered to
  ## anybody yet, which is the first run and not an error.
  var
    one: tuple[ok: bool, c: OfferCursor] = (false, default(OfferCursor))
  if not fileExists(offerPath(baseDir)):
    return @[]
  for line in lines(offerPath(baseDir)):
    if line.strip().len == 0:
      continue
    one = parseOfferLine(line)
    if one.ok:
      result.add one.c

proc saveOffers*(baseDir: string,
    C: openArray[OfferCursor]): tuple[ok: bool, err: string] {.
    role: dataWriter, tag: "storageIo|sync|write".} =
  ## baseDir: store root.
  ## C: every known position, written as one atomic replacement.
  ##
  ## Durably, and behind rather than ahead: a position that lags re-sends
  ## rows the peer already has and they are ignored, where one that ran
  ## ahead would skip rows that never arrived anywhere.
  var
    text: string = ""
    i: int = 0
  while i < C.len:
    text = text & C[i].remote & '\t' & $C[i].epoch & '\t' & $C[i].cursor & '\n'
    i = i + 1
  result = replaceDurable(offerPath(baseDir), text)

proc indexOfRemote(C: openArray[OfferCursor], remote: string): int {.
    role: parser, tag: "sync".} =
  ## C/remote: where this peer sits, or -1.
  var
    i: int = 0
  result = -1
  while i < C.len:
    if C[i].remote == remote:
      return i
    i = i + 1

proc offerFor*(C: openArray[OfferCursor], remote: string): OfferCursor {.
    role: parser, tag: "sync".} =
  ## C/remote: this peer's position, or a zero one, which is what "has had
  ## nothing from me" looks like.
  var
    at: int = indexOfRemote(C, remote)
  result = if at < 0: OfferCursor(remote: remote) else: C[at]

proc noteOffer*(C: var seq[OfferCursor], c: OfferCursor) {.
    role: actor, tag: "sync".} =
  ## C/c: the table updated in place.
  var
    at: int = indexOfRemote(C, c.remote)
  if at < 0:
    C.add c
  else:
    C[at] = c

proc offerLoop(S: var Session, name: string, limit: int, maxRounds: int,
    round: OfferRound): OfferOutcome {.role: orchestrator,
    tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the LOCAL database whose rows are being sent. Opened read-only is
  ##   fine and normal -- offering reads here and writes there.
  ## name: what the other side's position is filed under.
  ## limit: rows per batch, bounded by `replyRowBudget` -- the same figure
  ##   an answer stops at, taken from `answer.nim` rather than restated
  ##   here, so an ordinary batch is one datagram in both directions.
  ## maxRounds: cap on batches, so a busy log cannot hold this open.
  ## round: how ONE batch is delivered -- the only thing that differs
  ##   between a routed client, a direct link and a store in this process.
  ##
  ## The cursor advances only after the other side's reply says `ok`. That
  ## order is the whole durability argument: a crash between sending and
  ## recording re-sends a batch the peer already applied, and `applyRow`
  ## skips a version it already has.
  var
    table: seq[OfferCursor] = loadOffers(S.baseDir)
    here: OfferCursor = offerFor(table, name)
    batch: seq[Row] = @[]
    got: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
    saved: tuple[ok: bool, err: string] = (false, "")
  # A local compaction makes every recorded position count rows that no
  # longer exist. Checked BEFORE the first batch, unlike `need`, because
  # the epoch in question is this node's own and is already known.
  if here.cursor > 0'u64 and here.epoch != S.logEpoch:
    here.cursor = 0'u64
    result.rewound = true
  here.remote = name
  here.epoch = S.logEpoch
  while result.rounds < maxRounds:
    batch = S.rowsSince(here.cursor, limit, replyRowBudget)
    if batch.len == 0:
      break
    got = round(batch)
    if not got.ok or not got.reply.ok:
      return (false, result.sent, result.rounds, here.cursor,
        result.rewound, got.err & got.reply.err)
    result.sent = result.sent + batch.len
    here.cursor = here.cursor + uint64(batch.len)
    result.rounds = result.rounds + 1
    noteOffer(table, here)
    saved = saveOffers(S.baseDir, table)
    if not saved.ok:
      return (false, result.sent, result.rounds, here.cursor,
        result.rewound, "rows sent but the position was not recorded: " &
        saved.err)
  noteOffer(table, here)
  saved = saveOffers(S.baseDir, table)
  if not saved.ok:
    return (false, result.sent, result.rounds, here.cursor,
      result.rewound, saved.err)
  result.cursor = here.cursor
  result.ok = true

proc offerVia*(S: var Session, client: var GeistClient, address: string,
    limit: int = 256, maxRounds: int = offerRoundLimit): OfferOutcome {.
    role: orchestrator, tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the local database whose rows are sent.
  ## client: a routed client, which picks the hop and fails over.
  ## address: where the rows go -- `geist://fjord/mail/alice/inbox`.
  ##   The position is filed under its destination, not the hop, so a
  ##   fallback daemon continues it instead of receiving the whole log.
  ## limit/maxRounds: as for `offerLoop`.
  ##
  ## Requires `prWrite` at the far end. A refusal comes back in `err`
  ## without moving the cursor, so nothing is recorded as delivered that
  ## was not -- and the next call retries the same rows.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string] =
      parseAddress(address)
    dialled: ptr GeistClient = addr client
  if not parsed.ok:
    return (false, 0, 0, 0'u64, false, "address " & address & ": " & parsed.err)
  result = offerLoop(S, parsed.a.destinationKey(), limit, maxRounds,
    proc (R: seq[Row]): tuple[ok: bool, reply: Reply, err: string] =
      var
        got: AskResult = dialled[].ask(Query(op: qoPut, collection: address,
          payload: encodeRows(R)))
      result = (got.ok, got.reply, got.err))

proc offerRemote*(S: var Session, link: var GeistLink, remote: string,
    limit: int = 256, maxRounds: int = offerRoundLimit): OfferOutcome {.
    role: orchestrator, tag: "appApi|db|networkSurface|orchestrator|sync|write".} =
  ## S: the local database whose rows are sent.
  ## link: an OPEN link to the peer, dialled directly.
  ## remote: the name the position is filed under -- normally the peer's
  ##   `dac://host:port`, the same name `needRemote` files ITS position
  ##   under for the other direction.
  ## limit/maxRounds: as for `offerLoop`.
  var
    dialled: ptr GeistLink = addr link
  result = offerLoop(S, remote, limit, maxRounds,
    proc (R: seq[Row]): tuple[ok: bool, reply: Reply, err: string] =
      dialled[].pushRemote(R))

proc offerLocal*(S: var Session, target: var Session, name: string,
    limit: int = 256, maxRounds: int = offerRoundLimit): OfferOutcome {.
    role: orchestrator, tag: "appApi|db|orchestrator|sync|write".} =
  ## S: the database whose rows are sent.
  ## target: another store open in THIS process, open for writing.
  ## name: what the position is filed under; one name per target.
  ## limit/maxRounds: as for `offerLoop`.
  ##
  ## No socket and no bytes on a wire: each batch is handed to the same
  ## `answerQuery` a daemon runs, so the rows land exactly as a network
  ## push would land them.
  var
    into: ptr Session = addr target
    cursors: SyncCursors = initSyncCursors()
    kept: ptr SyncCursors = addr cursors
  result = offerLoop(S, name, limit, maxRounds,
    proc (R: seq[Row]): tuple[ok: bool, reply: Reply, err: string] =
      var
        r: Reply = answerQuery(into[], kept[], Query(op: qoPut,
          payload: encodeRows(R)), localPeer())
      result = (r.ok, r, ""))

proc pending*(S: Session, baseDir: string, address: string): uint64 {.
    role: parser, tag: "status|sync".} =
  ## S/baseDir/address: how many rows this node still owes that peer.
  ##
  ## What a client shows as "3 messages waiting to send". Reads the file
  ## rather than remembering, so it is correct after a restart and cannot
  ## drift from what `offerVia` will actually do.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string] =
      (false, default(GeistAddress), "")
    here: OfferCursor = default(OfferCursor)
    total: uint64 = 0'u64
  parsed = parseAddress(address)
  if not parsed.ok:
    return 0'u64
  here = offerFor(loadOffers(baseDir), parsed.a.destinationKey())
  total = S.logCount()
  if here.epoch != S.logEpoch:
    # A compaction since the last offer: everything is owed again.
    return total
  if here.cursor >= total:
    return 0'u64
  result = total - here.cursor
