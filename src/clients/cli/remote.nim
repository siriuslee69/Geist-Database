## ---------------------------------------------------------------------
## geist cli <- commands sent to a running geistd, and catching up with one
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point and says how the parts fit:
##
##   common   options, userconfig, opening a store, printing rows
##   direct   commands that open the files in this process (--path)
##   remote   commands sent to a running geistd (--remote), and sync

import std/[strutils, tables]

import runePragmas
import ../../geist/network
import ./common

## --------------------------- remote commands ------------------------

proc mustAnswer(got: tuple[ok: bool, reply: Reply, err: string],
    doing: string): Reply {.role: sanitizer, tag: "cli|networkSurface".} =
  ## got/doing: a request's outcome -> its reply, or `fail` naming what
  ## was being done: the link failed, or the daemon refused.
  if not got.ok:
    fail(doing & " failed: " & got.err)
  if not got.reply.ok:
    fail(got.reply.err)
  result = got.reply

proc remotePut*(o: Options, link: var GeistLink) {.role: actor,
    tag: "cli|networkSurface|write".} =
  ## o: options whose trailing arguments are `field=value` pairs.
  ## link: an open session to the daemon.
  ##
  ## The row is built against the DAEMON's schema, which every reply
  ## carries, so a client needs no local copy of the database to add to
  ## it. The id is left at zero: this client has no id space of its own,
  ## so the receiving database names the row and reports what it chose.
  var
    pairs: tuple[ok: bool, values: Table[string, string], err: string] =
      (false, default(Table[string, string]), "")
    schema: Schema = default(Schema)
    built: tuple[ok: bool, data: ByteSeq, err: string] =
      (false, default(ByteSeq), "")
    stored: Reply = default(Reply)
  if o.args.len == 0:
    fail("put needs at least one field=value")
  pairs = parsePairs(o.args)
  if not pairs.ok:
    fail(pairs.err)
  schema = mustAnswer(link.send(Query(op: qoFind, limit: 0'u32)),
    "asking for the schema").schema
  built = buildRow(schema, pairs.values)
  if not built.ok:
    fail(built.err)
  stored = mustAnswer(link.pushRemote(@[Row(data: built.data)]), "put")
  echo "stored ", stored.matched, " row(s) remotely"

proc connectRemote*(o: Options): GeistLink {.role: orchestrator,
    tag: "ame|cli|networkSurface|orchestrator".} =
  ## o: options naming the peer, this side's identity and the peer's pin.
  ##
  ## Both halves of the pinning are required and neither has a default: a
  ## client that would connect without checking the pin is a client that
  ## can be answered by anyone who reaches the port first.
  var
    parsed: tuple[ok: bool, a: GeistDacAddress] =
      (false, default(GeistDacAddress))
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
    peer: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    got: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  parsed = parseDacAddress(o.remote)
  if not parsed.ok:
    fail("--remote must be dac://host:port, got '" & o.remote & "'")
  if o.identity.len == 0 or o.peerPin.len == 0:
    fail("--remote needs --identity and --peer-pin. Pinned trust means " &
      "each side must already know the other's public keys; run `geist " &
      "keygen` on both and exchange the .pin files.")
  mine = loadOrCreateIdentity(o.identity, resolvePassword(o), o.subject,
    geistSignatureSlots())
  if not mine.ok:
    fail(mine.err)
  peer = loadPin(o.peerPin)
  if not peer.ok:
    fail(peer.err)
  got = connectGeist(parsed.a, mine.key, peer.pin, defaultTierPolicy())
  if not got.ok:
    fail("connect failed: " & got.err)
  result = got.link

proc cmdSync*(o: Options) {.
    role: orchestrator, tag: "ame|cli|db|networkSurface|orchestrator|sync|write".} =
  ## o: options naming BOTH a local database (--path) and a peer
  ## (--remote). This is the one command that is neither direct nor remote
  ## but both: it reads there and writes here.
  ##
  ## Catching up is what makes a chain of desktops work. Rows arrive with
  ## the identity the peer stored them under, so a row that started three
  ## desktops away keeps the id it was born with, and this database can be
  ## followed in turn by somebody else.
  var
    link: GeistLink = default(GeistLink)
    db: Session = default(Session)
    caught: NeedOutcome = default(NeedOutcome)
  if o.path.len == 0:
    fail("sync needs --path (the database rows are applied TO) as well as " &
      "--remote (the peer they come FROM)")
  link = connectRemote(o)
  db = openDirect(o, forWriting = true)
  # The default row limit is a display default, and a catch-up is not a
  # display: 20 rows a round would take twenty round trips to move a
  # small database. An explicit --limit still wins.
  caught = needRemote(db, link, o.remote,
    uint32(if o.limit == 20: 256 else: o.limit))
  link.close()
  db.close()
  if not caught.ok:
    fail(caught.err)
  if caught.rewound:
    echo "the peer's log was rewritten since last time, so this caught up " &
      "from the beginning"
  echo "applied ", caught.applied, " row(s) in ", caught.rounds,
    " request(s); now at log position ", caught.cursor

proc runRemote*(o: Options, q: Query) {.role: orchestrator,
    tag: "ame|cli|networkSurface|orchestrator".} =
  ## o: options carrying --remote.
  ## q: the same Query the direct path would have run locally.
  var
    got: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
    reply: Reply = default(Reply)
  got.link = connectRemote(o)
  # `put` is the one command that has to ASK before it can send: the row
  # must be built against the daemon's schema, and only the daemon has it.
  if o.command == "put":
    remotePut(o, got.link)
    got.link.close()
    return
  try:
    reply = mustAnswer(got.link.send(q), "request")
  finally:
    got.link.close()
  if q.op == qoDelete:
    echo "deleted row id ", q.cursor
    return
  emitRows(reply.schema, reply.rows, o.json)
  if not o.json:
    echo ""
    echo reply.rows.len, " row(s), ", reply.matched, " matched"

proc remoteQuery*(o: Options): Query {.role: truthBuilder,
    tag: "cli|networkSurface|parsing".} =
  ## o: options translated into the Query a daemon can answer.
  result.limit = uint32(o.limit)
  case o.command
  of "list":
    result.op = qoFind
  of "get":
    if o.args.len == 0:
      fail("get needs a row index")
    result.op = qoGet
    result.cursor = uint64(parseInt(o.args[0]))
  of "find":
    if o.args.len < 2:
      fail("find needs a field and a value")
    result.op = qoFind
    result.where = @[Predicate(field: o.args[0], text: o.args[1],
      isText: true)]
  of "info", "inspect", "schema":
    result.op = qoSync
  of "put":
    # Built later, against the schema the daemon reports. This placeholder
    # is never sent.
    result.op = qoFind
    result.limit = 0'u32
  of "delete", "del", "rm":
    if o.args.len == 0:
      fail("delete needs a row id")
    result.op = qoDelete
    try:
      result.cursor = parseBiggestUInt(o.args[0])
    except ValueError:
      fail("a remote delete needs the row ID, not an @position: the " &
        "positions `list` shows are this terminal's, and the row may have " &
        "moved by the time the daemon reads them")
  else:
    fail("command '" & o.command & "' is direct-only; it needs --path. " &
      "Commands that need the password or rewrite local files are never " &
      "sent to a daemon.")


