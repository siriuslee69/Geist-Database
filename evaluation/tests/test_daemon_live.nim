## Live sockets: a real handshake, real datagrams, real replies.
##
## Everything below runs an actual `GeistServer` on a bound UDP port in a
## second thread and talks to it over the real AME/DAC stack. Nothing here
## is a codec test -- those live in test_masks_transport.nim, and they pass
## just as happily when the socket layer is broken.
##
## What that catches, and unit tests do not:
##
##   * a handshake that completes but whose session cannot open a frame
##   * a server that answers one request and stops listening
##   * a second peer being unable to connect while a first is connected
##   * a reply aimed at the wrong address
##   * rights that are checked in the wrong order, or not at all
##
## The two-desktop exchange at the bottom is the whole point of the
## daemon: two databases, each with its own rows, ending up holding the
## same set without either one being told what the other had.

import runePragmas
import std/[os, strutils, tables, unittest]
import geist/network

type
  Note = object
    noteId: int
    title: string
    body: string

  ServeArgs = object
    ## Everything the server thread needs, passed by pointer so nothing is
    ## shared implicitly. `stop` and `ready` are the only fields the two
    ## threads both touch, and only one side writes each.
    root: string
    listen: string
    identityFile: string
    peerPinFile: string
    writable: bool
    port: uint16
    stop: bool
    ready: bool
    failed: bool
    served: int
    err: string

proc freshRoot(name: string): string {.role: helper.} =
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc runServer(a: ptr ServeArgs) {.role: orchestrator.} =
  ## a: server configuration and the flags the test drives it with.
  ##
  ## A miniature geistd: same session, same GeistServer, same handler
  ## shape. Kept here rather than spawning the binary so a failure points
  ## at a line of Geist instead of at a process exit code.
  var
    S: Session = default(Session)
    cursors: SyncCursors = initSyncCursors()
    identity: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
    pin: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    address: tuple[ok: bool, a: GeistDacAddress] =
      (false, default(GeistDacAddress))
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
    step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    rights: set[PeerRight] = default(set[PeerRight])
  try:
    identity = loadOrCreateIdentity(a.identityFile, "server-pw", "server",
      geistSignatureSlots())
    if not identity.ok:
      a.err = identity.err
      a.failed = true
      a.ready = true
      return
    pin = loadPin(a.peerPinFile)
    if not pin.ok:
      a.err = pin.err
      a.failed = true
      a.ready = true
      return
    address = parseDacAddress(a.listen)
    S = openSessionWithSchema(a.root, "main", Schema(), appConfig(), "",
      readOnly = not a.writable)
    rights = if a.writable: {prRead, prWrite} else: {prRead}
    server = initGeistServer(address.a, identity.key,
      [TrustedPeer(pin: pin.pin, rights: rights)], defaultTriggerPolicy())
    if not server.ok:
      a.err = server.err
      a.failed = true
      a.ready = true
      S.close()
      return
    a.ready = true
    while not a.stop:
      step = serveOnce(server.server,
        proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
          {.cast(gcsafe).}:
            result = answerQuery(S, cursors, q, p),
        200)
      if step.served:
        a.served = a.served + 1
      elif not step.ok and a.err.len == 0:
        a.err = step.err
    server.server.closeServer()
    S.close()
  except CatchableError as exc:
    a.err = exc.msg
    a.failed = true
    a.ready = true

proc serverThread(a: ptr ServeArgs) {.role: orchestrator, thread.} =
  ## a: the same loop, entered as a thread. The cast is the honest kind:
  ## this thread owns its Session outright and shares nothing with the
  ## test but the flags in `a`, which the compiler cannot see.
  {.cast(gcsafe).}:
    runServer(a)

proc startServer(a: ptr ServeArgs, t: var Thread[ptr ServeArgs]) {.
    role: orchestrator.} =
  ## a/t: spawn the server and wait until its socket is bound, so a client
  ## never races the listener.
  var
    spins: int = 0
  createThread(t, serverThread, a)
  while not a.ready and spins < 500:
    sleep(10)
    spins = spins + 1
  check a.ready
  check not a.failed

proc stopServer(a: ptr ServeArgs, t: var Thread[ptr ServeArgs]) {.
    role: actor.} =
  ## a/t: ask the loop to leave and wait for it.
  a.stop = true
  joinThread(t)

proc seedNotes(root: string, titles: openArray[string]): seq[RowId] {.
    role: dataWriter.} =
  ## root/titles: a database with one row per title, saved and closed, so
  ## the server thread can open it afterwards.
  var
    db = openGeist[Note](root, appConfig())
  for t in titles:
    result.add db.put(Note(noteId: result.len + 1, title: t, body: "b-" & t))
  check db.save().ok
  db.close()

proc clientFor(port: uint16, identityFile,
    peerPinFile: string): tuple[ok: bool, link: GeistLink, err: string] {.
        role: configurator.} =
  ## port/identityFile/peerPinFile: connect to a server on loopback with a
  ## pinned identity on both sides.
  var
    identity = loadOrCreateIdentity(identityFile, "client-pw", "client",
      geistSignatureSlots())
    pin = loadPin(peerPinFile)
    address = parseDacAddress("dac://127.0.0.1:" & $port)
  check identity.ok
  check pin.ok
  result = connectGeist(address.a, identity.key, pin.pin,
    defaultTriggerPolicy(), 1'u64, 4000)

suite "a live daemon answers over a real socket":
  test "connect, read, and keep the session across several requests":
    var
      root = freshRoot("geist_t_live1")
      keys = freshRoot("geist_t_live1_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47811",
        port: 47811'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin")
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["alpha", "beta", "gamma"])
    # Both sides mint an identity and hand over the public half.
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check clientKey.ok
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check serverKey.ok
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47811'u16, keys / "client.id", keys / "server.pin")
    check link.ok
    check link.err == ""

    # THREE requests on ONE session. The old server closed its socket after
    # the first, so this is the property that regressed silently before.
    var listed = link.link.send(Query(op: qoFind, limit: 10'u32))
    check listed.ok
    check listed.reply.ok
    check listed.reply.rows.len == 3

    var one = link.link.send(Query(op: qoGet, cursor: 1'u64))
    check one.ok
    check one.reply.ok
    check one.reply.rows.len == 1
    check renderRow(one.reply.schema, one.reply.rows[0].data).contains("beta")

    var matched = link.link.send(Query(op: qoFind, limit: 10'u32,
      where: @[Predicate(field: "title", isText: true, text: "gamma")]))
    check matched.ok
    check matched.reply.rows.len == 1

    check args.served >= 3
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

  test "two peers hold sessions at the same time":
    var
      root = freshRoot("geist_t_live2")
      keys = freshRoot("geist_t_live2_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47812",
        port: 47812'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin")
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["one", "two"])
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    # Both connect BEFORE either sends: with a one-shot server the second
    # handshake would find nothing listening.
    var
      a = clientFor(47812'u16, keys / "client.id", keys / "server.pin")
      b = clientFor(47812'u16, keys / "client.id", keys / "server.pin")
    check a.ok
    check b.ok
    var
      fromA = a.link.send(Query(op: qoFind, limit: 10'u32))
      fromB = b.link.send(Query(op: qoFind, limit: 10'u32))
    check fromA.reply.rows.len == 2
    check fromB.reply.rows.len == 2
    # Interleaved, not just sequential: the sessions must not depend on
    # whose turn it is.
    check a.link.send(Query(op: qoGet, cursor: 0'u64)).reply.ok
    check b.link.send(Query(op: qoGet, cursor: 1'u64)).reply.ok
    a.link.close()
    b.link.close()
    stopServer(addr args, t)
    check args.err == ""

suite "syncing between two desktops":
  test "a follower catches up by log position and stops when caught up":
    var
      root = freshRoot("geist_t_live3")
      keys = freshRoot("geist_t_live3_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47813",
        port: 47813'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin")
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["r1", "r2", "r3", "r4"])
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47813'u16, keys / "client.id", keys / "server.pin")
    check link.ok

    # An empty follower asks from zero and receives the rows themselves,
    # not a count.
    var
      mirrorRoot = freshRoot("geist_t_live3_mirror")
      mirror = openSessionWithSchema(mirrorRoot, "main", Schema(),
        appConfig())
    var first = link.link.syncRemote(0'u64, 2'u32)
    check first.ok
    check first.reply.ok
    check first.reply.rows.len == 2
    check first.reply.cursor == 2'u64
    check first.reply.matched == 4'u32
    # The follower adopts the sender's schema: it had none of its own.
    mirror.entries.schema = first.reply.schema
    check mirror.applyRows(first.reply.rows).ok

    var rest = link.link.syncRemote(first.reply.cursor, 100'u32)
    check rest.reply.rows.len == 2
    check rest.reply.cursor == 4'u64
    check mirror.applyRows(rest.reply.rows).ok

    # Caught up: the same call now returns nothing and moves nothing.
    var idle = link.link.syncRemote(rest.reply.cursor, 100'u32)
    check idle.reply.ok
    check idle.reply.rows.len == 0
    check idle.reply.cursor == 4'u64

    check mirror.entryCount() == 4'u32
    check find[Note](mirror, "title", "r3").len == 1
    # Ids came across UNCHANGED -- including the sender's node tag, which is
    # what makes a later update from that peer land on this same row rather
    # than beside it.
    var senderId = first.reply.schema.rowIdOf(first.reply.rows[0].data)
    check senderId != 0'u64
    check byId[Note](mirror, senderId).value.title == "r1"
    check mirror.rowIds()[0] == senderId
    mirror.close()
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

  test "a subscription remembers its cursor on the server":
    var
      root = freshRoot("geist_t_live4")
      keys = freshRoot("geist_t_live4_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47814",
        port: 47814'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin")
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["s1", "s2"])
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47814'u16, keys / "client.id", keys / "server.pin")
    check link.ok
    # From zero: the subscription replays everything, then nothing.
    var sub = link.link.send(Query(op: qoSubscribe, subscriptionId: "mirror",
      cursor: 0'u64))
    check sub.reply.ok
    var firstPoll = link.link.pollRemote("mirror", 100'u32)
    check firstPoll.reply.rows.len == 2
    var secondPoll = link.link.pollRemote("mirror", 100'u32)
    check secondPoll.reply.rows.len == 0
    # An unknown subscription is refused rather than silently starting one.
    var stray = link.link.pollRemote("never-registered", 10'u32)
    check not stray.reply.ok
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

suite "payloads bigger than a datagram":
  test "a reply too large for one frame arrives whole":
    var
      root = freshRoot("geist_t_live7")
      keys = freshRoot("geist_t_live7_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47817",
        port: 47817'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin")
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    # One row far past the 32 KB whole-frame threshold, so the reply has to
    # be packaged whatever the row limit is.
    var
      big = openGeist[Note](root, appConfig())
      bigId = big.put(Note(noteId: 1, title: "huge",
        body: repeat("0123456789", 20_000)))    # 200 KB
    discard big.put(Note(noteId: 2, title: "small", body: "x"))
    check big.save().ok
    big.close()
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47817'u16, keys / "client.id", keys / "server.pin")
    check link.ok
    var got = link.link.fetchRemote(bigId)
    check got.ok
    check got.reply.ok
    check got.reply.rows.len == 1
    # Whole, not truncated: the body is exactly what was stored, and the
    # digest in the package manifest is what proves it.
    var cells = renderRow(got.reply.schema, got.reply.rows[0].data)
    check cells[^1].len == 200_000
    check cells[^1].endsWith("0123456789")
    # The session still works afterwards -- a package must not leave the
    # peer's assembly state half open.
    var after = link.link.send(Query(op: qoFind, limit: 10'u32))
    check after.reply.ok
    # One row, because the byte budget stops there: an answer is kept
    # inside a datagram when it can be. The cursor says where to resume,
    # so nothing is lost, only deferred.
    check after.reply.rows.len == 1
    check after.reply.cursor == 1'u64
    var rest = link.link.send(Query(op: qoFind, limit: 10'u32,
      cursor: after.reply.cursor))
    check rest.reply.rows.len == 1
    check renderRow(rest.reply.schema, rest.reply.rows[0].data).contains("small")
    check rest.reply.cursor == 2'u64
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

suite "writing across the wire":
  test "a read-only peer is refused, and told why":
    var
      root = freshRoot("geist_t_live5")
      keys = freshRoot("geist_t_live5_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47815",
        port: 47815'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin", writable: false)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["w1"])
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47815'u16, keys / "client.id", keys / "server.pin")
    check link.ok
    var sending = openSessionWithSchema(freshRoot("geist_t_live5_src"),
      "main", Schema(), appConfig())
    sending.entries.schema = link.link.send(Query(op: qoFind,
      limit: 1'u32)).reply.schema
    var built = buildRow(sending.entries.schema,
      {"noteId": "9", "title": "intruder", "body": "x"}.toTable,
      sending.sidecarStore, 99'u64)
    check built.ok
    var refused = link.link.pushRemote(@[Row(data: built.data)])
    check refused.ok                      # the exchange itself worked
    check not refused.reply.ok            # the operation did not
    check refused.reply.err.contains("may read but not write")
    sending.close()
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

  test "a writing peer pushes rows and the receiver stores them":
    var
      root = freshRoot("geist_t_live6")
      keys = freshRoot("geist_t_live6_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47816",
        port: 47816'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin", writable: true)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      receiverIds = seedNotes(root, ["kept"])
      clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
        "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok
    check receiverIds.len == 1

    startServer(addr args, t)
    var link = clientFor(47816'u16, keys / "client.id", keys / "server.pin")
    check link.ok

    # The sender is a database in its own right; its rows go over as they
    # are stored, identity and all.
    var
      srcRoot = freshRoot("geist_t_live6_src")
      src = openGeist[Note](srcRoot, appConfig())
    discard src.put(Note(noteId: 7, title: "from-peer", body: "hello"))
    discard src.put(Note(noteId: 8, title: "also-peer", body: "there"))
    var outgoing = src.rowsSince(0'u64, 100)
    check outgoing.len == 2

    var pushed = link.link.pushRemote(outgoing)
    check pushed.ok
    check pushed.reply.ok
    check pushed.reply.matched == 2'u32

    # Idempotent: sending the same rows again applies them without
    # duplicating anything, because a peer that retries must not be
    # punished for it.
    var again = link.link.pushRemote(outgoing)
    check again.reply.ok
    var afterRetry = link.link.send(Query(op: qoFind, limit: 50'u32))
    check afterRetry.reply.rows.len == 3

    src.close()
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

    # And it is on DISK, not just in the server's memory. It has to be:
    # the peer was TOLD the rows were stored and will not send them again,
    # so an acknowledgement that a crash could undo would be a lie. The
    # server here never closed its session cleanly before this check --
    # `stopServer` only sets a flag -- so what is on disk was written when
    # the write was accepted.
    var re = openGeist[Note](root, appConfig())
    check re.entryCount() == 3'u32
    check find[Note](re, "title", "from-peer").len == 1
    re.close()

  test "a client with no database of its own can still add a row":
    var
      root = freshRoot("geist_t_live8")
      keys = freshRoot("geist_t_live8_keys")
      args = ServeArgs(root: root, listen: "dac://127.0.0.1:47818",
        port: 47818'u16, identityFile: keys / "server.id",
        peerPinFile: keys / "client.pin", writable: true)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    discard seedNotes(root, ["existing"])
    var clientKey = loadOrCreateIdentity(keys / "client.id", "client-pw",
      "client", geistSignatureSlots())
    check savePin(keys / "client.pin", pinOf(clientKey.key)).ok
    var serverKey = loadOrCreateIdentity(keys / "server.id", "server-pw",
      "server", geistSignatureSlots())
    check savePin(keys / "server.pin", pinOf(serverKey.key)).ok

    startServer(addr args, t)
    var link = clientFor(47818'u16, keys / "client.id", keys / "server.pin")
    check link.ok
    # The schema comes from the server, and the row carries NO id: this
    # client has no id space of its own, so the receiver names the row.
    var probe = link.link.send(Query(op: qoFind, limit: 0'u32))
    check probe.reply.ok
    var built = buildRow(probe.reply.schema,
      {"noteId": "5", "title": "added-remotely", "body": "b"}.toTable)
    check built.ok
    check rowIdOf(probe.reply.schema, built.data) == 0'u64
    var sent = link.link.pushRemote(@[Row(data: built.data)])
    check sent.reply.ok
    check sent.reply.matched == 1'u32
    var listed = link.link.send(Query(op: qoFind, limit: 10'u32))
    check listed.reply.rows.len == 2
    # It was given a real id, not stored as an unaddressable row.
    var ids: seq[RowId] = @[]
    for row in listed.reply.rows:
      ids.add rowIdOf(listed.reply.schema, row.data)
    check ids[1] != 0'u64
    check ids[0] != ids[1]
    link.link.close()
    stopServer(addr args, t)
    check args.err == ""

## ---------------------------------------------------------------------
## A CHAIN. Two desktops exchanging is the common case; three is the one
## that proves the design, because the middle desktop is not special. It
## follows the first with the same call the third uses to follow it, and
## nothing in the middle knows it is in the middle.
##
##   A --sync--> B --sync--> C
##
## The property under test is IDENTITY SURVIVAL. A row must arrive at C
## under the id A gave it, or the chain is a copier rather than a
## replicator: a later update from A would land beside the row instead of
## on it, and the two desktops would silently disagree for ever.
## ---------------------------------------------------------------------

proc chainIdentities(keys: string) {.role: dataWriter.} =
  ## keys: directory given one identity per ROLE, plus the pin each hop
  ## checks the other against. B gets two, because B is a client to A and a
  ## server to C, and reusing one key for both would blur which of the two
  ## roles a pin actually authorises.
  var k: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
    (false, default(AmeIdentityKey), false, "")
  for who in ["b", "c"]:
    k = loadOrCreateIdentity(keys / (who & ".id"), "client-pw", "client",
      geistSignatureSlots())
    check k.ok
    check savePin(keys / (who & ".pin"), pinOf(k.key)).ok
  for who in ["a", "b-server"]:
    k = loadOrCreateIdentity(keys / (who & ".id"), "server-pw", "server",
      geistSignatureSlots())
    check k.ok
    check savePin(keys / (who & ".pin"), pinOf(k.key)).ok

suite "a chain of three desktops":
  test "a row relayed through the middle keeps the id it was born with":
    var
      rootA = freshRoot("geist_t_chain1_a")
      rootB = freshRoot("geist_t_chain1_b")
      rootC = freshRoot("geist_t_chain1_c")
      keys = freshRoot("geist_t_chain1_keys")
      argsA = ServeArgs(root: rootA, listen: "dac://127.0.0.1:47821",
        port: 47821'u16, identityFile: keys / "a.id",
        peerPinFile: keys / "b.pin")
      argsB = ServeArgs(root: rootB, listen: "dac://127.0.0.1:47822",
        port: 47822'u16, identityFile: keys / "b-server.id",
        peerPinFile: keys / "c.pin")
      tA: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
      tB: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    chainIdentities(keys)
    var originIds = seedNotes(rootA, ["origin-1", "origin-2"])
    check originIds.len == 2

    # HOP ONE. B starts with no database at all -- no rows and no schema --
    # which is what joining a chain actually looks like.
    startServer(addr argsA, tA)
    var toA = clientFor(47821'u16, keys / "b.id", keys / "a.pin")
    check toA.ok
    var
      mid = openSessionWithSchema(rootB, "main", Schema(), appConfig())
      caughtB = needRemote(mid, toA.link, "dac://127.0.0.1:47821")
    check caughtB.ok
    check caughtB.err == ""
    check caughtB.applied == 2
    check not caughtB.rewound
    check mid.entryCount() == 2'u32
    mid.close()
    toA.link.close()
    stopServer(addr argsA, tA)
    check argsA.err == ""

    # HOP TWO. B is now an ordinary source, serving what it was given.
    startServer(addr argsB, tB)
    var toB = clientFor(47822'u16, keys / "c.id", keys / "b-server.pin")
    check toB.ok
    var
      tail = openSessionWithSchema(rootC, "main", Schema(), appConfig())
      caughtC = needRemote(tail, toB.link, "dac://127.0.0.1:47822")
    check caughtC.ok
    check caughtC.err == ""
    check caughtC.applied == 2

    # THE POINT: C's rows carry A's ids, node tag included, having been
    # named by a desktop C has never spoken to.
    check tail.entryCount() == 2'u32
    check tail.rowIds() == originIds
    check byId[Note](tail, originIds[0]).value.title == "origin-1"
    check byId[Note](tail, originIds[1]).value.title == "origin-2"

    # The position is kept, so a second catch-up is a single empty request
    # rather than a re-read of the whole log.
    check fileExists(cursorPath(rootC))
    var idle = needRemote(tail, toB.link, "dac://127.0.0.1:47822")
    check idle.ok
    check idle.applied == 0
    check idle.cursor == 2'u64
    tail.close()
    toB.link.close()
    stopServer(addr argsB, tB)
    check argsB.err == ""

  test "an update and a delete travel the whole chain":
    var
      rootA = freshRoot("geist_t_chain2_a")
      rootB = freshRoot("geist_t_chain2_b")
      rootC = freshRoot("geist_t_chain2_c")
      keys = freshRoot("geist_t_chain2_keys")
      argsA = ServeArgs(root: rootA, listen: "dac://127.0.0.1:47823",
        port: 47823'u16, identityFile: keys / "a.id",
        peerPinFile: keys / "b.pin")
      argsB = ServeArgs(root: rootB, listen: "dac://127.0.0.1:47824",
        port: 47824'u16, identityFile: keys / "b-server.id",
        peerPinFile: keys / "c.pin")
      tA: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
      tB: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    chainIdentities(keys)
    var originIds = seedNotes(rootA, ["keep", "change", "remove"])
    check originIds.len == 3

    # A changes its mind AFTER the rows exist: one row is rewritten and one
    # is removed. Both are log entries, not edits in place, so both travel.
    var origin = openGeist[Note](rootA, appConfig())
    check origin.set(originIds[1], Note(noteId: 2, title: "changed",
      body: "second thoughts"))
    check origin.delete(originIds[2])
    check origin.save().ok
    origin.close()

    proc relayHop(fromPort: uint16, clientId, peerPin, intoRoot,
        remote: string): int {.role: orchestrator.} =
      ## One hop, run to completion: connect, catch up, leave. Written once
      ## because the two hops differ only in who is at each end -- which is
      ## the claim this test exists to check.
      var link = clientFor(fromPort, clientId, peerPin)
      check link.ok
      var
        db = openSessionWithSchema(intoRoot, "main", Schema(), appConfig())
        caught = needRemote(db, link.link, remote)
      check caught.ok
      check caught.err == ""
      result = caught.applied
      db.close()
      link.link.close()

    startServer(addr argsA, tA)
    # Five log rows, not three: the update and the delete are entries of
    # their own, and a follower needs all five to arrive where A is.
    check relayHop(47823'u16, keys / "b.id", keys / "a.pin", rootB,
      "dac://127.0.0.1:47823") == 5
    stopServer(addr argsA, tA)
    check argsA.err == ""

    startServer(addr argsB, tB)
    check relayHop(47824'u16, keys / "c.id", keys / "b-server.pin", rootC,
      "dac://127.0.0.1:47824") == 5
    stopServer(addr argsB, tB)
    check argsB.err == ""

    # C ends up where A is: two visible rows, the rewritten one carrying
    # its new value under its ORIGINAL id, and the removed one gone rather
    # than merely hidden from one query.
    var tail = openGeist[Note](rootC, appConfig())
    check tail.entryCount() == 2'u32
    check byId[Note](tail, originIds[0]).value.title == "keep"
    check byId[Note](tail, originIds[1]).value.title == "changed"
    check byId[Note](tail, originIds[1]).value.body == "second thoughts"
    check byId[Note](tail, originIds[2]).found == false
    check find[Note](tail, "title", "remove").len == 0
    tail.close()
