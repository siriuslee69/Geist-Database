## Two-way sync over a real socket, through a route table.
##
## This is the client-and-server story end to end, with nothing stubbed:
## a registry-backed server on a bound UDP port, a `GeistClient` that
## reaches it by address rather than by endpoint, and both halves of the
## exchange.
##
##   phone                                    server
##   -----                                    ------
##   offerVia  --- what was written offline -->  applied
##   needVia   <-- what arrived meanwhile ------  sent
##
## The properties that only a live run can settle:
##
##   * an address chooses a store on the far side, not just a socket
##   * a push remembers what it already sent, across calls
##   * a pull and a push keep SEPARATE positions, in separate files
##   * an address the server does not serve comes back as a refusal
##     rather than as a dead hop
##
## The server here is a miniature Fjord: one registry, many mailboxes,
## one handler. If this passes, an application server is configuration
## rather than code.

import runePragmas
import std/[os, strutils, unittest]
import geist/network

type
  Note = object
    noteId: int
    title: string
    body: string

  ServeArgs = object
    root: string
    listen: string
    identityFile: string
    peerPinFile: string
    port: uint16
    stop: bool
    ready: bool
    failed: bool
    served: int
    err: string

proc freshRoot(name: string): string {.role: helper.} =
  result = getTempDir() / "geist_routed_sync" / name
  removeDir(result)
  createDir(result)

proc runServer(a: ptr ServeArgs) {.role: orchestrator.} =
  ## a: server configuration and the flags the test drives it with.
  ##
  ## A miniature application server: a `StoreRegistry` that serves one app
  ## and opens a store per address, exactly as a Fjord or Eris daemon
  ## would. The handler is `registry.serveQuery` and nothing else -- which
  ## the claim this file exists to check.
  var
    identity: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
    pin: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    address: tuple[ok: bool, a: GeistDacAddress] =
      (false, default(GeistDacAddress))
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
    home: tuple[ok: bool, home: GeistHome, err: string] =
      (false, default(GeistHome), "")
    reg: tuple[ok: bool, registry: StoreRegistry, err: string] =
      (false, default(StoreRegistry), "")
    step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    opener: OpenStore = default(OpenStore)
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
    home = openHome(a.root, nrServer)
    if not home.ok:
      a.err = home.err
      a.failed = true
      a.ready = true
      return
    discard home.home.ensureHome()
    opener = proc (h: GeistHome, ad: GeistAddress, path: string,
        S: var Session): tuple[ok: bool, writable: bool, err: string] =
      # Opened with the record type's schema, the way a real application
      # server does -- Fjord opens `StoredMessage`, Eris its game rows. A
      # push carries rows and no schema (unlike a pull, whose reply
      # carries the sender's), so a destination that did not already know
      # its shape would refuse every row that arrived.
      S = openSessionWithSchema(path, "main", schemaFor[Note](), appConfig(),
        "", readOnly = false)
      result = (true, true, "")
    reg = initRegistry(home.home, opener, ["fjord"], 8)
    if not reg.ok:
      a.err = reg.err
      a.failed = true
      a.ready = true
      return
    address = parseDacAddress(a.listen)
    server = initGeistServer(address.a, identity.key,
      [TrustedPeer(pin: pin.pin, rights: {prRead, prWrite})],
      defaultTriggerPolicy())
    if not server.ok:
      a.err = server.err
      a.failed = true
      a.ready = true
      return
    a.ready = true
    while not a.stop:
      step = serveOnce(server.server,
        proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
          {.cast(gcsafe).}:
            result = reg.registry.serveQuery(q, p),
        200)
      if step.served:
        a.served = a.served + 1
      elif not step.ok and a.err.len == 0:
        a.err = step.err
    server.server.closeServer()
    discard reg.registry.closeRegistry()
  except CatchableError as exc:
    a.err = exc.msg
    a.failed = true
    a.ready = true

proc serverThread(a: ptr ServeArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    runServer(a)

proc startServer(a: ptr ServeArgs, t: var Thread[ptr ServeArgs]) {.
    role: orchestrator.} =
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
  a.stop = true
  joinThread(t)

proc routedClient(port: uint16, identityFile,
    peerPinFile: string): GeistClient {.role: configurator.} =
  ## port/identityFile/peerPinFile: a client that reaches the server by
  ## ADDRESS. The route is the `*` catch-all, so nothing in the test names
  ## an endpoint after this line.
  var
    identity = loadOrCreateIdentity(identityFile, "client-pw", "client",
      geistSignatureSlots())
    table = defaultRouteTable("phone")
    made: tuple[ok: bool, client: GeistClient, err: string] =
      (false, default(GeistClient), "")
  check identity.ok
  table.route.add Route(app: "*", instance: "*", hops: @[
    Hop(name: "vps", endpoint: "dac://127.0.0.1:" & $port,
      pin: peerPinFile, priority: 0'u8)])
  made = initGeistClient(identity.key, table)
  check made.ok
  result = made.client

proc localStore(root: string, titles: openArray[string]): Session {.
    role: dataWriter.} =
  ## root/titles: a client-side database with one row per title.
  result = openSessionWithSchema(root, "main", schemaFor[Note](), appConfig())
  for t in titles:
    discard result.put(Note(noteId: int(result.entryCount()) + 1, title: t,
      body: "b-" & t))
  check result.save().ok

suite "a client pushes what it wrote while it was away":

  test "rows offered by address arrive, and can be pulled back":
    var
      base = freshRoot("push")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47811",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47811'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    # Both identities exist before either side starts, so the pins match.
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok
    check serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok

    startServer(addr args, t)
    var
      client = routedClient(47811'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "outbox", ["one", "two", "three"])
      pushed = mine.offerVia(client, "geist://fjord/mail/alice/inbox")
    check pushed.ok
    check pushed.sent == 3
    mine.close()

    # A DIFFERENT local database pulls the same address back. Nothing is
    # read out of the server thread: if the rows are there, this is the
    # only way they could arrive.
    var
      other = openSessionWithSchema(base / "elsewhere", "main", Schema(),
        appConfig())
      pulled = other.needVia(client, "geist://fjord/mail/alice/inbox")
    check pulled.ok
    check pulled.applied == 3
    check other.entryCount() == 3
    other.close()
    client.closeClient()
    stopServer(addr args, t)

  test "the second push sends nothing, because the first was remembered":
    var
      base = freshRoot("cursor")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47812",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47812'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok and serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok
    startServer(addr args, t)
    var
      client = routedClient(47812'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "outbox", ["a", "b"])

    check mine.offerVia(client, "geist://fjord/mail/bob/inbox").sent == 2
    # Nothing new was written, so nothing is owed.
    var
      again = mine.offerVia(client, "geist://fjord/mail/bob/inbox")
    check again.ok
    check again.sent == 0
    check again.rounds == 0

    # Write one more and only that one goes.
    discard mine.put(Note(noteId: 3, title: "c", body: "b-c"))
    check mine.save().ok
    var
      third = mine.offerVia(client, "geist://fjord/mail/bob/inbox")
    check third.ok
    check third.sent == 1

    mine.close()
    client.closeClient()
    stopServer(addr args, t)

  test "pending says what is owed, and reads it off the disk":
    var
      base = freshRoot("pending")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47813",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47813'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok and serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok
    startServer(addr args, t)
    var
      client = routedClient(47813'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "outbox", ["x", "y"])
    check mine.pending(base / "outbox", "geist://fjord/mail/c/inbox") == 2'u64
    check mine.offerVia(client, "geist://fjord/mail/c/inbox").ok
    check mine.pending(base / "outbox", "geist://fjord/mail/c/inbox") == 0'u64
    mine.close()
    client.closeClient()
    stopServer(addr args, t)

suite "the two directions keep separate books":

  test "a pull cursor and a push cursor are different files":
    var
      base = freshRoot("books")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47814",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47814'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok and serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok
    startServer(addr args, t)
    var
      client = routedClient(47814'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "box", ["m"])
    check mine.offerVia(client, "geist://fjord/mail/d/inbox").ok
    check mine.needVia(client, "geist://fjord/mail/d/inbox").ok

    # One store, two positions, two files. Sharing one would make "I have
    # taken 1 of yours" and "you have taken 1 of mine" the same number.
    check fileExists(base / "box" / offerCursorFile)
    check fileExists(base / "box" / needCursorFile)
    mine.close()
    client.closeClient()
    stopServer(addr args, t)

  test "a cursor is filed under the destination, not the hop":
    var
      base = freshRoot("filing")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47815",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47815'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok and serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok
    startServer(addr args, t)
    var
      client = routedClient(47815'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "box", ["m", "n"])
    check mine.offerVia(client, "geist://fjord/mail/e/inbox?ttl=4").ok
    var
      filed = readFile(base / "box" / offerCursorFile)
    # The endpoint does not appear. If it did, a fallback daemon taking
    # over would look like a peer that has had nothing, and the whole log
    # would be re-sent to a machine that already had it.
    check "fjord/mail/e/inbox" in filed
    check "127.0.0.1" notin filed
    check "ttl" notin filed

    # And a second call spelling the address differently continues the
    # same position rather than starting a new one.
    var
      again = mine.offerVia(client, "geist://fjord/mail/e/inbox?ttl=2&via=vps")
    check again.ok
    check again.sent == 0
    mine.close()
    client.closeClient()
    stopServer(addr args, t)

suite "a refusal is not a dead hop":

  test "an app the server does not serve comes back as an answer":
    var
      base = freshRoot("refuse")
      args = ServeArgs(root: base / "server", listen: "dac://127.0.0.1:47816",
        identityFile: base / "server.id", peerPinFile: base / "client.pin",
        port: 47816'u16)
      t: Thread[ptr ServeArgs] = default(Thread[ptr ServeArgs])
    var
      clientKey = loadOrCreateIdentity(base / "client.id", "client-pw",
        "client", geistSignatureSlots())
      serverKey = loadOrCreateIdentity(base / "server.id", "server-pw",
        "server", geistSignatureSlots())
    check clientKey.ok and serverKey.ok
    check savePin(base / "client.pin", clientKey.key.pinOf()).ok
    check savePin(base / "server.pin", serverKey.key.pinOf()).ok
    startServer(addr args, t)
    var
      client = routedClient(47816'u16, base / "client.id", base / "server.pin")
      mine = localStore(base / "box", ["m"])
      pushed = mine.offerVia(client, "geist://eris/games/alderreach")
    check not pushed.ok
    check "does not serve 'eris'" in pushed.err
    # The hop ANSWERED, so it is still healthy. A client that demoted it
    # here would move its mail to a machine that will say exactly the
    # same thing, and demote the only host that has the data.
    check "DOWN" notin client.healthReport()
    var
      after = mine.offerVia(client, "geist://fjord/mail/f/inbox")
    check after.ok
    check after.sent == 1
    mine.close()
    client.closeClient()
    stopServer(addr args, t)
