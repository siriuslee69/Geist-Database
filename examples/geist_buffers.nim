## ---------------------------------------------------------------------
## Geist Buffers <- two instances trading rows with NO database at all
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nimble exampleBuffers
##
## The other examples open a store and write to disk. This one does not
## touch the disk at all, on either side. It exists to show the second
## thing Geist is for: two programs that hold rows in memory and hand
## them to each other, knowing only
##
##   * where the other one is   -- dac://host:port
##   * who the other one is     -- a .pin file, its public signing keys
##   * who this one is          -- its own identity
##
## and nothing else. No schema shared at compile time, no store, no file.
##
##   receiver (this process, a thread)      sender (this process)
##   --------------------------------       ----------------------
##   initGeistServer(addr, identity,        connectGeist(addr,
##     [TrustedPeer(pin, rights)])            identity, pin, policy)
##        |                                       |
##        |  a handler that closes over a         |  pushRemote(rows)
##        |  `seq[Row]` in RAM -- there is        |
##        |  no Session anywhere                  |
##        v                                       v
##   serveOnce(handler)  <------ AME over DAC -----+
##
## THE POINT: `initGeistServer` takes an identity and a trust list. It
## does NOT take a Session. `ServedHandler` is `proc (q: Query,
## p: PeerContext): Reply` -- an ordinary function. Whatever that function
## closes over is the storage, and here it closes over a sequence.
##
## `geistd` closes over a database. `geist-relayd` closes over a ring
## buffer in memory. This example closes over a `seq[Row]`. All three are
## the same program with a different handler.

## os is here for `sleep` and strutils for `join`. Nothing in this file
## opens a path.
import std/[os, strutils, tables]

import geist/network

type
  Mailbox = object
    ## The whole "database": rows in memory, and a count of what arrived.
    ## A real program would put its own state here.
    rows: seq[Row]
    schema: Schema
    received: int

  ServeArgs = object
    ## Passed to the receiver thread by pointer. `ready` and `stop` are
    ## the only fields both threads touch, and each is written by one side.
    ##
    ## The two keys are VALUES, not paths. Nothing here has a file.
    listen: string
    identity: AmeIdentityKey
    peerPin: AmePinnedPeerIdentity
    ready: bool
    stop: bool
    failed: bool
    err: string


var
  box: Mailbox

proc answer(q: Query, p: PeerContext): Reply {.gcsafe.} =
  ## q: what the peer asked for.
  ## p: WHO asked, proved by the handshake, and what they may do.
  ##
  ## This is the whole receiver. Note that the rights check is not
  ## optional politeness: `p.rights` came from the pin the handshake
  ## verified, and a handler that ignored it would let any peer that can
  ## reach the socket write into the buffer.
  {.cast(gcsafe).}:
    result.schema = box.schema
    case q.op
    of qoPut:
      if prWrite notin p.rights:
        return Reply(ok: false, err: "peer '" & p.subject & "' may not write")
      var
        incoming: seq[Row] = @[]
        o: int = 0
      incoming = decodeRows(q.payload, o)
      for r in incoming:
        box.rows.add r
        box.received = box.received + 1
      result.ok = true
      result.matched = uint32(incoming.len)
    of qoFind, qoSync:
      result.ok = true
      result.rows = box.rows
      result.matched = uint32(box.rows.len)
    else:
      result = Reply(ok: false, err: "this endpoint only holds a buffer")

proc runReceiver(a: ptr ServeArgs) =
  ## a: where to listen, and the two key files.
  var
    address: tuple[ok: bool, a: GeistDacAddress] = (false,
      default(GeistDacAddress))
    server: tuple[ok: bool, server: GeistServer, err: string] = (false,
      GeistServer(), "")
    step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
  try:
    address = parseDacAddress(a.listen)
    ## No Session, no path, no store. An identity, and a list of who is
    ## allowed to talk to it.
    server = initGeistServer(address.a, a.identity,
      [TrustedPeer(pin: a.peerPin, rights: {prRead, prWrite})],
      defaultTriggerPolicy())
    if not server.ok:
      a.err = server.err
      a.failed = true
      a.ready = true
      return
    a.ready = true
    while not a.stop:
      step = serveOnce(server.server, answer, 200)
      if not step.ok and a.err.len == 0 and step.err.len > 0:
        a.err = step.err
    server.server.closeServer()
  except CatchableError as exc:
    a.err = exc.msg
    a.failed = true
    a.ready = true

proc receiverThread(a: ptr ServeArgs) {.thread.} =
  {.cast(gcsafe).}:
    runReceiver(a)

when isMainModule:
  var
    args: ServeArgs
    t: Thread[ptr ServeArgs]
    spins: int = 0
    senderKey: AmeIdentityKey = default(AmeIdentityKey)
    receiverKey: AmeIdentityKey = default(AmeIdentityKey)
    link: tuple[ok: bool, link: GeistLink, err: string] = (false,
      GeistLink(), "")
    built: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    sent: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
    got: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
    rows: seq[Row] = @[]

  ## ── 1. Two identities, each keeping the other's public half ──
  ##
  ## `geistIdentity` mints a signing stack IN MEMORY. `geistPeerPin`
  ## takes the public half of one, which is what the other side has to
  ## know. No file is involved in either.
  ##
  ## A real deployment persists these instead -- `loadOrCreateIdentity`
  ## and `savePin` write the `.id` and `.pin` files the CLI uses -- so
  ## that a restart is the same peer rather than a stranger. Kept in
  ## memory here only to show that the transport itself needs no disk.
  senderKey = geistIdentity("sender")
  receiverKey = geistIdentity("receiver")
  echo "identities: sender=", senderKey.subject,
    "  receiver=", receiverKey.subject, "  (in memory, no files)"

  ## The buffer the receiver will fill. A schema is still needed, because
  ## a row is packed bytes and something has to say what the fields are --
  ## but it is built in memory and never written anywhere.
  box.schema = parseSchemaSpec("Note", "noteId:int,title:text,body:text").s

  ## ── 2. Start the receiver ──
  args = ServeArgs(listen: "dac://127.0.0.1:47901",
    identity: receiverKey, peerPin: geistPeerPin(senderKey))
  createThread(t, receiverThread, addr args)
  while not args.ready and spins < 500:
    sleep(10)
    spins = spins + 1
  doAssert args.ready and not args.failed, args.err
  echo "receiver: listening on ", args.listen, " with nothing on disk"

  ## ── 3. The sender connects, knowing only address + pin ──
  link = connectGeist(parseDacAddress("dac://127.0.0.1:47901").a,
    senderKey, geistPeerPin(receiverKey),
    defaultTriggerPolicy(), 1'u64, 4000)
  doAssert link.ok, link.err
  echo "sender:   handshake done, session open"

  ## ── 4. Ask what shape a row is, then send some ──
  ##
  ## The sender has no schema of its own either -- it asks. That is what
  ## makes this work between two programs that were never compiled
  ## together.
  got = link.link.send(Query(op: qoFind, limit: 0'u32))
  doAssert got.ok and got.reply.ok, got.err & got.reply.err
  echo "sender:   schema from the wire -> ",
    describeSchema(got.reply.schema)

  for i in 1 .. 3:
    built = buildRow(got.reply.schema,
      {"noteId": $i, "title": "row-" & $i, "body": "in memory only"}.toTable)
    doAssert built.ok, built.err
    rows.add Row(data: built.data)
  sent = link.link.pushRemote(rows)
  doAssert sent.ok and sent.reply.ok, sent.err & sent.reply.err
  echo "sender:   pushed ", sent.reply.matched, " row(s)"

  ## ── 5. Read them back out of the other side's memory ──
  got = link.link.send(Query(op: qoFind, limit: 10'u32))
  doAssert got.ok and got.reply.ok
  echo "sender:   receiver now holds ", got.reply.matched, " row(s):"
  for r in got.reply.rows:
    echo "            ", renderRow(got.reply.schema, r.data).join("  ")

  link.link.close()
  args.stop = true
  joinThread(t)
  doAssert args.err.len == 0 or args.err.contains("closed"), args.err
  echo "done. Nothing was written to disk by either side."
