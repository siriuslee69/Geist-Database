## A pure message relay: bytes in, bytes out, nothing stored.
##
## The mirror of storage_only.nim. That file proves `import geist` needs
## no network stack; this one proves `import geist/wire` needs no
## database -- no packed rows, no write lease, no generation swap.
##
## The proof is not that this compiles: it is WHAT it compiles, which
## `nimble checkRelay` checks by looking at the C files the compiler
## emitted for it. If someone makes the wire half import the storage half,
## a `@mgeist@ssession.nim.c` appears in that directory and the task
## fails. A comment asking people to keep them apart would not have
## caught it.

import runePragmas
import std/[os, strutils]

import geist/wire

const logPath = "build/relay-check/relayed.log"

proc main() {.role: metaOrchestrator.} =
  var
    D: RelayDesk = initRelayDesk(rsFile, rfJson)
    phone: PeerContext = PeerContext(subject: "phone", address: "dac://a:1",
      rights: {prRead, prWrite})
    reader: PeerContext = PeerContext(subject: "desk", address: "dac://b:1",
      rights: {prRead})
    reply: Reply = default(Reply)
    m: RelayMessage = default(RelayMessage)
  removeDir("build/relay-check")
  D.file = logPath
  # A message arrives from a peer whose name came from its pin.
  reply = answerRelay(D, Query(op: qoPut, collection: "voice",
    payload: asBytes("hello from a phone")), phone)
  doAssert reply.ok, reply.err
  doAssert reply.cursor == 1'u64
  # A second peer, allowed only to read, collects it.
  reply = answerRelay(D, Query(op: qoPoll, collection: "voice",
    subscriptionId: "desk"), reader)
  doAssert reply.ok, reply.err
  doAssert reply.rows.len == 1
  m = decodeMessage(reply.rows[0].data)
  doAssert m.sender == "phone"
  doAssert asText(m.body) == "hello from a phone"
  # A read-only peer may not send.
  reply = answerRelay(D, Query(op: qoPut, collection: "voice",
    payload: asBytes("nope")), reader)
  doAssert not reply.ok
  doAssert "may read but not send" in reply.err
  # And this endpoint says plainly that it is not a database.
  reply = answerRelay(D, Query(op: qoFind, collection: "voice"), reader)
  doAssert not reply.ok
  doAssert "not a database" in reply.err
  D.closeRelay()
  doAssert fileExists(logPath)
  doAssert "\"from\":\"phone\"" in readFile(logPath).replace(" ", "")
  echo "relay-only build: ok"

main()
