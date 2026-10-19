## Monitor client <- the same Geist calls for desktop, CLI and Android JNI.
import std/[os, json, times]
import runePragmas
import geist/network
import ./provision
import ./events

type
  MonitorClient* {.role: truthState, expectedCount: 1, lifeCycle: lcForever.} = ref object
    root: string
    subject: string
    config: JsonNode
    identity: AmeIdentityKey
    shared: GeistSharedKey
    relay: GeistLink
    store: GeistLink
    relayCursor: uint64
    storeCursor: uint64
    events: JsonNode
    messages: JsonNode
    nextSession: uint64

proc boundedAdd(A: var JsonNode, n: JsonNode) {.role: actor.} =
  ## A/n: retain at most 256 UI entries, even during long sessions.
  if A.len >= 256:
    A.elems.delete(0)
  A.add n

proc remember(S: MonitorClient, e: GeistNetworkEvent) {.role: dataWriter.} =
  ## S/e: public handshake metadata, also kept in a small local debug log.
  var
    n = eventJson(e)
  S.events.boundedAdd(n)
  writeDebug(S.root, n)

proc openMonitor*(root: string): MonitorClient {.role: configurator.} =
  ## root: one private device installation, including public endpoint config.
  result = MonitorClient(root: root, events: newJArray(), messages: newJArray())
  result.config = parseFile(root / "config.json")
  result.subject = result.config{"subject"}.getStr()
  result.identity = deviceIdentity(root, result.subject)
  result.shared = deviceSharedKey(root)
  result.nextSession = uint64(getTime().toUnix())

proc ensureLink(S: MonitorClient, kind: string): ptr GeistLink {.
    role: orchestrator.} =
  ## S/kind: connect strictly to the one configured relay or storage endpoint.
  var
    endpoint: string = S.config{kind}.getStr()
    address = parseDacAddress(endpoint)
    pin = loadPin(S.root / "peers" / ("vps-" & kind & ".pin"))
    policy = defaultTriggerPolicy()
    made: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  result = if kind == "relay": addr S.relay else: addr S.store
  if result[].open:
    return
  if not address.ok:
    raise newException(ValueError, "invalid Geist endpoint for " & kind)
  checked((pin.ok, pin.err))
  policy.startTier = gtRecovery
  S.nextSession = S.nextSession + 1
  made = connectGeist(address.a, S.identity, pin.pin, policy,
    sessionId = S.nextSession, timeoutMs = 60000, shared = S.shared,
    observer = proc(e: GeistNetworkEvent) {.gcsafe.} =
      {.cast(gcsafe).}: S.remember(e))
  checked((made.ok, made.err))
  result[] = made.link

proc exchange(S: MonitorClient, kind: string, q: Query): Reply {.
    role: orchestrator.} =
  ## S/kind/q: every data byte passes through Geist.send on the pinned link.
  var
    link: ptr GeistLink = S.ensureLink(kind)
    got = link[].send(q, 60000)
  if not got.ok:
    link[].close()
    raise newException(IOError, got.err)
  checked((got.reply.ok, got.reply.err))
  result = got.reply

proc pollKind(S: MonitorClient, kind: string) {.role: orchestrator.} =
  ## S/kind: receive the device's relay mailbox or the persistent VPS history.
  var
    cursor: uint64 = if kind == "relay": S.relayCursor else: S.storeCursor
    stream: string = if kind == "relay": S.subject else: "messages"
    reply = S.exchange(kind, Query(op: qoSync, collection: stream,
      cursor: cursor, limit: 64))
    msg: RelayMessage = default(RelayMessage)
  for row in reply.rows:
    msg = decodeMessage(row.data)
    S.messages.boundedAdd(%*{"at": msg.at, "sender": msg.sender,
      "body": asText(msg.body), "channel": kind, "direction": "in",
      "ordinal": $msg.ordinal})
  if kind == "relay": S.relayCursor = reply.cursor
  else: S.storeCursor = reply.cursor

proc disconnect*(S: MonitorClient) {.role: actor.} =
  ## S: close both links; the next explicit operation makes fresh handshakes.
  S.relay.close()
  S.store.close()

proc monitorRequest*(S: MonitorClient, q: JsonNode): JsonNode {.
    role: orchestrator.} =
  ## S/q: UI commands; no UI command can select a weaker mode or tier.
  var
    kind: string = q{"channel"}.getStr("relay")
    body: string = q{"body"}.getStr()
    target: string = if S.subject == "pc": "phone" else: "pc"
    reply: Reply = default(Reply)
  if kind notin ["relay", "store"]:
    raise newException(ValueError, "channel must be relay or store")
  case q{"op"}.getStr()
  of "poll", "connect":
    S.pollKind("relay")
    S.pollKind("store")
  of "send":
    if body.len == 0 or body.len > 16384:
      raise newException(ValueError, "message must contain 1..16384 bytes")
    reply = S.exchange(kind, Query(op: qoPut,
      collection: if kind == "relay": target else: "messages",
      payload: asBytes(body)))
    S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": S.subject,
      "body": body, "channel": kind, "direction": "out", "ordinal": $reply.cursor})
    if kind == "store" and reply.rows.len > 0:
      S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": "vps-store",
        "body": asText(reply.rows[0].data), "channel": kind, "direction": "echo"})
  of "handshake":
    S.disconnect()
    S.pollKind("relay")
    S.pollKind("store")
  of "status": discard
  else: raise newException(ValueError, "unknown monitor operation")
  result = %*{"ok": true, "subject": S.subject, "relay": S.relay.open,
    "store": S.store.open, "messages": S.messages, "events": S.events,
    "auth": "AM1P+S", "tier": "recovery", "kemMask": "FC", "signatureMask": "F0"}

proc monitorCall*(S: MonitorClient, request: string): string {.
    role: orchestrator.} =
  ## S/request: local UI bridge; malformed commands return an error object.
  try:
    result = $S.monitorRequest(parseJson(request))
  except CatchableError as exc:
    result = $(%*{"ok": false, "error": exc.msg, "events": S.events,
      "messages": S.messages, "subject": S.subject})
