## Monitor client <- the same Geist calls for desktop, CLI and Android JNI.
import std/[os, json, times]
import runePragmas
import geist/network
import ./provision
import ./events
import ./connection

type
  MonitorPending {.role: truthState, expectedCount: [0, 16], lifeCycle: 60000.} = object
    ticket: string
    target: string
    kind: string

  MonitorClient* {.role: truthState, expectedCount: 1, lifeCycle: lcForever.} = ref object
    root: string
    subject: string
    config: JsonNode
    relay: GeistLink
    store: GeistLink
    relayCursor: uint64
    storeCursor: uint64
    events: JsonNode
    messages: JsonNode
    nextSession: uint64
    overlay: OverlayService
    pending: seq[MonitorPending]
    nextTick: int64

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
  result.nextSession = uint64(getTime().toUnix())
  result.overlay.allowedCallers = overlayAccess(result.config{"overlayCallers"})

proc ensureLink(S: MonitorClient, kind: string): ptr GeistLink {.
    role: orchestrator.} =
  ## S/kind: connect strictly to the one configured relay or storage endpoint.
  var
    endpoint: string = S.config{kind}.getStr()
  result = if kind == "relay": addr S.relay else: addr S.store
  if result[].open:
    return
  S.nextSession = S.nextSession + 1
  result[] = openDeviceLink(S.root, S.subject, endpoint, "vps-" & kind, S.nextSession,
    observer = proc(e: GeistNetworkEvent) {.gcsafe.} =
      {.cast(gcsafe).}: S.remember(e))

proc receiveOverlay(S: MonitorClient, q: Query, p: PeerContext): Reply {.
    role: actor.} =
  ## S/q/p: an allowed caller delivered a message through the authenticated relay.
  if q.op != qoPut or q.collection != "messages":
    return Reply(err: "device accepts message writes only")
  if q.payload.len == 0 or q.payload.len > 16384:
    return Reply(err: "message must contain 1..16384 bytes")
  S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": p.subject,
    "body": asText(q.payload), "channel": "relay", "direction": "in", "ordinal": ""})
  result = Reply(ok: true, rows: @[Row(data: asBytes("Geist zugestellt: " & S.subject))])

proc pollPending(S: MonitorClient) {.role: orchestrator.} =
  ## S: results are polled without blocking the local device's own service loop.
  var
    i: int = 0
    reply: OverlayResult = default(OverlayResult)
    error: string = ""
  while i < S.pending.len:
    error = ""
    try:
      reply = S.relay.overlayResult(S.pending[i].ticket)
    except ValueError as exc:
      error = exc.msg
    if error.len > 0:
      S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": S.pending[i].target,
        "body": error, "channel": S.pending[i].kind, "direction": "error", "ordinal": ""})
      S.pending.delete(i)
      continue
    if not reply.ready:
      inc i
      continue
    S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": reply.subject,
      "body": if reply.reply.ok and reply.reply.rows.len > 0: asText(reply.reply.rows[0].data)
        elif reply.reply.ok: "Geist bestätigt" else: reply.reply.err,
      "channel": S.pending[i].kind, "direction": if reply.reply.ok: "echo" else: "error", "ordinal": ""})
    S.relay.forgetOverlay(S.pending[i].ticket)
    S.pending.delete(i)

proc pollOverlay(S: MonitorClient) {.role: orchestrator.} =
  ## S: heartbeat, reverse request and metadata through the public Geist API.
  var
    link = S.ensureLink("relay")
    step: OverlayServiceStep = default(OverlayServiceStep)
  step = serveOverlayOnce(link[], S.overlay,
    proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
      {.cast(gcsafe).}: result = S.receiveOverlay(q, p))
  if step.renewed:
    S.remember(GeistNetworkEvent(at: getTime().toUnix(), step: "overlay.renewed",
      endpoint: step.observedEndpoint, subject: S.subject, mode: "AM1P+S",
      tier: gtRecovery, sessionId: link[].sessionId))
  if step.served:
    S.remember(GeistNetworkEvent(at: getTime().toUnix(), step: "overlay.served",
      endpoint: S.config{"relay"}.getStr(), subject: step.caller, mode: "AM1P+S",
      tier: gtRecovery, sessionId: link[].sessionId))
  S.pollPending()

proc selectRelay(S: MonitorClient, endpoint: string) {.role: configurator.} =
  ## S/endpoint: user supplies the public relay separately from its local alias.
  ## A different relay must still prove the already-configured relay pin.
  if endpoint.len == 0 or endpoint == S.config{"relay"}.getStr(): return
  if not parseDacAddress(endpoint).ok: raise newException(ValueError, "invalid public relay endpoint")
  S.relay.close()
  S.config["relay"] = %endpoint
  writeFile(S.root / "config.json.next", $S.config)
  moveFile(S.root / "config.json.next", S.root / "config.json")

proc monitorTick*(S: MonitorClient) {.role: orchestrator.} =
  ## S: native heartbeat; directory renewal does not depend on a visible page.
  if overlayNow() < S.nextTick: return
  S.nextTick = overlayNow() + 1
  try:
    S.pollOverlay()
  except CatchableError as exc:
    S.nextTick = overlayNow() + 5
    S.remember(GeistNetworkEvent(at: getTime().toUnix(), step: "overlay.error",
      endpoint: S.config{"relay"}.getStr(), subject: S.subject, mode: "AM1P+S",
      tier: gtRecovery, error: exc.msg))

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
    target: string = q{"target"}.getStr()
    submitted: OverlaySubmission = default(OverlaySubmission)
    resolution: JsonNode = newJNull()
  if kind notin ["relay", "store"]:
    raise newException(ValueError, "channel must be relay or store")
  S.selectRelay(q{"relay"}.getStr())
  if target.len == 0:
    target = if kind == "store": "store.geist"
      elif S.subject == "pc": "phone.geist" else: "pc.geist"
  case q{"op"}.getStr()
  of "poll", "connect":
    S.pollOverlay()
    S.pollKind("store")
  of "send":
    if body.len == 0 or body.len > 16384:
      raise newException(ValueError, "message must contain 1..16384 bytes")
    discard S.ensureLink("relay")
    submitted = S.relay.submitOverlay(target,
      Query(op: qoPut, collection: "messages", payload: asBytes(body)))
    S.pending.add MonitorPending(ticket: submitted.ticket, target: submitted.alias, kind: kind)
    S.messages.boundedAdd(%*{"at": getTime().toUnix(), "sender": S.subject,
      "body": body, "channel": kind, "direction": "out", "ordinal": ""})
  of "handshake":
    S.disconnect()
    S.pollOverlay()
    S.pollKind("store")
  of "status": discard
  of "resolve":
    discard S.ensureLink("relay")
    resolution = resolutionJson(S.relay.resolveOverlay(target))
  else: raise newException(ValueError, "unknown monitor operation")
  result = %*{"ok": true, "subject": S.subject, "relay": S.relay.open,
    "store": S.store.open, "messages": S.messages, "events": S.events,
    "relayEndpoint": S.config{"relay"}.getStr(), "resolution": resolution,
    "target": if S.subject == "pc": "phone.geist" else: "pc.geist",
    "pending": S.pending.len,
    "auth": "AM1P+S", "tier": "recovery", "kemMask": "FC", "signatureMask": "F0"}

proc monitorCall*(S: MonitorClient, request: string): string {.
    role: orchestrator.} =
  ## S/request: local UI bridge; malformed commands return an error object.
  try:
    result = $S.monitorRequest(parseJson(request))
  except CatchableError as exc:
    result = $(%*{"ok": false, "error": exc.msg, "events": S.events,
      "messages": S.messages, "subject": S.subject})
