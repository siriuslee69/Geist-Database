## Geist overlay <- public names and Query/Reply through one explicit relay.
## connectGeist(relay, pinned identity, shared key) -> alias -> submit -> result.
import std/[json, strutils]
import runePragmas
import ./types
import ./transport
import ./serve
import ./overlay_relay

export overlay_relay

type
  OverlaySubmission* {.role: preparedData.} = object
    ticket*: string
    subject*: string
    alias*: string

  OverlayResult* {.role: preparedData.} = object
    ready*: bool
    subject*: string
    remainingSeconds*: int64
    reply*: Reply

  OverlayAccess* {.role: configurator.} = object
    subject*: string
    rights*: set[PeerRight]

  OverlayService* {.role: truthState, expectedCount: [0, 256],
    lifeCycle: lcSession.} = object
    allowedCallers*: seq[OverlayAccess]
    renewAt: int64
    session: uint64
    pending: string
    answer: Reply

  OverlayServiceStep* {.role: preparedData.} = object
    renewed*: bool
    served*: bool
    observedEndpoint*: string
    alias*: string
    caller*: string

proc renewOverlay*(L: var GeistLink, timeoutMs: int = 4000): JsonNode {.
    role: orchestrator.} =
  ## L/timeoutMs: renew all administrator-assigned aliases of our pinned identity.
  result = L.overlayExchange(%*{"op": "renew"}, timeoutMs)

proc resolveOverlay*(L: var GeistLink, alias: string,
    timeoutMs: int = 4000): OverlayResolution {.role: orchestrator.} =
  ## L/alias/timeoutMs: alias is local to this relay, including any explicit port.
  var
    n: JsonNode = L.overlayExchange(%*{"op": "resolve", "alias": overlayAlias(alias)}, timeoutMs)
  result.alias = n{"alias"}.getStr()
  result.subject = n{"subject"}.getStr()
  result.observedEndpoint = n{"observedEndpoint"}.getStr()
  result.remainingSeconds = n{"remainingSeconds"}.getBiggestInt()
  result.revision = parseBiggestUInt(n{"revision"}.getStr())
  for name in n["aliases"]: result.aliases.add name.getStr()

proc submitOverlay*(L: var GeistLink, alias: string, q: Query,
    timeoutMs: int = 4000): OverlaySubmission {.role: orchestrator.} =
  ## L/alias/q/timeoutMs: queue one existing Geist Query for the exact owner.
  var
    n: JsonNode = L.overlayExchange(%*{"op": "submit", "alias": overlayAlias(alias),
      "query": overlayEncoded(encodeQuery(q))}, timeoutMs)
  result = OverlaySubmission(ticket: n{"ticket"}.getStr(),
    subject: n{"subject"}.getStr(), alias: n{"alias"}.getStr())

proc overlayResult*(L: var GeistLink, ticket: string,
    timeoutMs: int = 4000): OverlayResult {.role: orchestrator.} =
  ## L/ticket/timeoutMs: poll without consuming; other identities cannot read it.
  var
    n: JsonNode = L.overlayExchange(%*{"op": "result", "ticket": ticket}, timeoutMs)
  result.ready = n{"ready"}.getBool()
  result.subject = n{"subject"}.getStr()
  result.remainingSeconds = n{"remainingSeconds"}.getBiggestInt()
  if result.ready: result.reply = decodeReply(overlayReplyBytes(n{"reply"}.getStr()))

proc forgetOverlay*(L: var GeistLink, ticket: string,
    timeoutMs: int = 4000) {.role: orchestrator.} =
  ## L/ticket/timeoutMs: release our queue slot after reading the result.
  var
    response = L.overlayExchange(%*{"op": "forget", "ticket": ticket}, timeoutMs)
  if not response{"forgotten"}.getBool():
    raise newException(ValueError, "relay did not release overlay ticket")

proc localContext(S: OverlayService, n: JsonNode): PeerContext {.
    role: sanitizer.} =
  ## S/n: relay-proved caller rights intersect this service's explicit local grants.
  var
    local: set[PeerRight] = {}
    remote: set[PeerRight] = {}
    subject: string = n{"caller"}.getStr()
  for grant in S.allowedCallers:
    if grant.subject == subject: local = local + grant.rights
  if n{"read"}.getBool(): remote.incl prRead
  if n{"write"}.getBool(): remote.incl prWrite
  result = PeerContext(subject: subject, address: n{"callerEndpoint"}.getStr(),
    rights: local * remote)

proc callService(S: OverlayService, n: JsonNode, handler: ServedHandler): Reply {.
    role: orchestrator.} =
  ## S/n/handler: check the service's own caller grants before invoking app code.
  var
    q: Query = decodeQuery(overlayQueryBytes(n{"query"}.getStr()))
    p: PeerContext = S.localContext(n)
  if q.op in {qoPut, qoDelete} and prWrite notin p.rights:
    return Reply(err: "overlay service refuses caller write rights")
  if q.op notin {qoPut, qoDelete} and prRead notin p.rights:
    return Reply(err: "overlay service refuses caller read rights")
  try:
    result = handler(q, p)
  except CatchableError as exc:
    result = Reply(err: exc.msg)

proc finishPending(L: var GeistLink, S: var OverlayService,
    timeoutMs: int) {.role: orchestrator.} =
  ## L/S/timeoutMs: keep a computed answer until its control exchange succeeds.
  if S.pending.len == 0: return
  try:
    discard L.overlayExchange(%*{"op": "finish", "ticket": S.pending,
      "reply": overlayEncoded(encodeReply(S.answer))}, timeoutMs)
  except ValueError:
    S.pending = ""
    S.answer = Reply()
    raise
  S.pending = ""
  S.answer = Reply()

proc serveOverlayOnce*(L: var GeistLink, S: var OverlayService,
    handler: ServedHandler, timeoutMs: int = 4000): OverlayServiceStep {.
    role: metaOrchestrator.} =
  ## L/S/handler: one outgoing heartbeat and at most one application request.
  ## Keep S on the same Nim thread as L and the application handler.
  var
    now: int64 = overlayNow()
    n: JsonNode = nil
  if handler == nil: raise newException(ValueError, "overlay service needs a handler")
  if not L.open: raise newException(IOError, "overlay link is closed")
  if S.session != L.sessionId:
    S.renewAt = 0
    S.session = L.sessionId
    if S.pending.len > 0:
      S.pending = ""
      S.answer = Reply()
      raise newException(IOError, "overlay connection changed after execution; write was not replayed")
  if now >= S.renewAt:
    n = L.renewOverlay(timeoutMs)
    S.renewAt = now + overlayRenewSeconds
    result.renewed = true
    result.observedEndpoint = n{"observedEndpoint"}.getStr()
  L.finishPending(S, timeoutMs)
  n = L.overlayExchange(%*{"op": "take"}, timeoutMs)
  if not n{"ready"}.getBool(): return
  S.pending = n{"ticket"}.getStr()
  S.answer = S.callService(n, handler)
  # Oversized application replies fail explicitly, with a bounded error answer.
  if encodeReply(S.answer).len > maxOverlayObjectBytes:
    S.answer = Reply(err: "overlay service reply exceeds 65536 bytes")
  L.finishPending(S, timeoutMs)
  result.served = true
  result.alias = n{"alias"}.getStr()
  result.caller = n{"caller"}.getStr()
