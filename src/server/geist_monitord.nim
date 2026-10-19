## Geist monitor daemon <- relay mailbox OR persistent messages, public APIs only.
## Usage: geist-monitord <private-root> <relay|store> <dac://host:port>
import std/[os, json, times, strutils]
import runePragmas
import geist/network
import ../clients/monitor/[provision, events]
import ../geist/stop

type
  StoredMessage {.role: preparedData.} = object
    sender: string
    stream: string
    body: string
    at: int64

  MonitorStore {.role: truthState, expectedCount: 1, lifeCycle: lcForever.} = object
    db: Session

proc storeMessage(S: var MonitorStore, q: Query, p: PeerContext): Reply {.
    role: actor.} =
  ## S/q/p: save before acknowledging; the echo is the sender's reply.
  var
    msg = StoredMessage(sender: p.subject, stream: q.collection,
      body: asText(q.payload), at: getTime().toUnix())
    written: tuple[ok: bool, err: string] = (false, "")
  if prWrite notin p.rights:
    return Reply(err: "peer has no write right")
  if q.payload.len == 0 or q.payload.len > 16384:
    return Reply(err: "message must contain 1..16384 bytes")
  discard S.db.put(msg)
  written = S.db.save()
  if not written.ok:
    return Reply(err: written.err)
  result = Reply(ok: true, cursor: uint64(S.db.entryCount()), matched: 1,
    rows: @[Row(data: asBytes("VPS gespeichert: " & msg.body))])

proc readMessages(S: MonitorStore, q: Query, p: PeerContext): Reply {.
    role: dataFetcher.} =
  ## S/q/p: persistent messages in append order, using the caller's cursor.
  var
    ids = S.db.rowIds()
    i: int = int(min(q.cursor, uint64(ids.len)))
    msg: StoredMessage = default(StoredMessage)
    cap: int = if q.limit == 0: 64 else: min(int(q.limit), 128)
  if prRead notin p.rights:
    return Reply(err: "peer has no read right")
  result.ok = true
  result.cursor = uint64(i)
  result.matched = uint32(ids.len)
  while i < ids.len and result.rows.len < cap:
    msg = byId[StoredMessage](S.db, ids[i]).value
    i = i + 1
    result.cursor = uint64(i)
    result.rows.add asRow(RelayMessage(sender: msg.sender, stream: msg.stream,
      body: asBytes(msg.body), at: msg.at, ordinal: uint64(i)))

proc answerStore(S: var MonitorStore, q: Query, p: PeerContext): Reply {.
    role: orchestrator.} =
  ## S/q/p: only the monitor's append and history operations are supported.
  case q.op
  of qoPut: result = S.storeMessage(q, p)
  of qoSync: result = S.readMessages(q, p)
  else: result = Reply(err: "store accepts qoPut and qoSync")

proc runMonitorDaemon*(root, mode, endpoint: string): int {.
    role: metaOrchestrator.} =
  ## root/mode/endpoint: two independent daemons, roots, identities and ports.
  var
    subject: string = "vps-" & mode
    identity: AmeIdentityKey = deviceIdentity(root, subject)
    address = parseDacAddress(endpoint)
    trusted: seq[TrustedPeer] = @[]
    policy = defaultTriggerPolicy()
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
    desk = initRelayDesk()
    store: MonitorStore = default(MonitorStore)
    step: tuple[ok: bool, served: bool, err: string] = (false, false, "")
    loaded: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
  if mode notin ["relay", "store"] or not address.ok:
    raise newException(ValueError, "expected root relay|store dac://host:port")
  for kind, path in walkDir(root / "peers"):
    if path.endsWith(".pin"):
      loaded = loadPin(path)
      checked((loaded.ok, loaded.err))
      trusted.add TrustedPeer(pin: loaded.pin, rights: {prRead, prWrite})
  policy.startTier = gtRecovery
  desk.spool = 1024
  server = initGeistServer(address.a, identity, trusted, policy,
    shared = deviceSharedKey(root),
    observer = proc(e: GeistNetworkEvent) {.gcsafe.} =
      {.cast(gcsafe).}: writeDebug(root, eventJson(e)))
  checked((server.ok, server.err))
  if mode == "store":
    store.db = openGeist[StoredMessage](root / "messages", appConfig())
  installSignalHandlers()
  writeDebug(root, %*{"at": getTime().toUnix(), "step": "daemon.started", "mode": mode,
    "subject": subject, "endpoint": endpoint, "auth": "AM1P+S",
    "tier": "recovery", "kemMask": "FC", "signatureMask": "F0"})
  while not shutdownWanted():
    step = serveOnce(server.server,
      proc(q: Query, p: PeerContext): Reply {.gcsafe.} =
        {.cast(gcsafe).}:
          if mode == "relay": return answerRelay(desk, q, p)
          result = answerStore(store, q, p), 200)
    if not step.ok:
      writeDebug(root, %*{"at": getTime().toUnix(), "step": "daemon.error",
        "error": step.err})
  server.server.closeServer()
  desk.closeRelay()
  if mode == "store": store.db.close()
  result = 0

when isMainModule:
  try:
    if paramCount() != 3:
      raise newException(ValueError, "usage: geist-monitord <root> <relay|store> <dac://host:port>")
    quit(runMonitorDaemon(paramStr(1), paramStr(2), paramStr(3)))
  except CatchableError as exc:
    stderr.writeLine($(%*{"step": "daemon.fatal", "error": exc.msg}))
    quit(1)
