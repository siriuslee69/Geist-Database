## Overlay relay <- identity leases plus a bounded return path for Query/Reply.
## Owners poll outwards; relay traffic never needs an incoming owner socket.
import std/[tables, json, sysrand, strutils]
import runePragmas
import ./types
import ./relay
import ./address
import ./transport
import ./overlay_directory
import ./overlay_codec

export overlay_directory, overlay_codec

const
  maxOverlayJobs* = 128
  maxOverlayCallerJobs* = 16
  overlayJobSeconds* = 60'i64

type
  OverlayJob {.role: truthState, expectedCount: [0, 128],
    lifeCycle: 60000.} = object
    id: string
    caller: PeerContext
    owner: string
    alias: string
    deadline: int64
    query: ByteSeq
    reply: ByteSeq
    dispatched: bool
    completed: bool
    endpoint: string
    revision: uint64

  OverlayRelay* {.role: truthState, expectedCount: 1,
    lifeCycle: lcForever.} = object
    directory*: OverlayDirectory
    jobs: OrderedTable[string, OverlayJob]
    prefix: string
    nextId: uint64

proc initOverlayRelay*(G: openArray[OverlayGrant]): OverlayRelay {.
    role: configurator.} =
  ## G: persistent operator grants; a boot nonce prevents ticket reuse on restart.
  var
    random: array[16, byte] = default(array[16, byte])
  result.directory = initOverlayDirectory(G)
  result.jobs = initOrderedTable[string, OverlayJob]()
  if not urandom(random): raise newException(IOError, "overlay boot randomness failed")
  for b in random: result.prefix.add toHex(b, 2)

proc sweepOverlay(S: var OverlayRelay, now: int64) {.role: actor.} =
  ## S/now: release expired work before admitting more; no background timer needed.
  var
    expired: seq[string] = @[]
  for id, job in S.jobs:
    if job.deadline <= now: expired.add id
  for id in expired: S.jobs.del(id)

proc callerJobs(S: OverlayRelay, subject: string): int {.role: parser.} =
  ## S/subject: one caller cannot consume the whole global queue.
  for job in S.jobs.values:
    if job.caller.subject == subject: inc result

proc submit(S: var OverlayRelay, n: JsonNode, p: PeerContext,
    now: int64): JsonNode {.role: actor.} =
  ## S/n/p/now: resolve once; queued work is bound to the owner, not the IP.
  var
    resolved = S.directory.resolveOverlayAlias(n{"alias"}.getStr(), now)
    bytes: ByteSeq = overlayQueryBytes(n{"query"}.getStr())
    q: Query = decodeQuery(bytes)
    parsed = parseAddress(q.collection)
    job: OverlayJob = default(OverlayJob)
  if not parsed.ok: raise newException(ValueError, parsed.err)
  if parsed.a.onBehalfOf.len > 0: raise newException(ValueError, "overlay does not accept delegated identity claims")
  if q.collection == overlayControl: raise newException(ValueError, "nested overlay control is refused")
  if q.op in {qoPut, qoDelete} and prWrite notin p.rights:
    raise newException(ValueError, "request needs write rights")
  if q.op notin {qoPut, qoDelete} and prRead notin p.rights:
    raise newException(ValueError, "request needs read rights")
  if S.jobs.len >= maxOverlayJobs or S.callerJobs(p.subject) >= maxOverlayCallerJobs:
    raise newException(ValueError, "overlay queue is full")
  inc S.nextId
  job = OverlayJob(id: S.prefix & "-" & $S.nextId, caller: p,
    owner: resolved.subject, alias: resolved.alias,
    deadline: now + overlayJobSeconds, query: bytes)
  S.jobs[job.id] = job
  result = %*{"ticket": job.id, "subject": job.owner, "alias": job.alias,
    "remainingSeconds": overlayJobSeconds}

proc take(S: var OverlayRelay, p: PeerContext, now: int64): JsonNode {.
    role: actor.} =
  ## S/p/now: only the current authenticated owner endpoint may take work.
  var
    lease = S.directory.liveOverlayLease(p.subject, now)
    chosen: string = ""
    job: OverlayJob = default(OverlayJob)
  if prWrite notin p.rights: raise newException(ValueError, "taking work needs write rights")
  if lease.endpoint != p.address: raise newException(ValueError, "owner endpoint changed; renew this connection first")
  for id, pending in S.jobs:
    if pending.owner == p.subject and not pending.dispatched:
      chosen = id
      break
  if chosen.len == 0: return %*{"ready": false}
  job = S.jobs[chosen]
  job.dispatched = true
  job.endpoint = p.address
  job.revision = lease.revision
  S.jobs[chosen] = job
  result = %*{"ready": true, "ticket": job.id, "alias": job.alias,
    "caller": job.caller.subject, "callerEndpoint": job.caller.address,
    "read": prRead in job.caller.rights, "write": prWrite in job.caller.rights,
    "query": overlayEncoded(job.query)}

proc finish(S: var OverlayRelay, n: JsonNode, p: PeerContext,
    now: int64): JsonNode {.role: actor.} =
  ## S/n/p/now: a guessed ticket or a previous owner session cannot answer.
  var
    id: string = n{"ticket"}.getStr()
    lease = S.directory.liveOverlayLease(p.subject, now)
    job: OverlayJob = default(OverlayJob)
    bytes: ByteSeq = overlayReplyBytes(n{"reply"}.getStr())
  if not S.jobs.hasKey(id): raise newException(ValueError, "unknown or expired overlay ticket")
  job = S.jobs[id]
  if prWrite notin p.rights or job.owner != p.subject or not job.dispatched:
    raise newException(ValueError, "only the dispatched owner can answer")
  if job.endpoint != p.address or lease.endpoint != p.address or job.revision != lease.revision:
    raise newException(ValueError, "dispatched connection changed; request will not be replayed")
  if job.completed:
    if job.reply != bytes: raise newException(ValueError, "ticket already has a different reply")
    return %*{"completed": true}
  job.reply = bytes
  job.query = @[]
  job.completed = true
  S.jobs[id] = job
  result = %*{"completed": true}

proc jobResult(S: OverlayRelay, n: JsonNode, p: PeerContext,
    now: int64): JsonNode {.role: dataFetcher.} =
  ## S/n/p/now: results remain repeat-readable until their deadline.
  var
    id: string = n{"ticket"}.getStr()
    job: OverlayJob = default(OverlayJob)
  if not S.jobs.hasKey(id): raise newException(ValueError, "unknown or expired overlay ticket")
  job = S.jobs[id]
  if job.caller.subject != p.subject: raise newException(ValueError, "ticket belongs to another caller")
  result = %*{"ready": job.completed, "subject": job.owner,
    "remainingSeconds": job.deadline - now}
  if job.completed: result["reply"] = %overlayEncoded(job.reply)

proc forgetJob(S: var OverlayRelay, n: JsonNode, p: PeerContext): JsonNode {.
    role: actor.} =
  ## S/n/p: release caller-owned queue space; this cannot undo an executed write.
  var
    id: string = n{"ticket"}.getStr()
  if not S.jobs.hasKey(id): return %*{"forgotten": true}
  if S.jobs[id].caller.subject != p.subject:
    raise newException(ValueError, "ticket belongs to another caller")
  S.jobs.del(id)
  result = %*{"forgotten": true}

proc resolve(S: OverlayRelay, n: JsonNode, p: PeerContext,
    now: int64): JsonNode {.role: dataFetcher.} =
  ## S/n/p/now: directory metadata is visible only to permitted readers.
  if prRead notin p.rights: raise newException(ValueError, "resolution needs read rights")
  result = resolutionJson(S.directory.resolveOverlayAlias(n{"alias"}.getStr(), now))

proc answerOverlay*(S: var OverlayRelay, q: Query, p: PeerContext,
    now: int64 = -1): Reply {.role: orchestrator.} =
  ## S/q/p: call only for the exact reserved bare collection. No `as` claims.
  ## now: injected monotonic seconds for tests; -1 reads the local clock.
  var
    n: JsonNode = nil
    reply: JsonNode = nil
    at: int64 = if now < 0: overlayNow() else: now
    lease: OverlayLease = default(OverlayLease)
  try:
    if q.collection != overlayControl or q.op != qoPut:
      raise newException(ValueError, "expected overlay control request")
    if p.subject.len == 0 or p.rights == {}:
      raise newException(ValueError, "overlay requires an authenticated permitted peer")
    if q.payload.len > maxOverlayControlBytes: raise newException(ValueError, "overlay command is too large")
    n = parseJson(asText(q.payload))
    if n.kind != JObject: raise newException(ValueError, "overlay command must be an object")
    S.sweepOverlay(at)
    case n{"op"}.getStr()
    of "renew":
      lease = S.directory.renewOverlayLease(p, at)
      reply = %*{"remainingSeconds": overlayLeaseSeconds,
        "revision": $lease.revision, "observedEndpoint": lease.endpoint}
    of "resolve": reply = S.resolve(n, p, at)
    of "submit": reply = S.submit(n, p, at)
    of "take": reply = S.take(p, at)
    of "finish": reply = S.finish(n, p, at)
    of "result": reply = S.jobResult(n, p, at)
    of "forget": reply = S.forgetJob(n, p)
    else: raise newException(ValueError, "unknown overlay operation")
    result = overlayJsonReply(reply)
  except CatchableError as exc:
    result = Reply(ok: false, err: exc.msg)
