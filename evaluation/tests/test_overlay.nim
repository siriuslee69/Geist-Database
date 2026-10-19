## Overlay tests <- exact aliases, identity leases and bounded reverse requests.
import std/[unittest, json]
import runePragmas
import geist/wire

proc peer(s, endpoint: string, rights: set[PeerRight] = {prRead, prWrite}): PeerContext {.
    role: configurator.} =
  ## s/endpoint/rights: simulated already-authenticated context, never request fields.
  result = PeerContext(subject: s, address: endpoint, rights: rights)

proc desk(): OverlayRelay {.role: configurator.} =
  ## A shared physical IP and shared local IP, separated by port and identity.
  result = initOverlayRelay([
    OverlayGrant(subject: "a", aliases: @["one.geist", "alias.geist", "10.76.0.5:8080"]),
    OverlayGrant(subject: "b", aliases: @["two.geist", "10.76.0.5:8081"])])

proc control(n: JsonNode): Query {.role: configurator.} =
  ## n: the same reserved collection and envelope used on the real wire.
  result = Query(op: qoPut, collection: overlayControl, payload: asBytes($n))

proc rpc(S: var OverlayRelay, n: JsonNode, p: PeerContext,
    now: int64 = 100): JsonNode {.role: orchestrator.} =
  ## S/n/p/now: unwrap successful responses, make refusals readable by tests.
  var
    reply: Reply = S.answerOverlay(control(n), p, now)
  if not reply.ok: return %*{"error": reply.err}
  result = parseJson(asText(reply.rows[0].data))

proc enqueue(S: var OverlayRelay, alias: string, p: PeerContext,
    now: int64 = 100): JsonNode {.role: orchestrator.} =
  ## S/alias/p/now: a real encoded application Query inside a relay request.
  result = S.rpc(%*{"op": "submit", "alias": alias,
    "query": overlayEncoded(encodeQuery(Query(op: qoGet, collection: "index")))}, p, now)

suite "overlay aliases":
  # {.testKind: tkUnit, covers: "overlayAlias".}
  test "names and addresses have stable canonical forms":
    check overlayAlias("Archive.Geist.") == "archive.geist"
    check overlayAlias("Archive.Geist.:08080") == "archive.geist:8080"
    check overlayAlias("10.76.0.5:8080") != overlayAlias("10.76.0.5:8081")
    check overlayAlias("[FD00:0:0:0:0:0:0:1]:8080") == overlayAlias("[fd00::1]:8080")
    check overlayAlias("fd00::1") == overlayAlias("[fd00::1]")

  # {.testKind: tkEdgeCase, covers: "overlayAlias".}
  test "malformed names paths and ports are refused":
    for name in ["", "a..b", "-a.geist", "a-.geist", "a/b", "a@b", "a%20b", "é.geist",
        "999.1.1.1", "a:", "a:0", "a:65536", "a:+2", "a:two", "[fd00::1", "[a]:1", " a"]:
      expect ValueError: discard overlayAlias(name)

  # {.testKind: tkEdgeCase, covers: "initOverlayDirectory".}
  test "conflicting owners and duplicate canonical aliases stop startup":
    expect ValueError:
      discard initOverlayRelay([OverlayGrant(subject: "a", aliases: @["One.Geist."]),
        OverlayGrant(subject: "b", aliases: @["one.geist"])])
    expect ValueError:
      discard initOverlayRelay([OverlayGrant(subject: "a", aliases: @["one", "ONE"])])

suite "identity leases":
  # {.testKind: tkIntegration, covers: "renewOverlayLease|resolveOverlayAlias".}
  test "several aliases resolve to one identity and full observed endpoint":
    var
      S = desk()
      a = peer("a", "dac://203.0.113.1:1001")
      b = peer("b", "dac://203.0.113.1:1002")
    check not S.rpc(%*{"op": "renew"}, a).hasKey("error")
    check not S.rpc(%*{"op": "renew"}, b).hasKey("error")
    check S.directory.resolveOverlayAlias("ONE.GEIST", 101).subject == "a"
    check S.directory.resolveOverlayAlias("alias.geist", 101).observedEndpoint == a.address
    check S.directory.resolveOverlayAlias("10.76.0.5:8080", 101).subject == "a"
    check S.directory.resolveOverlayAlias("10.76.0.5:8081", 101).subject == "b"
    check S.directory.resolveOverlayAlias("two.geist", 101).observedEndpoint == b.address
    expect ValueError: discard S.directory.resolveOverlayAlias("10.76.0.5", 101)

  # {.testKind: tkRegression, covers: "renewOverlayLease", pins: "identity keyed by full endpoint rather than IP".}
  test "renewal updates IP and port while retaining every owned name":
    var
      S = desk()
      a = peer("a", "dac://203.0.113.1:1001")
      first = S.rpc(%*{"op": "renew"}, a)
      same = S.rpc(%*{"op": "renew"}, a, 120)
    check first["revision"] == same["revision"]
    a.address = "dac://198.51.100.2:2002"
    discard S.rpc(%*{"op": "renew", "address": "forged"}, a, 130)
    check S.directory.resolveOverlayAlias("alias.geist", 131).observedEndpoint == a.address
    check $S.directory.resolveOverlayAlias("one.geist", 131).revision != first["revision"].getStr()
    expect ValueError: discard S.directory.resolveOverlayAlias("one.geist", 220)

  # {.testKind: tkEdgeCase, covers: "renewOverlayLease|answerOverlay".}
  test "expiration never gives names to another identity or a read-only peer":
    var
      S = desk()
      stranger = peer("unknown", "dac://203.0.113.1:1003")
      reader = peer("a", "dac://203.0.113.1:1001", {prRead})
    check S.rpc(%*{"op": "renew", "subject": "a", "aliases": ["one.geist"]}, stranger).hasKey("error")
    check S.rpc(%*{"op": "renew"}, reader).hasKey("error")
    discard S.rpc(%*{"op": "renew"}, peer("a", reader.address))
    check S.rpc(%*{"op": "resolve", "alias": "one.geist"}, stranger, 190).hasKey("error")
    check S.rpc(%*{"op": "renew", "subject": "a"}, stranger, 191).hasKey("error")

suite "reverse requests":
  # {.testKind: tkIntegration, covers: "answerOverlay".}
  test "only the owner executes and only the caller reads the encoded reply":
    var
      S = desk()
      owner = peer("a", "dac://203.0.113.1:1001")
      caller = peer("caller", "dac://203.0.113.1:2001")
      b = peer("b", "dac://203.0.113.1:1002")
      job: JsonNode = nil
      work: JsonNode = nil
      response = overlayEncoded(encodeReply(Reply(ok: true, rows: @[Row(data: asBytes("hello"))])))
    discard S.rpc(%*{"op": "renew"}, owner)
    discard S.rpc(%*{"op": "renew"}, b)
    job = S.enqueue("alias.geist", caller)
    check not job.hasKey("error")
    check not S.rpc(%*{"op": "take"}, b)["ready"].getBool()
    check not S.rpc(%*{"op": "result", "ticket": job["ticket"]}, caller)["ready"].getBool()
    work = S.rpc(%*{"op": "take"}, owner)
    check work["ready"].getBool()
    check work["caller"].getStr() == caller.subject
    check decodeQuery(overlayQueryBytes(work["query"].getStr())).collection == "index"
    check S.rpc(%*{"op": "finish", "ticket": job["ticket"], "reply": response}, b).hasKey("error")
    check not S.rpc(%*{"op": "finish", "ticket": job["ticket"], "reply": response}, owner).hasKey("error")
    check not S.rpc(%*{"op": "finish", "ticket": job["ticket"], "reply": response}, owner).hasKey("error")
    check S.rpc(%*{"op": "result", "ticket": job["ticket"]}, b).hasKey("error")
    check S.rpc(%*{"op": "result", "ticket": job["ticket"]}, caller)["ready"].getBool()
    check not S.rpc(%*{"op": "forget", "ticket": job["ticket"]}, caller).hasKey("error")
    check S.rpc(%*{"op": "result", "ticket": job["ticket"]}, caller).hasKey("error")

  # {.testKind: tkRegression, covers: "answerOverlay", pins: "no automatic replay of dispatched writes after owner migration".}
  test "queued work follows identity but dispatched work is never retaken":
    var
      S = desk()
      old = peer("a", "dac://203.0.113.1:1001")
      fresh = peer("a", "dac://203.0.113.1:1002")
      caller = peer("caller", "dac://203.0.113.1:2001")
      job: JsonNode = nil
      work: JsonNode = nil
      response = overlayEncoded(encodeReply(Reply(ok: true)))
    discard S.rpc(%*{"op": "renew"}, old)
    job = S.enqueue("one.geist", caller)
    discard S.rpc(%*{"op": "renew"}, fresh, 110)
    check S.rpc(%*{"op": "take"}, old, 110).hasKey("error")
    work = S.rpc(%*{"op": "take"}, fresh, 110)
    check work["ready"].getBool()
    check not S.rpc(%*{"op": "take"}, fresh, 110)["ready"].getBool()
    discard S.rpc(%*{"op": "renew"}, old, 120)
    check S.rpc(%*{"op": "finish", "ticket": job["ticket"], "reply": response}, fresh, 120).hasKey("error")
    check S.rpc(%*{"op": "finish", "ticket": job["ticket"], "reply": response}, old, 120).hasKey("error")
    check not S.rpc(%*{"op": "take"}, old, 120)["ready"].getBool()
    check S.rpc(%*{"op": "result", "ticket": job["ticket"]}, caller, 160).hasKey("error")

  # {.testKind: tkEdgeCase, covers: "answerOverlay".}
  test "malformed binary bodies and nested identity claims never reach an owner":
    var
      S = desk()
      owner = peer("a", "dac://203.0.113.1:1001")
      caller = peer("caller", "dac://203.0.113.1:2001")
    discard S.rpc(%*{"op": "renew"}, owner)
    check S.rpc(%*{"op": "submit", "alias": "one.geist", "query": "AA=="}, caller).hasKey("error")
    check S.rpc(%*{"op": "submit", "alias": "one.geist", "query": "!"}, caller).hasKey("error")
    check S.rpc(%*{"op": "submit", "alias": "one.geist", "query": overlayEncoded(encodeQuery(
      Query(collection: "geist://app/index?as=admin")))}, caller).hasKey("error")
    check S.rpc(%*{"op": "submit", "alias": "one.geist", "query": overlayEncoded(encodeQuery(
      Query(collection: overlayControl)))}, caller).hasKey("error")
    check not S.rpc(%*{"op": "take"}, owner)["ready"].getBool()

  # {.testKind: tkEdgeCase, covers: "answerOverlay".}
  test "rights and queue limits are enforced and expired slots are reclaimed":
    var
      S = desk()
      owner = peer("a", "dac://203.0.113.1:1001")
      caller = peer("caller", "dac://203.0.113.1:2001", {prRead})
    discard S.rpc(%*{"op": "renew"}, owner)
    check S.rpc(%*{"op": "submit", "alias": "one.geist", "query": overlayEncoded(encodeQuery(
      Query(op: qoPut, collection: "index")))}, caller).hasKey("error")
    for i in 1..maxOverlayCallerJobs: check not S.enqueue("one.geist", caller).hasKey("error")
    check S.enqueue("one.geist", caller).hasKey("error")
    check not S.enqueue("one.geist", caller, 160).hasKey("error")
    check S.enqueue("unknown.geist", caller).hasKey("error")

  # {.testKind: tkRegression, covers: "answerOverlay", pins: "control collection must not accept delegated addresses".}
  test "a routed address cannot impersonate a registering owner":
    var
      S = desk()
      q = control(%*{"op": "renew"})
    q.collection = "geist://app/geist-overlay-v1?as=a"
    check not S.answerOverlay(q, peer("a", "dac://203.0.113.1:1001"), 100).ok
