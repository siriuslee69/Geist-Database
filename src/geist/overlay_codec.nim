## Overlay codec <- bounded envelopes around Geist's existing binary Query/Reply.
import std/[json, base64]
import runePragmas
import ./types
import ./relay
import ./transport
import ./bytecheck

const
  overlayControl* = "geist-overlay-v1"
  maxOverlayObjectBytes* = 65536
  maxOverlayControlBytes* = 96 * 1024

proc overlayBytes*(s: string): ByteSeq {.role: sanitizer.} =
  ## s: bounded base64 from a control request or reply.
  var
    decoded: string = ""
  if s.len > maxOverlayControlBytes: raise newException(ValueError, "overlay object is too large")
  decoded = base64.decode(s)
  if decoded.len > maxOverlayObjectBytes: raise newException(ValueError, "overlay object is too large")
  result = asBytes(decoded)

proc overlayQueryBytes*(s: string): ByteSeq {.role: sanitizer.} =
  ## s: check every binary length and enum before the Query decoder sees it.
  var
    problem: string = ""
  result = overlayBytes(s)
  problem = checkQueryBytes(result)
  if problem.len > 0: raise newException(ValueError, problem)

proc overlayReplyBytes*(s: string): ByteSeq {.role: sanitizer.} =
  ## s: check every binary length and enum before the Reply decoder sees it.
  var
    problem: string = ""
  result = overlayBytes(s)
  problem = checkReplyBytes(result)
  if problem.len > 0: raise newException(ValueError, problem)

proc overlayEncoded*(A: ByteSeq): string {.role: encryptor.} =
  ## A: already-encoded Query or Reply, with a hard object bound.
  if A.len > maxOverlayObjectBytes: raise newException(ValueError, "overlay object is too large")
  result = base64.encode(A)

proc overlayJsonReply*(n: JsonNode): Reply {.role: helper.} =
  ## n: one control response inside an ordinary Geist Reply.
  result = Reply(ok: true, rows: @[Row(data: asBytes($n))])

proc overlayExchange*(L: var GeistLink, n: JsonNode,
    timeoutMs: int = 4000): JsonNode {.role: orchestrator.} =
  ## L/n/timeoutMs: use the existing Geist session, never a second carrier.
  var
    response: tuple[ok: bool, reply: Reply, err: string] = (false, Reply(), "")
    encoded: string = $n
  if encoded.len > maxOverlayControlBytes: raise newException(ValueError, "overlay command is too large")
  response = L.send(Query(op: qoPut, collection: overlayControl,
    payload: asBytes(encoded)), timeoutMs)
  if not response.ok:
    L.close()
    raise newException(IOError, response.err)
  if not response.reply.ok: raise newException(ValueError, response.reply.err)
  if response.reply.rows.len != 1: raise newException(ValueError, "invalid overlay response")
  if response.reply.rows[0].data.len > maxOverlayControlBytes:
    raise newException(ValueError, "overlay response is too large")
  result = parseJson(asText(response.reply.rows[0].data))
