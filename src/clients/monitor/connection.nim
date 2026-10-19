## Device connection <- one pinned Geist endpoint, AM1P+S and recovery only.
import std/[os, json]
import runePragmas
import geist/wire
import ./provision

proc openDeviceLink*(root, subject, endpoint, peer: string, session: uint64,
    observer: GeistNetworkObserver = nil): GeistLink {.role: orchestrator.} =
  ## root/subject/endpoint/peer/session: local keys and one explicit remote pin.
  var
    address = parseDacAddress(endpoint)
    pin = loadPin(root / "peers" / (peer & ".pin"))
    policy = defaultTriggerPolicy()
    made: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  if not address.ok: raise newException(ValueError, "invalid Geist endpoint")
  checked((pin.ok, pin.err))
  policy.startTier = gtRecovery
  made = connectGeist(address.a, deviceIdentity(root, subject), pin.pin, policy,
    sessionId = session, timeoutMs = 60000, shared = deviceSharedKey(root), observer = observer)
  checked((made.ok, made.err))
  result = made.link

proc overlayAccess*(n: JsonNode): seq[OverlayAccess] {.role: sanitizer.} =
  ## n: explicit local allow list, absent means no forwarded callers.
  if n.isNil: return
  if n.kind != JArray: raise newException(ValueError, "overlayCallers must be an array")
  for subject in n:
    result.add OverlayAccess(subject: subject.getStr(), rights: {prRead, prWrite})
