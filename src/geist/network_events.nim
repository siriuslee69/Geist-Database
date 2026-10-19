## Network events <- public progress without secret material or message bodies.
import std/times
import runePragmas
import ./masks

type
  GeistNetworkEvent* {.role: preparedData, expectedCount: [0, 256],
      lifeCycle: lcJob.} = object
    at*: int64
    step*: string
    endpoint*: string
    subject*: string
    mode*: string
    tier*: GeistTier
    sessionId*: uint64
    bytes*: int
    error*: string

  GeistNetworkObserver* = proc(e: GeistNetworkEvent) {.gcsafe.}

proc reportNetwork*(observer: GeistNetworkObserver, step, endpoint,
    subject, mode: string, tier: GeistTier, sessionId: uint64 = 0,
    bytes: int = 0, error: string = "") {.role: dataWriter.} =
  ## observer/...: deliver metadata only; an observer cannot break networking.
  if observer == nil:
    return
  try:
    observer(GeistNetworkEvent(at: getTime().toUnix(), step: step,
      endpoint: endpoint, subject: subject, mode: mode, tier: tier,
      sessionId: sessionId, bytes: bytes, error: error))
  except CatchableError:
    discard
