## ---------------------------------------------------------------------
## Lane recovery <- a link whose message lane fell behind gets moving again
## ---------------------------------------------------------------------
##
## Every AME session has two lanes, one per direction. If a burst of lost
## datagrams is wider than the receiver's reorder window, the receiver
## refuses every later message on that lane: it cannot check them without
## deriving every key in between, and a forger could make it do that for
## free. Bifrost's cure is a proved JUMP (Bifrost README, FOMKE, Step 8):
##
##   stuck side                                  other side
##   ----------                                  ----------
##   frame refused, "behind"
##   ask   ── AME 0x15, sealed on MY lane ──────▶ (my lane still works)
##                                               answer = proved jump
##   jump  ◀── AME 0x16, proved with JK ────────
##   lane moved; next frame opens
##
## Both ends of a Geist link use the two calls here, the client in
## ./transport and the server in ./serve. Neither SENDS anything: each
## returns the bytes to send, because how a frame reaches the peer differs
## (a direct socket, or wrapped for a router -- see ./hop_link).
##
## What is lost: the frames that hit the wall. A client that answered an
## ask sends its current request again (./transport, `send`); a reply the
## client could not open is not resent -- the request times out and the
## caller retries, which the lane now carries.

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types

const
  geistJumpAskSeconds* = 1.0
    ## At most one jump ask per link per second. "Behind" is a hint set
    ## before any tag is checked, so a stream of forged frames could set it
    ## over and over; this keeps the cost of that to one small frame a
    ## second.

type
  LaneStep* = enum
    lsNone,
      ## not a lane frame: open it as data
    lsAnswered,
      ## the peer could not follow OUR lane; `reply` proves where it is
    lsJumped,
      ## the peer proved where ITS lane is; our copy has moved there
    lsRefused
      ## a lane frame that did not check out; nothing changed

  LaneOutcome* {.role: preparedData, tag: "ame|networkSurface|types".} = tuple
    ## What one lane frame did. `reply` is non-empty only on lsAnswered.
    step: LaneStep
    reply: ByteSeq
    gaveUp: uint64
    err: string

proc lanePacketKind(A: openArray[uint8]): bfx.AmePacketKind {.role: parser.} =
  ## A: one datagram; its AME packet kind, or ampkUnknown when it is not an
  ## AME frame at all. The kind sits in the clear header.
  try:
    result = bfx.decodeAmeFrameHeader(A).packetKind
  except CatchableError:
    result = bfx.ampkUnknown

proc handleLaneFrame*(S: var bfx.AmeSession,
    A: openArray[uint8]): LaneOutcome {.role: orchestrator,
    tag: "ame|networkSurface".} =
  ## S: the session the frame belongs to.
  ## A: one datagram. Returns lsNone for anything that is not an ask or a
  ## jump, so a caller can try this first and fall through to data.
  var
    opened: bfx.FomkeJumpResult = default(bfx.FomkeJumpResult)
  result = (lsNone, @[], 0'u64, "")
  case lanePacketKind(A)
  of bfx.ampkJumpAsk:
    try:
      result = (lsAnswered, bfx.answerAmeJumpAsk(S, bfx.acrDac, A), 0'u64, "")
    except CatchableError as exc:
      result = (lsRefused, @[], 0'u64, exc.msg)
  of bfx.ampkJump:
    opened = bfx.openAmeJump(S, bfx.acrDac, A)
    if opened.ok:
      result = (lsJumped, @[], opened.gaveUp, "")
    else:
      result = (lsRefused, @[], 0'u64, opened.err)
  else:
    discard

proc jumpAskIfBehind*(S: var bfx.AmeSession, lastAskAt: var float,
    now: float): ByteSeq {.role: actor, tag: "ame|networkSurface".} =
  ## S: a session whose last frame failed to open.
  ## lastAskAt/now: when this link last asked, and the time now (seconds).
  ## Returns the ask to send, or nothing: not behind, or asked too recently.
  if not bfx.ameSessionBehind(S) or now - lastAskAt < geistJumpAskSeconds:
    return @[]
  try:
    result = bfx.sealAmeJumpAsk(S, bfx.acrDac)
    lastAskAt = now
  except CatchableError:
    result = @[]
