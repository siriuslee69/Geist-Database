## ---------------------------------------------------------------------
## Payload <- one Query or Reply, however many datagrams it takes
## ---------------------------------------------------------------------
##
##   sendPayload(bytes)  ->  one frame, or a manifest and its chunks
##   feedPayload(frame)  ->  "read another", or the whole payload
##
## Shared by both ends of a link: the client sends a Query and reads a
## Reply with these, the server (./serve) reads the Query and sends the
## Reply with the same two calls. Kept apart from both so neither end has
## to reach into the other's module for them.

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./types
import ./format

const
  geistDacFrameMaxBytes* = 65_507
    ## One DAC datagram. Bifrost exposes no such constant, so Geist pins it
    ## here. Handshakes at gtArchive and above exceed this because the
    ## code-based KEM public keys are ~1.3 MB; those tiers must use DAC
    ## package transfer. `./masks.nim` says which tiers those are and why.

type
  SendOutcome* {.tag: "ame|networkSurface|types".} = tuple
    ## What one outgoing payload did. `frames` counts datagrams actually
    ## put on the wire, which is 1 for a whole payload and 1 + chunks for
    ## a packaged one -- a caller measuring cost wants the frames, not the
    ## calls.
    ok: bool
    frames: int
    err: string

  FeedOutcome* {.tag: "ame|networkSurface|types".} = tuple
    ## What one incoming frame did to a half-built payload. `done` is the
    ## distinction that matters: false means "read another frame", not
    ## "something went wrong".
    ok: bool
    done: bool
    payload: ByteSeq
    err: string

## ------------------------ payloads too big to send ------------------
##
## A datagram has a ceiling and a database does not. One row with a 200 KB
## text column, or a sync answer carrying a hundred rows, does not fit a
## frame -- and a transport that silently truncates at that point would
## hand back a Reply that decodes to fewer rows than were sent.
##
## So every payload travels under a one-byte envelope:
##
##   0  whole      the rest of this frame IS the payload
##   1  manifest   a package follows: how many chunks, how long, its digest
##   2  chunk      one piece, addressed by index
##
## Splitting and reassembly are Bifrost's `planDacPackage` and
## `DacPackageReceiver`; Geist only decides WHEN to use them and carries
## the pieces inside ordinary AME frames, so every chunk is sealed and
## authenticated exactly like a small reply. The manifest's digest is
## checked on assembly, so a package that arrives wrong is refused rather
## than decoded.
##
##   sender                              receiver
##   ------                              --------
##   fits?  -> [0][payload] ------------> payload
##   too big-> [1][manifest] -----------> open a receiver
##             [2][chunk 0] ------------> accept
##             [2][chunk 1] ------------> accept ... digest ok -> payload
##
## Chunks are MTU-sized, so this path is slower than one frame by design:
## it is the fallback, not the norm. The server keeps replies inside one
## frame whenever it can by answering with fewer rows -- see `rowBudget`.

const
  envWhole = 0'u8
  envManifest = 1'u8
  envChunk = 2'u8
  geistWholeMaxBytes* = 32_000
    ## Above this a payload is packaged. Well under the 65507-byte datagram
    ## ceiling: AME framing, the epoch header and the tag all ride in the
    ## same datagram, and guessing that overhead wrong would turn a large
    ## reply into a send error rather than a package.

type
  PackageAssembly* {.role: truthState, tag: "ame|networkSurface|types".} = object
    ## Half a package. `active` is false between packages, which is also
    ## how a stray chunk with no manifest is recognised and dropped.
    active*: bool
    receiver*: bfx.DacPackageReceiver

proc packageDefaults(): bfx.DacScenarioDefaults {.role: configurator,
    tag: "ame|networkSurface".} =
  ## MTU-sized chunks with XOR repair groups. The same-room profile's
  ## 32 KB chunks would be faster on loopback and would fragment on any
  ## real network between two desktops, which is the case this exists for.
  ##
  ## Bifrost used to spell this `cleanLanDacDefaults()`. The twelve
  ## per-scenario procs are now one table read by name, so the scenario is
  ## an argument rather than part of the call.
  result = bfx.dacDefaultsFor(bfx.dscCleanLan)

proc sendPayload*(sock: bfx.DacSocket, remote: bfx.DacAddress,
    session: var bfx.AmeSession, payload: openArray[uint8],
    packageId: uint64): SendOutcome {.
    role: orchestrator, tag: "ame|networkSurface|write".} =
  ## sock/remote/session: an established AME session.
  ## payload: the encoded Query or Reply.
  ## packageId: nonzero, distinct per package on this session.
  var
    body: ByteSeq = @[]
    plan: bfx.DacPackagePlan = default(bfx.DacPackagePlan)
    i: int = 0
  try:
    if payload.len <= geistWholeMaxBytes:
      body = @[envWhole]
      body.addBytes(payload)
      bfx.sendAmeDac(sock, remote, session, body)
      return (true, 1, "")
    plan = bfx.planDacPackage(packageId, payload, packageDefaults())
    body = @[envManifest]
    body.addBytes(bfx.encodeDacPackageManifest(plan.manifest))
    bfx.sendAmeDac(sock, remote, session, body)
    result.frames = 1
    while i < plan.chunks.len:
      body = @[envChunk]
      body.addBytes(bfx.encodeDacPackageChunk(plan.chunks[i]))
      bfx.sendAmeDac(sock, remote, session, body)
      result.frames = result.frames + 1
      i = i + 1
    result.ok = true
  except CatchableError as exc:
    result = (false, result.frames, exc.msg)

proc feedPayload*(A: var PackageAssembly,
    frame: openArray[uint8]): FeedOutcome {.role: parser,
    tag: "ame|networkSurface|read".} =
  ## A: assembly state for ONE sender.
  ## frame: the decrypted body of one AME frame.
  ##
  ## Returns done = false for a chunk that leaves the package incomplete,
  ## which is the caller's cue to read another frame rather than to answer.
  var
    assembled: bfx.DacPackageResult = default(bfx.DacPackageResult)
  if frame.len < 1:
    return (false, false, @[], "empty frame")
  case frame[0]
  of envWhole:
    return (true, true, @frame[1 .. ^1], "")
  of envManifest:
    try:
      A.receiver = bfx.initDacPackageReceiver(
        bfx.decodeDacPackageManifest(frame[1 .. ^1]))
      A.active = true
    except CatchableError as exc:
      A.active = false
      return (false, false, @[], "bad package manifest: " & exc.msg)
    return (true, false, @[], "")
  of envChunk:
    if not A.active:
      # A chunk with no manifest is either a stray from a package we gave
      # up on or a peer confused about its own state. Dropping it is right;
      # accepting it would build a payload nobody described.
      return (false, false, @[], "package chunk arrived without a manifest")
    try:
      bfx.acceptDacPackageChunk(A.receiver,
        bfx.decodeDacPackageChunk(frame[1 .. ^1]))
    except CatchableError as exc:
      A.active = false
      return (false, false, @[], "bad package chunk: " & exc.msg)
    if bfx.missingChunkIds(A.receiver).len > 0:
      return (true, false, @[], "")
    assembled = bfx.finishDacPackage(A.receiver)
    A.active = false
    if not assembled.ok:
      return (false, false, @[], assembled.err)
    return (true, true, assembled.payload, "")
  else:
    return (false, false, @[], "unknown transport envelope " & $frame[0])
