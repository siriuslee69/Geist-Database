## ---------------------------------------------------------------------
## geist-hopd <- the router machines link to, so they can reach each other
## ---------------------------------------------------------------------
##
##   geist-hopd --config /etc/geist/hop.toml
##
##   phone ==link==> geist-hopd <==link== nas (geistd --hop, dials out)
##                       |
##                       +==link==> another geist-hopd ==> cam
##
## Each machine makes ONE handshake, with this router. Through it, a
## client opens an ordinary end-to-end Geist link to any target the router
## shows it. The router hands the frames on and reads none of them: it
## sees who talks to whom and how much, never what (docs/hop.md).
##
## IT COMPILES NO DATABASE. `import ../geist/wire`, like geist-routed:
## `nimble checkHop` fails the build if a store module ever reaches it.
##
## The logic is ../geist/hop_router; this file is configuration and the
## loop.

import std/[os, times]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ../geist/stop
import ../geist/wire
import ../geist/hop_router
import ./geist_hopd_config

export stop, geist_hopd_config

proc note(quiet: bool, line: string) {.role: helper, tag: "server|status".} =
  ## quiet/line: one status line on stderr, unless asked for silence.
  if not quiet:
    stderr.writeLine(line)

proc writeExample(a: HopArgs): bool {.role: dataWriter,
    tag: "config|server|write".} =
  ## a: when --write-config was given, the example file is written.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  if a.writeConfig.len == 0:
    return false
  written = writeDoc(a.writeConfig, exampleHopConfig(), hopNotes())
  if not written.ok:
    raise newException(IOError, written.err)
  stderr.writeLine("wrote " & a.writeConfig &
    "  <- every option, with defaults and comments")
  result = true

proc hopIdentity(c: HopConfig): AmeIdentityKey {.role: dataFetcher,
    tag: "cryptoBoundary|server".} =
  ## c: this router's signing key, created on first use.
  var
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
  if c.identity.len == 0:
    raise newException(ValueError, "identity is required: a router with a " &
      "new key on every start can never be pinned")
  mine = loadOrCreateIdentity(c.identity, resolveHopPassword(c), c.subject,
    geistSignatureSlots())
  if not mine.ok:
    raise newException(IOError, mine.err)
  result = mine.key

proc neighboursFrom(c: HopConfig): seq[HopNeighbour] {.role: dataFetcher,
    tag: "cryptoBoundary|config|server".} =
  ## c: every configured neighbour with its pin loaded. A pin that will not
  ## load is fatal, as everywhere in Geist.
  var
    loaded: tuple[ok: bool, pin: bfx.AmePinnedPeerIdentity, err: string] =
      (false, default(bfx.AmePinnedPeerIdentity), "")
  for p in c.peer:
    loaded = loadPin(p.pin)
    if not loaded.ok:
      raise newException(IOError, p.pin & ": " & loaded.err)
    result.add(HopNeighbour(pin: loaded.pin, id: uint64(p.id),
      router: p.router, endpoint: p.endpoint))

proc targetsFrom(c: HopConfig): seq[bfx.AmeRouteTarget] {.role: configurator,
    tag: "config|server".} =
  ## c: the directory, as Bifrost's router takes it.
  for t in c.target:
    result.add(bfx.AmeRouteTarget(id: uint64(t.id), name: t.name,
      visibleTo: t.visibleTo, via: uint64(t.via)))

proc startHop(c: HopConfig, key: AmeIdentityKey): HopNode {.
    role: orchestrator, tag: "networkSurface|server".} =
  ## c/key: the router, bound and ready.
  var
    problem: string = checkHopConfig(c)
    address: tuple[ok: bool, a: GeistDacAddress] = parseDacAddress(c.listen)
    made: tuple[ok: bool, node: HopNode, err: string] =
      (false, default(HopNode), "")
  if problem.len > 0:
    raise newException(ValueError, problem)
  if not address.ok:
    raise newException(ValueError, "listen must be dac://host:port, got '" &
      c.listen & "'")
  made = initHopNode(address.a, key, uint64(c.id), neighboursFrom(c),
    targetsFrom(c), defaultTriggerPolicy(), float(c.idleSeconds), c.timeoutMs)
  if not made.ok:
    raise newException(IOError, made.err)
  note(c.quiet, "geist-hopd listening on " & c.listen)
  note(c.quiet, "  route id: " & $c.id & "  subject: " & key.subject)
  for p in c.peer:
    note(c.quiet, "  peer:     " & p.pin & "  id " & $p.id &
      (if p.router: "  (router" & (if p.endpoint.len > 0: ", dials " &
        p.endpoint else: "") & ")" else: ""))
  result = made.node

proc reportTurn(N: HopNode, c: HopConfig, lastReport: var float,
    lastErr: var string) {.role: dataWriter, tag: "server|status".} =
  ## N/c: one status line a minute, and every new error once.
  var
    t: float = epochTime()
  if N.lastErr.len > 0 and N.lastErr != lastErr:
    note(c.quiet, "[" & now().format("HH:mm:ss") & "] " & N.lastErr)
    lastErr = N.lastErr
  if t - lastReport < 60.0:
    return
  lastReport = t
  note(c.quiet, "[" & now().format("HH:mm:ss") & "] links " & $N.linked &
    ", forwarded " & $N.forwarded & ", dropped " & $N.dropped)

proc runHopd*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|networkSurface|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    a: HopArgs = default(HopArgs)
    c: HopConfig = default(HopConfig)
    loaded: tuple[ok: bool, c: HopConfig, err: string] =
      (false, default(HopConfig), "")
    key: AmeIdentityKey = default(AmeIdentityKey)
    N: HopNode = default(HopNode)
    written: tuple[ok: bool, err: string] = (false, "")
    lastReport: float = 0.0
    lastErr: string = ""
  clearShutdown()
  try:
    a = parseHopArgs(argv)
    if a.help:
      echo usageText
      return 0
    installSignalHandlers()
    if writeExample(a):
      return 0
    written = initGeistWireDefaults()
    if not written.ok:
      raise newException(ValueError, written.err)
    loaded = loadHopConfig(a.configFile)
    if not loaded.ok:
      raise newException(ValueError, loaded.err)
    c = loaded.c.applyHopArgs(a)
    key = hopIdentity(c)
    if a.pinOut.len > 0:
      discard savePin(a.pinOut, pinOf(key))
      stderr.writeLine("wrote " & a.pinOut & "  <- hand this to neighbours")
      return 0
    N = startHop(c, key)
    while not shutdownWanted():
      N.hopStep(500)
      N.reportTurn(c, lastReport, lastErr)
    N.closeHopNode()
    note(c.quiet, "stopped: " & $N.forwarded & " forwarded, " & $N.dropped &
      " dropped")
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geist-hopd: " & exc.msg)
    result = 1

when isMainModule:
  quit(runHopd(commandLineParams()))
