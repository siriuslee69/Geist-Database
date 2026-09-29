## ---------------------------------------------------------------------
## geist-routed <- the daemon that answers for other daemons
## ---------------------------------------------------------------------
##
##   geist-routed --config /etc/geist/router.toml
##
##                          +-------------------------+
##   any client  -------->  |  geist-routed           |
##   any app                |  no store, no pipe      |
##                          +------------+------------+
##                                       |
##              +------------------------+------------------------+
##     eris.* p0|             fjord.* p0 |             avalon.* p0|
##              v                        v                        v
##      +---------------+        +---------------+        +---------------+
##      | D1 eris+fjord |        | D1  (same)    |        | D4 avalon     |
##      +-------+-------+        +-------+-------+        +---------------+
##              |  p1                    |  p1
##              v                        v
##      +---------------+        +---------------+
##      | D2  eris only |        | D3 fjord only |
##      +---------------+        +---------------+
##
## `geistd` serves one database. `geist-relayd` serves one pipe. Neither
## can serve a VPS running three apps behind one public address, and
## neither can hand the work to a fallback when it dies. This does both,
## and stores nothing itself.
##
## WHAT IT DOES WITH A REQUEST, IN ORDER:
##
##   1. read the address out of `q.collection`     address.nim
##   2. refuse a loop or an exhausted ttl          address.hop
##   3. choose a hop by priority and health        route.chooseHop
##   4. stamp `?as=` with the subject that CONNECTED, which the handshake
##      proved -- never with anything the request claimed
##   5. forward, failing over on a broken link      link.ask
##   6. hand the reply straight back
##
## IT CANNOT GRANT WHAT IT DOES NOT HAVE. The upstream intersects `?as=`
## with the router's own pin, so a router trusted for reading cannot turn
## a client's request into a write however it addresses it. See
## `delegatedContext` in transport.nim -- the check is in `serveOnce`, so
## it applies whether or not this daemon remembers to ask for it.
##
## IT COMPILES NO DATABASE. `import ../geist/wire`, like `geist-relayd`:
## no store, no lease, no generation swap, no packed rows. A router that
## could open a database would eventually be given one to open.
##
## THE WHOLE DEPLOYMENT IS ONE TOML FILE, and `--write-config` prints it
## with every option present, defaulted and commented. An operator should
## never have to read this source to find out what can be set.

## Configuration -- router.toml, the options and how they merge -- is in
## geist_routed_config.nim, re-exported here.

import std/[os, strutils, times]

import runePragmas
import ../geist/wire
import ./geist_routed_config

export geist_routed_config

type
  RouterState* {.
      role: truthState, tag: "networkSurface|server|status|types".} = object
    ## client: the outgoing half, with the health view failover reads.
    ## forwarded/refused: what the operator sees per request.
    client*: GeistClient
    node*: string
    quiet*: bool
    forwarded*: int
    refused*: int
    lastErr*: string

var
  shutdownRequested*: bool = false

proc requestShutdown*() {.role: actor,
    tag: "entrypoint|lifecycle|server".} =
  ## Ask the serve loop to stop after the request in flight.
  shutdownRequested = true

when defined(posix):
  import std/posix

  proc onSignal(sig: cint) {.role: actor, noconv.} =
    ## sig: SIGTERM or SIGINT; only used to leave the loop cleanly.
    requestShutdown()

proc installSignalHandlers*() {.role: orchestrator,
    tag: "entrypoint|lifecycle|server".} =
  ## Make SIGTERM and SIGINT request a graceful stop.
  when defined(posix):
    signal(SIGTERM, onSignal)
    signal(SIGINT, onSignal)

## ---------------------------- routing -------------------------------

proc refuse(err: string): Reply {.role: helper, inline,
    tag: "networkSurface|server".} =
  ## err: a refusal a client can act on.
  result = Reply(ok: false, err: err)

proc routeQuery*(S: var RouterState, q: Query, p: PeerContext): Reply {.
    role: metaOrchestrator, tag: "networkSurface|orchestrator|server".} =
  ## S: this router and its health view.
  ## q: the request as it arrived; `q.collection` carries the address.
  ## p: who asked, proved by the handshake.
  ##
  ## Every refusal below names the rule it broke. A router that answered
  ## an unroutable request with an empty result set would look exactly
  ## like a database with nothing in it, and the difference between "your
  ## address is wrong" and "there is nothing there" is an afternoon.
  var
    parsed: tuple[ok: bool, a: GeistAddress, err: string] =
      (false, default(GeistAddress), "")
    stepped: tuple[ok: bool, err: string] = (false, "")
    forward: Query = q
    answer: AskResult = default(AskResult)
  parsed = parseAddress(q.collection)
  if not parsed.ok:
    S.refused = S.refused + 1
    return refuse("address '" & q.collection & "': " & parsed.err)
  if not parsed.a.isRouted() and S.client.routes.table.matchRoute(
      parsed.a) < 0:
    S.refused = S.refused + 1
    return refuse("'" & q.collection & "' names no app, and this is a " &
      "router with no catch-all route. Address it as " &
      "geist://<app>/<target>")
  # Loop and ttl are checked BEFORE a hop is chosen: a request that has
  # already been here must be refused whether or not there is somewhere
  # to send it.
  stepped = parsed.a.hop(S.node)
  if not stepped.ok:
    S.refused = S.refused + 1
    return refuse(stepped.err)
  # The subject the HANDSHAKE proved, never one the request claimed. The
  # upstream intersects this with our own pin's rights, so this can only
  # ever narrow what the request may do.
  parsed.a.onBehalfOf = p.subject
  forward.collection = $parsed.a
  answer = S.client.ask(forward)
  if not answer.ok:
    S.refused = S.refused + 1
    S.lastErr = answer.err
    return refuse("could not reach a daemon for '" & q.collection & "': " &
      answer.err & (if answer.tried.len > 0:
        " (tried " & answer.tried.join(", ") & ")" else: ""))
  S.forwarded = S.forwarded + 1
  result = answer.reply

## ---------------------------- the daemon ----------------------------

proc note(quiet: bool, line: string) {.role: helper,
    tag: "server|status".} =
  ## quiet/line: one status line, on stderr.
  if not quiet:
    stderr.writeLine(line)

## ------------------------------ starting ----------------------------
##
##   parseArgs -> --write-config?  write the example file and stop
##             -> routerConfigFrom (router.toml, then the options)
##             -> routerIdentity -> --pin-out?  write the pin and stop
##             -> startRouter (routes, trust, client, socket)
##             -> routeStep until stopped

proc writeExample(a: RouterArgs): bool {.role: dataWriter,
    tag: "config|server|write".} =
  ## a: when --write-config names a file, write every option there with
  ## its default and comment, and say so. Raises when it cannot be written.
  var
    written: tuple[ok: bool, err: string] = (false, "")
  if a.writeConfig.len == 0:
    return false
  written = writeDoc(a.writeConfig, exampleRouterConfig(), routerNotes())
  if not written.ok:
    raise newException(IOError, written.err)
  stderr.writeLine("wrote " & a.writeConfig &
    "  <- every option, with defaults and comments")
  result = true

proc routerConfigFrom(a: RouterArgs): RouterConfig {.role: configurator,
    tag: "config|server".} =
  ## a: the options -> router.toml with them laid over it. Raises on a
  ## file that will not load.
  var
    written: tuple[ok: bool, err: string] = initGeistWireDefaults()
    loaded: tuple[ok: bool, c: RouterConfig, err: string] =
      (false, default(RouterConfig), "")
  if not written.ok:
    raise newException(ValueError, written.err)
  loaded = loadRouterConfig(a.configFile)
  if not loaded.ok:
    raise newException(ValueError, loaded.err)
  result = loaded.c.applyArgs(a)
  if loaded.err.len > 0:
    note(result.quiet, loaded.err)

proc routerIdentity(c: RouterConfig): AmeIdentityKey {.role: dataFetcher,
    tag: "cryptoBoundary|server".} =
  ## c: the router's signing identity, created on first start.
  var
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
  if c.identity.len == 0:
    raise newException(ValueError,
      "identity is required: a router that mints a fresh key on every " &
      "start can never be pinned by a client")
  mine = loadOrCreateIdentity(c.identity, resolveIdentityPassword(c),
    c.subject, geistSignatureSlots())
  if not mine.ok:
    raise newException(IOError, mine.err)
  result = mine.key

proc writeRouterPin(path: string, key: AmeIdentityKey) {.role: dataWriter,
    tag: "cryptoBoundary|server|write".} =
  ## path/key: the shareable half of the router's identity.
  var
    written: tuple[ok: bool, err: string] = savePin(path, pinOf(key))
  if not written.ok:
    raise newException(IOError, written.err)
  stderr.writeLine("wrote " & path & "  <- hand this to clients")
  stderr.writeLine("")
  stderr.writeLine(describePin(pinOf(key)))

proc startRouter(c: RouterConfig, key: AmeIdentityKey,
    S: var RouterState): GeistServer {.role: orchestrator,
    tag: "networkSurface|server".} =
  ## c/key: routes, trust list, the outgoing client in S, and the bound
  ## socket. Raises on anything that would make the router useless.
  var
    checked: tuple[ok: bool, err: string] = c.routing.validate()
    trusted: tuple[ok: bool, peers: seq[TrustedPeer], err: string] =
      (false, @[], "")
    address: tuple[ok: bool, a: GeistDacAddress] = parseDacAddress(c.listen)
    client: tuple[ok: bool, client: GeistClient, err: string] =
      (false, default(GeistClient), "")
    server: tuple[ok: bool, server: GeistServer, err: string] =
      (false, default(GeistServer), "")
  if not checked.ok:
    raise newException(ValueError, "route table: " & checked.err)
  if c.trust.len == 0 and c.allowWrite.len == 0:
    raise newException(ValueError,
      "trust (or allowWrite) is required: without a pin there is no " &
      "peer to trust, and every handshake would be refused")
  trusted = trustListFrom(c.trust, c.allowWrite)
  if not trusted.ok:
    raise newException(IOError, trusted.err)
  if not address.ok:
    raise newException(ValueError,
      "listen must be dac://host:port, got '" & c.listen & "'")
  client = initGeistClient(key, c.routing)
  if not client.ok:
    raise newException(ValueError, client.err)
  S.client = client.client
  S.client.timeoutMs = c.timeoutMs
  S.node = c.routing.node
  S.quiet = c.quiet
  server = initGeistServer(address.a, key, trusted.peers,
    defaultTriggerPolicy(), int64(c.idleSeconds),
    transportDefaults().requireCookie)
  if not server.ok:
    raise newException(IOError, server.err)
  note(c.quiet, "geist-routed listening on " & c.listen)
  note(c.quiet, "  node:    " & c.routing.node)
  note(c.quiet, "  subject: " & key.subject)
  for t in trusted.peers:
    note(c.quiet, "  trusts:  " & t.pin.subject &
      (if prWrite in t.rights: "  (may write)" else: "  (may read)"))
  note(c.quiet, S.client.healthReport())
  result = server.server

## ------------------------------ running -----------------------------

proc routeStep(S: var RouterState, c: RouterConfig, a: RouterArgs,
    server: var GeistServer, served: var int): bool {.role: orchestrator,
    tag: "networkSurface|server".} =
  ## S/c/a/server/served: wait for one frame and route it. Returns true
  ## when --oneshot or maxRequests says to stop.
  var
    state: ptr RouterState = addr S
    step: tuple[ok: bool, served: bool, err: string] = serveOnce(server,
      proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
        {.cast(gcsafe).}:
          result = routeQuery(state[], q, p),
      c.timeoutMs)
  if step.served:
    served = served + 1
    note(c.quiet, "[" & now().format("HH:mm:ss") & "] request " & $served &
      ": " & $S.forwarded & " forwarded, " & $S.refused & " refused" &
      (if S.lastErr.len > 0: "  last: " & S.lastErr else: ""))
  # An idle window is ok = true with served = false, so only a real
  # failure reaches this line.
  if not step.ok:
    note(c.quiet, "request failed: " & step.err)
  result = (a.oneshot and step.served) or
    (c.maxRequests > 0 and served >= c.maxRequests)

proc runRouted*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|networkSurface|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    a: RouterArgs = default(RouterArgs)
    c: RouterConfig = default(RouterConfig)
    S: RouterState = default(RouterState)
    key: AmeIdentityKey = default(AmeIdentityKey)
    server: GeistServer = default(GeistServer)
    served: int = 0
  # A fresh run: a stop asked of an earlier run in this process must not
  # end this one at once.
  shutdownRequested = false
  try:
    a = parseArgs(argv)
    if a.help:
      echo usageText
      return 0
    installSignalHandlers()
    if writeExample(a):
      return 0
    c = routerConfigFrom(a)
    key = routerIdentity(c)
    if a.pinOut.len > 0:
      writeRouterPin(a.pinOut, key)
      return 0
    server = startRouter(c, key, S)
    while not shutdownRequested and not routeStep(S, c, a, server, served):
      discard
    S.client.closeClient()
    server.closeServer()
    note(c.quiet, "stopped after " & $served & " request(s), " &
      $S.forwarded & " forwarded, " & $S.refused & " refused")
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geist-routed: " & exc.msg)
    result = 1

when isMainModule:
  quit(runRouted(commandLineParams()))
