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

import std/[json, os, strutils, times]

import runePragmas
import ../geist/wire

const
  defaultRouterListen* = "dac://127.0.0.1:47657"
    ## One port above `geist-relayd`, so all three daemons can run on one
    ## machine without an operator choosing numbers.
  routerConfigName* = "router.toml"

type
  RouterConfig* {.role: configurator, tag: "config|entrypoint|networkSurface|server|types".} = object
    ## The whole deployment. Written and read by `doc.nim`, so this object
    ## IS the file's schema: a field here is an option there, and there is
    ## no second list to keep in step.
    listen*: string
    subject*: string
    identity*: string
    identityPasswordFile*: string
    trust*: seq[string]
    allowWrite*: seq[string]
    timeoutMs*: int
    idleSeconds*: int
    maxRequests*: int
    quiet*: bool
    routing*: RouteTable

  RouterState* {.role: truthState, tag: "networkSurface|server|status|types".} = object
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

  proc onSignal(sig: cint) {.noconv.} =
    ## sig: SIGTERM or SIGINT; only used to leave the loop cleanly.
    requestShutdown()

proc installSignalHandlers*() {.role: orchestrator,
    tag: "entrypoint|lifecycle|server".} =
  ## Make SIGTERM and SIGINT request a graceful stop.
  when defined(posix):
    signal(SIGTERM, onSignal)
    signal(SIGINT, onSignal)

## ---------------------------- configuration -------------------------

proc defaultRouterConfig*(): RouterConfig {.role: configurator,
    tag: "config|server".} =
  ## Every option at the value the daemon uses when the file says nothing.
  ##
  ## The route list is EMPTY on purpose. A router that shipped with a
  ## guess about where anything lived would forward somebody's mail to a
  ## machine chosen by a default.
  result.listen = defaultRouterListen
  result.subject = "geist-router"
  result.timeoutMs = 1000
  result.idleSeconds = 900
  result.routing = defaultRouteTable("")

proc routerNotes*(): DocStyle {.role: configurator,
    tag: "config|docs|server".} =
  ## The comments written above the options whose names do not explain
  ## themselves. Everything else is left bare -- a file where every line
  ## has a comment is a file nobody reads.
  result = defaultDocStyle()
  result.header = @[
    "geist-routed: which daemon answers for which app.",
    "",
    "Written by `geist-routed --write-config`. Every option this daemon",
    "reads is listed below with its default, so nothing has to be looked",
    "up in the source. Keys this version does not know are KEPT, not",
    "deleted -- see docs/federation.md.",
    "",
    "An address looks like:  geist://<app>.<instance>@<node>/<target>",
    "and a bare name (`notes`) is a legal address that names a target."]
  result.noteOn("subject",
    "the name this router presents in a handshake; peers pin the key, " &
    "not the name")
  result.noteOn("trust",
    "pin files whose holders may READ through this router")
  result.noteOn("allowWrite",
    "pin files whose holders may read AND write; a superset of trust")
  result.noteOn("timeoutMs",
    "how long one attempt at one hop may take; the whole request may " &
    "take this times the number of hops tried")
  result.noteOn("idleSeconds",
    "a peer that has said nothing for this long is forgotten (DAC is " &
    "connectionless, so nobody announces leaving)")
  result.noteOn("maxRequests", "0 means serve forever")
  result.noteOn("routing",
    "the route table: which endpoints serve which app, in priority order")
  result.noteOn("routing.node",
    "this router's own name. Written into every forwarded address so a " &
    "loop through this daemon is detected by name. Must be unique among " &
    "the daemons that can reach each other")
  result.noteOn("routing.maxHops",
    "hops a request may still take when it arrives without a ttl")
  result.noteOn("routing.takeoverAfterSeconds",
    "continuous failure before a lower priority takes over. One timed-" &
    "out request is not a dead daemon")
  result.noteOn("routing.probeEverySeconds",
    "how often a hop that is down is tried again")
  result.noteOn("routing.yieldAfterSeconds",
    "how long a link to a demoted hop is kept open, so a long poll is " &
    "not cut in half when a higher priority returns")
  result.noteOn("routing.probeSuccesses",
    "consecutive successes before a hop that was down carries traffic " &
    "again. One is not enough: a crash-looping daemon answers every " &
    "third probe")
  result.noteOn("routing.route",
    "one block per (app, instance) pattern. '*' matches anything; the " &
    "most specific match wins, and two blocks with the same pattern are " &
    "refused")
  result.noteOn("routing.route.hops",
    "one block per endpoint. Lowest priority number is tried first; two " &
    "hops in one route may not share a priority. local = true means this " &
    "daemon answers it itself")

proc exampleRouterConfig*(): RouterConfig {.role: configurator,
    tag: "config|docs|server".} =
  ## The four-daemon VPS from docs/federation.md, as a file.
  ##
  ## `--write-config` emits this rather than an empty table: a route
  ## table with no routes is syntactically complete and tells a reader
  ## nothing about how one is shaped.
  result = defaultRouterConfig()
  result.subject = "gateway"
  result.identity = "/var/lib/geist/gateway.id"
  result.trust = @["/var/lib/geist/peers/client.pin"]
  result.routing = defaultRouteTable("gateway")
  result.routing.route = @[
    Route(app: "eris", instance: "*", hops: @[
      Hop(name: "d1", endpoint: "dac://10.0.0.1:47655",
        pin: "/var/lib/geist/peers/d1.pin", priority: 0'u8),
      Hop(name: "d2", endpoint: "dac://10.0.0.2:47655",
        pin: "/var/lib/geist/peers/d2.pin", priority: 1'u8)]),
    Route(app: "fjord", instance: "*", hops: @[
      Hop(name: "d1", endpoint: "dac://10.0.0.1:47655",
        pin: "/var/lib/geist/peers/d1.pin", priority: 0'u8),
      Hop(name: "d3", endpoint: "dac://10.0.0.3:47655",
        pin: "/var/lib/geist/peers/d3.pin", priority: 1'u8)]),
    Route(app: "avalon", instance: "*", hops: @[
      Hop(name: "d4", endpoint: "dac://10.0.0.4:47655",
        pin: "/var/lib/geist/peers/d4.pin", priority: 0'u8)])]

const
  usageText* = """
geist-routed <- forward a request to whichever daemon serves it

  geist-routed --config /etc/geist/router.toml
  geist-routed --write-config /etc/geist/router.toml
  geist-routed --config router.toml --pin-out gateway.pin

Options (anything typed here wins over the file):
  --config <file>        the route table and everything else
  --write-config <file>  write a complete, commented example and exit
  --listen <dac://h:p>   where to accept requests
  --node <name>          this router's own name, for loop detection
  --identity <file>      signing key; created on first use
  --identity-password-file <file>
  --trust <peer.pin>     may read through this router (repeatable)
  --allow-write <peer.pin>   may read and write (repeatable)
  --pin-out <file>       write this router's pin and exit
  --timeout-ms <n>       per-hop attempt timeout
  --max-requests <n>     stop after n requests (0 = forever)
  --oneshot              stop after the first request
  --quiet                no per-request status lines
  --help

Status goes to stderr. See docs/federation.md for the address grammar,
the failover rules and the enumerated edge cases.
"""

type
  RouterArgs* {.role: configurator, tag: "config|entrypoint|server|types".} = object
    ## What was typed. Kept apart from `RouterConfig` because the file and
    ## the command line are different surfaces: the file describes a
    ## deployment, these describe this run of it.
    configFile*: string
    writeConfig*: string
    pinOut*: string
    listen*: string
    node*: string
    identity*: string
    identityPasswordFile*: string
    trust*: seq[string]
    allowWrite*: seq[string]
    timeoutMs*: int
    maxRequests*: int
    oneshot*: bool
    quiet*: bool

proc parseArgs*(argv: openArray[string]): RouterArgs {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    at: int = 0
  result.timeoutMs = -1
  result.maxRequests = -1
  while i < argv.len:
    if not argv[i].startsWith("--"):
      raise newException(ValueError, "unexpected argument '" & argv[i] & "'")
    key = argv[i][2 .. ^1]
    value = ""
    at = key.find('=')
    if at > 0:
      value = key[at + 1 .. ^1]
      key = key[0 ..< at]
    elif key notin ["oneshot", "quiet", "help"]:
      if i + 1 >= argv.len:
        raise newException(ValueError, "option --" & key & " needs a value")
      value = argv[i + 1]
      i = i + 1
    case key
    of "config": result.configFile = value
    of "write-config": result.writeConfig = value
    of "pin-out": result.pinOut = value
    of "listen": result.listen = value
    of "node": result.node = value
    of "identity": result.identity = value
    of "identity-password-file": result.identityPasswordFile = value
    of "trust": result.trust.add value
    of "allow-write": result.allowWrite.add value
    of "timeout-ms": result.timeoutMs = parseInt(value)
    of "max-requests": result.maxRequests = parseInt(value)
    of "oneshot": result.oneshot = true
    of "quiet": result.quiet = true
    of "help":
      echo usageText
      quit(0)
    else:
      raise newException(ValueError, "unknown option --" & key)
    i = i + 1

proc routerConfigCandidates*(named: string,
    home: string = ""): seq[string] {.role: parser,
    tag: "config|server".} =
  ## named: `--config`, or nothing.
  ## home: an explicit Geist folder, or nothing for this machine's.
  ##
  ## A router is a SERVER, so its folder defaults to the system's rather
  ## than to the user's -- a router started by a service manager and one
  ## started by hand must read the same file, or the second will appear to
  ## have no routes.
  var
    h: tuple[ok: bool, home: GeistHome, err: string]
  if named.len > 0:
    return @[named]
  result = @[routerConfigName]
  h = openHome(home, nrServer)
  if h.ok:
    result.add h.home.configPath(routerConfigName)
  result.add getConfigDir() / "geist" / routerConfigName
  result.add "/etc/geist/" & routerConfigName

proc applyArgs*(c: RouterConfig, a: RouterArgs): RouterConfig {.
    role: configurator, tag: "config|server".} =
  ## c/a: the file, then whatever was typed over the top of it.
  ##
  ## An option WINS over the file. A config file is a way to stop typing,
  ## not a way to override what was typed -- the same rule `geistd` and
  ## `geist-relayd` follow.
  result = c
  if a.listen.len > 0: result.listen = a.listen
  if a.node.len > 0: result.routing.node = a.node
  if a.identity.len > 0: result.identity = a.identity
  if a.identityPasswordFile.len > 0:
    result.identityPasswordFile = a.identityPasswordFile
  if a.trust.len > 0: result.trust = a.trust
  if a.allowWrite.len > 0: result.allowWrite = a.allowWrite
  if a.timeoutMs >= 0: result.timeoutMs = a.timeoutMs
  if a.maxRequests >= 0: result.maxRequests = a.maxRequests
  if a.quiet: result.quiet = true

proc resolveIdentityPassword(c: RouterConfig): string {.role: sanitizer,
    tag: "config|cryptoBoundary|server".} =
  ## c: the identity password, from its file. There is no option that
  ## takes it inline: a key password on a command line is in the process
  ## table for every user on the machine.
  if c.identityPasswordFile.len == 0:
    return ""
  result = readFile(c.identityPasswordFile).strip()

proc collectTrust(c: RouterConfig): tuple[ok: bool, peers: seq[TrustedPeer],
    err: string] {.role: dataFetcher,
    tag: "peerDirectory|server".} =
  ## c: every `.pin` named by trust or allowWrite, loaded once.
  ##
  ## A pin that will not load is FATAL rather than skipped. Starting with
  ## a shorter trust list than the operator wrote means quietly refusing
  ## peers they believe are allowed.
  var
    i: int = 0
    loaded: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string]
  while i < c.trust.len:
    loaded = loadPin(c.trust[i])
    if not loaded.ok:
      return (false, @[], c.trust[i] & ": " & loaded.err)
    result.peers.add TrustedPeer(pin: loaded.pin, rights: {prRead})
    i = i + 1
  i = 0
  while i < c.allowWrite.len:
    loaded = loadPin(c.allowWrite[i])
    if not loaded.ok:
      return (false, @[], c.allowWrite[i] & ": " & loaded.err)
    result.peers.add TrustedPeer(pin: loaded.pin,
      rights: {prRead, prWrite})
    i = i + 1
  result.ok = true

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
    parsed: tuple[ok: bool, a: GeistAddress, err: string]
    stepped: tuple[ok: bool, err: string]
    forward: Query = q
    answer: AskResult
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

proc loadRouterConfig*(named: string, home: string = ""): tuple[ok: bool,
    c: RouterConfig,
    err: string] {.role: orchestrator, tag: "config|server".} =
  ## named: `--config`, or nothing to search the usual places.
  ##
  ## A config file that will not parse is FATAL. Running a router on
  ## built-in defaults means running one with no routes, which would
  ## refuse every request while looking healthy.
  var
    path: string = ""
    loaded: tuple[value: RouterConfig, node: JsonNode, report: DocReport]
    i: int = 0
    candidates: seq[string] = routerConfigCandidates(named, home)
  while i < candidates.len:
    if fileExists(candidates[i]):
      path = candidates[i]
      break
    i = i + 1
  if path.len == 0:
    if named.len > 0:
      return (false, defaultRouterConfig(), named & " does not exist")
    return (true, defaultRouterConfig(), "")
  loaded = readDoc(path, defaultRouterConfig())
  if not loaded.report.ok:
    return (false, defaultRouterConfig(), loaded.report.describe())
  result = (true, loaded.value, loaded.report.describe())

proc runRouted*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|networkSurface|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    a: RouterArgs
    c: RouterConfig
    S: RouterState
    loaded: tuple[ok: bool, c: RouterConfig, err: string]
    address: tuple[ok: bool, a: GeistDacAddress]
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string]
    trusted: tuple[ok: bool, peers: seq[TrustedPeer], err: string]
    written: tuple[ok: bool, err: string]
    client: tuple[ok: bool, client: GeistClient, err: string]
    server: tuple[ok: bool, server: GeistServer, err: string]
    step: tuple[ok: bool, served: bool, err: string]
    checked: tuple[ok: bool, err: string]
    served: int = 0
  try:
    a = parseArgs(argv)
    installSignalHandlers()
    if a.writeConfig.len > 0:
      written = writeDoc(a.writeConfig, exampleRouterConfig(), routerNotes())
      if not written.ok:
        raise newException(IOError, written.err)
      stderr.writeLine("wrote " & a.writeConfig &
        "  <- every option, with defaults and comments")
      return 0
    installSignalHandlers()
    written = initGeistWireDefaults()
    if not written.ok:
      raise newException(ValueError, written.err)
    loaded = loadRouterConfig(a.configFile)
    if not loaded.ok:
      raise newException(ValueError, loaded.err)
    c = loaded.c.applyArgs(a)
    if loaded.err.len > 0:
      note(c.quiet, loaded.err)
    if c.identity.len == 0:
      raise newException(ValueError,
        "identity is required: a router that mints a fresh key on every " &
        "start can never be pinned by a client")
    mine = loadOrCreateIdentity(c.identity, resolveIdentityPassword(c),
      c.subject, geistSignatureSlots())
    if not mine.ok:
      raise newException(IOError, mine.err)
    if a.pinOut.len > 0:
      written = savePin(a.pinOut, pinOf(mine.key))
      if not written.ok:
        raise newException(IOError, written.err)
      stderr.writeLine("wrote " & a.pinOut & "  <- hand this to clients")
      stderr.writeLine("")
      stderr.writeLine(describePin(pinOf(mine.key)))
      return 0
    checked = c.routing.validate()
    if not checked.ok:
      raise newException(ValueError, "route table: " & checked.err)
    if c.trust.len == 0 and c.allowWrite.len == 0:
      raise newException(ValueError,
        "trust (or allowWrite) is required: without a pin there is no " &
        "peer to trust, and every handshake would be refused")
    trusted = collectTrust(c)
    if not trusted.ok:
      raise newException(IOError, trusted.err)
    address = parseDacAddress(c.listen)
    if not address.ok:
      raise newException(ValueError,
        "listen must be dac://host:port, got '" & c.listen & "'")
    client = initGeistClient(mine.key, c.routing)
    if not client.ok:
      raise newException(ValueError, client.err)
    S.client = client.client
    S.client.timeoutMs = c.timeoutMs
    S.node = c.routing.node
    S.quiet = c.quiet
    server = initGeistServer(address.a, mine.key, trusted.peers,
      defaultTriggerPolicy(), int64(c.idleSeconds),
      transportDefaults().requireCookie)
    if not server.ok:
      raise newException(IOError, server.err)
    note(c.quiet, "geist-routed listening on " & c.listen)
    note(c.quiet, "  node:    " & c.routing.node)
    note(c.quiet, "  subject: " & mine.key.subject)
    for t in trusted.peers:
      note(c.quiet, "  trusts:  " & t.pin.subject &
        (if prWrite in t.rights: "  (may write)" else: "  (may read)"))
    note(c.quiet, S.client.healthReport())
    while not shutdownRequested:
      step = serveOnce(server.server,
        proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
          {.cast(gcsafe).}:
            result = routeQuery(S, q, p),
        c.timeoutMs)
      if step.served:
        served = served + 1
        if not c.quiet:
          stderr.writeLine("[" & now().format("HH:mm:ss") & "] request " &
            $served & ": " & $S.forwarded & " forwarded, " & $S.refused &
            " refused" &
            (if S.lastErr.len > 0: "  last: " & S.lastErr else: ""))
      elif not step.ok:
        note(c.quiet, "request failed: " & step.err)
      if a.oneshot and step.served:
        break
      if c.maxRequests > 0 and served >= c.maxRequests:
        break
    S.client.closeClient()
    server.server.closeServer()
    note(c.quiet, "stopped after " & $served & " request(s), " &
      $S.forwarded & " forwarded, " & $S.refused & " refused")
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geist-routed: " & exc.msg)
    result = 1

when isMainModule:
  quit(runRouted(commandLineParams()))
