## ---------------------------------------------------------------------
## geist-routed config <- router.toml, command-line options, and the two
## merged
## ---------------------------------------------------------------------
##
##   router.toml --loadRouterConfig--> RouterConfig
##   argv --parseArgs--> RouterArgs --applyArgs--> RouterConfig (args win)
##
## Everything here decides WHAT the router will do; geist_routed.nim runs
## it.

import std/[json, os, strutils]

import runePragmas
import ../geist/args
import ../geist/wire

const
  defaultRouterListen* = "dac://127.0.0.1:47657"
    ## One port above `geist-relayd`, so all three daemons can run on one
    ## machine without an operator choosing numbers.
  routerConfigName* = "router.toml"


type
  RouterConfig* {.
      role: configurator, tag: "config|entrypoint|networkSurface|server|types".} = object
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
  RouterArgs* {.
      role: configurator, tag: "config|entrypoint|server|types".} = object
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
    help*: bool
      ## --help was asked for: print the usage and stop.

proc parseArgs*(argv: openArray[string]): RouterArgs {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    step: OptionStep = ("", "", false, 0)
  result.timeoutMs = -1
  result.maxRequests = -1
  while i < argv.len:
    step = nextOption(argv, i, ["oneshot", "quiet", "help"])
    if step.bare:
      raise newException(ValueError, "unexpected argument '" & step.value &
        "'")
    i = step.last
    key = step.key
    value = step.value
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
    of "help": result.help = true
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
    h: tuple[ok: bool, home: GeistHome, err: string] =
      (false, default(GeistHome), "")
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

proc resolveIdentityPassword*(c: RouterConfig): string {.role: sanitizer,
    tag: "config|cryptoBoundary|server".} =
  ## c: the identity password, from its file. There is no option that
  ## takes it inline: a key password on a command line is in the process
  ## table for every user on the machine.
  if c.identityPasswordFile.len == 0:
    return ""
  result = readFile(c.identityPasswordFile).strip()

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
    loaded: tuple[value: RouterConfig, node: JsonNode, report: DocReport] =
      (default(RouterConfig), default(JsonNode), default(DocReport))
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

