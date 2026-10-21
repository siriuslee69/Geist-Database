## ---------------------------------------------------------------------
## geist-hopd config <- hop.toml, command-line options, and the two merged
## ---------------------------------------------------------------------
##
##   hop.toml --loadHopConfig--> HopConfig
##   argv --parseHopArgs--> HopArgs --applyHopArgs--> HopConfig (args win)
##
## Everything here decides WHO this router links with and WHAT each may
## reach; geist_hopd.nim runs it.

import std/[json, os, strutils]

import runePragmas
import ../geist/args
import ../geist/wire

const
  defaultHopListen* = "dac://127.0.0.1:47658"
    ## docs/ports.md: 47658 is geist-hopd.
  hopConfigName* = "hop.toml"

type
  HopPeerEntry* {.role: configurator, tag: "config|networkSurface|types".} = object
    ## One neighbour: its pin file, its route id, and -- for another
    ## router this one dials -- where it listens.
    pin*: string
    id*: int64
    router*: bool
    endpoint*: string

  HopTargetEntry* {.role: configurator, tag: "config|networkSurface|types".} = object
    ## One line of the directory: what a client may address, who may see
    ## it (pin SUBJECTS; "*" = everyone), and the router behind which it
    ## sits (0 = it links to this router itself).
    id*: int64
    name*: string
    visibleTo*: seq[string]
    via*: int64

  HopConfig* {.role: configurator,
      tag: "config|entrypoint|networkSurface|server|types".} = object
    ## The whole deployment; this object IS the file's schema.
    listen*: string
    subject*: string
    id*: int64
    identity*: string
    identityPasswordFile*: string
    timeoutMs*: int
    idleSeconds*: int
    quiet*: bool
    peer*: seq[HopPeerEntry]
    target*: seq[HopTargetEntry]

  HopArgs* {.role: configurator, tag: "config|entrypoint|server|types".} = object
    ## What was typed, apart from the file (same split as geist-routed).
    configFile*: string
    writeConfig*: string
    pinOut*: string
    listen*: string
    identity*: string
    identityPasswordFile*: string
    timeoutMs*: int
    quiet*: bool
    help*: bool

const
  usageText* = """
geist-hopd <- hand Geist links on between machines, reading none of them

  geist-hopd --config /etc/geist/hop.toml
  geist-hopd --write-config hop.toml
  geist-hopd --config hop.toml --pin-out router.pin

Options (anything typed here wins over the file):
  --config <file>        neighbours, route ids and the directory
  --write-config <file>  write a complete, commented example and exit
  --listen <dac://h:p>   where neighbours dial in (default port 47658)
  --identity <file>      signing key; created on first use
  --identity-password-file <file>
  --pin-out <file>       write this router's pin and exit
  --timeout-ms <n>       per dial of another router
  --quiet                no status lines
  --help

See docs/hop.md for what the router can and cannot see.
"""

proc defaultHopConfig*(): HopConfig {.role: configurator,
    tag: "config|server".} =
  ## Every option at the value the daemon uses when the file says nothing.
  ## No neighbours and no targets: a router that guessed who may link to it
  ## would let strangers in.
  result.listen = defaultHopListen
  result.subject = "geist-hop"
  result.timeoutMs = 2000
  result.idleSeconds = 900

proc exampleHopConfig*(): HopConfig {.role: configurator,
    tag: "config|docs|server".} =
  ## A VPS router with a phone, a home NAS that dials in, and a second
  ## router behind which a camera sits.
  result = defaultHopConfig()
  result.listen = "dac://0.0.0.0:47658"
  result.subject = "vps-hop"
  result.id = 16
  result.identity = "/var/lib/geist/hop.id"
  result.peer = @[
    HopPeerEntry(pin: "/var/lib/geist/peers/phone.pin", id: 48),
    HopPeerEntry(pin: "/var/lib/geist/peers/nas.pin", id: 32),
    HopPeerEntry(pin: "/var/lib/geist/peers/office-hop.pin", id: 17,
      router: true, endpoint: "dac://office.example:47658")]
  result.target = @[
    HopTargetEntry(id: 32, name: "nas", visibleTo: @["phone"]),
    HopTargetEntry(id: 33, name: "cam", visibleTo: @["phone"], via: 17)]

proc hopNotes*(): DocStyle {.role: configurator, tag: "config|docs|server".} =
  ## Comments for the options whose names do not explain themselves.
  result = defaultDocStyle()
  result.header = @[
    "geist-hopd: who links to this router, and whom each may reach.",
    "",
    "Written by `geist-hopd --write-config`. A neighbour is a pin plus the",
    "route id this router gives it. A target is a line of the directory a",
    "client reads with `routeDirectory`; `visibleTo` names pin SUBJECTS.",
    "The router never reads what passes through: see docs/hop.md."]
  result.noteOn("id", "this router's own route id (any nonzero number)")
  result.noteOn("idleSeconds",
    "a link nobody has heard from for this long is dropped")
  result.noteOn("peer",
    "neighbours; router = true and an endpoint for a router this one dials")
  result.noteOn("target",
    "the directory; via = the id of the router a target sits behind")

proc parseHopArgs*(argv: openArray[string]): HopArgs {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    step: OptionStep = ("", "", false, 0)
  result.timeoutMs = -1
  while i < argv.len:
    step = nextOption(argv, i, ["quiet", "help"])
    if step.bare:
      raise newException(ValueError, "unexpected argument '" & step.value &
        "'")
    i = step.last
    case step.key
    of "config": result.configFile = step.value
    of "write-config": result.writeConfig = step.value
    of "pin-out": result.pinOut = step.value
    of "listen": result.listen = step.value
    of "identity": result.identity = step.value
    of "identity-password-file": result.identityPasswordFile = step.value
    of "timeout-ms": result.timeoutMs = parseInt(step.value)
    of "quiet": result.quiet = true
    of "help": result.help = true
    else:
      raise newException(ValueError, "unknown option --" & step.key)
    i = i + 1

proc applyHopArgs*(c: HopConfig, a: HopArgs): HopConfig {.
    role: configurator, tag: "config|server".} =
  ## c/a: the file, then whatever was typed over the top of it.
  result = c
  if a.listen.len > 0: result.listen = a.listen
  if a.identity.len > 0: result.identity = a.identity
  if a.identityPasswordFile.len > 0:
    result.identityPasswordFile = a.identityPasswordFile
  if a.timeoutMs >= 0: result.timeoutMs = a.timeoutMs
  if a.quiet: result.quiet = true

proc hopConfigCandidates*(named: string): seq[string] {.role: parser,
    tag: "config|server".} =
  ## named: `--config`, or nothing for the usual places.
  if named.len > 0:
    return @[named]
  result = @[hopConfigName, getConfigDir() / "geist" / hopConfigName,
    "/etc/geist/" & hopConfigName]

proc checkHopConfig*(c: HopConfig): string {.role: sanitizer,
    tag: "config|server|validation".} =
  ## c: everything wrong with it that the daemon cannot run with, or "".
  var
    seen: seq[int64] = @[c.id]
  if c.id <= 0:
    return "id (this router's route id) must be a positive number"
  if c.peer.len == 0:
    return "no peer: a router nobody may link to refuses every handshake"
  for p in c.peer:
    if p.id <= 0 or p.id in seen:
      return "peer " & p.pin & ": id must be positive and unique"
    seen.add p.id
    if p.endpoint.len > 0 and not p.router:
      return "peer " & p.pin & ": only a router has an endpoint to dial"

proc resolveHopPassword*(c: HopConfig): string {.role: sanitizer,
    tag: "config|cryptoBoundary|server".} =
  ## c: the identity password, from its file -- never typed inline.
  if c.identityPasswordFile.len == 0:
    return ""
  result = readFile(c.identityPasswordFile).strip()

proc loadHopConfig*(named: string): tuple[ok: bool, c: HopConfig,
    err: string] {.role: orchestrator, tag: "config|server".} =
  ## named: `--config`, or nothing to search the usual places. A file that
  ## will not parse is fatal: a router on defaults links with nobody.
  var
    loaded: tuple[value: HopConfig, node: JsonNode, report: DocReport] =
      (default(HopConfig), default(JsonNode), default(DocReport))
  for path in hopConfigCandidates(named):
    if not fileExists(path):
      continue
    loaded = readDoc(path, defaultHopConfig())
    if not loaded.report.ok:
      return (false, defaultHopConfig(), loaded.report.describe())
    return (true, loaded.value, loaded.report.describe())
  if named.len > 0:
    return (false, defaultHopConfig(), named & " does not exist")
  result = (true, defaultHopConfig(), "")
