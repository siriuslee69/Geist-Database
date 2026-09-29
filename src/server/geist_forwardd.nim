## ---------------------------------------------------------------------
## geist-forwardd <- the VPS end of Client -> VPS -> Home, no handshake here
## ---------------------------------------------------------------------
##
##   geist-forwardd --listen dac://0.0.0.0:47655 --to dac://10.8.0.2:47655
##
##   laptop                     VPS                        home server
##   ------                     ---                        -----------
##   geist --remote dac://vps:47655 ...
##        |                      |                              |
##        +--- datagram -------->+--- same datagram ----------->+
##        |                      |   (a socket of its own per   |
##        +<--- answer ----------+<--  client, so home can tell) +
##
## The laptop dials the VPS as if it were the home server and pins the
## HOME server's key. The handshake is made between those two; this
## program never sees a key and opens no frame. That is the whole point:
## a program that shook hands in the middle would make every new link cost
## two handshakes, and it would be able to read what passes.
##
## The home server needs nothing special. It runs `geistd` as always; it
## just has to be reachable from the VPS (a VPN address, a forwarded port
## or a public IPv6 address -- see docs/forwarding.md).
##
## Every status line goes to stderr.

import std/[os, strutils, times]

import runePragmas
import ../geist/args
import ../geist/forward
import ../geist/forward_settings
import ../geist/stop

export stop

type
  ForwardConfig* {.role: configurator,
      tag: "config|entrypoint|forward|server|types".} = object
    ## listen/to: the two ends. options: the bounds, from the settings file
    ## unless a flag replaced them. given: the flags actually typed, so the
    ## file only fills in what was left out.
    listen*: string
    to*: string
    options*: ForwardOptions
    configFile*: string
    reportSeconds*: int
    maxSeconds*: int
    quiet*: bool
    help*: bool
    given*: seq[string]

const
  usageText = """
geist-forwardd --listen <dac://host:port> --to <dac://host:port> [options]

  --listen dac://host:port  where clients dial (this machine), default
                            dac://0.0.0.0:47655
  --to dac://host:port      where the home server is, from HERE. Required.
  --follow-home             chase a home address that changed. Off by
                            default: it also lets anyone who can reach the
                            control socket move this forwarder.
  --max-clients <n>         clients held at once, default 512
  --client-idle <s>         seconds before a quiet client loses its place,
                            default 120
  --ping <s>                seconds between "still there?" pings, default 20
  --silent <s>              seconds of silence before home counts as away,
                            default 60 (must exceed --ping)
  --buffer <n>              datagrams held for an away home, default 64
  --buffer-bytes <n>        the same limit in bytes, default 262144

  --config <file>           configs/default.toml to read [runtime.forward] from
  --report <s>              print counts every s seconds, default 60, 0 none
  --max-seconds <s>         stop after s seconds, 0 means forever
  --quiet                   no status lines

The forwarder holds no key and opens no frame; clients pin the HOME
server's key, not this machine's.
"""

proc parseArgs*(argv: openArray[string]): ForwardConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    step: OptionStep = ("", "", false, 0)
  result.listen = "dac://0.0.0.0:47655"
  result.reportSeconds = 60
  result.options = forwardDefaults()
  while i < argv.len:
    step = nextOption(argv, i, ["follow-home", "quiet", "help"])
    if step.bare:
      raise newException(ValueError, "unexpected argument '" & step.value &
        "'")
    i = step.last
    case step.key
    of "listen": result.listen = step.value
    of "to": result.to = step.value
    of "follow-home": result.options.followHome = true
    of "max-clients": result.options.maxClients = parseInt(step.value)
    of "client-idle": result.options.clientIdleSeconds = parseInt(step.value)
    of "ping": result.options.pingSeconds = parseInt(step.value)
    of "silent": result.options.silentSeconds = parseInt(step.value)
    of "buffer": result.options.bufferDatagrams = parseInt(step.value)
    of "buffer-bytes": result.options.bufferBytes = parseInt(step.value)
    of "config": result.configFile = step.value
    of "report": result.reportSeconds = parseInt(step.value)
    of "max-seconds": result.maxSeconds = parseInt(step.value)
    of "quiet": result.quiet = true
    of "help": result.help = true
    else:
      raise newException(ValueError, "unknown option --" & step.key)
    result.given.add step.key
    i = i + 1

proc fileFills(c: ForwardConfig, key: string): bool {.role: parser,
    tag: "config|parsing", inline.} =
  ## c/key: whether the settings file may set this option (it was not typed).
  result = key notin c.given

proc withFile*(c: ForwardConfig): ForwardConfig {.role: configurator,
    tag: "config|entrypoint|parsing|read".} =
  ## c: options as typed. The settings file fills in the ones left out.
  ## A named file that cannot be read is an error; the default one being
  ## absent is not.
  var
    got: tuple[ok: bool, options: ForwardOptions, err: string] = (false,
      forwardDefaults(), "")
    path: string = "configs/default.toml"
  result = c
  if c.configFile.len > 0:
    path = c.configFile
  if c.configFile.len == 0 and not fileExists(path):
    return
  got = loadForwardOptions(path)
  if not got.ok:
    raise newException(ValueError, got.err)
  if c.fileFills("max-clients"): result.options.maxClients = got.options.maxClients
  if c.fileFills("client-idle"):
    result.options.clientIdleSeconds = got.options.clientIdleSeconds
  if c.fileFills("ping"): result.options.pingSeconds = got.options.pingSeconds
  if c.fileFills("silent"):
    result.options.silentSeconds = got.options.silentSeconds
  if c.fileFills("buffer"):
    result.options.bufferDatagrams = got.options.bufferDatagrams
  if c.fileFills("buffer-bytes"):
    result.options.bufferBytes = got.options.bufferBytes
  if c.fileFills("follow-home"):
    result.options.followHome = got.options.followHome

proc note(c: ForwardConfig, line: string) {.role: helper,
    tag: "server|status".} =
  ## c/line: one status line, on stderr.
  if not c.quiet:
    stderr.writeLine(line)

proc reportLine(F: Forwarder): string {.role: parser,
    tag: "server|status|read".} =
  ## F: the counts, in one line an operator can read at a glance.
  var
    n: ForwardCounts = F.forwardCounts()
  result = "[" & now().format("HH:mm:ss") & "] " & $n.clients & " clients, " &
    $n.forwarded & " forwarded, " & $n.dropped & " dropped, " & $n.foreign &
    " from strangers, " & $n.buffered & " held, " & $n.sockets & " sockets"

proc runForwardd*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|orchestrator|server".} =
  ## argv: command line without the executable name.
  var
    c: ForwardConfig = default(ForwardConfig)
    listen: tuple[ok: bool, a: DacAddress] = (false, default(DacAddress))
    home: tuple[ok: bool, a: DacAddress] = (false, default(DacAddress))
    made: tuple[ok: bool, f: Forwarder, err: string] = (false,
      default(Forwarder), "")
    started: float = epochTime()
    lastReport: float = epochTime()
    step: tuple[ok: bool, moved: int, err: string] = (false, 0, "")
  try:
    c = parseArgs(argv)
    if c.help:
      echo usageText
      return 0
    c = c.withFile()
    listen = parseDacAddress(c.listen)
    home = parseDacAddress(c.to)
    if not listen.ok:
      raise newException(ValueError, "--listen must be dac://host:port, got '" &
        c.listen & "'")
    if not home.ok:
      raise newException(ValueError, "--to must be dac://host:port, got '" &
        c.to & "'")
    clearShutdown()
    installSignalHandlers()
    made = initForwarder(listen.a, home.a, c.options)
    if not made.ok:
      raise newException(IOError, made.err)
    c.note("geist-forwardd listening on " & c.listen & ", forwarding to " & c.to)
    while not shutdownWanted():
      step = made.f.forwardStep(200)
      if not step.ok:
        c.note("forward: " & step.err)
      if c.reportSeconds > 0 and epochTime() - lastReport >= float(c.reportSeconds):
        c.note(made.f.reportLine())
        lastReport = epochTime()
      if c.maxSeconds > 0 and epochTime() - started >= float(c.maxSeconds):
        break
    made.f.closeForwarder()
    c.note("geist-forwardd stopped: " & made.f.reportLine())
  except CatchableError as exc:
    stderr.writeLine("geist-forwardd: " & exc.msg)
    return 1

when isMainModule:
  quit(runForwardd(commandLineParams()))
