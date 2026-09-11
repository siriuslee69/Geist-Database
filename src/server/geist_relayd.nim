## ---------------------------------------------------------------------
## geist-relayd <- the daemon with a pipe where the database would be
## ---------------------------------------------------------------------
##
##   geist-relayd --listen dac://0.0.0.0:47656 --identity keys/pc.id \
##                --allow-write peers/phone.pin --to exec \
##                --exec 'whisper --model base -'
##
##   phone                                   desktop
##   -----                                   -------
##   arecord | geist-relay send --stream voice
##        |                                     |
##        +---- pinned AME/DAC handshake -------+
##        |                                     v
##        |                              geist-relayd --to exec
##        |                                     |  bytes on stdin
##        |                                     v
##        |                                 whisper
##        |                                     |  transcript on stdout
##        +<----------- reply -------------------+
##
## Same trust model as `geistd`, same handshake, same `.pin` files. The
## difference is what happens to what arrives: `geistd` stores it,
## this stores NOTHING. It runs a command, appends a log line, or writes
## to its own stdout so a shell pipeline can take it from there.
##
##   --to exec    the command's stdout becomes the sender's reply
##   --to file    one line per message, plain or JSON
##   --to stdout  the same lines, on this process's stdout
##   --to spool   nothing local; a reader collects them with `geist-relay poll`
##
## EVERY STATUS LINE GOES TO STDERR, including the banner and the errors.
## `--to stdout` is meant to be piped, and a daemon that wrote "served
## request 3" into that pipe would corrupt the thing it exists to deliver.
##
## WHAT THIS DAEMON NEVER COMPILES is the database: it imports
## `geist/wire`, not `geist/network`. No store, no lease, no generation
## swap, no packed rows. `nimble checkRelay` proves it rather than
## asserting it.

import std/[json, os, strutils, times]

import runePragmas
import ../geist/wire

type
  RelayConfig* {.role: configurator, tag: "config|entrypoint|server|stream|types".} = object
    listen*: string
    subject*: string
    identity*: string
    identityPassword*: string
    identityPasswordFile*: string
    trust*: seq[string]
    allowWrite*: seq[string]
    pinOut*: string
    to*: string
    file*: string
    format*: string
    exec*: string
    execTimeoutMs*: int
    streams*: seq[string]
    spool*: int
    maxRequests*: int
    timeoutMs*: int
    idleSeconds*: int
    configFile*: string
    oneshot*: bool
    quiet*: bool
    ## given: the long option names ACTUALLY TYPED, so a config file can
    ## fill in what was left out without overruling what was not. `--spool
    ## 256` is a thing an operator writes on purpose and also happens to
    ## be the default, so the value alone cannot say which it was.
    given*: seq[string]

const
  usageText = """
geist-relayd --identity <file> --trust <pin> [options]

  --listen dac://host:port  endpoint to bind, default dac://127.0.0.1:47656
  --subject <name>          local identity subject, default geist-relay
  --identity <file>         signing identity; created on first start
  --identity-password <t>   password sealing the identity's secret keys
  --identity-password-file <file>  read that password from a file
  --trust <file>            peer pin allowed to COLLECT messages; repeatable
  --allow-write <file>      peer pin allowed to SEND messages; repeatable
  --pin-out <file>          write this daemon's shareable pin and exit

  --to <sink>               spool | stdout | file | exec, default spool
  --file <path>             log to append to, for --to file
  --format <name>           lines | json | raw, default lines
  --exec <command>          command to run, for --to exec. The message
                            goes to its STDIN; its stdout is the reply.
  --exec-timeout-ms <n>     how long that command may run, default 30000.
                            0 starts it and does not wait.
  --stream <name>           accept only these streams; repeatable
  --spool <n>               messages held per stream, default 256, 0 none

  --max-requests <n>        stop after n requests, 0 means forever
  --timeout-ms <n>          socket poll window, default 1000
  --idle-seconds <n>        drop a silent peer session, default 900
  --config <file>           userconfig.toml to read; defaults to the one in
                            the working directory, then ~/.config/geist
  --oneshot                 serve exactly one request and exit
  --quiet                   suppress per-request logging

Every status line is written to stderr, so --to stdout stays a clean pipe.
"""

var
  shutdownRequested: bool = false

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

proc note(c: RelayConfig, line: string) {.role: helper,
    tag: "server|status".} =
  ## c/line: one status line, on stderr because stdout may be the product.
  if not c.quiet:
    stderr.writeLine(line)

proc parseSink*(name: string): RelaySink {.role: parser,
    tag: "config|parsing|stream".} =
  ## name: `--to` as the sink it selects.
  case name.toLowerAscii()
  of "", "spool", "queue", "none": result = rsSpool
  of "stdout", "-": result = rsStdout
  of "file", "log": result = rsFile
  of "exec", "command", "pipe": result = rsExec
  else:
    raise newException(ValueError,
      "--to must be spool, stdout, file or exec, got '" & name & "'")

proc parseFormat*(name: string): RelayFormat {.role: parser,
    tag: "config|formatting|parsing|stream".} =
  ## name: `--format` as the layout it selects.
  case name.toLowerAscii()
  of "", "lines", "line", "plain", "text": result = rfLines
  of "json", "jsonl", "ndjson": result = rfJson
  of "raw", "bytes": result = rfRaw
  else:
    raise newException(ValueError,
      "--format must be lines, json or raw, got '" & name & "'")

proc parseArgs*(argv: openArray[string]): RelayConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    at: int = 0
  result.listen = "dac://127.0.0.1:47656"
  result.subject = "geist-relay"
  result.to = "spool"
  result.format = "lines"
  result.execTimeoutMs = defaultExecTimeoutMs
  result.spool = defaultSpoolDepth
  result.timeoutMs = 1000
  result.idleSeconds = 900
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
    of "listen": result.listen = value
    of "subject": result.subject = value
    of "identity": result.identity = value
    of "identity-password": result.identityPassword = value
    of "identity-password-file": result.identityPasswordFile = value
    of "trust": result.trust.add value
    of "allow-write": result.allowWrite.add value
    of "pin-out": result.pinOut = value
    of "to": result.to = value
    of "file": result.file = value
    of "format": result.format = value
    of "exec": result.exec = value
    of "exec-timeout-ms": result.execTimeoutMs = parseInt(value)
    of "stream": result.streams.add value
    of "spool": result.spool = parseInt(value)
    of "max-requests": result.maxRequests = parseInt(value)
    of "timeout-ms": result.timeoutMs = parseInt(value)
    of "idle-seconds": result.idleSeconds = parseInt(value)
    of "config": result.configFile = value
    of "oneshot": result.oneshot = true
    of "quiet": result.quiet = true
    of "help":
      echo usageText
      quit(0)
    else:
      raise newException(ValueError, "unknown option --" & key)
    result.given.add key
    i = i + 1

proc relayConfigCandidates*(named: string): seq[string] {.role: parser,
    tag: "config|parsing|server".} =
  ## named: `--config`, or nothing.
  ##
  ## The same two places `geistd` looks, because an operator running both
  ## on one machine should not have to remember two rules.
  if named.len > 0:
    return @[named]
  result = @["userconfig.toml",
    getConfigDir() / "geist" / "userconfig.toml"]

proc withUserConfig*(c: RelayConfig): RelayConfig {.role: configurator,
    tag: "config|parsing|server".} =
  ## c: options straight off the command line.
  ##
  ## Fills in only what was NOT typed, from the `[relay]` section. A relay
  ## is the thing most likely to be started by a service manager with no
  ## arguments at all, so the file can carry the whole deployment -- but
  ## an argument still wins, or debugging one by hand would be impossible.
  var
    where: string = ""
    doc: tuple[ok: bool, node: JsonNode, err: string]
    relay: JsonNode
    complaint: string = ""
  result = c
  for candidate in relayConfigCandidates(c.configFile):
    if fileExists(candidate):
      where = candidate
      break
  if where.len == 0:
    if c.configFile.len > 0:
      raise newException(IOError, "no config file at " & c.configFile)
    return
  doc = tomlOf(where)
  if not doc.ok:
    raise newException(ValueError, doc.err)
  relay = doc.node.section("relay")
  complaint = relay.checkKeys(["listen", "subject", "identity",
    "identityPasswordFile", "trust", "allowWrite", "to", "file", "format",
    "exec", "execTimeoutMs", "stream", "spool", "timeoutMs", "idleSeconds"],
    where & " [relay]")
  if complaint.len > 0:
    raise newException(ValueError, complaint)
  if "listen" notin result.given:
    result.listen = relay.setting("listen", result.listen)
  if "subject" notin result.given:
    result.subject = relay.setting("subject", result.subject)
  if "identity" notin result.given:
    result.identity = relay.setting("identity", result.identity)
  if "identity-password-file" notin result.given:
    result.identityPasswordFile = relay.setting("identityPasswordFile",
      result.identityPasswordFile)
  if "trust" notin result.given:
    result.trust = relay.setting("trust", result.trust)
  if "allow-write" notin result.given:
    result.allowWrite = relay.setting("allowWrite", result.allowWrite)
  if "to" notin result.given:
    result.to = relay.setting("to", result.to)
  if "file" notin result.given:
    result.file = relay.setting("file", result.file)
  if "format" notin result.given:
    result.format = relay.setting("format", result.format)
  if "exec" notin result.given:
    result.exec = relay.setting("exec", result.exec)
  if "exec-timeout-ms" notin result.given:
    result.execTimeoutMs = relay.setting("execTimeoutMs", result.execTimeoutMs)
  if "stream" notin result.given:
    result.streams = relay.setting("stream", result.streams)
  if "spool" notin result.given:
    result.spool = relay.setting("spool", result.spool)
  if "timeout-ms" notin result.given:
    result.timeoutMs = relay.setting("timeoutMs", result.timeoutMs)
  if "idle-seconds" notin result.given:
    result.idleSeconds = relay.setting("idleSeconds", result.idleSeconds)

proc resolveConfig*(argv: openArray[string]): RelayConfig {.role: parser,
    tag: "entrypoint|parsing|server".} =
  ## argv: command line, merged with the config file and then checked.
  ## The check happens AFTER the merge, or a setting supplied by the file
  ## would be reported missing.
  result = withUserConfig(parseArgs(argv))
  if parseSink(result.to) == rsExec and result.exec.len == 0:
    raise newException(ValueError, "--to exec needs --exec <command>")
  if parseSink(result.to) == rsFile and result.file.len == 0:
    raise newException(ValueError, "--to file needs --file <path>")

proc resolveIdentityPassword(c: RelayConfig): string {.role: sanitizer,
    tag: "cryptoBoundary|server".} =
  ## c: relay config. A password file wins over the inline form, which is
  ## visible in the process list.
  if c.identityPasswordFile.len > 0:
    if not fileExists(c.identityPasswordFile):
      raise newException(IOError,
        "no identity password file at " & c.identityPasswordFile)
    return readFile(c.identityPasswordFile).strip()
  result = c.identityPassword

proc collectTrust(c: RelayConfig): tuple[ok: bool, peers: seq[TrustedPeer],
    err: string] {.role: configurator,
    tag: "cryptoBoundary|server".} =
  ## c: relay config whose pin files become the trust list.
  ##
  ## The FLAG grants the right, not the peer: `--trust` may collect from
  ## the spool, `--allow-write` may also send. A pin listed under both
  ## gets the union, because the operator clearly meant the wider one.
  var
    i: int = 0
    loaded: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string]
    at: int = -1
    j: int = 0
  while i < c.trust.len + c.allowWrite.len:
    loaded = loadPin(if i < c.trust.len: c.trust[i]
                     else: c.allowWrite[i - c.trust.len])
    if not loaded.ok:
      return (false, @[], loaded.err)
    at = -1
    j = 0
    while j < result.peers.len:
      if result.peers[j].pin.subject == loaded.pin.subject:
        at = j
      j = j + 1
    if at >= 0:
      if i >= c.trust.len:
        result.peers[at].rights.incl prWrite
    else:
      result.peers.add TrustedPeer(pin: loaded.pin,
        rights: if i < c.trust.len: {prRead} else: {prRead, prWrite})
    i = i + 1
  result.ok = true

proc deskFor*(c: RelayConfig): RelayDesk {.role: configurator,
    tag: "config|server|stream".} =
  ## c: relay options resolved to the pipe they describe.
  result = initRelayDesk(parseSink(c.to), parseFormat(c.format))
  result.file = c.file
  result.exec = c.exec
  result.execTimeoutMs = c.execTimeoutMs
  result.spool = c.spool
  result.streams = c.streams

proc runRelayd*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "entrypoint|lifecycle|orchestrator|server|stream".} =
  ## argv: command line without the executable name.
  var
    c: RelayConfig
    D: RelayDesk
    address: tuple[ok: bool, a: GeistDacAddress]
    mine: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string]
    trusted: tuple[ok: bool, peers: seq[TrustedPeer], err: string]
    written: tuple[ok: bool, err: string]
    server: tuple[ok: bool, server: GeistServer, err: string]
    step: tuple[ok: bool, served: bool, err: string]
    served: int = 0
  try:
    c = resolveConfig(argv)
    installSignalHandlers()
    # config.toml carries the tier policy. A relay has no storage settings
    # to adopt, so it validates only the section it acts on.
    written = initGeistWireDefaults()
    if not written.ok:
      raise newException(ValueError, written.err)
    address = parseDacAddress(c.listen)
    if not address.ok:
      raise newException(ValueError,
        "--listen must be dac://host:port, got '" & c.listen & "'")
    if c.identity.len == 0:
      raise newException(ValueError,
        "--identity is required: a relay that mints a fresh key on every " &
        "start can never be pinned by a client")
    mine = loadOrCreateIdentity(c.identity, resolveIdentityPassword(c),
      c.subject, geistSignatureSlots())
    if not mine.ok:
      raise newException(IOError, mine.err)
    if c.pinOut.len > 0:
      written = savePin(c.pinOut, pinOf(mine.key))
      if not written.ok:
        raise newException(IOError, written.err)
      stderr.writeLine("wrote " & c.pinOut & "  <- hand this to clients")
      stderr.writeLine("")
      stderr.writeLine(describePin(pinOf(mine.key)))
      return 0
    if c.trust.len == 0 and c.allowWrite.len == 0:
      raise newException(ValueError,
        "--trust <peer.pin> (or --allow-write) is required: without a pin " &
        "there is no peer to trust, and every handshake would be refused")
    trusted = collectTrust(c)
    if not trusted.ok:
      raise newException(IOError, trusted.err)
    D = deskFor(c)
    server = initGeistServer(address.a, mine.key, trusted.peers,
      defaultTierPolicy(), int64(c.idleSeconds),
      transportDefaults().requireCookie)
    if not server.ok:
      raise newException(IOError, server.err)
    c.note("geist-relayd listening on " & c.listen)
    c.note("  subject: " & mine.key.subject)
    c.note("  to:      " & c.to & (case parseSink(c.to)
      of rsExec: "  -> " & c.exec
      of rsFile: "  -> " & c.file & " (" & c.format & ")"
      of rsStdout: "  (" & c.format & ")"
      of rsSpool: ""))
    c.note("  spool:   " & $c.spool & " per stream" &
      (if c.streams.len > 0: ", streams: " & c.streams.join(", ")
       else: ", any stream"))
    for t in trusted.peers:
      c.note("  trusts:  " & t.pin.subject &
        (if prWrite in t.rights: "  (may send)" else: "  (may collect)"))
    while not shutdownRequested:
      step = serveOnce(server.server,
        proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
          {.cast(gcsafe).}:
            result = answerRelay(D, q, p),
        c.timeoutMs)
      if step.served:
        served = served + 1
        if not c.quiet:
          stderr.writeLine("[" & now().format("HH:mm:ss") & "] request " &
            $served & ": " & $D.accepted & " accepted, " & $D.delivered &
            " delivered, " & $D.refused & " refused" &
            (if D.failed > 0: ", " & $D.failed & " failed (" & D.lastErr & ")"
             else: ""))
      elif not step.ok:
        # An idle window is ok = true with served = false, so only a real
        # failure reaches this line.
        c.note("request failed: " & step.err)
      if c.oneshot and step.served:
        break
      if c.maxRequests > 0 and served >= c.maxRequests:
        break
    server.server.closeServer()
    D.closeRelay()
    c.note("stopped after " & $served & " request(s), " & $D.accepted &
      " message(s) accepted, " & $D.delivered & " delivered")
    result = 0
  except CatchableError as exc:
    stderr.writeLine("geist-relayd: " & exc.msg)
    result = 1

when isMainModule:
  quit(runRelayd(commandLineParams()))
