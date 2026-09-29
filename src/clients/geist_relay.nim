## ---------------------------------------------------------------------
## geist-relay <- the other end of the pipe
## ---------------------------------------------------------------------
##
##   arecord -f S16_LE -r 16000 | \
##     geist-relay send --remote dac://desktop:47656 --stream voice
##
## and the transcript comes back on stdout, because the relay ran the
## transcriber and answered with what it said. One process on the phone,
## one on the desktop, one pinned handshake between them.
##
##   send   bytes in, whatever the far side answered out
##   poll   collect what a relay is holding for you
##   pin    write this client's shareable pin
##
## STDIN IS THE INPUT and stdout IS THE OUTPUT, always. That is what makes
## this composable with everything else on the machine:
##
##   journalctl -f | geist-relay send --stream logs --split-lines
##   geist-relay poll --stream notes --follow | while read -r l; do ...; done
##
## Nothing here compiles a database: it imports `geist/wire`. A client
## that only moves messages should not carry a packed-row store, and this
## one does not.

import std/[os, json, strutils]

import runePragmas
import ../geist/args
import ../geist/wire

type
  Verb {.role: configurator, tag: "cli|entrypoint|types".} = enum
    vSend, vPoll, vPin

  Options* {.role: configurator, tag: "cli|config|entrypoint|stream|types".} = object
    verb*: Verb
    help*: bool
      ## no verb, or --help: print the usage and stop.
    remote*: string
    identity*: string
    identityPassword*: string
    identityPasswordFile*: string
    subject*: string
    peerPin*: string
    pinOut*: string
    stream*: string
    file*: string
    consumer*: string
    format*: string
    limit*: int
    timeoutMs*: int
    intervalMs*: int
    splitLines*: bool
    follow*: bool
    verbose*: bool
    configFile*: string
    given*: seq[string]

const
  usageText = """
geist-relay <verb> [options]

  send    read stdin (or --file) and hand it to a relay
  poll    collect messages a relay is holding
  pin     write this client's shareable pin and exit

  --remote dac://host:port  the relay, default dac://127.0.0.1:47656
  --identity <file>         this client's signing identity, created if absent
  --identity-password <t>   password sealing its secret keys
  --identity-password-file <file>  read that password from a file
  --subject <name>          identity subject, default geist-relay-client
  --peer-pin <file>         the relay's pin; pinned trust needs it
  --pin-out <file>          where `pin` writes this client's pin

  --stream <name>           which stream, default 'default'
  --file <path>             send this file instead of stdin
  --split-lines             send one message per input line
  --as <name>               reader name for poll, default the subject
  --limit <n>               messages per poll, default 64
  --format <name>           lines | json | raw, default raw
  --follow                  keep polling
  --interval-ms <n>         how often, with --follow, default 1000
  --timeout-ms <n>          how long to wait for a reply, default 30000
  --config <file>           userconfig.toml to read
  --verbose                 say what happened, on stderr
"""

proc parseOptions*(argv: openArray[string]): Options {.role: parser,
    tag: "cli|entrypoint|parsing".} =
  ## argv: command line without the executable name.
  var
    i: int = 0
    key: string = ""
    value: string = ""
    step: OptionStep = ("", "", false, 0)
  result.remote = "dac://127.0.0.1:47656"
  result.subject = "geist-relay-client"
  result.stream = "default"
  result.format = "raw"
  result.limit = 64
  # Generous by default because the far side may be running a transcriber,
  # and a client that gave up after four seconds would look like a broken
  # relay rather than an impatient client.
  result.timeoutMs = 30_000
  result.intervalMs = 1000
  if argv.len == 0:
    result.help = true
    return
  case argv[0]
  of "send": result.verb = vSend
  of "poll", "recv", "collect": result.verb = vPoll
  of "pin", "pin-out": result.verb = vPin
  of "--help", "-h", "help":
    result.help = true
    return
  else:
    raise newException(ValueError, "unknown verb '" & argv[0] &
      "'; expected send, poll or pin")
  i = 1
  while i < argv.len:
    step = nextOption(argv, i, ["split-lines", "follow", "verbose", "help"])
    if step.bare:
      raise newException(ValueError, "unexpected argument '" & step.value &
        "'")
    i = step.last
    key = step.key
    value = step.value
    case key
    of "remote": result.remote = value
    of "identity": result.identity = value
    of "identity-password": result.identityPassword = value
    of "identity-password-file": result.identityPasswordFile = value
    of "subject": result.subject = value
    of "peer-pin": result.peerPin = value
    of "pin-out": result.pinOut = value
    of "stream": result.stream = value
    of "file": result.file = value
    of "as": result.consumer = value
    of "format": result.format = value
    of "limit": result.limit = parseInt(value)
    of "timeout-ms": result.timeoutMs = parseInt(value)
    of "interval-ms": result.intervalMs = parseInt(value)
    of "split-lines": result.splitLines = true
    of "follow": result.follow = true
    of "verbose": result.verbose = true
    of "config": result.configFile = value
    of "help": result.help = true
    else:
      raise newException(ValueError, "unknown option --" & key)
    result.given.add key
    i = i + 1
  if result.consumer.len == 0:
    result.consumer = result.subject

proc withUserConfig*(o: Options): Options {.role: configurator,
    tag: "cli|config|parsing".} =
  ## o: options straight off the command line, completed from
  ## `[relayClient]`.
  ##
  ## Its own section, next to the daemon's `[relay]`, for the same reason
  ## `[client]` sits next to `[daemon]`: one machine often runs both ends,
  ## and a single section would make "which side is this?" a guess.
  var
    where: string = ""
    doc: tuple[ok: bool, node: JsonNode, err: string] =
      (false, default(JsonNode), "")
    client: JsonNode = default(JsonNode)
    complaint: string = ""
  result = o
  for candidate in (if o.configFile.len > 0: @[o.configFile]
                    else: @["userconfig.toml",
                            getConfigDir() / "geist" / "userconfig.toml"]):
    if fileExists(candidate):
      where = candidate
      break
  if where.len == 0:
    if o.configFile.len > 0:
      raise newException(IOError, "no config file at " & o.configFile)
    return
  doc = tomlOf(where)
  if not doc.ok:
    raise newException(ValueError, doc.err)
  client = doc.node.section("relayClient")
  complaint = client.checkKeys(["remote", "peerPin", "identity",
    "identityPasswordFile", "subject", "stream", "format", "limit",
    "timeoutMs", "intervalMs"], where & " [relayClient]")
  if complaint.len > 0:
    raise newException(ValueError, complaint)
  if "remote" notin result.given:
    result.remote = client.setting("remote", result.remote)
  if "peer-pin" notin result.given:
    result.peerPin = client.setting("peerPin", result.peerPin)
  if "identity" notin result.given:
    result.identity = client.setting("identity", result.identity)
  if "identity-password-file" notin result.given:
    result.identityPasswordFile = client.setting("identityPasswordFile",
      result.identityPasswordFile)
  if "subject" notin result.given:
    result.subject = client.setting("subject", result.subject)
    if "as" notin result.given:
      result.consumer = result.subject
  if "stream" notin result.given:
    result.stream = client.setting("stream", result.stream)
  if "format" notin result.given:
    result.format = client.setting("format", result.format)
  if "limit" notin result.given:
    result.limit = client.setting("limit", result.limit)
  if "timeout-ms" notin result.given:
    result.timeoutMs = client.setting("timeoutMs", result.timeoutMs)
  if "interval-ms" notin result.given:
    result.intervalMs = client.setting("intervalMs", result.intervalMs)

proc identityPassword(o: Options): string {.role: sanitizer,
    tag: "cli|cryptoBoundary".} =
  ## o: the password sealing this client's identity file.
  if o.identityPasswordFile.len > 0:
    if not fileExists(o.identityPasswordFile):
      raise newException(IOError,
        "no identity password file at " & o.identityPasswordFile)
    return readFile(o.identityPasswordFile).strip()
  result = o.identityPassword

proc mineFor(o: Options): AmeIdentityKey {.role: configurator,
    tag: "cli|cryptoBoundary".} =
  ## o: this client's signing identity, created on first use.
  var
    loaded: tuple[ok: bool, key: AmeIdentityKey, created: bool, err: string] =
      (false, default(AmeIdentityKey), false, "")
  if o.identity.len == 0:
    raise newException(ValueError,
      "--identity <file> is required: the relay pins its peers, and a key " &
      "minted fresh on every run could never be pinned")
  loaded = loadOrCreateIdentity(o.identity, identityPassword(o), o.subject,
    geistSignatureSlots())
  if not loaded.ok:
    raise newException(IOError, loaded.err)
  result = loaded.key

proc connectRelay(o: Options): GeistLink {.role: orchestrator,
    tag: "cli|networkSurface|orchestrator".} =
  ## o: options naming the relay and the pin it is checked against.
  var
    address: tuple[ok: bool, a: GeistDacAddress] =
      (false, default(GeistDacAddress))
    pin: tuple[ok: bool, pin: AmePinnedPeerIdentity, err: string] =
      (false, default(AmePinnedPeerIdentity), "")
    link: tuple[ok: bool, link: GeistLink, err: string] =
      (false, default(GeistLink), "")
  address = parseDacAddress(o.remote)
  if not address.ok:
    raise newException(ValueError,
      "--remote must be dac://host:port, got '" & o.remote & "'")
  if o.peerPin.len == 0:
    raise newException(ValueError,
      "--peer-pin <file> is required: trust here is pinned, so this client " &
      "must already know which relay it is willing to talk to")
  pin = loadPin(o.peerPin)
  if not pin.ok:
    raise newException(IOError, pin.err)
  link = connectGeist(address.a, mineFor(o), pin.pin, defaultTierPolicy(),
    1'u64, o.timeoutMs)
  if not link.ok:
    raise newException(IOError, "could not reach " & o.remote & ": " & link.err)
  result = link.link

proc sendOne(link: var GeistLink, o: Options,
    body: ByteSeq): tuple[ok: bool, answer: ByteSeq, err: string] {.
    role: orchestrator, tag: "cli|networkSurface|write".} =
  ## link/o/body: one message, and whatever the far side answered.
  ##
  ## The body is the payload RAW -- no envelope, no row encoding. A relay
  ## stamps who sent it from the pin it verified, so there is nothing for
  ## a sender to describe.
  var
    sent: tuple[ok: bool, reply: Reply, err: string] =
      (false, default(Reply), "")
  sent = link.send(Query(op: qoPut, collection: o.stream, payload: body),
    o.timeoutMs)
  if not sent.ok:
    return (false, @[], sent.err)
  if not sent.reply.ok:
    return (false, @[], sent.reply.err)
  if sent.reply.rows.len > 0:
    result.answer = sent.reply.rows[0].data
  result.ok = true

proc sendAndEcho(link: var GeistLink, o: Options, text: string) {.
    role: orchestrator, tag: "cli|networkSurface|write".} =
  ## link/o/text: send one message; whatever the far side answered goes to
  ## stdout. A refused message raises, which ends the whole send.
  var
    sent: tuple[ok: bool, answer: ByteSeq, err: string] =
      sendOne(link, o, asBytes(text))
  if not sent.ok:
    raise newException(IOError, sent.err)
  if sent.answer.len > 0:
    stdout.write(asText(sent.answer))

proc sendLines(link: var GeistLink, o: Options, input: string): int {.
    role: orchestrator, tag: "cli|networkSurface|write".} =
  ## link/o/input: one message per non-empty line, on ONE link -> how many
  ## were sent. A log fan-in sends thousands, and a handshake per line
  ## would cost more than the lines do.
  for line in input.splitLines():
    if line.len > 0:
      sendAndEcho(link, o, line)
      result = result + 1

proc cmdSend(o: Options): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|stream|write".} =
  ## o: read the input and hand it over, one message or one per line.
  var
    link: GeistLink = default(GeistLink)
    input: string = ""
    count: int = 0
  if o.file.len > 0:
    if not fileExists(o.file):
      raise newException(IOError, "no file at " & o.file)
    input = readFile(o.file)
  else:
    input = stdin.readAll()
  link = connectRelay(o)
  try:
    if o.splitLines:
      count = sendLines(link, o, input)
    elif input.len == 0:
      raise newException(ValueError, "nothing to send: stdin was empty")
    else:
      sendAndEcho(link, o, input)
      count = 1
    stdout.flushFile()
    if o.verbose:
      stderr.writeLine("sent " & $count & " message(s) to " & o.remote &
        " on stream '" & o.stream & "'")
  finally:
    link.close()
  result = 0

proc showMessage(m: RelayMessage, format: RelayFormat) {.role: helper,
    tag: "cli|formatting|stream".} =
  ## m/format: one collected message, written out.
  stdout.write(render(m, format))

proc parseFormat(s: string): RelayFormat {.role: parser,
    tag: "cli|parsing|stream".} =
  ## s: --format, as typed -> the format, or ValueError.
  case s.toLowerAscii()
  of "", "raw", "bytes": result = rfRaw
  of "lines", "line", "plain", "text": result = rfLines
  of "json", "jsonl", "ndjson": result = rfJson
  else:
    raise newException(ValueError,
      "--format must be lines, json or raw, got '" & s & "'")

proc pollOnce(link: var GeistLink, o: Options, format: RelayFormat): int {.
    role: orchestrator, tag: "cli|read|stream".} =
  ## link/o/format: one poll; every message it returned written out.
  ## Returns how many there were.
  var
    got: tuple[ok: bool, reply: Reply, err: string] = link.send(Query(
      op: qoPoll, collection: o.stream, subscriptionId: o.consumer,
      limit: uint32(o.limit)), o.timeoutMs)
  if not got.ok:
    raise newException(IOError, got.err)
  if not got.reply.ok:
    raise newException(IOError, got.reply.err)
  for row in got.reply.rows:
    showMessage(decodeMessage(row.data), format)
  result = got.reply.rows.len

proc pollUntilDone(link: var GeistLink, o: Options,
    format: RelayFormat): int {.role: orchestrator, tag: "cli|read|stream".} =
  ## link/o/format: poll once, or -- with --follow -- every --interval-ms
  ## until stopped. Returns how many messages were written out.
  while true:
    result = result + pollOnce(link, o, format)
    stdout.flushFile()
    if not o.follow:
      return
    sleep(o.intervalMs)

proc cmdPoll(o: Options): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|read|stream".} =
  ## o: collect what the relay is holding for this reader, once or forever.
  var
    link: GeistLink = default(GeistLink)
    format: RelayFormat = rfRaw
    seen: int = 0
  format = parseFormat(o.format)
  link = connectRelay(o)
  try:
    seen = pollUntilDone(link, o, format)
  finally:
    link.close()
  if o.verbose:
    stderr.writeLine("collected " & $seen & " message(s) from " & o.remote)
  result = 0

proc cmdPin(o: Options): int {.role: orchestrator,
    tag: "cli|cryptoBoundary|entrypoint".} =
  ## o: write this client's pin, which the relay must be given to trust it.
  var
    written: tuple[ok: bool, err: string] = (false, "")
    where: string = o.pinOut
  if where.len == 0:
    where = o.identity & ".pin"
  written = savePin(where, pinOf(mineFor(o)))
  if not written.ok:
    raise newException(IOError, written.err)
  stderr.writeLine("wrote " & where & "  <- hand this to the relay operator")
  stderr.writeLine("")
  stderr.writeLine(describePin(pinOf(mineFor(o))))
  result = 0

proc runRelayClient*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name.
  var
    o: Options = default(Options)
  try:
    o = parseOptions(argv)
    if o.help:
      echo usageText
      return 0
    o = withUserConfig(o)
    case o.verb
    of vSend: result = cmdSend(o)
    of vPoll: result = cmdPoll(o)
    of vPin: result = cmdPin(o)
  except CatchableError as exc:
    stderr.writeLine("geist-relay: " & exc.msg)
    result = 1

when isMainModule:
  quit(runRelayClient(commandLineParams()))
