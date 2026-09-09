## ---------------------------------------------------------------------
## Relay <- one Query against a pipe, with the asker's rights
## ---------------------------------------------------------------------
##
##   Query + RelayDesk + PeerContext  ->  Reply
##
## The same shape as `answer.nim`, and deliberately so: that module says
## what a Query means against a DATABASE, this one says what it means
## against a PIPE. A relay stores nothing. It takes the bytes a pinned
## peer sent and hands them to something local -- a command, a file, this
## process's stdout -- and hands whatever comes back to the peer.
##
##   phone                          desktop
##   -----                          -------
##   arecord | geist-relay send --> geist-relayd --to exec
##                                     |  body on stdin
##                                     v
##                                  whisper --stdin
##                                     |  transcript on stdout
##   transcript printed          <-----+
##
## WHY THIS IS NOT A DATABASE CALL. Nothing here opens a store, takes a
## lease, or keeps a generation. The spool below is a bounded ring in
## memory: a relay holds a message only for as long as it takes the other
## side to ask for it, and if nobody asks, it is dropped and counted. A
## message that must survive a restart wants the storage half, and that is
## a different program.
##
## WHO SENT IT is `p.subject`, which comes from the pin the handshake
## verified -- not from the payload, which a peer controls. That is the
## one field a relay can state as fact, so it is the one field it stamps.
##
## AN EXEC NEVER SEES THE BODY ON ITS COMMAND LINE. The operator's command
## string is evaluated by a shell; the peer's bytes go to stdin and only
## to stdin. A relay that interpolated a message into a command would be
## handing every pinned peer a shell.
##
## WHAT TRAVELS. Inbound is RAW: `q.collection` is the stream -- as an
## address, so a relay behind a router is reached the same way a database
## is, and a bare name still means itself. `q.payload` is the body, so a
## client that can send bytes needs to know
## nothing else. Outbound is an ENVELOPE (`encodeMessage`), because a
## message being handed on has already left its sender behind and the
## reader would otherwise have no way to learn who wrote it or when.

import std/[base64, json, os, osproc, streams, strtabs, strutils, tables,
  times, unicode]

import runePragmas
import ./types
import ./address
import ./format

const
  relayEnvelopeId* = 0xFFF1'u16
    ## The `Row.schemaId` every relayed message carries. Far outside the
    ## range a database assigns, so an envelope can never be mistaken for
    ## a stored row -- and a reader can tell the two apart without being
    ## told which kind of endpoint it is talking to.
  relayReplyBudget* = 28_000
    ## Bytes of messages one poll answers before it stops and lets the
    ## reader ask again. The transport's whole-frame threshold, same as
    ## the database's row budget, for the same reason: an ordinary answer
    ## should be one datagram.
  defaultSpoolDepth* = 256
    ## Messages kept per stream when nothing says otherwise. Bounded on
    ## purpose: a relay nobody reads must lose the oldest message rather
    ## than the machine's memory.
  defaultExecTimeoutMs* = 30_000
    ## How long a delivered command may run. Generous, because the case
    ## this exists for is transcription and that is not quick. Zero means
    ## "do not wait", which is the fire-and-forget trigger.

type
  RelaySink* {.role: configurator, tag: "config|stream|types".} = enum
    ## Where an accepted message goes.
    ##
    ##   rsSpool   nowhere but the queue; a reader collects it later
    ##   rsStdout  this process's standard output, for a shell pipeline
    ##   rsFile    appended to a log
    ##   rsExec    a command's stdin; its stdout becomes the reply
    rsSpool, rsStdout, rsFile, rsExec

  RelayFormat* {.role: configurator, tag: "config|formatting|stream|types".} = enum
    ## How a message is written to stdout or a file.
    ##
    ##   rfLines  one plain line: when, who, which stream, the text
    ##   rfJson   one JSON object per line
    ##   rfRaw    the bytes, nothing added -- for piping audio onward
    rfLines, rfJson, rfRaw

  RelayMessage* {.role: truthState, tag: "stream|types".} = object
    ## One thing a peer sent.
    ##
    ## `at` is when THIS node accepted it, not when the sender claims it
    ## was made: a relay can vouch for the former and not the latter.
    ## `ordinal` is its position on its own stream, counted from one, so a
    ## reader that sees a gap knows it missed something.
    stream*: string
    sender*: string
    at*: int64
    ordinal*: uint64
    body*: ByteSeq

  RelayStream {.role: truthState, tag: "stream|types".} = object
    ## accepted: messages ever taken on this stream, which is also the
    ##   ordinal of the newest.
    ## queue: the ones still held, oldest first.
    ## dropped: how many fell off the back unread.
    accepted: uint64
    dropped: uint64
    queue: seq[RelayMessage]

  RelayDesk* {.role: truthState, tag: "server|stream|types".} = object
    ## The whole relay: what to do with a message, and what it is holding.
    ##
    ## streams: the accept-list. Empty means any stream is welcome; naming
    ##   some means a peer cannot invent a new one, which matters when the
    ##   sink is a command.
    ## spool: queue depth per stream, 0 to keep nothing.
    ## log: the open append handle for `rsFile`, opened on first write.
    sink*: RelaySink
    format*: RelayFormat
    file*: string
    exec*: string
    execTimeoutMs*: int
    spool*: int
    streams*: seq[string]
    accepted*: int
    delivered*: int
    refused*: int
    failed*: int
    lastErr*: string
    held: Table[string, RelayStream]
    readers: Table[string, uint64]
    running: seq[Process]
    log: File
    logOpen: bool

proc initRelayDesk*(sink: RelaySink = rsSpool,
    format: RelayFormat = rfLines): RelayDesk {.role: configurator,
    tag: "config|server|stream".} =
  ## sink/format: the two decisions everything else follows from.
  result.sink = sink
  result.format = format
  result.spool = defaultSpoolDepth
  result.execTimeoutMs = defaultExecTimeoutMs
  result.held = initTable[string, RelayStream]()
  result.readers = initTable[string, uint64]()

## --------------------------- the envelope ---------------------------

proc encodeMessage*(m: RelayMessage): ByteSeq {.role: encryptor,
    tag: "codecBoundary|stream|write".} =
  ## m: one message, serialised for the body of a relayed row.
  result = @[]
  result.addText(m.stream)
  result.addText(m.sender)
  result.addU64(cast[uint64](m.at))
  result.addU64(m.ordinal)
  result.addU32(uint32(m.body.len))
  result.addBytes(m.body)

proc decodeMessage*(A: openArray[uint8]): RelayMessage {.role: parser,
    tag: "codecBoundary|read|stream".} =
  ## A: bytes produced by `encodeMessage`.
  ##
  ## Every length is checked against what actually arrived. These bytes
  ## came off a socket, and a declared body of four billion must produce
  ## an empty message rather than an allocation.
  var
    o: int = 0
    n: int = 0
  if A.len < 1:
    return
  result.stream = A.readText(o)
  result.sender = A.readText(o)
  if o + 20 > A.len:
    return
  result.at = cast[int64](A.getU64(o)); o = o + 8
  result.ordinal = A.getU64(o); o = o + 8
  n = int(A.getU32(o)); o = o + 4
  if n < 0 or o + n > A.len:
    return
  result.body = newSeq[uint8](n)
  for i in 0 ..< n:
    result.body[i] = A[o + i]

proc asRow*(m: RelayMessage): Row {.role: helper,
    tag: "codecBoundary|stream".} =
  ## m: message wrapped as the row a Reply carries it in.
  result = Row(schemaId: relayEnvelopeId, data: encodeMessage(m))

## --------------------------- how it reads ---------------------------

proc asText*(body: openArray[uint8]): string {.role: helper,
    tag: "formatting|stream".} =
  ## body: bytes as a string, with no interpretation at all.
  result = newString(body.len)
  for i in 0 ..< body.len:
    result[i] = char(body[i])

proc asBytes*(s: string): ByteSeq {.role: helper,
    tag: "formatting|stream".} =
  ## s: a string as bytes, with no interpretation at all.
  result = newSeq[uint8](s.len)
  for i in 0 ..< s.len:
    result[i] = uint8(s[i])

proc isPrintableText(body: openArray[uint8]): bool {.role: parser,
    tag: "formatting|stream".} =
  ## body: whether these bytes can be shown as text.
  ##
  ## Valid UTF-8 with no NUL. Anything else is base64'd rather than
  ## written out, because a log line that contains a stray 0x00 breaks
  ## every tool that reads it and a JSON string cannot hold one at all.
  for b in body:
    if b == 0'u8:
      return false
  result = validateUtf8(asText(body)) < 0

proc oneLine(body: openArray[uint8]): string {.role: sanitizer,
    tag: "formatting|stream".} =
  ## body: text flattened to a single line.
  ##
  ## A plain-lines log promises one line per message; a message containing
  ## a newline would otherwise become two records, and the second would
  ## look like it came from nobody.
  var
    c: char
  for b in body:
    c = char(b)
    case c
    of '\n': result.add "\\n"
    of '\r': result.add "\\r"
    of '\t': result.add "\\t"
    of '\\': result.add "\\\\"
    else:
      if b < 0x20'u8 or b == 0x7F'u8:
        result.add "\\x" & toHex(b)
      else:
        result.add c

proc stamp*(at: int64): string {.role: helper,
    tag: "formatting|stream".} =
  ## at: a unix second as an ISO-8601 UTC instant.
  result = utc(fromUnix(at)).format("yyyy-MM-dd'T'HH:mm:ss'Z'")

proc render*(m: RelayMessage, f: RelayFormat): string {.role: helper,
    tag: "formatting|stream|write".} =
  ## m/f: one message as it is written to stdout or a log.
  ##
  ## `rfRaw` adds NOTHING -- not even a separator. It is the format for
  ## carrying bytes onward to another program, and a byte this function
  ## invented would corrupt them.
  case f
  of rfRaw:
    result = asText(m.body)
  of rfLines:
    result = stamp(m.at) & " " & m.sender & " " & m.stream & " " &
      oneLine(m.body) & "\n"
  of rfJson:
    var node = %*{
      "at": stamp(m.at),
      "from": m.sender,
      "stream": m.stream,
      "ordinal": int(m.ordinal),
      "bytes": m.body.len
    }
    # A body that is text goes in as text, because a log nobody can read
    # without a decoder is a log nobody reads. Anything else is base64,
    # which is the only honest option: JSON has no way to hold arbitrary
    # bytes, and lossy escaping would silently change the message.
    if isPrintableText(m.body):
      node["body"] = %asText(m.body)
    else:
      node["base64"] = %encode(m.body)
    result = $node & "\n"

## ---------------------------- the spool -----------------------------

proc holds*(D: RelayDesk, stream: string): int {.role: parser, inline,
    tag: "status|stream".} =
  ## D/stream: messages currently queued on one stream.
  if D.held.hasKey(stream):
    return D.held[stream].queue.len
  result = 0

proc streamCount*(D: RelayDesk, stream: string): uint64 {.role: parser, inline,
    tag: "status|stream".} =
  ## D/stream: messages ever accepted on one stream.
  if D.held.hasKey(stream):
    return D.held[stream].accepted
  result = 0'u64

proc droppedFrom*(D: RelayDesk, stream: string): uint64 {.role: parser, inline,
    tag: "status|stream".} =
  ## D/stream: messages that fell off the back before anyone read them.
  if D.held.hasKey(stream):
    return D.held[stream].dropped
  result = 0'u64

proc queue(D: var RelayDesk, m: RelayMessage) {.role: actor,
    tag: "stream|write".} =
  ## D/m: hold one message for whoever reads this stream next.
  ##
  ## The ring evicts the OLDEST, and counts what it evicted. A relay that
  ## dropped the newest would go quiet exactly when it got busy, and one
  ## that dropped silently would let a reader believe it had seen
  ## everything.
  var
    s: RelayStream
  if D.held.hasKey(m.stream):
    s = D.held[m.stream]
  s.accepted = m.ordinal
  if D.spool > 0:
    s.queue.add m
    while s.queue.len > D.spool:
      s.queue.delete(0)
      s.dropped = s.dropped + 1'u64
  D.held[m.stream] = s

proc nextOrdinal(D: var RelayDesk, stream: string): uint64 {.
    role: actor, tag: "stream|write".} =
  ## D/stream: the ordinal the next message on this stream will carry.
  var
    s: RelayStream
  if D.held.hasKey(stream):
    s = D.held[stream]
  result = s.accepted + 1'u64
  s.accepted = result
  D.held[stream] = s

proc readerKey(consumer, stream: string): string {.role: helper, inline,
    tag: "stream".} =
  ## consumer/stream: one reader's position on one stream.
  ##
  ## Two names joined by a byte neither can contain, so a reader called
  ## "a" on stream "b:c" and one called "a:b" on "c" stay distinct.
  result = consumer & "\x00" & stream

proc drain(D: var RelayDesk, consumer, stream: string,
    limit: int): tuple[msgs: seq[RelayMessage], cursor: uint64] {.
    role: actor, tag: "read|stream|sync".} =
  ## D/consumer/stream/limit: everything this reader has not seen yet.
  ##
  ## A cursor is an ORDINAL, not an index into the queue: the queue moves
  ## underneath a slow reader, and a position that meant "the third one
  ## still held" would silently re-deliver.
  var
    s: RelayStream
    used: int = 0
    seen: uint64 = 0'u64
  if D.held.hasKey(stream):
    s = D.held[stream]
  seen = D.readers.getOrDefault(readerKey(consumer, stream), 0'u64)
  for m in s.queue:
    if m.ordinal <= seen:
      continue
    if result.msgs.len >= limit or
        (result.msgs.len > 0 and used >= relayReplyBudget):
      break
    result.msgs.add m
    used = used + m.body.len
    seen = m.ordinal
  result.cursor = seen
  D.readers[readerKey(consumer, stream)] = seen

## ---------------------------- the sinks -----------------------------

proc reap*(D: var RelayDesk) {.role: actor,
    tag: "lifecycle|server|stream".} =
  ## D: collect any fire-and-forget command that has finished.
  ##
  ## `--exec-timeout-ms 0` starts a command and does not wait for it. Some
  ## thing still has to close the handle, or a daemon that triggers a job
  ## every minute accumulates a zombie every minute.
  var
    alive: seq[Process] = @[]
  for p in D.running:
    var q = p
    if q.peekExitCode() == -1:
      alive.add q
    else:
      q.close()
  D.running = alive

proc childEnv(m: RelayMessage): StringTableRef {.role: configurator,
    tag: "stream".} =
  ## m: the environment a delivered command is told about its input in.
  ##
  ## The BODY is not here. It goes on stdin, where a command reads data;
  ## an environment is for the small facts about it, and a 2 MB voice clip
  ## in an environment variable would fail at exec time anyway.
  result = newStringTable(modeCaseSensitive)
  for key, value in envPairs():
    result[key] = value
  result["GEIST_STREAM"] = m.stream
  result["GEIST_FROM"] = m.sender
  result["GEIST_AT"] = stamp(m.at)
  result["GEIST_BYTES"] = $m.body.len

proc runExec(D: var RelayDesk, m: RelayMessage): tuple[ok: bool,
    output: ByteSeq, err: string] {.role: orchestrator,
    tag: "server|stream|write".} =
  ## D/m: hand one message to the operator's command.
  ##
  ## The command string comes from this daemon's own flags and is
  ## evaluated by a shell. The message does NOT: it is written to stdin
  ## and nowhere else, so nothing a peer sends can become a command.
  ##
  ## A timeout of zero starts the command and returns at once -- the
  ## trigger case, where the answer is "accepted" rather than a result.
  ## Otherwise the child is waited for and killed if it overstays, so one
  ## wedged transcriber cannot wedge the daemon forever.
  ##
  ## The reply is the child's stdout, which must fit the operating
  ## system's pipe buffer (64 KiB on Linux) or the child will block until
  ## the timeout. A command with more than that to say should write it
  ## somewhere and answer with the path.
  var
    p: Process = nil
    waited: int = 0
    code: int = -1
  try:
    p = startProcess(D.exec, options = {poEvalCommand, poStdErrToStdOut},
      env = childEnv(m))
  except CatchableError as exc:
    return (false, @[], "could not start '" & D.exec & "': " & exc.msg)
  try:
    p.inputStream.write(asText(m.body))
    p.inputStream.flush()
    p.inputStream.close()
  except CatchableError as exc:
    p.kill()
    p.close()
    return (false, @[], "'" & D.exec & "' would not take the message: " &
      exc.msg)
  if D.execTimeoutMs <= 0:
    # Started, not awaited. The handle is kept so `reap` can close it.
    D.running.add p
    return (true, @[], "")
  while waited < D.execTimeoutMs:
    code = p.peekExitCode()
    if code != -1:
      break
    sleep(5)
    waited = waited + 5
  if code == -1:
    p.kill()
    discard p.waitForExit()
    p.close()
    return (false, @[], "'" & D.exec & "' did not finish within " &
      $D.execTimeoutMs & "ms and was stopped")
  result.output = asBytes(p.outputStream.readAll())
  p.close()
  if code != 0:
    return (false, result.output, "'" & D.exec & "' exited " & $code)
  result.ok = true

proc writeOut(D: var RelayDesk, m: RelayMessage): tuple[ok: bool,
    err: string] {.role: orchestrator,
    tag: "server|stream|write".} =
  ## D/m: the stdout and file sinks, which differ only in the handle.
  ##
  ## Flushed on every message. A log that is a relay's only record of what
  ## arrived is worth a syscall; buffering it would mean a crash loses
  ## precisely the messages that explain the crash.
  var
    text: string = render(m, D.format)
  try:
    if D.sink == rsStdout:
      stdout.write(text)
      stdout.flushFile()
      return (true, "")
    if not D.logOpen:
      if D.file.len == 0:
        return (false, "--to file needs --file <path>")
      if D.file.parentDir().len > 0:
        createDir(D.file.parentDir())
      D.log = open(D.file, fmAppend)
      D.logOpen = true
    D.log.write(text)
    D.log.flushFile()
    result = (true, "")
  except CatchableError as exc:
    result = (false, exc.msg)

proc deliver*(D: var RelayDesk, m: RelayMessage): tuple[ok: bool,
    output: ByteSeq, err: string] {.role: orchestrator,
    tag: "server|stream|write".} =
  ## D/m: one accepted message, handed to whatever this relay is for.
  ##
  ## The spool is fed WHATEVER the sink is, so a relay that pipes to a
  ## command can still be polled by a second reader, and a plain
  ## `--to spool` relay is just this with nothing else attached.
  D.queue(m)
  case D.sink
  of rsSpool:
    result.ok = true
  of rsStdout, rsFile:
    var written = D.writeOut(m)
    result = (written.ok, @[], written.err)
  of rsExec:
    result = D.runExec(m)
  if result.ok:
    D.delivered = D.delivered + 1
  else:
    D.failed = D.failed + 1
    D.lastErr = result.err

proc closeRelay*(D: var RelayDesk) {.role: actor,
    tag: "lifecycle|server|stream".} =
  ## D: release the log handle and wait out any command still running.
  if D.logOpen:
    try:
      D.log.close()
    except CatchableError:
      discard
    D.logOpen = false
  for p in D.running:
    var q = p
    try:
      discard q.waitForExit()
      q.close()
    except CatchableError:
      discard
  D.running = @[]

## --------------------------- the handler ----------------------------

proc refuse(err: string): Reply {.role: helper,
    tag: "server|status|stream".} =
  ## err: a refusal, said in full.
  result = Reply(ok: false, err: err)

proc welcome(D: RelayDesk, stream: string): bool {.role: parser,
    tag: "server|stream".} =
  ## D/stream: whether this relay takes messages on this stream.
  if D.streams.len == 0:
    return true
  result = stream in D.streams

proc answerRelay*(D: var RelayDesk, q: Query, p: PeerContext): Reply {.
    role: actor, tag: "appApi|networkSurface|server|stream|write".} =
  ## D: the pipe and what it is holding.
  ## q: the request.
  ## p: who is asking, and what their pin permits.
  ##
  ## The counterpart of `answerQuery`, and it answers the same wire. What
  ## it will not do is pretend to be a database: a find or a fetch is
  ## refused by name, because answering "no rows" to a program that
  ## thought it was querying a store would be a lie that costs an
  ## afternoon.
  var
    m: RelayMessage
    stream: string = parseAddress(q.collection).a.forLeaf()
    limit: int = 0
    sent: tuple[ok: bool, output: ByteSeq, err: string]
    drained: tuple[msgs: seq[RelayMessage], cursor: uint64]
  D.reap()
  limit = if q.limit == 0'u32: 64 else: int(q.limit)
  if stream.len == 0:
    stream = "default"
  case q.op
  of qoPut:
    # Sending IS writing. A peer pinned for reading may collect what other
    # peers left; it may not put anything into the pipe.
    if not (prWrite in p.rights):
      D.refused = D.refused + 1
      return refuse("'" & p.subject & "' may read but not send; the " &
        "operator grants that with --allow-write <pin>")
    if not D.welcome(stream):
      D.refused = D.refused + 1
      return refuse("this relay takes no stream '" & stream & "'; it takes " &
        D.streams.join(", "))
    if q.payload.len == 0:
      D.refused = D.refused + 1
      return refuse("a message carried no bytes")
    m.stream = stream
    m.sender = p.subject
    m.at = getTime().toUnix()
    m.ordinal = D.nextOrdinal(stream)
    m.body = q.payload
    D.accepted = D.accepted + 1
    sent = D.deliver(m)
    if not sent.ok:
      return Reply(ok: false, err: sent.err, cursor: m.ordinal)
    # The command's own answer travels back as the body of one row, so the
    # sender gets its transcript from the same call that sent the audio.
    if sent.output.len > 0:
      result.rows.add Row(schemaId: relayEnvelopeId, data: sent.output)
    result.cursor = m.ordinal
    result.matched = 1'u32
    result.ok = true
  of qoSubscribe, qoPoll, qoSync:
    # One drain, three spellings, because a relay has nothing a named
    # subscription would protect. `qoSubscribe` names a reader and takes
    # its first batch in the same call; `qoPoll` continues under that
    # name; `qoSync` is the same thing for a reader that would rather
    # keep its own position than be remembered.
    if not (prRead in p.rights):
      D.refused = D.refused + 1
      return refuse("'" & p.subject & "' may not read this relay")
    if q.op == qoSync:
      D.readers[readerKey(p.subject, stream)] = q.cursor
      drained = D.drain(p.subject, stream, limit)
    else:
      if q.subscriptionId.len == 0:
        return refuse("a subscription needs a name")
      # A name that has never been seen starts at zero and reads what is
      # still held. Unlike a database, that is bounded by construction --
      # the spool is -- so there is no need to make a reader say hello
      # before it may ask.
      drained = D.drain(q.subscriptionId, stream, limit)
    for msg in drained.msgs:
      result.rows.add msg.asRow()
    result.cursor = drained.cursor
    # What this stream has taken IN TOTAL. A reader whose cursor moved
    # further than the rows it received knows the spool dropped the
    # difference, which is the only way it could find out.
    result.matched = uint32(D.streamCount(stream))
    result.ok = true
  of qoGet, qoFind, qoFetch, qoDelete:
    result = refuse("this endpoint is a relay, not a database: it forwards " &
      "messages and keeps " & $D.spool & " per stream in memory. Point " &
      $q.op & " at a geistd instead.")
