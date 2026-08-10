## The relay: a Query answered by a pipe instead of a database.
##
## Nothing here opens a socket -- the live-socket work is
## test_daemon_live.nim, and these are the semantics that sit behind it.
## What is checked is what a relay actually promises:
##
##   * who sent a message is the PIN's name, never the payload's
##   * a peer pinned for reading cannot send
##   * a bounded spool drops the oldest and says how many
##   * two readers of one stream do not consume each other's messages
##   * a command gets the body on stdin and its stdout becomes the reply
##   * a command that hangs is stopped rather than hanging the relay
##   * a database question gets a refusal that explains itself

import std/[json, os, strutils, unittest]

import geist/wire

proc peer(name: string, rights: set[PeerRight]): PeerContext =
  result = PeerContext(subject: name, address: "dac://127.0.0.1:1",
    rights: rights)

let
  phone = peer("phone", {prRead, prWrite})
  watcher = peer("watcher", {prRead})

proc put(D: var RelayDesk, stream, body: string,
    who: PeerContext = phone): Reply =
  result = answerRelay(D, Query(op: qoPut, collection: stream,
    payload: asBytes(body)), who)

suite "a message keeps who sent it":

  test "the sender is the pin's subject, not anything the payload said":
    var D = initRelayDesk()
    var reply = D.put("voice", "sender: someone-else")
    check reply.ok
    reply = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "r"), watcher)
    check reply.rows.len == 1
    let m = decodeMessage(reply.rows[0].data)
    # The body says one thing; the envelope says who the handshake proved.
    check m.sender == "phone"
    check asText(m.body) == "sender: someone-else"

  test "an envelope survives a round trip":
    var m = RelayMessage(stream: "voice", sender: "phone", at: 1_700_000_000'i64,
      ordinal: 7'u64, body: asBytes("bytes\x00with a nul"))
    let back = decodeMessage(encodeMessage(m))
    check back.stream == "voice"
    check back.sender == "phone"
    check back.at == 1_700_000_000'i64
    check back.ordinal == 7'u64
    check back.body == m.body

  test "a truncated envelope decodes to nothing rather than reading past it":
    var m = RelayMessage(stream: "voice", sender: "phone", body: asBytes("hi"))
    var wire = encodeMessage(m)
    check decodeMessage(wire[0 ..< wire.len - 1]).body.len == 0
    check decodeMessage(@[]).stream == ""

  test "ordinals count from one, per stream":
    var D = initRelayDesk()
    check D.put("a", "one").cursor == 1'u64
    check D.put("a", "two").cursor == 2'u64
    # A second stream starts again: they are separate queues.
    check D.put("b", "one").cursor == 1'u64
    check D.streamCount("a") == 2'u64
    check D.streamCount("b") == 1'u64

suite "rights come from the pin":

  test "a peer pinned for reading may collect but not send":
    var D = initRelayDesk()
    discard D.put("voice", "from the phone")
    let refused = D.put("voice", "from the watcher", watcher)
    check not refused.ok
    check "may read but not send" in refused.err
    check "--allow-write" in refused.err
    let allowed = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "w"), watcher)
    check allowed.ok
    check allowed.rows.len == 1

  test "a peer with no rights at all may not even collect":
    var D = initRelayDesk()
    discard D.put("voice", "held")
    let refused = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "n"), peer("nobody", {}))
    check not refused.ok
    check "may not read" in refused.err

  test "an empty message is refused, and counted":
    var D = initRelayDesk()
    let refused = answerRelay(D, Query(op: qoPut, collection: "voice"), phone)
    check not refused.ok
    check "carried no bytes" in refused.err
    check D.refused == 1

  test "a named accept-list keeps a peer from inventing streams":
    var D = initRelayDesk()
    D.streams = @["voice", "notes"]
    check D.put("voice", "fine").ok
    let refused = D.put("whatever", "not fine")
    check not refused.ok
    check "takes no stream 'whatever'" in refused.err
    check "voice, notes" in refused.err

suite "the spool is bounded and says so":

  test "the oldest falls off and is counted":
    var D = initRelayDesk()
    D.spool = 3
    for i in 1 .. 10:
      check D.put("voice", "message " & $i).ok
    check D.holds("voice") == 3
    check D.droppedFrom("voice") == 7'u64
    let reply = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "late"), watcher)
    check reply.rows.len == 3
    # What is left is the NEWEST three: a relay that shed the newest would
    # go quiet exactly when it got busy.
    check asText(decodeMessage(reply.rows[0].data).body) == "message 8"
    check asText(decodeMessage(reply.rows[2].data).body) == "message 10"
    # The reader can tell it missed some: the stream has taken ten, and it
    # has been handed three.
    check reply.matched == 10'u32
    check reply.cursor == 10'u64

  test "a spool of zero holds nothing but still counts":
    var D = initRelayDesk()
    D.spool = 0
    check D.put("voice", "gone").ok
    check D.holds("voice") == 0
    check D.streamCount("voice") == 1'u64

suite "readers do not consume each other":

  test "two names on one stream each see everything once":
    var D = initRelayDesk()
    discard D.put("voice", "first")
    discard D.put("voice", "second")
    var a = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "alpha"), watcher)
    var b = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "beta"), watcher)
    check a.rows.len == 2
    check b.rows.len == 2
    # And neither sees them twice.
    check answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "alpha"), watcher).rows.len == 0
    discard D.put("voice", "third")
    let more = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "alpha"), watcher)
    check more.rows.len == 1
    check asText(decodeMessage(more.rows[0].data).body) == "third"

  test "a poll limit leaves the rest for the next call":
    var D = initRelayDesk()
    for i in 1 .. 5:
      discard D.put("voice", $i)
    let first = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "r", limit: 2'u32), watcher)
    check first.rows.len == 2
    check first.cursor == 2'u64
    let rest = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "r", limit: 10'u32), watcher)
    check rest.rows.len == 3

  test "a sync keeps its own position instead of being remembered":
    var D = initRelayDesk()
    for i in 1 .. 4:
      discard D.put("voice", $i)
    # Ask from zero twice: a client-held cursor means the relay does not
    # get to decide what has been seen.
    check answerRelay(D, Query(op: qoSync, collection: "voice",
      cursor: 0'u64), watcher).rows.len == 4
    check answerRelay(D, Query(op: qoSync, collection: "voice",
      cursor: 0'u64), watcher).rows.len == 4
    check answerRelay(D, Query(op: qoSync, collection: "voice",
      cursor: 3'u64), watcher).rows.len == 1

suite "a relay says it is not a database":

  test "every stored-data question is refused by name":
    var D = initRelayDesk()
    for op in [qoGet, qoFind, qoFetch, qoDelete]:
      let refused = answerRelay(D, Query(op: op, collection: "voice"), phone)
      check not refused.ok
      check "not a database" in refused.err
      check "geistd" in refused.err

suite "how a message is written down":

  test "plain lines stay one line each":
    let m = RelayMessage(stream: "logs", sender: "phone", at: 1_700_000_000'i64,
      ordinal: 1'u64, body: asBytes("two\nlines\there"))
    let line = render(m, rfLines)
    check line.count('\n') == 1
    check line.endsWith("\n")
    check "\\n" in line
    check "\\t" in line
    check "2023-11-14T" in line
    check " phone logs " in line

  test "json carries text as text":
    let m = RelayMessage(stream: "notes", sender: "phone", at: 1_700_000_000'i64,
      ordinal: 3'u64, body: asBytes("hello \"world\""))
    let node = parseJson(render(m, rfJson))
    check node["from"].getStr() == "phone"
    check node["stream"].getStr() == "notes"
    check node["ordinal"].getInt() == 3
    check node["bytes"].getInt() == 13
    check node["body"].getStr() == "hello \"world\""
    check not node.hasKey("base64")

  test "json carries bytes as base64":
    let m = RelayMessage(stream: "voice", sender: "phone",
      body: @[0'u8, 1'u8, 2'u8, 255'u8])
    let node = parseJson(render(m, rfJson))
    check not node.hasKey("body")
    check node["base64"].getStr() == "AAEC/w=="
    check node["bytes"].getInt() == 4

  test "raw adds nothing at all":
    let m = RelayMessage(stream: "voice", sender: "phone",
      body: asBytes("exactly these bytes"))
    check render(m, rfRaw) == "exactly these bytes"

  test "a file sink appends and can be read back":
    let path = "build/test-relay/log.jsonl"
    removeDir("build/test-relay")
    var D = initRelayDesk(rsFile, rfJson)
    D.file = path
    check D.put("logs", "first").ok
    check D.put("logs", "second").ok
    D.closeRelay()
    let lines = readFile(path).strip().splitLines()
    check lines.len == 2
    check parseJson(lines[0])["body"].getStr() == "first"
    check parseJson(lines[1])["ordinal"].getInt() == 2
    # Appending, not replacing: a second run continues the same log.
    var again = initRelayDesk(rsFile, rfJson)
    again.file = path
    check again.put("logs", "third").ok
    again.closeRelay()
    check readFile(path).strip().splitLines().len == 3

suite "a delivered command":

  test "gets the body on stdin and answers with its stdout":
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "tr a-z A-Z"
    let reply = D.put("voice", "pretend this is a transcript")
    check reply.ok
    check reply.rows.len == 1
    check asText(reply.rows[0].data).strip() == "PRETEND THIS IS A TRANSCRIPT"

  test "is told about the message in its environment":
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "printf '%s/%s/%s' \"$GEIST_STREAM\" \"$GEIST_FROM\" \"$GEIST_BYTES\""
    let reply = D.put("voice", "0123456789")
    check reply.ok
    check asText(reply.rows[0].data) == "voice/phone/10"

  test "never sees the message on its command line":
    var D = initRelayDesk(rsExec, rfRaw)
    # If the body were interpolated into the command, this would run `id`.
    D.exec = "cat"
    let reply = D.put("voice", "$(id) `id` ; id")
    check reply.ok
    check asText(reply.rows[0].data) == "$(id) `id` ; id"

  test "that fails is reported with what it exited":
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "exit 3"
    let reply = D.put("voice", "anything")
    check not reply.ok
    check "exited 3" in reply.err
    check D.failed == 1

  test "that hangs is stopped rather than hanging the relay":
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "sleep 30"
    D.execTimeoutMs = 200
    let reply = D.put("voice", "anything")
    check not reply.ok
    check "did not finish within 200ms" in reply.err

  test "with no timeout is started and not waited for":
    let flag = "build/test-relay/triggered"
    removeDir("build/test-relay")
    createDir("build/test-relay")
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "sleep 0.2; touch " & flag
    D.execTimeoutMs = 0
    let reply = D.put("voice", "go")
    # Answered immediately, with nothing to say yet.
    check reply.ok
    check reply.rows.len == 0
    check not fileExists(flag)
    D.closeRelay()
    check fileExists(flag)

  test "spooling happens whatever the sink is":
    var D = initRelayDesk(rsExec, rfRaw)
    D.exec = "cat"
    check D.put("voice", "also kept").ok
    let reply = answerRelay(D, Query(op: qoPoll, collection: "voice",
      subscriptionId: "r"), watcher)
    check reply.rows.len == 1
    check asText(decodeMessage(reply.rows[0].data).body) == "also kept"
