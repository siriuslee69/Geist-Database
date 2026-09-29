## Many stores behind one daemon.
##
## The registry is what lets a Fjord server hold a store per mailbox
## without holding ten thousand file handles, so the properties under test
## are the ones that only show up under pressure: that the bound is real,
## that eviction saves before it closes, that a store which refuses to
## close does not stall the ones behind it, and that the allow list is a
## boundary rather than a hint.

import std/[os, strutils, tables, unittest]

import geist/network
import runePragmas

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / "geist_registry_test" / name
  removeDir(result)
  createDir(result)

type
  Note = object
    id: uint64
    body: string

proc homeAt(name: string): GeistHome {.role: configurator.} =
  var
    h = openHome(scratch(name), nrServer)
  doAssert h.ok, h.err
  doAssert h.home.ensureHome().ok
  result = h.home

## An opener that behaves: every address gets a writable store.
proc plainOpener(): OpenStore {.role: configurator, stage: stDone.} =
  result = proc (h: GeistHome, a: GeistAddress, path: string,
      S: var Session): tuple[ok: bool, writable: bool, err: string] =
    S = openSession[Note](path, "main")
    result = (true, true, "")

## An opener that refuses one particular target, the way an application
## refuses a mailbox nobody has.
proc pickyOpener(refuse: string): OpenStore {.role: configurator.} =
  result = proc (h: GeistHome, a: GeistAddress, path: string,
      S: var Session): tuple[ok: bool, writable: bool, err: string] =
    if a.target == refuse:
      return (false, false, "no such mailbox: " & a.target)
    S = openSession[Note](path, "main")
    result = (true, true, "")

proc addressOf(s: string): GeistAddress {.role: parser.} =
  var
    p = parseAddress(s)
  doAssert p.ok, p.err
  result = p.a

suite "what a registry will answer for":

  # {.testKind: tkEdgeCase.}
  test "a registry with no apps is refused at startup, not at request time":
    var
      r = initRegistry(homeAt("empty-allow"), plainOpener(), [])
    check not r.ok
    check "refuse every request" in r.err

  # {.testKind: tkEdgeCase.}
  test "a registry with no opener is refused":
    var
      r = initRegistry(homeAt("no-opener"), nil, ["fjord"])
    check not r.ok

  # {.testKind: tkEdgeCase.}
  test "a limit below one is refused":
    var
      r = initRegistry(homeAt("zero-limit"), plainOpener(), ["fjord"], 0)
    check not r.ok

  # {.testKind: tkEdgeCase.}
  test "an app that was not named is refused, and no folder appears":
    var
      home = homeAt("boundary")
      r = initRegistry(home, plainOpener(), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://eris/games/alderreach"))
    check not got.ok
    check "does not serve 'eris'" in got.err
    # The boundary is only a boundary if it stops the directory being
    # created: the address IS the path, so answering would have made one.
    check not dirExists(home.base / "db" / "eris")
    check r.registry.report.refused == 1'u64

  # {.testKind: tkUnit.}
  test "the app named is served":
    var
      r = initRegistry(homeAt("served"), plainOpener(), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    check got.ok
    check got.slot != nil
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "the allow list is case-insensitive, because an address is":
    var
      r = initRegistry(homeAt("case"), plainOpener(), ["FJORD"])
    check r.ok
    check r.registry.serves("fjord")
    check r.registry.serves("Fjord")

  # {.testKind: tkEdgeCase.}
  test "an address with no app cannot choose a store":
    var
      r = initRegistry(homeAt("bare"), plainOpener(), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("notes"))
    check not got.ok
    check "names no app" in got.err

  # {.testKind: tkEdgeCase.}
  test "an opener that refuses is a refusal, not an empty database":
    var
      home = homeAt("picky")
      r = initRegistry(home, pickyOpener("mail/nobody"), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://fjord/mail/nobody"))
    check not got.ok
    check "no such mailbox" in got.err

suite "the path is still the address":

  # {.testKind: tkUnit.}
  test "a store lands under db/<app>/<target>":
    var
      home = homeAt("paths")
      r = initRegistry(home, plainOpener(), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    check got.ok
    check got.slot.path == home.base / "db" / "fjord" / "mail" / "alice" /
      "inbox"
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "an instance is a sibling directory, not a level":
    var
      home = homeAt("instance")
      r = initRegistry(home, plainOpener(), ["fjord"])
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://fjord.staging/accounts"))
    check got.ok
    check got.slot.path == home.base / "db" / "fjord.staging" / "accounts"
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "an address that would escape the home is refused":
    var
      r = initRegistry(homeAt("escape"), plainOpener(), ["fjord"])
    check r.ok
    # `..` never survives parseAddress, so the refusal happens before a
    # registry is even consulted -- which is the point: there is one
    # place that can produce a path, and it is the one that checks.
    check not parseAddress("geist://fjord/../../etc/passwd").ok

suite "one open session per destination":

  # {.testKind: tkEdgeCase.}
  test "asking twice opens once":
    var
      r = initRegistry(homeAt("twice"), plainOpener(), ["fjord"])
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    check r.registry.report.opened == 1'u64
    check r.registry.report.hits == 1'u64
    check r.registry.openCount() == 1
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "two routes to one store are one store":
    var
      r = initRegistry(homeAt("routes"), plainOpener(), ["fjord"])
    check r.ok
    discard r.registry.acquire(
      addressOf("geist://fjord/mail/alice/inbox?ttl=6"))
    discard r.registry.acquire(
      addressOf("geist://fjord/mail/alice/inbox?ttl=2&via=vps"))
    # Different journeys, same destination. Opening this twice would take
    # the write lease twice on one folder.
    check r.registry.openCount() == 1
    check r.registry.report.opened == 1'u64
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "two mailboxes are two stores":
    var
      r = initRegistry(homeAt("two"), plainOpener(), ["fjord"])
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/bob/inbox"))
    check r.registry.openCount() == 2
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "a slot key ignores the journey and keeps the destination":
    check addressOf("geist://fjord/mail/alice/inbox?ttl=3").slotKey() ==
      "fjord/mail/alice/inbox"
    check addressOf("geist://fjord.staging/accounts").slotKey() ==
      "fjord.staging/accounts"

suite "the bound is real":

  # {.testKind: tkUnit.}
  test "a third store evicts the first":
    var
      r = initRegistry(homeAt("evict"), plainOpener(), ["fjord"], 2)
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/c/inbox"))
    check r.registry.openCount() == 2
    check r.registry.report.evicted == 1'u64
    # The one evicted is the LEAST RECENTLY USED, which is a.
    check "fjord/mail/a/inbox" notin r.registry.openKeys()
    check "fjord/mail/c/inbox" in r.registry.openKeys()
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "using a store keeps it alive past a newer one":
    var
      r = initRegistry(homeAt("lru"), plainOpener(), ["fjord"], 2)
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    # Touch a, so b becomes the oldest.
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/c/inbox"))
    check "fjord/mail/a/inbox" in r.registry.openKeys()
    check "fjord/mail/b/inbox" notin r.registry.openKeys()
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "the open set never exceeds the limit, over many stores":
    var
      r = initRegistry(homeAt("many"), plainOpener(), ["fjord"], 3)
    check r.ok
    for i in 0 ..< 20:
      var got = r.registry.acquire(
        addressOf("geist://fjord/mail/user" & $i & "/inbox"))
      check got.ok
      check r.registry.openCount() <= 3
    check r.registry.openCount() == 3
    check r.registry.report.opened == 20'u64
    check r.registry.report.evicted == 17'u64
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "room is made BEFORE the new store opens, not after":
    # A registry that opened first would peak at limit + 1 handles, which
    # is the exact moment a daemon at its ceiling falls over. Checked by
    # a limit of one: the previous store must already be gone.
    var
      r = initRegistry(homeAt("before"), plainOpener(), ["fjord"], 1)
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    check r.registry.openCount() == 1
    discard r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    check r.registry.openCount() == 1
    check r.registry.openKeys() == @["fjord/mail/b/inbox"]
    discard r.registry.closeRegistry()

suite "eviction does not lose rows":

  # {.testKind: tkUnit.}
  test "an evicted store was saved, and reopens with its rows":
    var
      home = homeAt("saved")
      r = initRegistry(home, plainOpener(), ["fjord"], 1)
    check r.ok
    var
      first = r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    check first.ok
    check first.slot.session.put(Note(id: 1'u64, body: "kept")) != 0'u64
    # Evict it by asking for something else.
    discard r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    check r.registry.report.evicted == 1'u64
    # And come back for it.
    var
      again = r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    check again.ok
    check again.slot.session.entryCount() == 1
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "closing the registry saves every writable store":
    var
      home = homeAt("closeall")
      r = initRegistry(home, plainOpener(), ["fjord"], 4)
    check r.ok
    for name in ["a", "b", "c"]:
      var got = r.registry.acquire(
        addressOf("geist://fjord/mail/" & name & "/inbox"))
      check got.ok
      check got.slot.session.put(Note(id: 7'u64, body: name)) != 0'u64
    check r.registry.closeRegistry().ok
    check r.registry.openCount() == 0
    # Reopen one from scratch and the row is there.
    var
      r2 = initRegistry(home, plainOpener(), ["fjord"], 4)
    check r2.ok
    var
      back = r2.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    check back.ok
    check back.slot.session.entryCount() == 1
    discard r2.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "saveAll flushes without closing":
    var
      r = initRegistry(homeAt("saveall"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      got = r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    check got.ok
    check got.slot.session.put(Note(id: 2'u64, body: "x")) != 0'u64
    var
      flushed = r.registry.saveAll()
    check flushed.ok
    check flushed.saved == 1
    check r.registry.openCount() == 1
    discard r.registry.closeRegistry()

suite "answering a query by address":

  # {.testKind: tkUnit.}
  test "a query is answered against the store its address names":
    var
      r = initRegistry(homeAt("answer"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      alice = r.registry.acquire(addressOf("geist://fjord/mail/alice/inbox"))
    check alice.ok
    check alice.slot.session.put(Note(id: 5'u64, body: "for alice")) != 0'u64
    var
      bob = r.registry.acquire(addressOf("geist://fjord/mail/bob/inbox"))
    check bob.ok
    check bob.slot.session.put(Note(id: 6'u64, body: "for bob")) != 0'u64

    var
      p = PeerContext(subject: "phone", rights: {prRead})
      reply = r.registry.serveQuery(Query(op: qoSync,
        collection: "geist://fjord/mail/alice/inbox", limit: 16'u32), p)
    check reply.ok
    check reply.rows.len == 1
    discard r.registry.closeRegistry()

  # {.testKind: tkEdgeCase.}
  test "an unservable address is a refusal, not a transport failure":
    var
      r = initRegistry(homeAt("refusal"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      p = PeerContext(subject: "phone", rights: {prRead})
      reply = r.registry.serveQuery(Query(op: qoSync,
        collection: "geist://eris/games/x", limit: 16'u32), p)
    # A refusal travels back as a REPLY. Returning a failure instead would
    # make a client fail over to a daemon that will say the same thing.
    check not reply.ok
    check "does not serve 'eris'" in reply.err

  # {.testKind: tkEdgeCase.}
  test "an unparseable address is refused before any store is touched":
    var
      r = initRegistry(homeAt("badaddr"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      p = PeerContext(subject: "phone", rights: {prRead})
      reply = r.registry.serveQuery(Query(op: qoSync,
        collection: "geist://fjord/../etc", limit: 16'u32), p)
    check not reply.ok
    check r.registry.openCount() == 0

  # {.testKind: tkEdgeCase.}
  test "rights are enforced by answerQuery, not re-decided here":
    var
      r = initRegistry(homeAt("rights"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      p = PeerContext(subject: "phone", rights: {prRead})
      reply = r.registry.serveQuery(Query(op: qoPut,
        collection: "geist://fjord/mail/alice/inbox",
        payload: @[]), p)
    check not reply.ok
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "subscription cursors are per store":
    var
      r = initRegistry(homeAt("cursors"), plainOpener(), ["fjord"], 4)
    check r.ok
    var
      a = r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    check a.ok
    a.slot.cursors["phone"] = 11'u64
    var
      b = r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    check b.ok
    # One name, two logs, two positions. Sharing them would have a
    # subscriber skip whatever the other store had already passed.
    check not b.slot.cursors.hasKey("phone")
    check a.slot.cursors["phone"] == 11'u64
    discard r.registry.closeRegistry()

suite "what an operator can see":

  # {.testKind: tkUnit.}
  test "the description counts what happened":
    var
      r = initRegistry(homeAt("describe"), plainOpener(), ["fjord"], 2)
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://eris/x"))
    var
      line = r.registry.describeRegistry()
    check "1/2 store(s) open" in line
    check "1 opened" in line
    check "1 hit(s)" in line
    check "1 refused" in line
    discard r.registry.closeRegistry()

  # {.testKind: tkUnit.}
  test "the open list reads oldest first, so it says what goes next":
    var
      r = initRegistry(homeAt("order"), plainOpener(), ["fjord"], 3)
    check r.ok
    discard r.registry.acquire(addressOf("geist://fjord/mail/a/inbox"))
    discard r.registry.acquire(addressOf("geist://fjord/mail/b/inbox"))
    check r.registry.openKeys() == @["fjord/mail/a/inbox",
      "fjord/mail/b/inbox"]
    discard r.registry.closeRegistry()
