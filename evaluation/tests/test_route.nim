## Failover, made deterministic.
##
## Nothing here opens a socket. `route.nim` treats an endpoint as a string
## and takes `now` as an argument, so the whole takeover sequence -- fail,
## fail, cross the threshold, take over, probe, recover -- is a list of
## calls with the clock written down rather than a test that sleeps and
## hopes.
##
## The topology under test is the one from docs/federation.md: D1 serves
## eris and fjord at priority 0, D2 and D3 each serve one of them at
## priority 1, D4 serves avalon alone.

import std/[strutils, tables, unittest]

import geist/address
import geist/route

proc hop(name, endpoint: string, priority: uint8): Hop =
  result = Hop(name: name, endpoint: endpoint, pin: name & ".pin",
    priority: priority)

proc vpsTable(): RouteTable =
  result = defaultRouteTable("gateway")
  result.route = @[
    Route(app: "eris", instance: "*", hops: @[
      hop("d1", "dac://10.0.0.1:47655", 0'u8),
      hop("d2", "dac://10.0.0.2:47655", 1'u8)]),
    Route(app: "fjord", instance: "*", hops: @[
      hop("d1", "dac://10.0.0.1:47655", 0'u8),
      hop("d3", "dac://10.0.0.3:47655", 1'u8)]),
    Route(app: "avalon", instance: "*", hops: @[
      hop("d4", "dac://10.0.0.4:47655", 0'u8)])]

proc at(s: string): GeistAddress =
  var r = parseAddress(s)
  doAssert r.ok, r.err
  result = r.a

suite "a table is refused when routing would be ambiguous":

  test "a valid table passes":
    check vpsTable().validate().ok

  test "two routes with the same pattern":
    var t = vpsTable()
    t.route.add Route(app: "eris", instance: "*", hops: @[
      hop("x", "dac://10.0.0.9:1", 0'u8)])
    var r = t.validate()
    check not r.ok
    check "two routes match eris.*" in r.err

  test "two hops sharing a priority":
    var t = vpsTable()
    t.route[0].hops.add hop("d9", "dac://10.0.0.9:1", 0'u8)
    var r = t.validate()
    check not r.ok
    check "share priority 0" in r.err

  test "a router with no name of its own":
    var t = vpsTable()
    t.node = ""
    check not t.validate().ok

  test "a route with no hops":
    var t = vpsTable()
    t.route[0].hops = @[]
    check not t.validate().ok

  test "a hop that is neither local nor reachable":
    var t = vpsTable()
    t.route[0].hops[0].endpoint = ""
    check not t.validate().ok

  test "probeSuccesses of zero, which would strand a down hop":
    var t = vpsTable()
    t.probeSuccesses = 0'u8
    check not t.validate().ok

suite "matching picks the most specific route":

  test "an exact app beats the catch-all":
    var t = vpsTable()
    t.route.add Route(app: "*", instance: "*", hops: @[
      hop("home", "dac://10.0.0.9:1", 0'u8)])
    check t.route[t.matchRoute(at("geist://eris/notes"))].app == "eris"

  test "an exact instance beats an app wildcard":
    var t = vpsTable()
    t.route.add Route(app: "eris", instance: "games", hops: @[
      hop("g", "dac://10.0.0.8:1", 0'u8)])
    check t.route[t.matchRoute(at("geist://eris.games/score"))].instance ==
      "games"
    check t.route[t.matchRoute(at("geist://eris.main/notes"))].instance == "*"

  test "an app nothing serves has no route":
    check vpsTable().matchRoute(at("geist://snotra/cards")) < 0

  test "and the catch-all catches it once there is one":
    var t = vpsTable()
    t.route.add Route(app: "*", instance: "*", hops: @[
      hop("home", "dac://10.0.0.9:1", 0'u8)])
    check t.matchRoute(at("geist://snotra/cards")) >= 0

suite "with everything healthy, priority zero serves":

  test "eris goes to d1":
    var
      v = initRouteView(vpsTable())
      c = v.chooseHop(at("geist://eris/notes"), 100)
    check c.ok
    check c.hop.name == "d1"
    check not c.probing

  test "fjord goes to d1 as well":
    var v = initRouteView(vpsTable())
    check v.chooseHop(at("geist://fjord/mail"), 100).hop.name == "d1"

  test "an unroutable app is refused by name":
    var
      v = initRouteView(vpsTable())
      c = v.chooseHop(at("geist://snotra/cards"), 100)
    check not c.ok
    check "no route for snotra" in c.err

suite "takeover":

  test "one failure is not a dead daemon":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 110)
    check v.chooseHop(at("geist://eris/notes"), 110).hop.name == "d1"

  test "continuous failure past the threshold moves eris to d2":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 112)
    v.noteFailure("dac://10.0.0.1:47655", 120)
    check v.chooseHop(at("geist://eris/notes"), 120).hop.name == "d1"
    v.noteFailure("dac://10.0.0.1:47655", 131)
    var c = v.chooseHop(at("geist://eris/notes"), 131)
    check c.ok
    check c.hop.name == "d2"
    check not c.probing

  test "and fjord to d3 at the same moment, from the same health record":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    check v.chooseHop(at("geist://eris/notes"), 131).hop.name == "d2"
    check v.chooseHop(at("geist://fjord/mail"), 131).hop.name == "d3"

  test "avalon is untouched: it never used d1":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    check v.chooseHop(at("geist://avalon/vault"), 131).hop.name == "d4"

  test "a success in the middle resets the clock":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 120)
    v.noteSuccess("dac://10.0.0.1:47655", 125)
    v.noteFailure("dac://10.0.0.1:47655", 150)
    check v.chooseHop(at("geist://eris/notes"), 150).hop.name == "d1"

  test "a hop that never worked at all goes down on its own timer":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    check v.chooseHop(at("geist://eris/notes"), 100).hop.name == "d1"
    v.noteFailure("dac://10.0.0.1:47655", 131)
    check v.chooseHop(at("geist://eris/notes"), 131).hop.name == "d2"

suite "recovery":

  test "one success does not promote a crash-looping daemon":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    check v.chooseHop(at("geist://eris/notes"), 131).hop.name == "d2"
    v.noteSuccess("dac://10.0.0.1:47655", 200)
    check v.chooseHop(at("geist://eris/notes"), 200).hop.name == "d2"

  test "two in a row do":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    v.noteSuccess("dac://10.0.0.1:47655", 200)
    v.noteSuccess("dac://10.0.0.1:47655", 210)
    check v.chooseHop(at("geist://eris/notes"), 210).hop.name == "d1"

  test "a failure between them starts the count again":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    v.noteSuccess("dac://10.0.0.1:47655", 200)
    v.noteFailure("dac://10.0.0.1:47655", 205)
    v.noteSuccess("dac://10.0.0.1:47655", 210)
    check v.chooseHop(at("geist://eris/notes"), 210).hop.name == "d2"

suite "when everything is down":

  test "the best hop is probed rather than the route refused":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    v.noteFailure("dac://10.0.0.2:47655", 100)
    v.noteFailure("dac://10.0.0.2:47655", 131)
    var c = v.chooseHop(at("geist://eris/notes"), 200)
    check c.ok
    check c.probing
    check c.hop.name == "d1"

  test "but not more often than the probe interval":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    v.noteFailure("dac://10.0.0.2:47655", 100)
    v.noteFailure("dac://10.0.0.2:47655", 131)
    var c = v.chooseHop(at("geist://eris/notes"), 133)
    check not c.ok
    check "every hop is down" in c.err
    check "d1" in c.err and "d2" in c.err

suite "an address that names a machine":

  test "is pinned to it, even when a healthier hop exists":
    var v = initRouteView(vpsTable())
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    var c = v.chooseHop(at("geist://eris@d1/notes"), 200)
    check c.ok
    check c.hop.name == "d1"
    check c.probing

  test "and a machine that serves no such app is refused, not redirected":
    var
      v = initRouteView(vpsTable())
      c = v.chooseHop(at("geist://eris@d4/notes"), 100)
    check not c.ok
    check "no hop is named d4" in c.err

suite "a local hop":

  test "is served here rather than forwarded":
    var t = defaultRouteTable("vps-1")
    t.route = @[Route(app: "eris", instance: "*", hops: @[
      Hop(name: "self", local: true, priority: 0'u8),
      hop("d2", "dac://10.0.0.2:47655", 1'u8)])]
    check t.validate().ok
    var v = initRouteView(t)
    check v.servesLocally(at("geist://eris/notes"))
    check v.chooseHop(at("geist://eris/notes"), 100).hop.local

  test "and a fallback takes over when it is not priority zero":
    var t = defaultRouteTable("vps-1")
    t.route = @[Route(app: "eris", instance: "*", hops: @[
      hop("d1", "dac://10.0.0.1:47655", 0'u8),
      Hop(name: "self", local: true, priority: 1'u8)])]
    var v = initRouteView(t)
    check not v.servesLocally(at("geist://eris/notes"))
    v.noteFailure("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.1:47655", 131)
    check v.chooseHop(at("geist://eris/notes"), 131).hop.local

suite "an application error is not a transport failure":

  test "only noteFailure moves health, so a refusal never demotes":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    # a hundred replies saying "no such collection" arrive; each one is a
    # successful exchange and is recorded as one
    var i = 0
    while i < 100:
      v.noteSuccess("dac://10.0.0.1:47655", 101 + int64(i))
      i = i + 1
    check v.chooseHop(at("geist://eris/notes"), 300).hop.name == "d1"
    check not v.healthOf("dac://10.0.0.1:47655").down

suite "what an operator is shown":

  test "names every hop, its priority and its state":
    var v = initRouteView(vpsTable())
    v.noteSuccess("dac://10.0.0.1:47655", 100)
    v.noteFailure("dac://10.0.0.2:47655", 100)
    v.noteFailure("dac://10.0.0.2:47655", 131)
    var text = v.describe(131)
    check "node gateway" in text
    check "route eris.*" in text
    check "d1" in text and "up" in text
    check "DOWN for" in text
