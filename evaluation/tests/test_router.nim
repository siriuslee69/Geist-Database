## The router: what it refuses, and what its config file looks like.
##
## `routeQuery` is exercised without a socket. Choosing a hop, detecting a
## loop and refusing an unroutable address all happen before anything is
## connected, so the refusal paths -- which are the ones a misconfigured
## deployment actually hits -- are tested as ordinary calls.
##
## The forwarding path itself needs two live daemons and is covered by the
## NixOS test in nix/tests/.

import runePragmas
import std/[os, strutils, unittest]

import geist/wire

import server/geist_routed

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / "geist_router_test"
  createDir(result)
  result = result / name

proc stateFor(t: RouteTable): RouterState {.role: configurator.} =
  var made = initGeistClient(geistIdentity("gateway"), t)
  doAssert made.ok, made.err
  result.client = made.client
  result.node = t.node
  result.quiet = true

proc gatewayTable(): RouteTable {.role: configurator.} =
  result = defaultRouteTable("gateway")
  result.route = @[
    Route(app: "eris", instance: "*", hops: @[
      Hop(name: "d1", endpoint: "dac://127.0.0.1:47901",
        pin: "d1.pin", priority: 0'u8)]),
    Route(app: "fjord", instance: "*", hops: @[
      Hop(name: "d3", endpoint: "dac://127.0.0.1:47903",
        pin: "d3.pin", priority: 0'u8)])]

proc asker(): PeerContext {.role: configurator.} =
  result = PeerContext(subject: "phone", address: "127.0.0.1:1",
    rights: {prRead, prWrite})

suite "the config file lists every option":

  test "the example writes and reads back":
    var p = scratch("router.toml")
    removeFile(p)
    check writeDoc(p, exampleRouterConfig(), routerNotes()).ok
    var back = readDoc(p, defaultRouterConfig())
    check back.report.ok
    check back.report.unknown.len == 0
    check back.value.routing.node == "gateway"
    check back.value.routing.route.len == 3
    check back.value.routing.route[0].app == "eris"
    check back.value.routing.route[0].hops.len == 2
    check back.value.routing.route[0].hops[1].priority == 1'u8

  test "and the file names the things an operator has to set":
    var p = scratch("router2.toml")
    check writeDoc(p, exampleRouterConfig(), routerNotes()).ok
    var text = readFile(p)
    check "[routing]" in text
    check "[[routing.route]]" in text
    check "[[routing.route.hops]]" in text
    check "takeoverAfterSeconds = 30" in text
    check "probeSuccesses = 2" in text
    check "# this router's own name" in text
    check text.startsWith("# geist-routed:")

  test "a hand-trimmed file still loads, with the defaults filled in":
    var p = scratch("router3.toml")
    writeFile(p, """
listen = "dac://0.0.0.0:9999"

[routing]
node = "edge"

[[routing.route]]
app = "eris"
instance = "*"
  [[routing.route.hops]]
  name = "only"
  endpoint = "dac://10.0.0.1:47655"
  pin = "d1.pin"
  priority = 0
""")
    var r = loadRouterConfig(p)
    check r.ok
    check r.c.listen == "dac://0.0.0.0:9999"
    check r.c.routing.node == "edge"
    check r.c.routing.takeoverAfterSeconds == defaultTakeoverSeconds
    check r.c.routing.probeSuccesses == defaultProbeSuccesses
    check r.c.routing.validate().ok

  test "a config that will not parse is fatal, not a shrug":
    var p = scratch("broken.toml")
    writeFile(p, "listen = \n[[[\n")
    check not loadRouterConfig(p).ok

  test "a named config that does not exist is fatal":
    check not loadRouterConfig(scratch("absent.toml")).ok

  test "but no config at all is the built-in defaults":
    var r = loadRouterConfig("")
    check r.ok

suite "what an option on the command line does":

  test "it wins over the file":
    var
      c = exampleRouterConfig()
      a = parseArgs(@["--listen", "dac://0.0.0.0:1", "--node", "edge",
        "--timeout-ms", "50"])
    var t = c.applyArgs(a)
    check t.listen == "dac://0.0.0.0:1"
    check t.routing.node == "edge"
    check t.timeoutMs == 50

  test "and what was not typed is left alone":
    var
      c = exampleRouterConfig()
      t = c.applyArgs(parseArgs(@["--quiet"]))
    check t.listen == c.listen
    check t.routing.node == c.routing.node
    check t.quiet

  test "an unknown option is refused by name":
    expect ValueError:
      discard parseArgs(@["--nonsense", "1"])

  test "an option with no value is refused":
    expect ValueError:
      discard parseArgs(@["--listen"])

suite "what the router refuses, and why":

  test "an address that is not one":
    var
      S = stateFor(gatewayTable())
      r = S.routeQuery(Query(op: qoFind, collection: "geist://eris/../x"),
        asker())
    check not r.ok
    check "'..'" in r.err

  test "a bare name, when there is no catch-all":
    var
      S = stateFor(gatewayTable())
      r = S.routeQuery(Query(op: qoFind, collection: "notes"), asker())
    check not r.ok
    check "names no app" in r.err
    check "geist://<app>/<target>" in r.err

  test "a bare name IS routed once there is a catch-all":
    var t = gatewayTable()
    t.route.add Route(app: "*", instance: "*", hops: @[
      Hop(name: "home", endpoint: "dac://127.0.0.1:47909", pin: "home.pin",
        priority: 0'u8)])
    var
      S = stateFor(t)
      r = S.routeQuery(Query(op: qoFind, collection: "notes"), asker())
    # It gets as far as trying to connect, which is the point: it was not
    # refused for being unaddressed.
    check "names no app" notin r.err

  test "an app nothing serves, by name":
    var
      S = stateFor(gatewayTable())
      r = S.routeQuery(Query(op: qoFind, collection: "geist://snotra/x"),
        asker())
    check not r.ok
    check "no route for snotra" in r.err

  test "a request that has already been here":
    var
      S = stateFor(gatewayTable())
      r = S.routeQuery(Query(op: qoFind,
        collection: "geist://eris/notes?ttl=4&via=gateway"), asker())
    check not r.ok
    check "routing loop" in r.err
    check "gateway" in r.err

  test "a request that has run out of hops":
    var
      S = stateFor(gatewayTable())
      r = S.routeQuery(Query(op: qoFind,
        collection: "geist://eris/notes?ttl=0"), asker())
    check not r.ok
    check "hop limit" in r.err

  test "and every refusal is counted":
    var S = stateFor(gatewayTable())
    discard S.routeQuery(Query(op: qoFind, collection: "notes"), asker())
    discard S.routeQuery(Query(op: qoFind, collection: "geist://snotra/x"),
      asker())
    check S.refused == 2
    check S.forwarded == 0

suite "a request on its way out":

  test "carries this router in via, and the caller in as":
    # The forward is built before the connection is attempted, so the
    # address the upstream WOULD see is observable through the failure.
    var
      S = stateFor(gatewayTable())
      a = parseAddress("geist://eris/notes").a
    check a.hop(S.node).ok
    a.onBehalfOf = asker().subject
    check $a == "geist://eris/notes?ttl=5&via=gateway&as=phone"

  test "and a second router appends itself without erasing the first":
    var a = parseAddress("geist://eris/notes?ttl=5&via=gateway&as=phone").a
    check a.hop("vps-1").ok
    check a.via == @["gateway", "vps-1"]
    check a.ttl == 4'u8
    check a.onBehalfOf == "phone"
