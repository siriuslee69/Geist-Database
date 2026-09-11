## Rights can only narrow.
##
## A router connects with its OWN key, so without this rule every request
## it forwarded would arrive carrying the router's rights and a read-only
## client would gain write access by being routed.
##
## `?as=` is the claim a router makes about who it is carrying for. It is
## a claim and not a proof, so the server intersects rather than believes:
##
##   effective = rights(the pin that actually connected)
##           AND rights(the subject the address claims)
##
## Everything below is that one line, tested from both sides.

import std/[os, unittest]

import geist/network

proc peerNamed(name: string, rights: set[PeerRight]): TrustedPeer =
  var key = geistIdentity(name)
  result = TrustedPeer(pin: geistPeerPin(key), rights: rights)

proc serverWith(peers: openArray[TrustedPeer], port: int): GeistServer =
  var
    me = geistIdentity("upstream")
    at = parseDacAddress("dac://127.0.0.1:" & $port)
  doAssert at.ok
  var made = initGeistServer(at.a, me, peers, defaultTriggerPolicy())
  doAssert made.ok, made.err
  result = made.server

suite "the address carries the claim":

  test "as= parses and renders":
    var r = parseAddress("geist://eris/notes?ttl=4&via=gw&as=phone")
    check r.ok
    check r.a.onBehalfOf == "phone"
    check $r.a == "geist://eris/notes?ttl=4&via=gw&as=phone"

  test "an empty claim is refused rather than treated as absent":
    check not parseAddress("geist://eris/notes?as=").ok

  test "a claim with an illegal character is refused":
    check not parseAddress("geist://eris/notes?as=a b").ok

  test "no claim at all is the ordinary case":
    check parseAddress("geist://eris/notes").a.onBehalfOf == ""

suite "the server intersects":

  setup:
    var s = serverWith(@[
      peerNamed("router", {prRead, prWrite}),
      peerNamed("reader", {prRead}),
      peerNamed("writer", {prRead, prWrite})], 47771)

  teardown:
    s.closeServer()

  test "a peer this server has never heard of has no rights at all":
    check s.rightsFor("stranger") == {}

  test "with no claim, the connecting peer's own rights stand":
    var p = PeerContext(subject: "router", rights: {prRead, prWrite})
    var a = parseAddress("geist://eris/notes").a
    var e = s.delegatedContext(p, a)
    check e.subject == "router"
    check e.rights == {prRead, prWrite}

  test "a write-capable router forwarding for a reader gets read only":
    var p = PeerContext(subject: "router", rights: {prRead, prWrite})
    var a = parseAddress("geist://eris/notes?as=reader").a
    var e = s.delegatedContext(p, a)
    check e.subject == "reader"
    check e.rights == {prRead}

  test "a read-only router can never hand out write":
    var p = PeerContext(subject: "reader", rights: {prRead})
    var a = parseAddress("geist://eris/notes?as=writer").a
    var e = s.delegatedContext(p, a)
    check e.rights == {prRead}

  test "forwarding for someone this server does not know grants nothing":
    var p = PeerContext(subject: "router", rights: {prRead, prWrite})
    var a = parseAddress("geist://eris/notes?as=stranger").a
    var e = s.delegatedContext(p, a)
    check e.subject == "stranger"
    check e.rights == {}

  test "a router cannot elevate itself by naming a stronger peer":
    var p = PeerContext(subject: "reader", rights: {prRead})
    var a = parseAddress("geist://eris/notes?as=router").a
    check s.delegatedContext(p, a).rights == {prRead}

  test "the claimed subject is what the handler is told, so a row is "&
      "attributed to the person who wrote it":
    var p = PeerContext(subject: "router", rights: {prRead, prWrite})
    var a = parseAddress("geist://eris/notes?as=writer").a
    var e = s.delegatedContext(p, a)
    check e.subject == "writer"
    check e.rights == {prRead, prWrite}
