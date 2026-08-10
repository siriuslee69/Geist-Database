## The address: what survives a hop, and what is refused outright.
##
## Two properties matter more than the rest and are asserted first:
## a bare collection name is still a legal address (every client written
## before routing existed keeps working), and a rendered address parses
## back to the same thing (a request crossing four daemons is parsed and
## re-rendered four times).

import std/[strutils, unittest]

import geist/address

suite "a bare name is an address":

  test "a collection name parses, and renders back unchanged":
    var r = parseAddress("notes")
    check r.ok
    check r.a.target == "notes"
    check r.a.app == ""
    check not r.a.isRouted()
    check $r.a == "notes"

  test "a path target survives":
    var r = parseAddress("mail/inbox")
    check r.ok
    check r.a.target == "mail/inbox"

  test "an empty string is an empty target, not an error":
    var r = parseAddress("")
    check r.ok
    check r.a.target == ""

suite "a routed address":

  test "every part is read":
    var r = parseAddress("geist://eris.main@vps-1/notes?ttl=6&via=home-1")
    check r.ok
    check r.a.app == "eris"
    check r.a.instance == "main"
    check r.a.node == "vps-1"
    check r.a.target == "notes"
    check r.a.ttl == 6'u8
    check r.a.via == @["home-1"]
    check r.a.isRouted()

  test "rendering round-trips":
    var s = "geist://eris.main@vps-1/notes?ttl=6&via=home-1,gateway"
    var r = parseAddress(s)
    check r.ok
    check $r.a == s

  test "optional parts are optional":
    var r = parseAddress("geist://fjord/mail")
    check r.ok
    check r.a.app == "fjord"
    check r.a.instance == ""
    check r.a.node == ""
    check r.a.target == "mail"

  test "an address with no ttl starts at the default":
    check parseAddress("geist://fjord/mail").a.ttl == defaultAddressTtl

  test "names are lowercased, so case never routes two ways":
    var r = parseAddress("geist://ERIS.Main@VPS-1/notes")
    check r.ok
    check r.a.app == "eris"
    check r.a.instance == "main"
    check r.a.node == "vps-1"

  test "the leaf sees the target alone":
    check parseAddress("geist://eris.main@vps-1/notes").a.forLeaf() == "notes"

suite "malformed is refused, never repaired":

  test "'..' in a target":
    check not parseAddress("geist://eris/../etc/passwd").ok

  test "a leading slash in a target":
    check not parseAddress("geist://eris//etc").ok

  test "an unknown parameter":
    var r = parseAddress("geist://eris/x?hops=2")
    check not r.ok
    check "unknown address parameter" in r.err

  test "a non-numeric ttl":
    check not parseAddress("geist://eris/x?ttl=soon").ok

  test "a routed address with no target separator":
    check not parseAddress("geist://eris").ok

  test "an illegal character in a name":
    check not parseAddress("geist://er is/x").ok

  test "an over-long address":
    var t = "geist://eris/"
    var i = 0
    while i < maxAddressBytes:
      t = t & "a"
      i = i + 1
    check not parseAddress(t).ok

  test "an empty instance after the dot":
    check not parseAddress("geist://eris./x").ok

suite "forwarding":

  test "a hop decrements the ttl and records the node":
    var a = parseAddress("geist://fjord/mail").a
    check a.hop("gateway").ok
    check a.ttl == defaultAddressTtl - 1'u8
    check a.via == @["gateway"]
    check $a == "geist://fjord/mail?ttl=5&via=gateway"

  test "a loop is refused by name, not by exhausting the ttl":
    var a = parseAddress("geist://fjord/mail").a
    check a.hop("gateway").ok
    check a.hop("vps-1").ok
    var r = a.hop("gateway")
    check not r.ok
    check "routing loop" in r.err

  test "the ttl runs out":
    var a = parseAddress("geist://fjord/mail?ttl=1").a
    check a.hop("a").ok
    var r = a.hop("b")
    check not r.ok
    check "hop limit" in r.err

  test "passedThrough ignores case, as the parser does":
    var a = parseAddress("geist://fjord/mail?via=gateway").a
    check a.passedThrough("GATEWAY")

  test "an unnamed forwarder is refused":
    var a = parseAddress("geist://fjord/mail").a
    check not a.hop("").ok

suite "two addresses that differ only in routing state":

  test "name the same destination":
    var a = parseAddress("geist://eris.main@vps-1/notes?ttl=6").a
    var b = parseAddress("geist://eris.main@vps-1/notes?ttl=2&via=x").a
    check sameDestination(a, b)

  test "but a different target does not":
    var a = parseAddress("geist://eris.main/notes").a
    var b = parseAddress("geist://eris.main/drafts").a
    check not sameDestination(a, b)
