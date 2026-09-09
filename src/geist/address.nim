## ---------------------------------------------------------------------
## Address <- what a request names, and where it has already been
## ---------------------------------------------------------------------
##
##   geist://eris.main@vps-1/notes?ttl=6&via=home-1
##   \____/ \__/ \__/ \____/ \___/ \____________/
##     |     |    |     |      |          |
##     |     |    |     |      |          `- rewritten by every hop
##     |     |    |     |      `- target: what inside the app
##     |     |    |     `- node: which machine answers ("" = whoever)
##     |     |    `- instance: which copy ("" = any)
##     |     `- app: which program
##     `- scheme
##
## A BARE NAME IS A VALID ADDRESS. `parseAddress("notes")` yields an
## address whose target is `notes` and whose every other field is empty.
## That is the whole compatibility story: `Query.collection` has always
## held a collection name, every client that predates routing sends one,
## and what they send is already legal here.
##
## WHY THE ROUTING STATE IS IN THE TEXT. A router has to REWRITE it --
## each hop decrements `ttl` and appends itself to `via` -- and both have
## to survive being handed to the next daemon. One string travels with a
## request and belongs to the routing layer, so that is where they live.
## `$a` after a hop is a complete address again, which is why a request
## can cross four daemons and still keep no state anywhere but in itself.
##
## MALFORMED IS REFUSED, NEVER REPAIRED. A router that sanitized a bad
## address into a good one would be deciding where a request goes on the
## strength of a typo. Every rejection below says which rule was broken.
##
## This module is PURE: strutils and nothing else. A program that only
## writes rows to disk can parse an address without compiling a socket,
## and the router can parse one without compiling a store.

import std/strutils

import runePragmas

const
  geistScheme* = "geist://"
    ## The only scheme. Present means "this is routed"; absent means the
    ## string is a bare target, which is the pre-federation case.
  maxAddressBytes* = 512
    ## The whole rendered address. Bounded because it arrives from a peer
    ## and is re-rendered at every hop, so an unbounded one would grow.
  maxNameBytes* = 63
    ## One label: app, instance, node, or one `via` entry. The DNS label
    ## limit, for the same reason -- it is long enough for a name and
    ## short enough that a list of them stays readable in a log line.
  maxTargetBytes* = 255
    ## The target. Longer than a label because it may carry a path.
  maxViaEntries* = 16
    ## How many nodes a trail may name. A request that has crossed
    ## sixteen daemons is lost regardless of what `ttl` says.
  defaultAddressTtl* = 6'u8
    ## Hops a routed address starts with when the sender did not say.
    ## Six is a deep topology; the point is that it is finite.

type
  GeistAddress* {.role: truthState, tag: "networkSurface|protocol|types".} = object
    ## One destination, plus what the routing layer has done to it.
    ##
    ## `app`, `instance` and `node` are the WHERE and are matched against
    ## a route table. `target` is the WHAT and is the only part the app at
    ## the far end sees -- a leaf `geistd` is handed `target` as its
    ## collection and never learns it was routed.
    ##
    ## `ttl` and `via` are the routing layer's own state. They are not
    ## part of the destination and two addresses that differ only in them
    ## name the same thing; `sameDestination` is the comparison that says
    ## so.
    ##
    ## `onBehalfOf` is the subject a ROUTER is forwarding for. It is a
    ## claim, not a proof, and the far end treats it as one: rights are
    ## the INTERSECTION of what the router's own pin allows and what the
    ## named subject's pin allows, so a router can only ever narrow. A
    ## name the far end has never heard of yields nothing at all. See
    ## `delegatedContext` in transport.nim.
    app*: string
    instance*: string
    node*: string
    target*: string
    ttl*: uint8
    via*: seq[string]
    onBehalfOf*: string

## ---------------------------- validation ----------------------------

proc isLabelByte(c: char): bool {.role: parser, inline,
    tag: "parsing|protocol".} =
  ## c: one byte of an app, instance, node or via label.
  result = c in {'a' .. 'z'} or c in {'0' .. '9'} or c == '-' or c == '_'

proc isTargetByte(c: char): bool {.role: parser, inline,
    tag: "parsing|protocol".} =
  ## c: one byte of a target. A target may be a path, so it also carries
  ## `/` and `.`; `..` is refused separately because the character alone
  ## is innocent and the pair is not.
  result = isLabelByte(c) or c == '/' or c == '.'

proc checkLabel(s, what: string): string {.role: sanitizer,
    tag: "parsing|protocol".} =
  ## s/what: one label and the name to complain about it by.
  ##
  ## Returns the complaint, empty when there is none. An empty label is
  ## allowed by the caller, not here: absent and malformed are different
  ## answers and only the caller knows which one it wanted.
  var
    i: int = 0
  if s.len > maxNameBytes:
    return what & " is longer than " & $maxNameBytes & " bytes"
  while i < s.len:
    if not isLabelByte(s[i]):
      return what & " has an illegal character at " & $i &
        "; allowed: a-z 0-9 - _"
    i = i + 1
  result = ""

proc checkTarget(s: string): string {.role: sanitizer,
    tag: "parsing|protocol".} =
  ## s: the target, which may be a path.
  ##
  ## `..` is refused outright rather than resolved. A target reaches a
  ## store as a collection name and a relay as a stream name, and both
  ## have been made to open a file by someone who was allowed to write
  ## `..` into them.
  var
    i: int = 0
  if s.len > maxTargetBytes:
    return "target is longer than " & $maxTargetBytes & " bytes"
  if s.contains(".."):
    return "target contains '..'"
  if s.startsWith("/"):
    return "target starts with '/'"
  while i < s.len:
    if not isTargetByte(s[i]):
      return "target has an illegal character at " & $i &
        "; allowed: a-z 0-9 - _ . /"
    i = i + 1
  result = ""

## ---------------------------- construction --------------------------

proc address*(app, instance, node, target: string,
    ttl: uint8 = defaultAddressTtl): GeistAddress {.role: configurator,
    tag: "networkSurface|protocol".} =
  ## app/instance/node/target: the four parts, none of them required.
  ## ttl: hops this address may still take.
  ##
  ## Does NOT validate: this is the constructor a program uses on values
  ## it chose itself. `parseAddress` is the one that takes bytes from a
  ## peer, and that one checks everything.
  result.app = app.toLowerAscii()
  result.instance = instance.toLowerAscii()
  result.node = node.toLowerAscii()
  result.target = target
  result.ttl = ttl

proc bareAddress*(target: string): GeistAddress {.role: configurator, inline,
    tag: "networkSurface|protocol".} =
  ## target: a plain collection or stream name, unrouted.
  result.target = target

proc isRouted*(a: GeistAddress): bool {.role: parser, inline,
    tag: "networkSurface|protocol".} =
  ## a: an address that names an app is one a router can act on. One that
  ## does not is a bare target and belongs to whoever received it.
  result = a.app.len > 0

proc sameDestination*(a, b: GeistAddress): bool {.role: parser,
    tag: "networkSurface|protocol".} =
  ## a/b: do these name the same thing, ignoring how far each has come?
  result = a.app == b.app and a.instance == b.instance and
    a.node == b.node and a.target == b.target

proc destinationKey*(a: GeistAddress): string {.role: helper,
    tag: "networkSurface|protocol".} =
  ## a: the address reduced to WHAT it names, dropping how it got there.
  ##
  ## `ttl`, `via` and `as` describe a journey, not a destination, so two
  ## requests for one store that arrived by different routes must produce
  ## the same key. Anything that files something per destination -- an
  ## open session, a sync cursor -- keys on this, and they agree because
  ## there is one definition rather than one each.
  ##
  ##   geist://fjord/mail/alice/inbox?ttl=4&via=vps -> fjord/mail/alice/inbox
  ##   geist://fjord.staging@home/accounts          -> fjord.staging@home/accounts
  ##
  ## Exactly the fields `sameDestination` compares, and that is not a
  ## coincidence to be maintained by hand: two addresses have the same key
  ## if and only if they are the same destination.
  result = a.app
  if a.instance.len > 0:
    result = result & "." & a.instance
  if a.node.len > 0:
    result = result & "@" & a.node
  if result.len > 0:
    result = result & "/"
  result = result & a.target

## ---------------------------- rendering -----------------------------

proc `$`*(a: GeistAddress): string {.role: helper,
    tag: "formatting|networkSurface|protocol".} =
  ## a: rendered back to the form `parseAddress` accepts.
  ##
  ## An unrouted address renders as its bare target, which is what makes
  ## the round trip through a pre-federation daemon lossless: it gets the
  ## same string it would have got before this module existed.
  var
    t: string = ""
    p: seq[string] = @[]
  if not a.isRouted():
    return a.target
  t = geistScheme & a.app
  if a.instance.len > 0:
    t = t & "." & a.instance
  if a.node.len > 0:
    t = t & "@" & a.node
  t = t & "/" & a.target
  if a.ttl > 0'u8:
    p.add "ttl=" & $a.ttl
  if a.via.len > 0:
    p.add "via=" & a.via.join(",")
  if a.onBehalfOf.len > 0:
    p.add "as=" & a.onBehalfOf
  if p.len > 0:
    t = t & "?" & p.join("&")
  result = t

## ---------------------------- parsing -------------------------------

proc refuse(err: string): tuple[ok: bool, a: GeistAddress, err: string] {.
    role: helper, inline, tag: "parsing|protocol".} =
  ## err: why this address is not one.
  result = (false, GeistAddress(), err)

proc parseParams(s: string, S: var GeistAddress): string {.role: parser,
    tag: "parsing|protocol".} =
  ## s: everything after the `?`.
  ## S: address being filled.
  ##
  ## Returns the complaint, empty when there is none. An unknown param is
  ## an ERROR: the two that exist decide whether a request is forwarded at
  ## all, and a third one silently ignored would be a routing rule that
  ## did not apply.
  var
    i: int = 0
    n: int = 0
    key: string = ""
    value: string = ""
    parts: seq[string] = @[]
    trail: seq[string] = @[]
  parts = s.split('&')
  while i < parts.len:
    n = parts[i].find('=')
    if n < 0:
      return "parameter '" & parts[i] & "' has no value"
    key = parts[i][0 ..< n]
    value = parts[i][n + 1 .. ^1]
    if key == "ttl":
      try:
        n = parseInt(value)
      except ValueError:
        return "ttl is not a number: '" & value & "'"
      if n < 0 or n > 255:
        return "ttl out of range: " & $n
      S.ttl = uint8(n)
    elif key == "via":
      trail = value.split(',')
      if trail.len > maxViaEntries:
        return "via names " & $trail.len & " nodes; the limit is " &
          $maxViaEntries
      S.via = @[]
      n = 0
      while n < trail.len:
        value = trail[n].toLowerAscii()
        key = checkLabel(value, "via entry")
        if key.len > 0:
          return key
        if value.len == 0:
          return "via has an empty entry"
        S.via.add value
        n = n + 1
    elif key == "as":
      S.onBehalfOf = value.toLowerAscii()
      key = checkLabel(S.onBehalfOf, "as")
      if key.len > 0:
        return key
      if S.onBehalfOf.len == 0:
        return "as is empty"
    else:
      return "unknown address parameter '" & key & "'; known: ttl, via, as"
    i = i + 1
  result = ""

proc parseAuthority(s: string, S: var GeistAddress): string {.role: parser,
    tag: "parsing|protocol".} =
  ## s: `app`, `app.instance`, `app@node` or `app.instance@node`.
  ## S: address being filled.
  ##
  ## Returns the complaint, empty when there is none.
  var
    n: int = 0
    t: string = s
    err: string = ""
  n = t.find('@')
  if n >= 0:
    S.node = t[n + 1 .. ^1].toLowerAscii()
    t = t[0 ..< n]
    err = checkLabel(S.node, "node")
    if err.len > 0:
      return err
    if S.node.len == 0:
      return "node is empty after '@'"
  n = t.find('.')
  if n >= 0:
    S.instance = t[n + 1 .. ^1].toLowerAscii()
    t = t[0 ..< n]
    err = checkLabel(S.instance, "instance")
    if err.len > 0:
      return err
    if S.instance.len == 0:
      return "instance is empty after '.'"
  S.app = t.toLowerAscii()
  result = checkLabel(S.app, "app")

proc parseAddress*(s: string): tuple[ok: bool, a: GeistAddress,
    err: string] {.role: parser,
    tag: "networkSurface|parsing|protocol".} =
  ## s: an address as it arrived, from a peer or from a config file.
  ##
  ## Two shapes, and the first is the common one:
  ##
  ##   "notes"                        -> target only, not routed
  ##   "geist://eris.main@vps-1/notes" -> routed
  ##
  ## A routed address with no `ttl` parameter gets `defaultAddressTtl`,
  ## because an address written by hand in a config file should not have
  ## to say a number to be forwardable, and one that arrived without a
  ## ttl has not been counted yet.
  var
    t: string = s
    n: int = 0
    err: string = ""
    a: GeistAddress
    hadTtl: bool = false
  if s.len > maxAddressBytes:
    return refuse("address is longer than " & $maxAddressBytes & " bytes")
  if not s.startsWith(geistScheme):
    err = checkTarget(s)
    if err.len > 0:
      return refuse(err)
    a.target = s
    return (true, a, "")
  t = s[geistScheme.len .. ^1]
  n = t.find('?')
  if n >= 0:
    hadTtl = t[n + 1 .. ^1].contains("ttl=")
    err = parseParams(t[n + 1 .. ^1], a)
    if err.len > 0:
      return refuse(err)
    t = t[0 ..< n]
  n = t.find('/')
  if n < 0:
    return refuse("routed address has no '/' before its target")
  a.target = t[n + 1 .. ^1]
  err = checkTarget(a.target)
  if err.len > 0:
    return refuse(err)
  err = parseAuthority(t[0 ..< n], a)
  if err.len > 0:
    return refuse(err)
  if not hadTtl:
    a.ttl = defaultAddressTtl
  result = (true, a, "")

## ---------------------------- forwarding ----------------------------

proc passedThrough*(a: GeistAddress, node: string): bool {.role: parser,
    tag: "networkSurface|protocol".} =
  ## a/node: has this request already been through this daemon?
  ##
  ## The loop check. `ttl` alone would eventually stop a cycle, but only
  ## after six pointless deliveries, and it would report "hop limit" for
  ## what is really a misconfigured table.
  var
    i: int = 0
    t: string = node.toLowerAscii()
  while i < a.via.len:
    if a.via[i] == t:
      return true
    i = i + 1
  result = false

proc hop*(S: var GeistAddress, node: string): tuple[ok: bool, err: string] {.
    role: actor,
    tag: "networkSurface|protocol|server".} =
  ## S: the address being forwarded, rewritten in place.
  ## node: the name of the daemon doing the forwarding.
  ##
  ## Called ONCE per daemon, before the request goes out again. It is the
  ## only thing that writes `ttl` and `via`, so every refusal a router can
  ## give for a request that will not settle comes from here.
  var
    t: string = node.toLowerAscii()
    err: string = ""
  err = checkLabel(t, "node")
  if err.len > 0:
    return (false, err)
  if t.len == 0:
    return (false, "the forwarding node has no name")
  if S.passedThrough(t):
    return (false, "routing loop: " & t & " is already in via=" &
      S.via.join(","))
  if S.ttl == 0'u8:
    return (false, "hop limit reached at " & t)
  if S.via.len >= maxViaEntries:
    return (false, "via already names " & $maxViaEntries & " nodes")
  S.ttl = S.ttl - 1'u8
  S.via.add t
  result = (true, "")

proc forLeaf*(a: GeistAddress): string {.role: helper, inline,
    tag: "networkSurface|protocol".} =
  ## a: what the final daemon should be handed as its collection.
  ##
  ## The target alone. A leaf `geistd` looks up a collection by this name
  ## and must not see the routing wrapper -- it never had to before, and
  ## a store whose collection was called `geist://eris.main@vps-1/notes`
  ## would be a different store from the one called `notes`.
  result = a.target
