# Names and return connections inside a Geist relay

A connection names two things: the public relay and the local destination.
Local names and IPs belong to that relay's own address book. They do not use
the operating system's DNS or install routes on the operating system.

```nim
import geist/wire

# identity, relayPin and sharedKey are loaded using Geist's key APIs.
var policy = defaultTriggerPolicy()
policy.startTier = gtRecovery
var endpoint = parseDacAddress("dac://PUBLIC_HOST:47656")
var connected = connectGeist(endpoint.a, identity, relayPin, policy,
  shared = sharedKey)
doAssert connected.ok
var link = connected.link
var found = resolveOverlay(link, "archive.geist")
var submitted = submitOverlay(link, "10.76.0.3:8080",
  Query(op: qoGet, collection: "index"))
# Poll the returned ticket with overlayResult; only its caller can read it.
```

The relay administrator assigns aliases to pinned subjects in
`overlay-grants.json`, in the relay's private root:

```json
[
  {"subject":"pc","aliases":["pc.geist","desktop.geist","10.76.0.1"]},
  {"subject":"phone","aliases":["phone.geist","mobile.geist","10.76.0.2"]},
  {"subject":"vps-store","aliases":["store.geist","archive.geist","10.76.0.3:8080"]}
]
```

Every alias has exactly one owner. Multiple aliases may have the same owner.
`10.76.0.3:8080` and `10.76.0.3:8081` may belong to different owners. The
same rule applies to names with ports and bracketed IPv6 addresses. Names
are ASCII, case-insensitive, and may end in a dot; IPs are canonicalized.
An explicit port is part of the alias; there is no implicit port fallback.
This local port selects an identity; it does not open a physical listening
port on that device. Restart the relay after changing the grants file.

The owner periodically calls `renewOverlay` over its authenticated link.
The relay records the source **IP and port it actually observed**, never an
address claimed in the request. Lease expiry makes the owner unavailable;
it does not release its names to another owner. A fresh connection from the
same pinned identity updates the observed endpoint. Two identities behind
one public IP remain separate, including when they use different ports.

```text
caller -- submit(alias, Query) --> relay -- take --> owner (outbound polling)
caller <-- result(ticket) -------- relay <-- finish(ticket, Reply) -- owner
```

The owner uses `serveOverlayOnce(link, service, handler)` in its event loop.
It renews its lease and takes work through the same outgoing Geist link.
No inbound port at the owner is needed. `OverlayService.allowedCallers`
explicitly lists caller subjects and their local rights; effective rights
are their intersection with the relay's rights. An empty list allows none.

```nim
var service = OverlayService(allowedCallers: @[
  OverlayAccess(subject: "pc", rights: {prRead, prWrite})])
while running:
  discard serveOverlayOnce(link, service, handler)
  sleep(200)
```

Requests and replies use Geist's existing binary Query/Reply codecs, carried
as versioned control requests on `geist-overlay-v1`. All network exchanges
use Geist.send, AME/FOMKE/DAC and the link's pinned authentication. There is
no DNS, HTTP, TCP or direct-connect fallback. The relay terminates both
authenticated links and can read the forwarded Query/Reply. This is the
same trust boundary as a Geist application router, not an end-to-end blind
datagram forwarder.

Tickets and leases are bounded and held in memory. Work expires after a
deadline; a target is never silently substituted. A dispatched request is
not automatically executed again after a lost reply or an IP change. A
timeout may mean the application already acted; callers must not blindly
repeat writes. Relay restarts lose outstanding work; owners renew again.
Alias ownership survives because the administrator's grants file persists.
The current bounds are 256 identities, 32 aliases per identity, 128 pending
tickets and 16 tickets per caller. A Query or Reply may encode at most
65,536 bytes. Tickets expire after 60 seconds. Owners renew every 30
seconds; a lease expires after 90 seconds without renewal. The device
monitor keeps this timer on its own native Nim worker while its process
runs, independently of whether the page is visible. Killing the app or
pausing its process makes its lease expire.

The device monitor serves this protocol on its existing relay port. Its
store daemon reads `overlay-service.json` in the store's private root:

```json
{"relay":"dac://127.0.0.1:47656","overlayCallers":["pc","phone"]}
```

The relay must trust the store's pin and grant its aliases. The store must
pin the relay in `peers/vps-relay.pin`. The PC and phone use the same
`overlayCallers` list in `config.json`. The PC/phone UI exposes public relay
and local destination separately. Changing the public endpoint still
requires that server to prove the configured relay identity.

The deployed relay logs `overlay.renew`, `overlay.submit`, `overlay.finish`
and control failures in its bounded `debug.jsonl`, including subject,
observed endpoint and alias, without application bodies. The store logs
lease renewals and served callers too.

This provides the request path a future Geist browser can use: public
relay plus local alias plus a resource in `Query.collection`. A renderer
and a document format can be added separately.
