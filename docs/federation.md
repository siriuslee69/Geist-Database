# Federation: addresses, routes, and who takes over when a daemon dies

`geistd` serves one database. `geist-relayd` serves one pipe. Both answer
whoever holds a pinned key, and both answer for **one thing**.

That stops working the moment a machine runs more than one of them. A VPS
with Eris, Fjord and Avalon on it has three apps, four daemons and one
public address, and a request arriving at that address has to reach the
right handler. When the daemon that normally handles it is dead, the
request has to reach a different one, and the answer has to come back
along the same path it went out on.

This document is the design for that. It defines:

- **an address** — what a request names, and how a daemon reads it without
  decoding the app's payload
- **a route table** — the mapping from an address to the endpoints that
  can serve it, in priority order
- **failover** — when a lower-priority daemon may take over, when it must
  give the work back, and why there is no election
- **the edge cases**, enumerated, with what each one does

---

## Terms

Read these in order; each one uses the ones above it.

| term | meaning |
|---|---|
| **node** | one machine, named. `vps-1`, `home-1`, `phone`. A name, never an IP — the IP is how you reach it, not what it is. |
| **endpoint** | where a node listens: `dac://198.51.100.4:47655`. A node may have several. |
| **pin** | the fingerprint of a node's identity key, in a `.pin` file. The handshake proves the far side holds the matching secret. Trust is a list of pins, never a list of IPs. |
| **app** | which program a request is for: `eris`, `fjord`, `avalon`. |
| **instance** | which copy of that app: `main`, `games`, `backup`. Empty means "any". |
| **target** | what inside the app is being asked for — a collection for a database, a stream for a relay, a room for a chat server. |
| **client** | who is asking. Comes from the pin the handshake verified, never from the request. |
| **hop** | one endpoint a request may be forwarded to, with a priority. |
| **route** | a pattern (`app`, `instance`) plus the hops that serve it. |
| **via** | the trail of node names a request has already passed through. |
| **ttl** | hops remaining before a request is refused. |

---

## The address

A request names its destination in `Query.collection`. That field already
exists, already travels, and is already the first thing every handler
looks at — so the address goes there rather than into a new wire field
that would change the byte layout every existing client writes.

```
  geist://eris.main@vps-1/notes?ttl=6&via=home-1
  \____/ \__/ \__/ \____/ \___/ \____________/
    |     |    |     |      |          |
    |     |    |     |      |          `- routing state, rewritten per hop
    |     |    |     |      `- target: what inside the app
    |     |    |     `- node: which machine should answer ("" = whoever)
    |     |    `- instance: which copy of the app ("" = any)
    |     `- app: which program
    `- scheme, always "geist"
```

**A bare name is a valid address.** `notes` parses to an address whose
`target` is `notes` and whose every other field is empty. That is the
whole back-compatibility story: every `geistd`, every test and every
client written before this document keeps working, because what they send
is already a legal address that names a target and nothing else.

```
  parseAddress("notes")
    -> app "", instance "", node "", target "notes", ttl 0

  parseAddress("geist://eris.main@vps-1/notes")
    -> app "eris", instance "main", node "vps-1", target "notes", ttl 6
```

### Why the routing state is in the text

A router must be able to **rewrite** it. Each hop decrements `ttl` and
appends its own name to `via`, and both have to survive being handed to
the next daemon. There is exactly one string that travels with a request
and belongs to the routing layer, so that is where they live.

Rewriting is textual and total: `$addr` after a hop is a complete address
again, so a request that passes through four daemons is parsed and
re-rendered four times and never accumulates state anywhere else.

### The grammar

```
  address   := [ "geist://" authority ] "/"? target [ "?" params ]
  authority := app [ "." instance ] [ "@" node ]
  params    := param { "&" param }
  param     := "ttl" "=" 1*DIGIT | "via" "=" node { "," node }
```

Names are `[a-z0-9_-]`, 1–63 bytes each; `target` also allows `/` and `.`
so a collection path survives. The whole address is capped at 512 bytes.
Anything outside that is **refused at parse**, not sanitized into
something else — a router that quietly repaired a malformed address would
be deciding where a request goes on the strength of a typo.

---

## The route table

A route says: *requests that look like this go to these endpoints, in this
order.*

```
  route  eris.*        ->  vps-1  priority 0    dac://198.51.100.4:47655
                           vps-2  priority 1    dac://198.51.100.5:47655
  route  fjord.*       ->  vps-1  priority 0
                           vps-3  priority 1
  route  avalon.*      ->  vps-4  priority 0
  route  *.*           ->  home-1 priority 0    (catch-all, upstream)
```

In TOML:

```toml
[routing]
node                 = "gateway"   # this daemon's own name
maxHops              = 6
takeoverAfterSeconds = 30
probeEverySeconds    = 10
yieldAfterSeconds    = 60
probeSuccesses       = 2

[[routing.route]]
app      = "eris"
instance = "*"
  [[routing.route.hops]]
  name     = "vps-1"
  endpoint = "dac://198.51.100.4:47655"
  pin      = "peers/vps-1.pin"
  priority = 0
  [[routing.route.hops]]
  name     = "vps-2"
  endpoint = "dac://198.51.100.5:47655"
  pin      = "peers/vps-2.pin"
  priority = 1
```

Matching is **most specific first**: an exact `app` beats `*`, and within
the same `app` an exact `instance` beats `*`. Ties are impossible because
two routes with the same `(app, instance)` pair are refused at load.

### The user's four-daemon VPS

```
                          +-------------------------+
   client  ------------>  |  gateway (a router)     |
                          |  no store, no pipe      |
                          +------------+------------+
                                       |
              +------------------------+------------------------+
              |                        |                        |
     eris.* p0|             fjord.* p0 |             avalon.* p0|
              v                        v                        v
      +---------------+        +---------------+        +---------------+
      | D1  eris+fjord|        | D1  (same)    |        | D4  avalon    |
      +-------+-------+        +-------+-------+        +---------------+
              |  p1                    |  p1
              v                        v
      +---------------+        +---------------+
      | D2  eris only |        | D3 fjord only |
      +---------------+        +---------------+
```

D1 covers two apps at priority 0. D2 and D3 each cover one at priority 1.
Nothing tells D2 that it is a fallback except its priority number, and
nothing has to: it answers whatever reaches it. What decides whether
anything reaches it is the router's health view of D1.

---

## Failover

```
   t=0     D1 answers               hop 0 up,   traffic -> D1
   t=12    D1 refuses connection    failure 1,  traffic -> D1 (still up)
   t=20    D1 times out             failure 2,  traffic -> D1
   t=31    31s since last success   hop 0 DOWN, traffic -> D2
   ...
   t=90    probe: D1 answers        success 1,  traffic -> D2 (not yet)
   t=100   probe: D1 answers        success 2,  hop 0 UP, traffic -> D1
```

Three rules, and each one exists because of a specific failure:

**Takeover needs continuous failure, not a single one.** A hop is down
only after `takeoverAfterSeconds` have passed with no success at all. One
timed-out request during a garbage collection pause is not a dead daemon.

**Recovery needs `probeSuccesses` consecutive successes.** A daemon that
is crash-looping answers every third probe. Promoting it on the first
success moves traffic back onto it in time for the next crash, and the
route oscillates — every request lands on whichever daemon is currently
mid-restart. Two successes in a row is the cheapest thing that stops it.

**Priority is static and total.** There is no election, no quorum and no
shared state between daemons. Two hops in one route may not share a
priority number — the loader refuses it. So "who serves eris right now" is
a pure function of (the route table, the health view), and two routers
with the same table and the same health view always agree. When they have
*different* health views they disagree, and that is fine: both D1 and D2
answering eris is a duplicate, not a corruption, and duplicates are
handled below.

**Yielding.** When a higher-priority hop comes back, the lower one is not
told and does not need to be. New requests go up because the router sends
them up. Work already in flight at D2 finishes at D2. `yieldAfterSeconds`
is how long a router keeps an already-open link to a demoted hop before
closing it, so a long poll is not cut in half.

---

## Both directions

A reply travels back down the links the request came up, because each hop
holds its link open until it has answered:

```
   client --req--> gateway --req--> D1
   client <--rep-- gateway <--rep-- D1
```

Server-initiated traffic — a new message for a client that is not asking —
uses the subscription ops that already exist. A router forwards
`qoSubscribe` upstream, remembers which downstream peer owns the
subscription id, and forwards `qoPoll` results back to it. The router
holds a cursor per (peer, subscription), not per peer, so two clients
following the same stream cannot consume each other's position.

```
   client  --qoSubscribe "inbox"-->  gateway  --qoSubscribe-->  D1
   client  --qoPoll      "inbox"-->  gateway  --qoPoll     -->  D1
   client  <--rows, cursor--------   gateway  <--rows, cursor--
```

---

## Rights do not grow by being forwarded

A router connects upstream with **its own** identity. If nothing else were
done, every request it forwarded would arrive with the router's rights,
and a read-only client would gain write access by being routed.

So the forwarded request carries the original subject, and the upstream
applies the **intersection**:

```
   effective rights = rights(router's pin) AND rights(client's subject)
```

The upstream needs the client's subject in its own trust list to grant
anything beyond read. A router cannot vouch for a peer the upstream has
never heard of — it can only ever narrow, never widen. This is stated here
because it is the one property of the whole design that is a security
boundary rather than an availability one.

---

## Edge cases

Each row is a real failure the design has to answer, what it does, and
where.

### Addressing

| # | case | behaviour |
|---|---|---|
| 1 | bare collection name (`notes`) | valid address, target only — every pre-federation client keeps working |
| 2 | unknown app | refused: `no route for x`. Never dropped silently, never guessed |
| 3 | empty instance | matches the `*` route; if several match, the most specific wins |
| 4 | address over 512 bytes | refused at parse |
| 5 | control characters, `..`, non-ASCII in a name | refused at parse |
| 6 | `geist://` with no app | legal — it names a target on whoever answers |

### Routing

| # | case | behaviour |
|---|---|---|
| 7 | loop A→B→A | B finds its own name in `via` and refuses `routing loop` |
| 8 | long chain with no loop | `ttl` decrements per hop; 0 refuses `hop limit` |
| 9 | every hop down | the highest-priority one is tried anyway, marked `probing` — refusing outright would keep a route dead after the daemons behind it recovered. Refused only when none is yet due for a probe, and then with the list of what was tried |
| 10 | hop answers `ok = false` | an **application** error. Health is untouched: one bad request must not demote a healthy daemon |
| 11 | connection refused | immediate failure, no waiting for the timeout |
| 12 | hop hangs | counts as a failure when the timeout expires |
| 13 | reply larger than a frame | existing package assembly; the router forwards packages, it does not reassemble to inspect |
| 14 | two routes with the same `(app, instance)` | refused at load — this is what makes priority total |

### Failover

| # | case | behaviour |
|---|---|---|
| 15 | flapping daemon | `probeSuccesses` consecutive successes before re-promotion |
| 16 | clock skew between nodes | every timer is local and monotonic; peer timestamps are never used for health |
| 17 | two routers disagree about who is up | both may deliver; duplicates are handled, not prevented |
| 18 | duplicate delivery across a takeover | the sink dedupes on `(stream, sender, ordinal)` inside a bounded window |
| 19 | messages lost during a takeover | ordinals are per-stream and monotonic, so a reader sees the gap and can ask again |
| 20 | higher-priority hop returns mid-poll | the open link is kept for `yieldAfterSeconds`; new requests go up immediately |

### Trust

| # | case | behaviour |
|---|---|---|
| 21 | peer pinned for one app reaches another | `TrustedPeer.covers` limits a pin to a set of apps; `*` for the ones that should reach everything |
| 22 | router forwards on a client's behalf | rights are intersected, never unioned — see above |
| 23 | pin file deleted while running | the old trust set is kept and the failure is logged loudly; a reload that cannot read its trust does not silently trust nobody, and does not silently trust everybody |
| 24 | a store is synced to a peer | rows travel decrypted inside an encrypted link, and the peer re-encrypts under its own key. The peer therefore sees plaintext — which is exactly what the pin is deciding |

### Configuration

| # | case | behaviour |
|---|---|---|
| 25 | unknown key in a settings table | error — a typo that is ignored is indistinguishable from a setting that did not work |
| 26 | unknown **name** in a per-entity table (`[friend.alcie]`) | **not** an error: an orphan. Kept verbatim, never applied, reported |
| 27 | roster name with no entry | a default entry is appended, with every option written out |
| 28 | config edited while a daemon runs | reload parses and validates into a new table and swaps only on success |
| 29 | a value of the wrong type | the documented default is used; running on a coerced guess is worse |

### Storage

| # | case | behaviour |
|---|---|---|
| 30 | client and server write the same row | row ids carry a 24-bit node tag, so two nodes cannot mint the same id |
| 31 | follower sees the epoch change | its cursor counts positions and the log was rewritten under it: restart from zero |
| 32 | two clients of one account, one store | the write lease is per store root; the second opens read-only and says so |

---

## What is implemented where

| module | what it owns |
|---|---|
| `geist/address.nim` | the address: parse, render, sanitize, hop rewriting |
| `geist/route.nim` | the route table, hop health, `chooseHop`, TOML loading |
| `geist/link.nim` | a client link that retries and fails over across a route |
| `geist/doc.nim` | object ⇄ TOML/JSON, unencrypted, all options written out |
| `geist/reconcile.nim` | the roster rule: orphans kept, defaults appended |
| `geist/keystore.nim` | where a key actually lives, per platform |
| `src/server/geist_routed.nim` | the router daemon |

None of it is compiled by a program that only writes rows to disk:
`address`, `doc` and `reconcile` are pure and depend on nothing;
`route` and `link` sit in the wire half beside `transport`.
