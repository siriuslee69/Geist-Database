# The registry: many stores behind one daemon

`geistd` serves one database. That is right for what it is — a
general-purpose daemon pointed at a folder — and wrong for every
application server built on Geist:

| server | one store per |
|---|---|
| Fjord | mailbox, and one per outbound queue |
| Eris | game, plus the account store |
| Avalon | vault |

Each was about to write the same forty lines: a table of open sessions, a
lazy open, a bound on how many stay open, and a rule about which
addresses it will answer at all. Three copies is three different answers
to *what happens at the thirty-third mailbox*.

```
   Query(collection: "geist://fjord/mail/alice/inbox")
        |
        +-- parseAddress                            address.nim
        +-- may this daemon serve "fjord"?          the allow list
        +-- storeFor(home, address) -> a path       layout.nim
        +-- open?  --yes-->  touch it
        |          --no -->  make room, then open
        +-- answerQuery(session, cursors, q, p)     answer.nim
```

An application server becomes configuration rather than code — this is
`fjord-geistd` in full, minus its argument parsing:

```nim
var reg = initRegistry(home, opener, ["fjord"], limit = 32)

step = serveOnce(server,
  proc (q: Query, p: PeerContext): Reply {.gcsafe.} =
    {.cast(gcsafe).}:
      result = reg.registry.serveQuery(q, p),
  200)
```

---

## The allow list is a boundary, not an optimisation

The address **is** the path. A Fjord server that answered
`geist://eris/games/alderreach` would create `db/eris/games/alderreach`
and serve whatever landed there — a general file server for any address
a peer can spell.

```nim
initRegistry(home, opener, [])   # refused, at startup
```

An empty list means **none**, not any, and it is refused when the
registry is built rather than on every request. One of those is a message
an operator reads while deploying; the other is a message a user reads
instead of their mail.

Two layers below it, `parseAddress` has already refused anything
containing `..`, so `storePath` is the only function that turns an
address into a path and it is the one that checks.

---

## Why there is a bound

Ten thousand accounts cannot be ten thousand open databases: each costs a
file handle, a write lease and its resident rows. The registry keeps the
most recently used.

```
   limit = 3, all open, a fourth arrives

   used: [ alice  bob  carol ]        <- least recent first
   ask dave
   used: [ bob  carol  dave ]         alice SAVED, then closed
```

Reopening is cheap. Running out of file handles halfway through a Tuesday
is not.

**Room is made before the new store opens**, not after. Opening first
would peak at `limit + 1` handles, which is precisely the moment a daemon
already at its ceiling falls over.

---

## Eviction saves first

A session is closed only after `save` succeeds. A save that fails leaves
that store open and evicts the next candidate instead:

```
   evict alice   ->  save fails (disk full)  ->  leave open, skip
   evict bob     ->  saved, closed           ->  room made
```

Dropping unsaved rows to stay under a limit trades a resource problem for
a data-loss problem, which is not a trade. And skipping rather than
retrying means one unsaveable database cannot stall every eviction behind
it.

---

## How a store is opened is the application's business

Schema, password and read-only-ness differ per app and per target —
Fjord's `accounts` is not shaped like its `mail`. So opening is a
callback:

```nim
opener = proc (h: GeistHome, a: GeistAddress, path: string,
    S: var Session): tuple[ok: bool, writable: bool, err: string] =
  S = openGeist[StoredMessage](path, appConfig())
  result = (true, true, "")
```

The registry owns **when** a store is open and **which** one. The
application owns **what** it is.

Returning `ok = false` refuses the address, and an application says
*there is no such mailbox* here. Opening a store for a name nobody has
ever used is how a typo becomes a directory.

`OpenStore` is deliberately **not** `gcsafe`: `openSession` is not, and a
type demanding it would be a promise no opener could keep. The cast
belongs at the `serveOnce` boundary, where `geistd` already puts it,
rather than once per application.

**The seam decides the record type**, and the opener is the one place
that mapping lives:

```nim
case readTarget(a.forLeaf()).seam
of fsMail:     S = openGeist[StoredMessage](path, c, password, false)
of fsQueue:    S = openGeist[QueuedMessage](path, c, password, false)
of fsAccounts: S = openGeist[AccountRecord](path, c, password, false)
of fsUnknown:  return (false, false, "not one of Fjord's targets")
```

The handler is `serveQuery`, not `answer` — `answer.nim` is a module in
the same namespace, and a proc sharing its name resolves to the module
the moment an application re-exports both, which every application does
because it needs `answerQuery` too.

---

## Two details that look like implementation and are not

**Slots are `ref`.** `Session` owns a move-only `Secret`, so it cannot be
copied and `Table[string, Session]` cannot exist. A table of refs copies
the pointer and never the session.

**Cursors are per store.** A subscription name means *where I am in this
log*. Two mailboxes with a subscriber called `phone` are two positions,
not one — sharing them would have a subscriber skip whatever the other
store had already passed.

---

## What an operator sees

```
2/32 store(s) open, 41 opened, 39 evicted, 118 hit(s), 2 refused
```

`openKeys` lists them **least recently used first**, because the question
asked of that list is *what is about to be evicted*. A high `evicted`
next to a high `opened` is the symptom of a limit set too low: the daemon
is closing a store and reopening it moments later.
