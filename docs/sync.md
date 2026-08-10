# Sync: the two calls, and why there are two

An application server can be dialled. A phone cannot — it is behind a
carrier NAT, it is asleep, and it has a different address every hour. So
replication cannot be pull-only, and it cannot be push-only either.

```
   phone                                 server
   -----                                 ------
   needVia   <-- rows ------------------  what arrived while away
   offerVia  --- rows ------------------> what was written offline
```

Both calls, and the two together are a two-way sync. Neither is enough
alone, and nothing else is required.

| | `need` | `offer` |
|---|---|---|
| direction | pull | push |
| whose log is counted | **the peer's** | **mine** |
| whose epoch guards it | the peer's | mine |
| cursor file | `.geist-cursors` | `.geist-offers` |
| right needed at the far end | `prRead` | `prWrite` |
| carries a schema | **yes**, in the reply | no — see below |

Two files rather than one, because a single table would make *"I have
taken 12 of yours"* and *"you have taken 12 of mine"* the same number.

---

## The cursor is filed under the destination

Not under the hop that answered. This is the whole reason `needVia` is
not just `needRemote` with a different link:

```
   phone  ->  vps-main   (down)
          ->  vps-fjord  (takes over)
```

Both serve `geist://fjord/mail/alice/inbox`, so both produce the same
`destinationKey` and continue the same position. Filing under the
endpoint would make a failover look like a brand-new peer whose log has
to be read from zero — a full mailbox re-sent to a machine that already
had it, at the exact moment the system is already degraded.

If the two hops turn out *not* to be serving the same log, the epoch
check notices and rewinds. That is what it is for.

```
geist://fjord/mail/alice/inbox?ttl=4&via=vps  ->  fjord/mail/alice/inbox
```

`ttl`, `via` and `as` describe a journey. A destination key keeps
exactly the fields `sameDestination` compares — and not by convention:
`destinationKey` is one function, and the registry, the sync cursors and
the offer cursors all call it.

---

## A push carries no schema

The one place a push is **not** the mirror of a pull.

A `qoSync` reply carries the sender's schema, so a database that has
never held a row adopts it. That is what lets a new desktop join a chain
by naming a peer and nothing else.

A `qoPut` carries rows and nothing else. There is nowhere for a schema
to ride along, so a destination that has never held a row refuses every
row that arrives:

```
row from peer does not fit the schema:
row has 40 trailing bytes that no column accounts for
```

That reads like corruption. It is not — it is an empty schema meeting a
packed row.

In practice it costs nothing, because the destination is an application
server that opened its store from a record type it compiled against:
`openGeist[StoredMessage]` knows the shape before the first row exists.
It is written down here because the error does not say so.

---

## Re-sending is safe, and is the design

Every row carries its own identity, so applying one twice has the same
effect as applying it once. Both cursors are therefore saved **after**
the work they describe:

```
   send the rows  ->  peer confirms  ->  record the position
                          ^
                    a crash here re-sends a batch the peer already has,
                    and applyRow skips a version it already holds
```

The other order would skip rows that never arrived anywhere. A position
that lags is recoverable; one that runs ahead is not.

---

## What an operator and a user each see

```nim
mine.pending(root, "geist://fjord/mail/alice/inbox")   # 3
```

`pending` reads the cursor file rather than remembering, so it is
correct after a restart and cannot drift from what `offerVia` will
actually do. It is what a client shows as *3 messages waiting to send*.

A compaction since the last offer makes everything owed again, and
`pending` says so rather than reporting zero and quietly re-sending
later.

---

## A refusal is not a dead hop

```nim
var pushed = mine.offerVia(client, "geist://eris/games/alderreach")
# pushed.ok  == false
# pushed.err == "this daemon does not serve 'eris'"
```

The hop **answered**. Its health is untouched, and the next call to a
`fjord` address uses the same hop. A client that demoted a daemon for
saying *no* would move its traffic to a fallback that will say exactly
the same thing, and would demote the only host holding the data.

That distinction lives in `link.ask` and every sync call inherits it:

```
   the link did not work   ->  noteFailure, try the next hop
   the far end said no     ->  return it, health untouched
```
