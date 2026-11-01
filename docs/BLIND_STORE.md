# Blind store <- a place that keeps other people's sealed data and cannot read it

STATE. Steps 1 to 4 of section 10 are built (`src/geist/blind.nim`, 26 checks in
`evaluation/tests/test_blind.nim`). Trim, the `[blind]` settings table and the
benchmark are not (section 9 and 10).

A person sends us their data after sealing it themselves. We keep it, we hand it
back to them on request, and we never hold a key that opens it. This page says how
Geist does that with the pieces it already has.

╭⟢ 1. In plain words 🌊
├⟢ 2. Examples first 🐦‍🔥
├⟢ 3. Definitions 🍣
├⟢ 4. What is on disk ⟡
├⟢ 5. Handing in an entry ❖
├⟢ 6. Asking for entries back ✧
├⟢ 7. Limits (hard and soft) ❧
├⟢ 8. Who does what ◈
╰⟢ 9. Open points ✜

## 1. In plain words

Think of a post-office box.

```
  THE PERSON                               THE BOX (our store)
  ──────────────────────────               ────────────────────────────
  has the key to the lock box
  puts data in a locked case
  signs a label with their stamp  ──────►  checks the stamp against the one
                                           stamp the box was made for
                                           stamp fits  -> shelves the case,
                                                          writes the time
                                           stamp wrong -> sends it back

  shows the stamp and asks         ──────►  checks the stamp again
  "give me everything since 9:00"  ◄──────  hands over the cases, still locked
```

The box never opens a case. It only checks stamps, writes down times and keeps
count of the space used. Anyone can walk past the shelf, and all they see is locked
cases and times.

The "stamp" is a public key. The stamp is made with the person's private key, which
never leaves them. Everything below is this picture in exact terms.

## 2. Examples first

What a program on the box (the host) writes:

```nim
import geist/blind

var
  S: BlindStore = default(BlindStore)
  R: BlindResult = default(BlindResult)
  F: FetchResult = default(FetchResult)

# 1. make a store that belongs to one owner (a BlindOwner = signer name + public keys)
R = S.createBlind(dir, "alice-main", aliceOwner)
if not R.ok: echo R.err

# 2. later runs open it
R = S.openBlind(dir, "alice-main")

# 3. keep one entry: `entryText` is the signed label, `blob` is the locked case
R = S.append(entryText, blob)
for w in R.warnings: echo w          # soft limits only warn

# 4. hand entries back: `requestText` is signed by the owner
F = S.fetch(requestText)
if F.ok:
  for e in F.entries: send(e.note, e.blob)
```

What the owner's program writes (it holds the private key; Geist never does):

```nim
import geist/blind

import tyr/signatures

var
  f: Fields = @[]
  sig: ByteSeq = @[]
  entryText: string = ""
  requestText: string = ""

# the label of a blob that is already sealed; the owner signs its signed text
f = entryFields(storeId, "alice", blob, prev = lastHead, sentAt = nowMs())
sig = sign(dilithium65, textBytes(noteSignedText(f)), secretKey)
entryText = renderNote(f, "dilithium65:" & hexText(sig))
# with several owner keys: one part per key, "alg:hex,alg:hex"

f = fetchFields(storeId, "alice", sinceMs = lastSeen, untilMs = 0, limit = 100,
  askedAt = nowMs())
sig = sign(dilithium65, textBytes(noteSignedText(f)), secretKey)
requestText = renderNote(f, "dilithium65:" & hexText(sig))
```

`entryFields` and `fetchFields` return the fields and do nothing else. `noteSignedText`
and `renderNote` are the ones of `trust.nim`. Signing is done with the keys library
(Tyr) by whoever holds the private key. The owner keeps `lastHead`: it is the head
that `append` leaves in `S.head`, and the owner learns it from the entries it fetches
(the hash of the newest label's signed text).

## 3. Definitions

```
Def. 1 (blind store)  a Geist store whose entries are blobs that Geist cannot
                      read. It keeps no key for them. It has exactly one owner.

Def. 2 (owner)        a signer name plus its public keys, written once into
                      <name>.owner when the store is made. One key, or several
                      (for example ed25519 and dilithium87). With several,
                      EVERY key must sign (the rule of trust.nim, Def. 1).

Def. 3 (blob)         the bytes the owner hands in. Sealed by the owner before
                      they reach us. For us they are a row of unknown bytes.

Def. 4 (entry)        one blob plus its signed label (Def. 5) plus two times.

Def. 5 (label)        a small signed text (a signed note, trust.nim) that says
                      which blob, which store, what came before it, and when
                      the owner sent it.

Def. 6 (head)         the hash of the newest entry's signed text. The next
                      entry must name it as `prev`. The first entry names
                      64 zeros.

Def. 7 (two times)    sentAt: the owner's clock, signed, so it cannot be changed.
                      receivedAt: our clock, never goes backwards, and is the
                      one the index uses. Reason: the owner's clock may be wrong
                      or made up; ours is the order in which things arrived.

Def. 8 (request)      a signed text that asks for entries. Same signing rule as
                      a label, with a different `kind` so the two cannot be
                      swapped for each other (Def. 9).

Def. 9 (kind)         a field inside the signed text: `entry` or `fetch`.
                      A signature made for one kind never verifies as the other.

Def. 10 (soft limit)  a size past which Geist keeps working and says so in
                      `warnings`. Def. 11 (hard limit) is the size past which
                      Geist refuses.
```

## 4. What is on disk

```
  folder/
  ├─ geist.version               \ the folder files, as for any Geist folder
  ├─ geist.permissions           / write = deny stops append, read = deny stops fetch
  ├─ alice-main.owner            who owns the store (Def. 2), with a digest
  ├─ alice-main.ge1st.g1 ...     the index: ONE plain table (below)
  └─ alice-main.blobs/
       └─ ab/cd/abcd...          the blobs, each named by its own hash
```

The blob folder belongs to the blind store alone and is not the index's own sidecar
folder. The index's sweep deletes payloads that no row names, and it would delete
blobs, which the index names only by hash text.

The blobs are NOT sealed again by Geist. They are already sealed, and a second seal
under a key we hold would put a key on our side for no reason. So the index is a
plain (unsealed) table.

The index table has one row per entry:

```
  column       type   what it holds
  ───────────  ─────  ─────────────────────────────────────────────────
  seq          int    0, 1, 2, ... never reused
  receivedAt   int    our clock, milliseconds, never backwards
  sentAt       int    the owner's clock, milliseconds, signed
  hash         text   64 hex: BLAKE3 of the blob
  size         int    blob length in bytes
  note         text   the signed label, kept to hand back (about 9 KB of hex
                      with a Dilithium-87 signature)
```

The blob is not a column: it is the file `<name>.blobs/ab/cd/<hash>`.

Why the blobs are not rows: saving a Geist table rewrites the whole file
(workloads.md, Def. 2). Rows stay small; big bytes stay in files that are written
once and never touched again. The label text is the one larger value left in a row;
a long-text column that moves it out of the row is a later improvement (point 4).

The signed label of an entry, exactly as text (digest = BLAKE3 of the lines above):

```
  geist-note = 1
  hash       = <64 hex: BLAKE3 of the blob>
  kind       = entry
  prev       = <64 hex: the head before this entry>
  sentAt     = 1761812345678
  signer     = alice
  store      = <64 hex: the store id>
  sig        = dilithium87:3c..,ed25519:9e..
  digest     = <64 hex>
```

The signature covers every field except `sig` and `digest`, sorted by name
(`noteSignedText`). A change to any one of them, even the `kind`, makes it fail.

The store id is 32 random bytes written into `<name>.owner` at creation. It sits in
every signed text so an entry made for one store cannot be shelved in another.

## 5. Handing in an entry

```
  append(entryText, blob)
     |
     |  folder says write = deny?             -> refused
     |  label does not parse / digest wrong?  -> refused
     |  kind is not "entry"?                  -> refused
     |  store field is not this store's id?   -> refused
     |  every owner key has a part in sig,
     |  and every part verifies?  (trustOf)   -> else refused
     |  BLAKE3(blob) differs from `hash`?     -> refused
     |  prev differs from the head?           -> refused ("stale head", see 9.3)
     |  blob is over the HARD blob limit?     -> refused
     |  the store would pass the HARD limit?  -> refused
     v
  write the blob file (named by hash), then the index row, then move the head
     |
     v
  result: ok, seq, receivedAt, warnings (soft limits, or a clock far from ours)
```

Order matters: the blob file is written first. A crash then leaves a file nobody
names (the sweep removes it), and never a row that names a missing file.

The same blob handed in twice has the same hash, so the file is kept once. The
second hand-in is still refused, because its `prev` no longer matches the head.

## 6. Asking for entries back

```
  fetch(requestText)
     |
     |  folder says read = deny?               -> refused
     |  signature fails (same rule as above)?  -> refused
     |  kind is not "fetch"?                   -> refused
     |  store field is not this store's id?    -> refused
     |  askedAt is more than 5 minutes from
     |  our clock?                             -> refused, says by how much
     v
  rows with receivedAt >= sinceMs (and < untilMs if given), in seq order,
  at most `limit` rows and at most `byteBudget` bytes (the first row always comes)
     v
  each entry comes back as  (note, blob)  -- unchanged bytes
```

The owner checks what came back with no help from us: every `note` verifies, every
`blob` matches its `hash`, and each `prev` is the hash of the entry before it. If
we dropped or reordered an entry, the chain breaks and the owner sees it.

```
  entry 7 ──prev──► entry 6 ──prev──► entry 5
  a hole at 6 means entry 7's `prev` names a hash the owner never receives
```

A request signed by someone else is refused with the same wording as a wrong
signature. The refusal never says whether the store exists with data in it.

The five-minute window stops a recorded request from being sent again later. Inside
the window, a replay only makes us answer the sender of the replay with the same
sealed bytes, which they cannot open.

## 7. Limits (hard and soft)

Two numbers per limit. Past the soft number the call works and `warnings` says so.
Past the hard number the call is refused.

```
  [blind] in configs/default.toml     soft (warn)       hard (refuse)
  ──────────────────────────────────  ────────────────  ────────────────
  one blob                            warnBlobBytes     maxBlobBytes
  all blobs of a store                warnStoreBytes    maxStoreBytes
  entries in a store                  warnEntries       maxEntries
```

Start values (an app changes them; 0 means no limit):

```
  warnBlobBytes   1 MiB          maxBlobBytes   8 MiB    (nebel Def. 4: above 8 MiB
                                                          needs a streaming transfer)
  warnStoreBytes  256 MiB        maxStoreBytes  1 GiB
  warnEntries     100000         maxEntries     1000000
```

Soft warnings read like: `store alice-main is at 82% of warnStoreBytes (210 of 256 MiB)`.
A warning is given on EVERY call past the line, not once, so a log shows how long it
has been true.

A whole database that is bigger than `maxBlobBytes` is sent as several entries. Which
entries belong to one snapshot is written INSIDE the sealed blobs, so we cannot see
it. The owner finds the newest complete snapshot from the chain order alone.

## 8. Who does what

```
  piece                       job
  ──────────────────────────  ───────────────────────────────────────────────
  owner's program (Nebel)     seals data, hashes the sealed bytes, signs label
                              and request, remembers the head
  Bifrost (AME frame)         carries label + blob + request between machines
  host program (Nebel)        receives, calls append / fetch, returns the result
  Geist: blind.nim            checks the signatures, the hash, the head, the
                              limits and the clock; stores; returns entries
  the app on the host         decides WHO may make a store (IP limits, accounts,
                              anything that fights fake accounts), BEFORE it
                              calls createBlind
```

The double hash, in these terms: the owner hashes the sealed message once for their
own private copy (inside the blob) and once more over the bytes that cross the wire.
Geist only ever sees and checks the OUTER hash (`hash` in the label). The inner one
is inside the blob and is Nebel's and Bifrost's business.

Geist adds no gate on creation. A call to `createBlind` always succeeds if the
folder allows writing. The host app puts its own checks in front of it.

## 9. Open points

1. **Settled: a request has no hash.** `parseNote(text, needHash = false)` reads
   a signed text that stands for no payload. Every other check is the same. The
   `kind` field keeps a label and a request apart (tests "a request cannot be handed
   in as an entry" and "a label cannot be used as a request").
1a. **Limits are an object, not yet a settings table.** `BlindLimits` is passed to
   `createBlind` / `openBlind` (`defaultBlindLimits()`). A `[blind]` table in
   `configs/default.toml` is not wired, so a daemon sets them in code.
2. **Freeing space.** A store that only grows reaches its hard limit. The owner needs
   a signed `kind = trim` request: "drop every entry before seq N", which keeps the
   head and records the hash of the last dropped entry as a new base so the chain
   still checks. Second step, after append and fetch work.
3. **Two devices, one owner.** The head rule lets only one device append at a time:
   the second gets "stale head", fetches the newest head, and signs again. That is
   simple and honest, and it is slow when many devices write at once. Forks (two
   chains) are not supported.
4. **Index size.** The index is rewritten on every save. Rows are small (the long
   texts live in sidecars), but this is not measured for 100,000 entries yet. A
   benchmark under `evaluation/benchmarks/` comes with the first build.
5. **Clock.** A host whose clock is far wrong refuses every fetch (Section 6).
   That is deliberate, and the message says by how much the clocks differ.

## 10. What gets built, in order

```
  step  what                                                   state
  ────  ─────────────────────────────────────────────────────  ─────────────────
  1     <name>.owner file + createBlind / openBlind             built, tested
  2     entryFields, append with all refusals                   built, tested
  3     fetchFields, fetch: signed request, range, byte budget  built, tested
  4     BlindLimits, warnings (settings table not wired)        built, tested
  5     trim (point 2)                                          not built
  6     benchmark of the index at 10^5 entries                  not built
```

All tests are in `evaluation/tests/test_blind.nim` (`nimble testBlind`). Every
refusal in Section 5 and 6 has a test that names it.
