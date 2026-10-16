# Geist Design Rationale

Every number here was measured on this machine (Nim 2.2.10, `--mm:orc
-d:release`, x86_64) during the rearchitecture, not estimated. The
prototypes that produced them are preserved under
`evaluation/benchmarks/prototypes/`.

The purpose of this file is to answer "why is it like this?" a year from
now without re-deriving anything. Each section states the decision, the
number that drove it, and what the alternative would have cost.

---

## 1. Why the rearchitecture happened at all

Measured on the previous implementation before it was moved to
`.geist-legacy/`:

| | value |
|---|---:|
| source | 48,650 lines / 132 files |
| public procs | 1,019 |
| public types | 282 (182 objects, 48 enums, 52 aliases) |
| `dac_transport.nim` | 2,801 lines |
| `binary_codec.nim` | 2,333 lines, 152 hand-written procs |
| `actCliCommand` | one 708-line proc, 88 `of` branches |
| `level3/` | 16,920 lines (35% of src) |

Eight files out of 132 held 14,810 lines — 30% of all source.

Three structural causes:

1. **The codec was hand-written per type.** ~70 mirrored `writeX`/`readX`
   pairs. Adding a field to one side and not the other is a silent wire
   desync, not a compile error.
2. **The transport re-implemented a dependency.** `dac_transport.nim`
   imported Bifrost and then rebuilt its replay cache, delivery-ack
   handshake, packaging and framing on top.
3. **No middle tier.** `import geist` gave ~40 procs; `import
   geist_database` gave ~700. Nothing in between.

Two concrete defects found by running it, both fixed by the rewrite:

- `nimble exampleSimpleApi` (a task since removed) — the flagship example — crashed:
  `gameConfig()` marks `matchId`/`playerId`/`tick` required, the example
  stored a `Position{player,tick,x,y}`.
- `geistd` loaded a snapshot at startup and never re-read the file
  (`reloadManagedServerFiles` was called only after a backup-sync run),
  while taking a `.lease` the library never checked. A library write
  during a daemon run succeeded silently.

---

## 2. Why rows are packed bytes and not objects

Three candidate in-memory representations were built and measured on the
same 9-field object.

| model | bytes/field | one object | 100k objects | allocations | field read x100k |
|---|---:|---:|---:|---:|---:|
| flat node (all slots present) | 128 | — | — | — | — |
| variant node (`case kind`, `ref Sealed`) | 24 | 337 B | 32 MiB | 4 | 0.56 ms |
| variant + interned name id | 24 | — | 22 MiB | 4 | — |
| **packed row (chosen)** | **~17** | **153 B** | **14 MiB** | **1** | **0.25 ms** |

Layout sizes that drove the middle rows (`sizeof`, ORC):

```
sizeof(string) = 16   sizeof(seq) = 16   sizeof(Sealed) = 64
A flat                         128 B/node   1M nodes = 122 MiB
B variant, inline Sealed        96 B/node   1M nodes =  91 MiB
C variant, ref Sealed           48 B/node   1M nodes =  45 MiB
D variant, ref Sealed + nameId  24 B/node   1M nodes =  22 MiB
```

**Decision: packed rows.** 2.2x smaller than the best node model, one
allocation instead of four, and — the part that mattered more than
memory — field access became a precomputed offset instead of a linear
name scan. The node model made *every* field read O(fields), which would
have been a real problem for the query path.

**Consequence:** there is no node type in the codebase at all. A
schema-driven view of a row is `renderRow` / `fieldOffsets` over the
stored bytes (dynamic.nim), which needs no second representation.

---

## 3. Why `Slot` stores a width and not an offset

An earlier draft cached a per-slot byte offset. It was removed, and the
distinction outlived the layout that prompted it.

An offset is a **prefix sum over widths** — a cached derivation, and one
that a schema change silently invalidates. A width is genuine
configuration: it is what the caller declared, and nothing else can
produce it. So `Slot` carries `{nameId, kind, column, width, onOverflow}`
and offsets are recomputed when the schema is decoded.

That held when every slot was 8 bytes wide and field *i* sat at `i * 8`,
and it still holds now that widths differ per column. The reasoning was
never about the arithmetic being cheap; it was about not storing two
facts that can disagree.

---

## 4. Why the cluster index is worth its bytes

The header is 32 B and each index row is 76 B, **regardless of file
size**. Measured on the observe example: a 16,677-byte file with three
clusters costs **260 bytes** to learn its complete shape — row counts,
row widths, addressing, per-cluster content hashes.

(80 B until format version 4 dropped the `layout` byte. It named a
table-level cell layout that no longer exists, and a stored byte that
duplicates a derivable fact can disagree with it.)

That is what makes passive observation possible. The previous
implementation's socket loop called `toProtocolDatabase(entire db)` and
back on **every single request**; with an index, a follower reads 260 B
and compares hashes.

It also buys:

- **append without rewrite** — append-only clusters extend, and only the
  76-byte index row is rewritten;
- **per-cluster integrity** — corruption localises;
- **random row access** — `at + schemaBytes + i * rowBytes`.

---

## 5. Why there is no overflow region

Variable-length bytes used to live in a region owned by their cluster,
with an 8-byte `(u32 start, u32 len)` pointer in the row. That is gone: a
row now carries its own values inline, length-prefixed.

The region was rejected on the same grounds that had already ruled out a
file-global one — a 4 GiB cap per region, compaction that rewrites more
than it must, and mixed write patterns fragmenting one another — plus two
the per-column model made unavoidable:

1. **A pointer is a second thing that can be wrong.** A row and a region
   have to agree, so every path that copied or sent a row had to copy or
   send the right slice of region with it. `Reply` carried one for exactly
   that reason, and got it wrong first (§16).
2. **The pointer costs 8 bytes whether or not it pays.** A 5-byte title
   cost 8 bytes of slot plus 5 in the region. Inline, it costs 4 + 5.

Chunk-indexed overflow (fixed-size blocks, so a slot stores a block
index) was measured and rejected before either: on representative
short-string data, 16-byte chunks turned 114 B into 176 B (**+54%**) and
8-byte chunks into 144 B (**+26%**). Short strings waste most of a chunk.

What replaced it is per-column storage — `colFixed`, `colCapped`,
`colVariable` (§12) — and, for values large enough that no row wants
them, the content-addressed sidecar. A capped column is the direct
descendant of the widening rule the next section describes: keep it
inline while it fits, escape when it does not.

---

## 6. Why a *rate* of overflow is the wrong signal for a width

This drove the design of `colCapped`, and the reasoning survives it: it
is how anyone choosing a cap width should think.

Measured over 100,000 synthetic rows, inline width 8:

```
  field    w   overflow      avgOver   p95    decision
  title    8   100.0%           5.0     17    keep
  body     8   100.0%         232.4    421    keep
  code     8     3.1%           4.0      6    keep
  payload  8   100.0%          24.0     32    WIDEN to 32
```

`title` overflows on **100% of rows** and must not be widened. `payload`
also overflows 100% and must be. Rate and average overage do not separate
them.

The reason: a value that does not fit pays for its escape *and* for the
value. So a wider column pays only when

```
w'  <  escape cost + mean(len)
```

which is a statement about **variance, not rate**. `payload` is always
exactly 32 bytes; `title` ranges 9..17, so widening it to 24 wastes more
than it saves on most rows.

A **16-bucket length histogram** (~64 B, O(1) update) is what answers
that, not a count and an average: `w' = ceil8(p95)`, adopted only when
`cost(w') < cost(w)`. The automatic widener that would have applied it
was never built — column widths are declared, not inferred — so this is
here as the method, not as a feature.

---

## 7. The ChaCha20 + AES-CTR cascade

**Why a cascade.** XOR of two independent keystreams is a sound
combiner: the result is at least as strong as the stronger leg, so a
break in one primitive does not break the database. The two legs derive
from distinct KDF labels (`geist-cascade-chacha-v1` /
`geist-cascade-aesctr-v1`) so they are genuinely independent.

**Why these two and not Gimli.** Seekability was verified against Tyr:

| algorithm | Tyr entry point | seekable |
|---|---|---|
| ChaCha20 | `chacha20Xor(key, nonce, initialCounter, input)` | yes |
| AES-256-CTR | `initAesCtrState` + counter pre-advance | yes (needs a 128-bit counter add) |
| Gimli | `gimliStreamXor` -> `gimliXofWithDomain(...)` | **no** — sponge squeeze is sequential |

Gimli therefore appears only on the authentication side, where
seekability is irrelevant. Offering it as a cipher would have silently
made single-row reads impossible on those columns.

**Threading threshold: 8 MiB.** Splitting the two legs across cores only
pays on bulk passes; spawning two threads to encrypt a few hundred bytes
is pure overhead. Below the threshold both legs run inline.

---

## 8. Two different combiners, deliberately

This is the subtlety most likely to be "cleaned up" incorrectly later.

| use | property needed | combiner | why |
|---|---|---|---|
| key file and secrets tags | unforgeability (PRF) | BLAKE3-HMAC **XOR** Gimli-HMAC | XOR is a sound PRF combiner: if either is a secure PRF, the XOR is |
| batch tag | unforgeability (PRF) | **keyed BLAKE3 alone**, own key derived from the batch key | one keyed hash per batch; the cascade already doubles the cipher |
| batch digest | detects damage, NO key | **Gimli alone** (unkeyed XOF) | checkable by anyone; a second family beside the BLAKE3 tag |
| Merkle tree | collision resistance | **BLAKE3 alone** | XOR is **not** a sound collision-resistance combiner — a collision in the XOR need not be a collision in either input |

Do not XOR the tree hash to "make it consistent" with the tag.

The batch digest and tag both cover the sealed bytes AND their binding:
position, row lengths, and the cluster's schema and row count. The offsets
and schema stay in clear (section 10), so without the binding the same
sealed bytes could be re-cut at other row boundaries, read under other
field types, or cut short through the index, and every check would pass.
Old ledgers (before the digest and tag existed) are refused, not accepted
without checks: accepting them would let anyone strip the checks off.

---

## 9. Nonce derivation, epoch width, and AAD

**No nonce is stored.** It derives from
`(keyRef, groupId, batchIndex, epoch)`, and `epoch` increments on every
seal. Re-encrypting a batch after an edit therefore cannot reuse a
`(key, nonce)` pair — which for a stream cipher leaks the XOR of both
plaintexts and, for a one-time MAC like Poly1305 or GHASH, the
authenticator key. A stored nonce makes reuse the *natural* mistake; the
format removes the opportunity.

**Epoch is u64, not u32.** Measured wrap for a single hot batch:

```
    10 rewrites/s -> 4971 days      1000 rewrites/s -> 49.7 days
   100 rewrites/s ->  497 days     10000 rewrites/s ->  5.0 days
   u64 at 10k/s   -> 58 million years
```

u32 wraps in seven weeks under `wmVolatile`. That is an operational
timeline, not a theoretical one. The extra 4 bytes cost 11.44 -> 12.97
MiB of ledger per million rows at N=10.

**AAD binds position:**
`databaseId || groupId || batchIndex || epoch || schemaVersion`.
Without it, a batch can be moved to a different ledger row — or a
different column group under the same key — and it decrypts cleanly and
authenticates. `evaluation/tests/test_crypto_batch.nim` covers all three relocations.

---

## 10. Why the row offset table stays in clear

A cluster whose rows vary carries a `rowCount + 1` offset table. The rows
are sealed; the table is not. Three reasons, and they are the same three
that once applied to the variable-slot pointer this section used to be
about:

1. Encrypting it makes the rows un-navigable: you would have to decrypt
   something to learn where the thing you want to decrypt starts.
2. It leaks row **length**, not row **content** — the same trade every
   practical column store makes.
3. It is what preserves single-row seek. Row *r*'s bounds are computable
   from the clear table alone, so one row opens without its neighbours.

`sealPacked` therefore takes the offsets as a separate argument and
leaves them alone. Within a row, nothing is in clear: the bitmaps and the
length prefixes are sealed with the values, so which columns were set
does not leak either.

---

## 11. Batch size N and the Merkle root

Ledger cost, 1M rows, 4 encrypted column groups:

| N | batches | ledger (stored nonce, 38 B) | epoch64, no nonce (34 B) |
|---:|---:|---:|---:|
| 1 | 1,000,000 | 144.96 MiB | 129.7 MiB |
| 10 | 100,000 | 14.50 MiB | 12.97 MiB |
| 20 | 50,000 | 7.25 MiB | 6.48 MiB |
| 100 | 10,000 | 1.45 MiB | 1.30 MiB |
| 1000 | 1,000 | 0.14 MiB | 0.13 MiB |

N=1 is field-level encryption: **145 MiB of ledger to store zero extra
data**. `validateGeistConfig` rejects it with that number in the error
message rather than letting someone discover it in production.

Naively, large N trades ledger size against read amplification. The
Merkle root removes that trade — verification cost for one row:

| N | whole-batch MAC | merkle path (32 B x log2 N) | |
|---:|---:|---:|---|
| 10 | 1000 B | 128 B | 7.8x less |
| 100 | 10000 B | 224 B | 44.6x less |
| 1000 | 100000 B | 320 B | 312.5x less |

Combined with a seekable cipher, one row costs one row of decryption and
a logarithmic proof. **Large N became strictly better except under write
churn**, which is why `archiveConfig` uses N=1024 and `chatConfig` — a
random-access workload — still uses N=16.

**Merkle padding:** leaves are padded to a power of two with a
domain-separated empty leaf. Promoting an odd level instead would make
some levels contribute no proof element, and a verifier replaying a path
cannot know which levels were skipped. This was caught during
implementation, not review.

---

## 12. Preset defaults and where they came from

`cellLayout` is gone. It made storage a property of the TABLE, so a
schema with one large text field and four counters had to choose which of
them to serve badly. Storage is per COLUMN now (`colFixed`, `colCapped`,
`colVariable`), and the old layouts fall out as special cases: `clInline`
is every column fixed with collapsing off, `clTruncate` is `colFixed`
with `onOverflow = opTruncate`.

| preset | identity | N | cipher | reasoning |
|---|:--:|---:|---|---|
| `app` | yes | 64 | none | plain local records |
| `collapsed` | yes | 64 | none | sparse or wide schemas: one bit per unset column instead of its bytes |
| `secure-app` | yes | 32 | cascade | general encrypted records |
| `secure-collapsed` | yes | 32 | cascade | collapsed *and* sealed — the bitmaps are sealed with the values, so which columns were set does not leak either |
| `chat` | yes | 16 | ChaCha20 | random access by message id — a large N would decrypt many neighbours per point read |
| `iot` | **no** | 256 | ChaCha20 | fixed-width telemetry: every column `colFixed`, so the rows stay dense, contiguous and memory-mappable. A reading is never edited, so 16 bytes of identity per row would buy nothing |
| `archive` | yes | 1024 | cascade | sequential scans; the Merkle path keeps point checks logarithmic |
| `stream` | **no** | 8 | ChaCha20 | volatile, history and backups off |
| `ledger` | yes | 128 | cascade | append-only, aggressive backup cadence |

`opTruncate` is never a default and reports a truncation count rather
than dropping bytes silently.

**Why `rowIdentity` is a choice and not a constant.** Two reserved
columns cost 16 bytes per row. On an edited record that is nothing
against what it buys — replacement, removal, and a name a peer also
understands. On a 32-byte sensor reading it is half again as much disk
for operations that workload never performs. The presets that turn it off
are exactly the ones whose rows are only ever appended.

---

## 13. Transport: what Geist owns

Geist defines **two** things: the AME suite layout and the per-tier
masks. Everything else — KEM handshake, identity certificates, framing,
packaging, replay defence, session state, tier transitions — is a Bifrost
call.

Slot order was chosen for a practical reason:

| slots | algorithms | public key size | frame |
|---|---|---:|---|
| 0..3 | ML-KEM-1024, NTRU-HPS4096821, FireSaber, Saber | 992–1568 B | fits one 65507 B DAC frame |
| 4..5 | FrodoKEM-1344-AES, HQC-5 | 21520 B / 7237 B | may need DAC package transfer |
| 6..7 | ML-KEM-768, NTRU-HPS2048677 | 1184 B / 930 B | declared, no tier uses them |

Putting the large KEMs at slot 0 — the obvious "strongest first" choice —
would make **every** handshake at **every** tier pay for them, including a
telemetry sensor's. Tiers 0–3 therefore use only slots 0–3; only
`gtArchive` and `gtRecovery` reach slots 4 and 5.

Families are mixed on purpose: structured lattices (ML-KEM, Saber), NTRU,
plain LWE (FrodoKEM, no ring structure to exploit) and codes (HQC) are
structurally distinct, so one broken family does not collapse a tier.

Until 2026-10-16 slots 4 and 5 held Classic McEliece. That year's
Goppa-code key-recovery papers (ePrint 2026/1630, 2026/1984) and the BSI
note of 29 Sep 2026 moved its estimated cost from ~2^256 to ~2^99..2^148,
so it was replaced. Neither FrodoKEM nor HQC is affected by those papers.

Signature slots are Geist's too — `defaultAmeLayout` is deliberately not
used, because it fixes signatures to Ed25519 + Falcon512. Geist declares
SPHINCS+ (hash-based, survives a lattice break), Dilithium87, Falcon1024
and Ed25519, and every tier selects at least one.

An earlier pinned Bifrost/Tyr stack derived mismatched Frodo secrets, so
Frodo was kept out of the masks. That is fixed; `test_masks_transport`
now round-trips every declared KEM slot through Bifrost to keep it so.

---

## 14. Key lifecycle

**Why a manifest.** Three files (`.ge1st`, `.keys`, `.ledger`) must swap
together. Renaming them one at a time leaves a window where the data is
generation N+1 and the ledger is still N — unrecoverable. Only `current`
is renamed, and `rename()` is atomic on POSIX and via `MoveFileEx` on
Windows.

**Why the protocol is write, fsync, verify, THEN rename.** The manifest
was the atomic swap point from the start, but for a while `save` wrote
the live generation in place, which meant the atomicity had nothing to
protect: a crash mid-write truncated the file every reader was using.

    write .gN+1  ->  fsync  ->  verify  ->  rename current  ->  drop .gN-1
    ^^^^^^^^^^^                             ^^^^^^^^^^^^^^
    invisible to readers                    the ONLY step that
                                            changes what anyone sees

Each step earns its place. Without the **fsync**, "the bytes are in the
file" only means the kernel agreed to remember them, and a power cut
leaves a file whose name says it is complete. Without the **verify**, a
write that stopped halfway gets published and the manifest cannot undo
it. Retaining **N-1** means a manifest that will not resolve always has a
complete set to fall back to, which is what `resolveGeneration` walks
down to. Generations above the live one are debris from an interrupted
save; only the lease holder sweeps them, because to anyone else they
might be a save in progress.

The cost is that the live file name changes on every save. Anything
following a database resolves it through the manifest each time —
`observeStore`, `liveDataPath`, the daemon's reload check. Backup slots
deliberately do NOT: they hang off a generation-free stem, or every save
would start a fresh rotation that never rotates.

**Why a lease and not an flock.** A Geist session holds the database in
memory and republishes it. Two of them do not interleave rows; the second
one's save simply describes a world in which the first one's writes never
happened, and both files are internally consistent, so nothing downstream
can detect it. The lease is a FILE because it must survive being read by
another process on a network filesystem where flock semantics vary, and
because "held by pid 4711 on thinkpad" is a message an operator can act
on. An in-process registry answers the half a lock file cannot: another
`Session` in the same program. A lock file naming our own pid that the
registry never issued is a dead process's leftover, and may be taken
over.

**Rekey is per batch first.** A fresh `keyRef` is a fresh nonce space,
and `keyRef` is already per (batch, column group). An epoch approaching
its high-water mark therefore needs **one batch** re-keyed, not a global
rewrite. Global rekey is reserved for key compromise and policy rotation.

`rekeyBatch` advances the allocator past the previous `keyRef` before
allocating. A ledger loaded from disk can reference a `keyRef` the
in-memory allocator has not caught up to; handing back the same reference
would reset the epoch on an *unchanged* key — precisely the reuse this
design exists to prevent. Found by `evaluation/tests/test_keys_backup.nim`.

**The ledger is public.** Algorithm, keyRef, epoch and root are not
secret; the ledger needs integrity, not confidentiality. Only the key
file is sealed (Argon2id, 3 passes, 64 MiB, 4 lanes). Encrypting the
ledger while loosely protecting the keys is the common inversion of this.

**2-of-2 is intentional and is a footgun.** An encrypted database without
*both* the key file and the ledger is unrecoverable, because the ledger
holds the epochs the nonces derive from. `artifactSet()` exists so
nothing copies one without the others, and `runBackup` refuses to rotate
an incomplete set.

---

## 15. Backup rotation

Rotation shifts from the **oldest** slot down (`.b2 -> .b3`, then
`.b1 -> .b2`, then `current -> .b1`), so an interrupted rotation can lose
at most the oldest copy and never leaves a newer slot half-written.

Defaults: 3 copies, every 64 writes or every 900 seconds, whole set
required. `iotConfig` raises the write trigger to 4096 (high row rate);
`ledgerConfig` lowers it to 16 (durability matters more than IO).

Slots hang off a **generation-free stem** (`main.ge1st.b1`), not off the
live artifact. Naming them after the live file was correct while the file
stayed put; once a save publishes a new generation it produced one `.b1`
per generation, growing forever, nothing ever ageing out, and the
previous rotation orphaned where the sidecar sweep could not see it.

A restore publishes the backed-up bytes as a NEW generation through the
same write-verify-rename protocol, patching the copied header's
generation field on the way. Copying them over the live file would leave
a header contradicting the manifest — which `verifyGeneration` would then
correctly refuse.

---

## 15a. Reclaiming space

Two different kinds of garbage, and they are reclaimed separately because
they become garbage for different reasons.

**Superseded rows** are reclaimed by `compact`, which rewrites the log
keeping the newest non-tombstone version of each id. The trade is stated
plainly: the space comes back, and a follower that had not caught up can
no longer be told what it missed row by row. That is what `logEpoch` is
for.

**Sidecar payloads** are reclaimed by `sweepSidecar`, and the mark phase
is where the danger is. It walks every version in the log — a superseded
version is a reference like any other — AND every backup slot, each
opened in a scratch directory because a sealed slot's rows are encrypted
under its own ledger and cannot be read any other way. A slot that will
not open aborts the sweep rather than risking the payload it might
reference. Backups copy the artifact set and not the sidecar, precisely
because payloads are shared between generations; that sharing is what
makes them cheap and it is also why the sweep has to look inside a slot
before deleting anything.

Order matters: `compact` first, then `sweep`. Nothing is reclaimable
while the log still carries the version that referenced it.

---

## 15b. Row identity

**A position is not an identity.** "Row 7" means a different row after
anything is inserted, replaced or removed, and a peer saying "I changed
this one" needs a name the other side also understands.

Identity is two ORDINARY columns at the front of every row, `__rowId` and
`__flags`, not a side table and not a hidden header. That choice is what
makes the sealing cover them, a seek address them, the wire carry them,
and a backup unable to lose them separately from the row they belong to.
`hasIdentityColumns` derives their presence from the schema, so a file
cannot claim an identity its columns contradict.

**The log and the live view.** An update appends a new version; a delete
appends a tombstone. `LiveIndex` is the newest version of each id, rebuilt
by one pass at open — the same pass that already loads the rows — and
maintained incrementally after that. `entryCount` is what a caller can
see, `logCount` what is stored.

**Why an id is not just a counter.** Two desktops each allocating from
one would both call their first row 1, and a push would land one on top of
the other silently: from the receiver's side, an id it already knows IS an
update by definition. An id is therefore `24-bit node tag | 40-bit
counter`, the tag minted once per database. Ten desktops collide at about
one in four hundred thousand; a trillion rows fit under one tag.

**Why an id is never reused.** The allocator's position is written to the
meta cluster, because "one past the largest stored id" goes backwards
after compaction removes the highest one — and a peer still holding that
tombstone would then delete a different row.

---

## 16. The CLI, the daemon, and what each is allowed to do

**Why the CLI is schema-driven.** `toRow[T]` needs the object type at
compile time, and a CLI does not have it -- the type lives in the user's
program. But the schema is stored in the cluster, so `src/geist/dynamic.nim`
reads it back and works slot-by-slot. That is why `geist list` works on any
database without being rebuilt for it.

**Why `inspect` needs no password.** The header, cluster index and schema
block are stored in clear. Only row bytes and overflow are sealed. So
`inspect` and `schema` answer "what is in here and how big is it" for an
encrypted database whose key you do not hold -- and for one another
process currently owns.

**What the daemon will and will not do.** It accepts ROWS from a peer
(`qoPut`, `qoDelete`) because that is the point of two desktops sharing a
dataset, and a row carries everything needed to apply it. It does not
accept operations that need the at-rest password or rewrite local files:
`init`, `checkpoint`, `compact`, `sweep`, `backup`, `restore` and `rekey`
are direct-mode only. Sending key material across a network boundary to
have a process on the other side write a local file widens the trust
boundary and buys nothing.

**Why rights are per pin.** A request cannot be trusted to describe its
own privileges, so `--trust` and `--allow-write` attach the right to the
PIN the handshake verified. The rights ride into the handler as a
`PeerContext` the request never touches.

**Why a writable daemon takes the lease.** Once it can apply rows it is a
writer like any other, and two writers on one store root do not interleave
rows -- they publish generations describing worlds in which the other's
writes never happened. A read-only daemon takes no lease, so `geist put`
on the same machine keeps working.

**Why a remote write saves before it answers.** `writeMode` governs local
writes, where the caller can see what it has not saved yet and decide. A
peer cannot: it is told the row was stored, and on that basis it never
sends the row again. So `qoPut` and `qoDelete` save before replying,
whatever the mode says -- except `wmVolatile`, which has declared that it
never persists and where "stored" honestly means "for as long as this
process lives".

**Why the receiver names an unidentified row.** Two different things
arrive through `qoPut`. A PEER replicating sends rows with their own ids
and keeps them. A CLIENT adding a row has no database and no id space, so
it sends id 0 and the receiver allocates. The row is rebuilt rather than
patched, because with collapsing on an id of zero is omitted entirely and
writing a real one would have to move a bitmap bit and every byte after
it. A row holding a sidecar reference is refused: its bytes are a pointer
into some other database's sidecar, which means it has an id of its own
and should have sent it.

**Why the daemon reloads.** `reloadIfChanged` costs ONE index read --
header plus cluster index, a few hundred bytes -- and runs before every
request. The previous implementation held a startup snapshot and wrote it
back, silently overwriting anything written underneath. Demonstrated
fixed: a direct `geist put` during a daemon run is picked up on the next
request.

**Three defects the transport surfaced, all real:**

1. *Both sides pinned themselves.* Each generated a fresh identity per run
   and pinned its own key, so the handshake correctly refused. Pinned
   trust needs persisted identities and exchanged pins -- hence
   `src/geist/identity.nim`, `geist keygen` and `geistd --pin-out`.
2. *Trust was dropped after a successful handshake.* `initAmeSession`
   requires `peerTrust` and defaults `peerTrustRequired` to true; not
   forwarding the handshake's result failed every request AFTER the
   handshake had already succeeded.
3. *The reply went to a dead socket.* The client used to close its
   handshake socket and reconnect, changing its source port. It now keeps
   ONE socket for the handshake and everything after it, which is what
   lets the server key a session by source address at all.

**Why a `Reply` no longer carries an overflow region.** It used to: rows
held `(start, len)` pointers into a cluster region, so sending rows
without it produced an index-out-of-bounds on the client, and
`projectRows` had to copy the referenced slices and rewrite the pointers.
Rows are self-contained now -- every value lives in the row that owns it
-- so there is nothing to project, nothing to rewrite, and no way to leak
a neighbouring row's bytes by sending too much region.

**Why the cursor is a log position.** A follower says how many rows it
has and gets the rest. That works because the entry cluster only ever
grows, and because a row carries its own identity: replaying rows in
order reproduces the sender's state whatever mixture of adds, updates and
deletes they were. The one thing a position cannot survive is the log
being REWRITTEN, which is why `compact` bumps `logEpoch` and every reply
carries it.

**Why replies are size-capped before they are packaged.** An answer stops
at ~28 KB of rows and says where to resume, so the ordinary case is one
datagram. Packaging exists for what that cannot help: a single row larger
than a frame. Doing it the other way round -- package everything, let the
receiver reassemble -- would pay chunking, per-chunk sealing and
reassembly on every list.

**Meta and journal sealing.** Each sealed cluster gets its OWN ledger.
Batch coordinates are `(batchIndex, groupId)` and would collide across
clusters otherwise. `sealMeta` and `sealJournal` default to true when a
cipher is selected, because "encrypted" quietly meaning "only your rows"
is discovered at the wrong moment: a journal leaks checkpoint labels and
timing, metadata leaks node and app identity.

---

## 17. Things deliberately not done

- **Manual row intervals per batch.** Explicit `(startRow, endRow)` in
  the ledger instead of `floor(i/N)`. Costs 16 B per ledger row and turns
  O(1) division into a binary search. Revisit if fixed intervals prove
  too rigid.
- **Row dedup.** `putSidecar` deduplicates by content hash; rows do not.
  Repeated `authorId`/`spaceId` values in `chatConfig` would collapse
  well. Wants the same traversal `sweepSidecar` already performs.
- **Columnar layout.** In a dense cluster every row is the same width, so
  storing column *k* for all rows contiguously is a transpose rather than
  a redesign. Would give the column-group config something more to
  control. Not available for a varying cluster at all.
- **`copyMem` for little-endian hosts.** All integers currently go
  through explicit byte loops so files survive x86 <-> ARM (Linux,
  Windows and Android are all targets). Can be swapped behind a
  compile-time endianness check once correctness is settled.
- **mmap for point reads.** A dense cluster is `i * rowBytes` from the
  cluster start and memory-mappable as it stands; nothing in the format
  has to change for it. A varying one needs its offset table first, which
  is one small read.
- **Streaming a cluster instead of loading it.** A session loads every
  row into memory and republishes the whole file on save, which is what
  makes `wmOnChange` quadratic. The seekable format already supports
  reading a row, a column or a window without the rest (`seek.nim`); what
  is missing is a session that uses it. This is the largest single thing
  left undone.
