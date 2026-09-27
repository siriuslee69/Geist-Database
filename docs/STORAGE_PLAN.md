# Geist Storage Plan

Status: **the layout question is settled; the access question is not.**
Phases 0a, 0b, 1, 3 and 5 have shipped — as one per-column model rather
than as the three separate profiles planned here — and phase 6 (a session
that reads without loading everything) is the largest thing still open.
See §7 for the current state of each.

Unlike `DESIGN_RATIONALE.md`, whose numbers were all measured, the
workload figures here are order-of-magnitude estimates for a workload
*class*. Numbers marked **(verified)** come from the code.

This document exists because the storage question was never actually
answered. The previous implementation had 18 presets
(`.geist-legacy/src/geist/config.nim:406`) that differentiated almost
entirely on *transport* — route, replication, tier, ECC — while every one
of them called the same `defaultDatabaseConfig`. Storage layout was a
constant pretending to be a policy.

---

## 1. Where we actually are

**(verified)** `openSessionWithSchema` calls `readCluster` for meta,
journal and entries, and `readCluster` reads every row into memory.
`save()` re-serialises the whole file as a new generation.

So Geist is still an **all-in-RAM database with a seekable format it does
not use** in the session path. `readRowAt`, `seekFixedColumn`,
`seekRange` and the index-only read exist, work, are tested — and are
called by tools (`seek.nim`, the daemon's change check), not by a
session.

That matters for planning: the fixed-width-for-seek-speed argument is
still partly aspirational. What has changed since this was written is
that the *layout* question is settled (§4 shipped as per-column storage),
so what remains here is the **access** question, and §7's phase 6 is the
one that answers it.

---

## 2. Workload scenarios

Estimates, not measurements. "Opaque" means the node cannot decrypt what
it stores.

| # | Scenario | Write int. | Write size | Read int. | Read size | W speed | R speed | Enc | RAM | Disk |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Local app records | minutes | ~1 KB | on open + rare | whole DB | low | low | opt | ample | <100 MB |
| 2 | Secure app / secrets | minutes | ~1 KB | rare | whole DB | low | low | **yes** | ample | <10 MB |
| 3 | Chat / messaging | 0.1–10 s burst | 0.1–2 KB | scrollback | 100s rows | med | med | **yes** | ample | 0.1–10 GB |
| 4 | Live position | 10–60 Hz | ~32 B | subscribe | tiny | high | high | opt | ample | ~0 |
| 5 | Game client state | 30–60 Hz | ~1 KB | on load | whole | high | low | no | ample | <100 MB |
| 6 | Gaming server | 10–60 Hz | ~1 KB | 10–60 Hz ×N | small | high | **critical** | opt | ample | 1–50 GB |
| 7 | Livestream chunks | 0.1–2 s | 64 KB–2 MB | sequential | large | high | high | yes | ample | ring, 1–100 GB |
| 8 | Voice/video call | 20 ms | 1–10 KB | realtime | small | **critical** | **critical** | yes | ample | ~0 (volatile) |
| 9 | IoT sensor (SD) | 1 s–5 min | 16–64 B | rare batch | whole | low | low | opt | **scarce (KB)** | 1–32 GB, wear-limited |
| 10 | IoT gateway | 0.1–1 s | ~1 KB | moderate | ranges | med | med | yes | moderate | 1–100 GB |
| 11 | File/blob transfer | per file | 1 MB–10 GB | per file | large seq | med | high | yes | ample | very large |
| 12 | Archive | weeks (batch) | GB | ~never | large seq | low | low | yes | ample | TB |
| 13 | Backup target | scheduled | 0.1–10 GB | restore only | whole | med | high | yes | ample | TB |
| 14 | Cloud sync | seconds | 1 KB–10 MB | moderate | mixed | med | med | yes | ample | 10 GB–TB |
| 15 | Evidence / history log | seconds | ~0.5 KB | verify, rare | full chain | med | low | yes | ample | unbounded |
| 16 | Decentralized replica | peer-driven | opaque blobs | peer-driven | opaque | med | med | **opaque** | ample | large |
| 17 | Relay routing table | rare | ~200 B | **very high** | tiny | low | **critical** | no | ample | <10 MB |
| 18 | Peer directory | rare | ~200 B | **very high** | tiny | low | **critical** | no | ample | <10 MB |
| E1 | Read-only mmap replica | never | — | constant | random | — | critical | opt | ample | any |
| E2 | DB ≫ RAM (100×) | varies | varies | random | narrow | med | high | opt | **relatively scarce** | TB |
| E3 | Wide sparse schema | moderate | ~2 KB nominal | random | few cols | med | med | opt | ample | large |
| E4 | Blob-dominated metadata | per object | ~300 B row + MB blob | per object | row then blob | low | med | yes | ample | very large |
| E5 | Power-loss-prone embedded | 1 s | ~64 B | rare | whole | low | low | opt | scarce | small |

### The relay is not a blob store

Scenario 17 was originally modelled as opaque store-and-forward with
delete-after-TTL. It is not. A relay stores **routing state** — sender,
receiver, endpoint, last-seen — which is a small hot read-dominated table
identical in shape to the peer directory (18). In-flight payloads stay in
RAM because transfer speed is the point; spilling to disk is an
exceptional path, not the steady state.

This matters more than it looks. See §5.

---

## 3. Derived requirements

| Group | Scenarios | Layout | Overflow | Nulls | Write mode |
|---|---|---|---|---|---|
| **Volatile realtime** | 4, 5, 8 | n/a | none | n/a | `wmVolatile`, RAM ring |
| **Rare-write** | 1, 2, 12, 13, 17, 18 | variable + nulls | none | yes, big win | whole-file rewrite |
| **Scarce RAM** | 9, E5 | fixed | none (every column `colFixed`) | bitmap only | interval batching |
| **Append-heavy** | 3, 6, 10, 15 | fixed | shared file, append-only | bitmap | append + in-place |
| **Blob-dominated** | 7, 11, 14, 16, E4 | either | sidecar *is* the store | minor | per-object |
| **Giant / sparse** | E2, E3 | variable + nulls | shared file | **critical** | varies |

---

## 4. Three profiles

### P1 — Rare-write (the new default)

Variable-width cells with a `u16` length prefix, null bitmap at the head
of each row, whole-file rewrite on save, previous generation retained by
the existing `.b1/.b2/.b3` rotation.

No free list. No compactor. No fragmentation. No padding. Deleting a row
is deleting a row.

Covers the largest group, including both critical-read scenarios (17, 18),
because a <10 MB table is fully resident and read speed is a RAM question.

### P2 — Fixed-width

Per-column declared widths, uniform row size, row *i* at `i * rowBytes`.
Values over their column's cap go to overflow. In-place row rewrite always
fits, so update and delete need no compaction of the data file.

Required by scarce-RAM (streaming reads without an allocator) and wanted
by append-heavy (seekable single-column decryption — see §6).

### P3 — Volatile

Bounded RAM ring buffer. No disk write except on explicit checkpoint.
Layout is irrelevant because nothing is serialised in steady state.

Five of the 18 legacy presets fall here (call, live-position, game, and
partially stream and relay). Currently `wmVolatile` exists in `WriteMode`
**(verified, `src/geist/config.nim:27`)** and nothing implements it.

---

## 5. What the relay correction removes

Hole reuse with 2-bit free flags, the crash-safe free list, and background
compaction were justified by exactly one scenario: a relay churning
through TTL'd blobs.

With the relay reclassified as a routing table, **no scenario in the set
requires a free list.** Chat rarely deletes. The gaming server appends. An
evidence log is append-only by definition. The IoT gateway appends.

Fragmentation reclaim is therefore a **generation rebuild**, which already
exists: write generation *N+1*, swap the manifest, drop *N*. That is the
same mechanism as the key reroll and the same atomic swap point.

**Decision: build no free list.** Revisit only if a real workload shows
delete-heavy churn on a database too large to rewrite.

---

## 6. Shared decisions, independent of profile

### 6.1 Overflow tiers and the reference cell

**(verified)** `encodeRef` (`src/geist/sidecar.nim:131`) writes 118 bytes:

| field | bytes |
|---|---:|
| target | 1 |
| locator length | 2 |
| locator | 66 |
| hash length | 1 |
| hash | 32 |
| size | 8 |
| entryId | 8 |
| **total** | **118** |

The locator is `ab/cd/abcdef…` — the hex rendering of the hash stored
immediately after it, derived deterministically by `sidecarLocator`
(`src/geist/sidecar.nim:58-64`). 66 of 118 bytes re-encode 32 bytes that
are already present.

#### The filesystem sets the tier boundary

On ext4 with default 4 KiB blocks a file occupies whole blocks, so a
100-byte payload costs 4 KiB plus an inode — **40× amplification**.
(`inline_data` exists but is off by default and caps near 156 B; btrfs
inlines to ~2 KB; F2FS inlines by default.) One filesystem block is
therefore the size below which per-file storage stops making sense.

| tier | value size | storage | addressed by |
|---|---|---|---|
| inline | ≤ column cap | in the row | slot offset |
| **packed** | cap … ~4 KiB | shared sidecar cluster | fileId + slot |
| **own file** | ≥ ~4 KiB | own file | hash (= path) |

#### The packed tier is a Geist cluster, not a new structure

A slotted file — directory at the head, payloads after it — is exactly
the shape a `Cluster` already has: fixed-width rows followed by a
variable region. So a sidecar file is a Geist file holding one cluster
with the schema:

```
flags:int | payload:bytes
```

`payload` is a variable slot, so its `(start, len)` pair **is** the
directory entry, the row index **is** the slot number, and compaction is
an ordinary cluster rebuild that recomputes those pairs. `readIndex`,
`readRowAt`, `readCluster`, `sealCluster` and the Merkle tree all apply
unchanged. `ClusterRole` gains `crSidecar`; nothing else is invented.

This deletes most of the bespoke machinery in `sidecar.nim` — the hex
fan-out, the per-value file handling, the separate codec.

#### Why slot, not byte offset

A byte offset is a direct seek but moves on every compaction, so every
referencing row would need rewriting — and *finding* those rows means
scanning every cluster. A slot number is stable: compaction rewrites the
sidecar cluster's own `(start, len)` pairs and no row anywhere changes.

| | offset direct | external table | **in-file directory** |
|---|---|---|---|
| read | 1 seek | RAM lookup + seek | directory read (cacheable) + seek |
| compact | rewrite all referencing rows | rewrite table | rewrite that cluster |
| extra artifact | none | **yes, a 4th file** | none |
| desync risk | none | **yes** | none by construction |

Dead slot numbers are reusable, so the directory is bounded by *peak
live* records, not total ever written.

#### Reference cell sizes

| tier | cell contents | size |
|---|---|---:|
| packed | hash(16) + fileId(2) + slot(4) | **22 B** |
| own file | hash(32) | **32 B** |

Against 118 B that is 5.4× and 3.7×.

The hash width differs by tier for a reason. In the packed tier the
address is explicit, so the hash is **verification-only** and 16 bytes
gives 2¹²⁸ second-preimage resistance. In the own-file tier the hash
**is** the address, so it must resist collisions — 16 bytes would put a
chosen-payload collision search at 2⁶⁴, which is reachable.

#### Deliberate redundancy

Each packed record keeps its own length prefix even though the directory
row already has `(start, len)`. That makes a sidecar file recoverable by
sequential scan if its directory is ever damaged — cheap insurance for a
structure that is now load-bearing.

Adding the hash to the sidecar row itself (so the file self-verifies
without the main database) needs a fixed-width 16/32 B column, which
depends on the width pragma in §6.5. Deferred to that phase.

#### Sealing

When the cluster is sealed, the directory is sealed with it: record sizes
and counts leak information about content. It is small, so decrypting on
open costs nothing. This differs from the main cluster's schema block,
which stays in clear deliberately so `inspect` works without a password.

#### Dedup is deferred

Content-addressing gave the own-file tier automatic dedup; the packed
tier has none, and reintroducing it needs a persistent hash→location map.
**Not in scope.** It belongs in a later module alongside orphan
collection — both are "walk the live set and act on it" passes and should
share one traversal.

### 6.2 Bind overflow into the hash tree

Today `Ref.hash` rides in the *overflow region*, so `sealCluster`'s Merkle
tree over row bytes does not commit to it. The pointer is in the tree; the
payload is not.

Moving the ref into the fixed row closes this: the row's leaf hash
transitively commits to the payload, so verifying the Merkle root verifies
the data file **and** every overflow file, with no second tree.

Verification becomes: check root → read row → fetch file → compare hash.

### 6.3 Null bitmap, not sentinels

One bit per column at the head of the row. A sentinel burns a value out of
the domain; a marker byte spends 8 bits to carry 1.

Saves bytes only under P1 (variable) — under P2 a null cell still occupies
its width. Under P2 it still earns its place for semantics (`""` vs
absent) and skipped decode.

### 6.4 Splitting reuses column groups

Row-splitting shards by row range. Column-splitting should reuse the
**existing** column-group partition (`columnGroupsFor`,
`src/geist/config.nim`), which is already the encryption batching unit —
one partition concept, two purposes.

Full-column scans across many shards need per-shard min/max in the index
to skip non-matching shards. Index cost is **(verified)** 32 B header +
80 B per cluster (`src/geist/format.nim`), so reading 100 shard indexes is
~8 KB.

### 6.5 Per-column widths need a pragma

`maxInline` and `sidecarThreshold` are currently **global**
**(verified, defaults 256 and 1024, `src/geist/types.nim:224-228`)** and
apply to every variable field alike. P2 needs them per column:

```nim
type Note = object
  id*: int
  title* {.width: 128.}: string
  body*: string                    # no width -> always external
```

`fieldPairs` cannot reliably see custom pragmas, so this needs
`getCustomPragmaVal` (verify it works inside a `fieldPairs` loop on Nim
2.2 before committing) or a macro over the type AST. Try the cheap path
first.

`Slot` gains `width: uint32`; offsets stay **derived** by prefix-sum at
schema decode. Width is configuration; offset stays computed — the reason
`Slot.offset` was removed still holds.

### 6.6 Encryption constrains P2 only

Batches are (row range × column group), and `column.nim` gathers a group
as a byte range so the cascade cipher can seek to it. That works only when
group *G* starts at the same offset in every row.

Under P1 (variable) that property is gone, so seekable single-column
decryption degrades to parse-then-decrypt. **P1 should seal whole rows,
not column groups.** P2 keeps column-group sealing.

This is not a defect in P1 — a rare-write database rewrites wholesale
anyway, so per-column seek buys nothing.

### 6.7 Algorithm agility

Everything cryptographic becomes a config choice with a preset default.
Tyr supplies all of it, and every primitive already takes a variable
output length, so digest width is a parameter rather than a fork:

| use | Tyr primitive | widths |
|---|---|---|
| hash | `blake3TyrHash(input, outLen)` | any |
| hash | `sha3TyrHash(input, outLen)` | any |
| hash | `gimliTyrXof(ks, ns, ms, outLen)` | any |
| MAC | `blake3CustomHmac(key, msg, outLen)` | any |
| MAC | `gimliCustomHmac(key, msg, outLen)` | any |
| MAC | `sha3CustomHmac(key, msg, outLen)` | any |
| cipher | `chacha20Xor(key, nonce, counter, input)` | — |
| cipher | `aesCtrXor(k, n, ps, backend)` | — |
| cipher | `gimliTyrStreamXor(ks, ns, input)` | — |
| KDF | `argon2idTyrHash(...)` | any |

New config surface:

```nim
HashKind* = enum
  hkBlake3, hkSha3, hkGimli

GeistConfig:
  contentHash*:      HashKind   ## sidecar / reference verification
  contentHashBytes*: uint8      ## 16 or 32
  treeHash*:         HashKind   ## Merkle leaf and node
  treeHashBytes*:    uint8
  chainHash*:        HashKind   ## cmChained journal links
  cipher*:           CipherKind ## existing
  mac*:              MacKind    ## existing, incl. mkCombined (XOR)
  macBytes*:         uint8      ## 16 or 32
```

#### One request that cannot be granted as asked

XOR-combining two hashes is offered for **MACs** and refused for
**hashes**. `mkCombined` (BLAKE3 ⊕ Gimli) already exists and is sound: XOR
is a valid PRF combiner, so the tag is secure if *either* function is.

Collision resistance does not combine that way. There is no
collision-resistance combiner shorter than concatenation (Boneh–Boyen),
so `blake3(x) xor gimli(x)` carries no proof of collision resistance and
must not be used where collisions matter: content addressing, Merkle
leaves and nodes, journal chain links.

This is not a new decision — `DESIGN_RATIONALE.md` §8 already settled it
("two different combiners, deliberately"). §6.7 keeps that boundary:
`HashKind` offers single algorithms only; `MacKind` keeps the XOR option.

A caller who wants two-function assurance on a *hash* should use
concatenation at full width, which costs 64 B instead of 32. Not offered
until something asks for it.

#### Defaults by preset

| preset | contentHash | bytes | treeHash | cipher | mac |
|---|---|---:|---|---|---|
| `app` | BLAKE3 | 16 | BLAKE3 | none | BLAKE3 |
| `secure-app` | BLAKE3 | 32 | BLAKE3 | cascade | combined |
| `chat` | BLAKE3 | 16 | BLAKE3 | ChaCha20 | combined |
| `iot` | BLAKE3 | 16 | BLAKE3 | ChaCha20 | BLAKE3 |
| `archive` | BLAKE3 | 32 | BLAKE3 | cascade | combined |
| `ledger` | SHA3 | 32 | SHA3 | cascade | combined |
| `stream` | BLAKE3 | 16 | BLAKE3 | ChaCha20 | BLAKE3 |

Rationale for the two outliers: `iot` takes single-function BLAKE3 MACs
because a second MAC pass is real CPU on a constrained part; `ledger`
takes SHA3 because a hash-linked record that outlives the software should
not depend on one hash family, and SHA3's sponge is structurally
independent of BLAKE3's tree.

Validation must reject `contentHashBytes = 16` when the own-file tier is
in use, per §6.1 — there the hash is the address.

---

## 7. Build order

| Phase | Work | Status |
|---|---|---|
| **0a** | `HashKind` + digest widths + per-use config; route every hardcoded `blake3TyrHash` through it | **done** |
| **0b** | Slim `Ref`; move it into the fixed row | **done** (23 B / 33 B, see below) |
| **—** | Ergonomic object API (`Collection[T]`) | **done**, not originally planned |
| **—** | Partial-read API (`seek.nim`) | **done**, not originally planned |
| **—** | Otter benchmark harness | **done**, not originally planned |
| **1** | P1: variable cells + null bitmap + whole-file rewrite | **done** — `collapsed` / `secure-collapsed` presets |
| **3** | Per-column `width` + `Slot.width` + derived offsets | **done** — P1 and P2 collapsed into one per-column model, so this replaced phase 5 rather than preceding it |
| **5** | P2: fixed-width rows | **done** as a *derived* property: an all-`colFixed` schema with collapsing off is dense, and `rowBytes == 0` in the index is how a reader is told |
| **—** | Durable generation swap + write lease | **done**, not originally planned — see DESIGN_RATIONALE §14 |
| **—** | Row identity, update, delete, compaction | **done**, not originally planned — see DESIGN_RATIONALE §15a |
| **—** | Orphan collection (`sweepSidecar`) | **done**; dedup itself still deferred. See §6.1 |
| **2** | P3: implement `wmVolatile` as a bounded RAM ring | not started — the mode exists and simply never persists |
| **4** | Packed tier: `crSidecar` cluster + slot addressing | encoding only |
| **6** | Streaming reads: a session that uses the seekable format instead of loading every cluster | not started — **the largest thing left** |
| **—** | Free list / hole reuse | **not planned.** See §5. |

0a went first because algorithm selection touches every structure the
later phases build; retrofitting it would have meant revisiting all of
them. 0b was worth doing regardless of which profile wins.

**What the implementation did to this plan.** Phases 1, 3 and 5 were
written as three layouts to be chosen between. They shipped as one:
storage moved to the COLUMN (`colFixed` / `colCapped` / `colVariable`),
and the profiles fell out as configurations of it rather than as separate
code paths. That is why phase 5 has no code of its own — see
DESIGN_RATIONALE §12.

Phase 4 is listed as "encoding only": `rtPacked` references encode and
decode at 23 B and `RefTarget` carries the tier, but no `crSidecar`
cluster is written yet, so nothing produces one. The own-file sidecar is
the only escape path in use.

---

## 7a. Corrections the implementation forced

Two claims in the first draft of this document were wrong. Both were
caught by tests or benchmarks rather than by review, which is the argument
for writing them.

**SHA3 is not an extendable-output function.** §6.7 asserted that "every
primitive already takes a variable output length, so digest width is a
parameter rather than a fork". True for BLAKE3 and the Gimli sponge; false
for SHA3, which is a fixed family of 224/256/384/512-bit digests and which
Tyr correctly refuses to run at any other width. `geistHash` now computes
at the nearest standard variant and truncates. Truncation preserves
preimage and second-preimage resistance at the truncated length -- which
is exactly what the packed tier needs -- but not collision resistance, so
`validateGeistConfig` refuses a truncated tree hash.

**The reference cell is 23/33 B, not 22/32 B.** The plan omitted the
discriminant byte. A reference has to say which tier it addresses, and
stealing a bit from `fileId` would buy one byte at the price of a decoding
rule nobody expects. Measured sizes are in §7b.

---

## 7b. Measured

Micron 1100 SATA SSD (non-rotational, ~92% full), i9-13900K, Nim 2.2.10,
`-d:release --mm:orc`. Reproduce with `nimble runBenchmarks`.

**The SSD matters and it is not an NVMe drive.** io figures are a
conservative floor: an NVMe drive or an emptier volume beats them.

### Reference cell

| encoding | bytes | vs legacy | per 1M cells |
|---|---:|---:|---:|
| legacy | 118 | — | 112 MiB |
| own-file (`tag \| hash32`) | 33 | 3.58x | 31 MiB |
| packed (`tag \| hash16 \| fileId \| slot`) | 23 | 5.13x | 21 MiB |

Deriving the path from the hash costs 78 ns, against 66 bytes saved per
cell. Decoding is 17-21 ns.

### Hash families

| | 41 B input | 64 KiB input |
|---|---:|---:|
| BLAKE3 | 511 ns | 107 µs |
| SHA3 | 272 ns | 107 µs |
| Gimli | 281 ns | 224 µs |

**BLAKE3 is the slowest of the three on small inputs** -- about 1.9x
SHA3 -- because its tree setup is fixed cost that a row-sized message
never amortises. At 64 KiB it matches SHA3 and Gimli falls to half speed.
Since almost everything Geist hashes is row-sized, BLAKE3 being the
default is a choice about ubiquity and review, not speed.

Digest width is not a performance lever: BLAKE3 costs 512 ns at 16 B and
506 ns at 32 B. The 16-byte packed reference is chosen for *space*, and
the space saving is the whole justification.

### MAC combiner

| | ns/op | vs single |
|---|---:|---:|
| `mkBlake3` | 2410 | 1.12x |
| `mkGimli` | 2147 | 1.00x |
| `mkCombined` | 4608 | **2.15x** |

The XOR combiner costs what it looks like it costs -- two full MAC passes.
This is the measurement behind `iot` and `stream` taking `mkBlake3`: on a
constrained part, doubling the authenticator to protect against a break in
one of two primitives is not obviously the right trade.

### Write throughput

5,000 rows of a 4-slot fixed schema, one save at the end:

| | rows/s |
|---|---:|
| plain | 3,543,666 |
| cascade + combined MAC | 23,607 |
| plain, `autoSave` per row (200 rows) | 23,004 |

Encryption costs **150x**. The plain figure is bounded by memory and one
160 KiB file write, not by durability, so read it as "the format is not
the bottleneck" rather than as a sustained rate.

`autoSave` rewrites the entire file per row, which lands it at the same
order as full-cascade encryption. That is why `add(openArray[T])` disables
it internally and saves once.

### Partial reads

20,000 fixed rows, 625 KiB file, 272 B index:

| operation | ns/op | vs best |
|---|---:|---:|
| `seekRow`, handle held | 1,283 | 1.00x |
| `seekRow`, index re-read each time | 5,830 | 4.54x |
| `seekObject` -> object | 1,290 | 1.01x |
| `seekFixedColumn` (one column) | 93 µs | 1.00x |
| `seekRange` whole cluster | 807 µs | 8.65x |
| `readCluster` + unpack every object | 941 µs | 10.09x |
| `seekRange(1000, 100)` | 5.4 µs | 1.00x |
| 100 separate `seekRow` calls | 128 µs | **23.81x** |

Two results decide how the API should be used. Holding a `SeekHandle`
across reads is worth 4.5x, because re-reading the index dominates a
single row fetch. And a contiguous window is worth **23.8x** over the same
rows fetched individually -- which is why `seekRange` exists rather than
letting callers loop.

Reading one column is 10x cheaper than materialising every object.

### Text columns

5,000 rows with two text fields, 349 KiB:

| operation | ns/op | vs best |
|---|---:|---:|
| `seekText` (that field's slice only) | 2,688 | 1.00x |
| `seekObject` (row + whole overflow region) | 9,281 | 3.45x |
| `seekColumnBytes` (two bulk reads) | 94 µs | 1.00x |
| `readCluster` + unpack every object | 720 µs | 7.65x |

Reading one text field without pulling the whole overflow region is 3.4x
cheaper, and the gap widens with the size of the region.

### P1 packed rows vs the fixed profile

5,000 rows of an 8-column schema. "Sparse" sets 2 of 8 columns; "dense"
sets all 8.

| | packed | fixed | ratio |
|---|---:|---:|---:|
| dense, file size | 381,126 B | 436,142 B | 1.14x smaller |
| **sparse, file size** | **105,582 B** | **320,582 B** | **3.04x smaller** |
| sparse, read one row | 74 ns | 139 ns | **1.88x faster** |
| sparse, scan all rows | 344 µs | 686 µs | **1.99x faster** |

P1 wins on both axes here, which was not the expected result -- the plan
justified it on write simplicity and expected to *pay* for it in read
speed.

#### Why a packed row is smaller even when nothing is omitted

The intuition that packed stores "the same bytes plus a bitmap", and must
therefore be larger, is wrong -- but not for the reason the sparse column
suggests. Isolating the two effects:

| schema, 5000 rows | packed | fixed | |
|---|---:|---:|---|
| 8 int columns, all non-zero | 69.1 B/row | 64.1 B/row | packed **1.078x larger** |
| 8 text columns, all non-empty | 75.3 B/row | 102.3 B/row | packed **0.736x** |

In the fixed profile a variable field costs an **8-byte (start, len)
pointer inside the row**, plus its payload in the overflow region. In a
packed row the bytes are where the field is, so it costs a **4-byte
length prefix** plus the same payload. That is 4 bytes saved per variable
column per row, and it has nothing to do with nulls.

Packed's own overhead is fixed per row: `ceil(C/8)` bitmap bytes plus a
4-byte offset-table entry.

So with C columns of which V are variable:

```
packed is smaller  iff  4V > ceil(C/8) + 4
```

For C <= 8 that means **two or more variable columns**. At zero variable
columns packed is strictly worse, which the all-int row above shows: it
pays 5 bytes of overhead and saves nothing.

The arithmetic closes on the dense `Wide` case: 4 string columns save
4x4 = 16 bytes, minus 5 bytes overhead = 11 B/row, times 5000 rows =
55,000 B. Measured difference 436,142 - 381,126 = **55,016 B**.

Nulls are a second, independent effect on top: an omitted fixed column
saves its whole 8 bytes and an omitted variable column saves its prefix
and payload. That is what widens 1.14x (dense) to 3.04x (sparse).

P1 is therefore not a universal improvement. It is the right answer for
the rare-write group, for sparse data, and for any schema with two or
more variable columns -- and the wrong answer for a narrow all-fixed
schema, which is exactly the IoT case the workload table assigned to a
fixed profile.

Not measured here, and the reason the fixed profile stays: per-column
seekable decryption. P1 seals whole rows, so it cannot decrypt one column
of one batch without the rest of the row.

### Benchmark methodology note

Otter warms each algorithm within a group, but the first group still pays
one-time costs and charges them to whichever entry runs first: BLAKE3
measured 1683 ns/op as the first entry of the first group and 559 ns/op
for the identical call two groups later. `globalWarmup()` exercises every
primitive before any measurement. Without it the first row of output
carries a 3x error.

---

## 8. Open questions

1. **Remote reads of externalised values.** With refs in rows, a remote
   `get` returns a ref the client cannot resolve. Still open: `qoFetch`
   now exists and returns a row by id, but a row whose capped column
   escaped to the sidecar still arrives as a reference the caller cannot
   follow. The answer is probably a second op that resolves one ref, or
   `qoFetch` resolving them on the way out and paying the size.
2. **Cap defaults for P2.** Should come from the histogram machinery in
   `evaluation/benchmarks/prototypes/proto5/`, run over real length distributions, not
   guessed.
3. **Packed-tier file size cap.** 2 B fileId + 4 B slot allows 65 K files
   × 4 G slots, but the practical limit is how large a sidecar cluster can
   get before compaction becomes expensive. Wants a measurement, not a
   guess.
4. **Convergent encryption**, if dedup ever returns. Hashing the plaintext
   preserves dedup but leaks plaintext equality to anyone who can list
   filenames; hashing the ciphertext breaks dedup. Deferred with dedup
   itself.
5. **Does opaque storage (16) belong here at all?** A node that stores
   sealed blobs it cannot read wants a blob store with TTL, not a
   database. Possibly a thin wrapper over the sidecar rather than a
   preset.

### Settled since the first draft

- **Free list / hole reuse** — dropped (§5), no scenario needs it once the
  relay is a routing table.
- **Dedup vs. safe delete** — safe delete shipped: `sweepSidecar` walks
  every stored version AND every backup slot before removing a payload
  (DESIGN_RATIONALE §15a). Dedup itself is still deferred; when it comes
  it shares that traversal.
- **How a deleted row is represented** — a tombstone in the append log,
  not a hole. That is what let the free list stay dropped: reclaiming
  space is `compact`, which is a generation rebuild.
- **Index vs. offset** — slot number in the cell, `(start, len)` in the
  sidecar cluster's own rows (§6.1).
- **XOR-combined hashes** — refused for content and tree hashing, kept for
  MACs (§6.7).
