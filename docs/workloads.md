# Workloads

What Geist can do today, measured rather than hoped, and which of five
jobs it is the right tool for.

╭⟢ 1. What is actually here 🌊
├⟢ 2. The three ways a choice can be made 🐦‍🔥
├⟢ 3. The ceilings 🍣
├⟢ 4. The five jobs, one by one ⟡
╰⟢ 5. What would have to change ❖

## 1. What is actually here

```text
  +-- STORAGE (import geist) -------------------------------------+
  |  packed rows in clusters, one file per generation             |
  |  columns: fixed / capped / variable, optional null bitmap     |
  |  values >= a threshold move to a content-addressed sidecar    |
  |  rows nameable (rowIdentity) -> set, delete, per-row sync     |
  |  sealed per batch: ChaCha20 / AES-CTR / both XORed            |
  |  MAC per batch: BLAKE3 / Gimli / both XORed                   |
  |  Merkle root per sealed batch -> single-row proofs possible   |
  |  hash-chained checkpoint journal                              |
  |  generations + backup rotation + a write lease                |
  |  optional column-first copy of the rows, for fast search      |
  +---------------------------------------------------------------+
  +-- TRANSPORT (import geist/network) ---------------------------+
  |  Query -> Reply over Bifrost AME sessions on DAC datagrams    |
  |  post-quantum handshake, pinned peers, per-peer rights        |
  |  ops: get put find delete sync fetch subscribe poll           |
  |  payloads over 32,000 B travel as a DAC package               |
  |  one socket, many peers, sessions outlive a request           |
  +---------------------------------------------------------------+
  +-- RELAY (import geist/wire) ----------------------------------+
  |  the same transport with a pipe where the database would be   |
  |  sinks: spool (bounded ring in RAM) / stdout / file / exec    |
  |  a router forwards on a third party's behalf, rights narrowed |
  +---------------------------------------------------------------+
```

**Def. 1 (round trip).** One `send` writes a request and then WAITS for
the reply before returning. Every operation in the list above is shaped
this way. There is no one-way send in Geist today.

This catches people out in one specific place, so it is worth stating
plainly: `geist-relay --follow` is NOT a stream. It is a loop that polls
every `--interval-ms` milliseconds, 1000 by default. Nothing in Geist is
pushed by a server; a reader always asks.

**Def. 2 (whole-file rewrite).** Saving serialises the entire store into
one buffer and replaces the file atomically. Nothing is appended in
place. So the cost of a save is proportional to the size of the
DATABASE, not to the size of the change.

## 2. The three ways a choice can be made

A library that runs on a desktop and on a microcontroller needs three
separate ways to decide "which algorithm", and they are not
interchangeable:

```text
  name              decided        cost in the binary      example
  ----------------  -------------  ----------------------  -------------
  BY BUILD          while          the alternatives are    -d:x=chacha
                    compiling      NOT COMPILED AT ALL
  BY CONSTANT       while          compiled, but this      f(ckChaCha20)
                    compiling      call has no branch
  BY VALUE          while          compiled, one `case`    f(c.cipher)
                    running        per call
```

Bifrost's AME layer has all three and says so in its own header. Here is
where Geist stands:

```text
  facade         state        what exists
  -------------  -----------  ------------------------------------------
  BY BUILD       PARTIAL      Separation is by MODULE, not by flag.
                              `import geist` compiles no network stack;
                              `import geist/wire` compiles no database.
                              Both are proved by a build that reads the
                              generated C file names and fails --
                              `nimble checkModular`, `checkRelay`,
                              `checkRouter`. That is real and it works.
                              But NO flag removes a primitive. There is
                              no -d:geistCiphers=chacha.
  BY CONSTANT    ABSENT       No routine takes a `static` argument and
                              no overload resolves an algorithm at
                              compile time. Generics exist, but over
                              TYPES (`[T: object]`, `when T is string`),
                              never over a chosen value.
  BY VALUE       COMPLETE     GeistConfig decides everything at runtime;
                              14 presets; nameable from configs/default.toml.
```

### What that costs, measured

The storage-only build is the smallest thing Geist can produce -- no
network, no relay, one preset's worth of algorithms actually used. Here
is what the compiler emitted for it:

```text
  $ rm -rf build/nimcache-modular && nimble checkModular
  $ ls build/nimcache-modular/*.nim.c | wc -l
  76 C files, 1,274,360 bytes (debug build)

  primitive   C files   used by the `iot` preset?
  ----------  --------  --------------------------------------------
  chacha20    6         yes
  gimli       4         yes
  blake3      2         yes (the default content and tree hash)
  aes         4         NO
  sha3        2         NO
  argon2      2         NO
  falcon      6         NO -- and this one is the telling case
```

An IoT node that seals with ChaCha20 and authenticates with Gimli still
carries AES-CTR, SHA-3 and Argon2 in its flash.

Falcon is the one worth staring at. It is a POST-QUANTUM SIGNATURE. The
storage half of Geist neither signs nor verifies anything -- there is no
code path in `import geist` that could reach it. It is present because
`crypto/hashing.nim` and `crypto/cipher.nim` say `import tyr`, and
`tyr.nim` is an umbrella that re-exports the whole library:

```text
  tyr.nim exports:  kems  signatures  hashes  macs  kdfs  ciphers
                    otp   aeads  certs/chain  signatures/registry
```

So asking Tyr for BLAKE3 asks it for everything. Two fixes, and they
compose: import the leaf modules Geist actually uses
(`tyr/hashes/blake3`, `tyr/ciphers/chacha20`, …) instead of the
umbrella, and then gate what remains behind a flag.

Nothing is wrong with the code. There is simply no way to say "not
those".

### The shape a fix would take

The pattern Bifrost already uses, applied to `crypto/cipher.nim`,
`crypto/mac.nim` and `crypto/hashing.nim`:

```nim
# geist/crypto/build.nim
const geistCiphers {.strdefine.} = "chacha20,aes"
const hasAes* = "aes" in geistCiphers.split(",")

# geist/crypto/cipher.nim
when hasAes:
  import ./aes_backend
...
  of ckAesCtr:
    when hasAes: raw = aesKeystream(k, ...)
    else: raise newException(ValueError, "this build has no AES-CTR")
```

Excluding a primitive must never change the FORMAT -- a store sealed
with AES stays readable by a build that has AES -- only what a given
binary can run. A store whose header names a primitive this build lacks
must fail at open, loudly, naming the flag.

## 3. The ceilings

Five numbers decide whether Geist suits a job. Every one of them is a
property of the current implementation, not a setting.

```text
  #  ceiling                        value        set by
  -  -----------------------------  -----------  -------------------------
  1  one datagram                   65,507 B     DAC / UDP
  2  payload sent whole, not         32,000 B    geistWholeMaxBytes
     packaged
  3  rows in one reply              ~28,000 B    replyRowBudget
  4  one DAC package                ~78 MB       65,535 chunks x 1,200 B
  5  updates per second per link    1 / RTT      request-and-reply only
```

Two more that are about memory rather than the wire:

```text
  6  a sidecar object is read and written WHOLE. putSidecar takes one
     openArray[uint8]; getSidecar returns one ByteSeq. A 5 GB object
     needs 5 GB of RAM, plus a copy. No chunked path exists.

  7  a save rewrites the whole store. The practical database size is
     therefore bounded by RAM, and write cost grows with the database.
```

Where ceiling 4 comes from, since it is the surprising one:

```text
  DacPackageManifest.dataCount : uint16   -> at most 65,535 chunks
  DacPackageChunk.chunkId      : uint16
  Geist's packageDefaults()    : dscCleanLan -> chunkBytes = 1,200

  65,535 x 1,200 = 78,642,000 bytes ~ 78 MB per transfer
```

The chunk size is 1,200 because a chunk must survive a real network's
MTU. Raising it to 32,768 (the same-room profile) would reach ~2 GB per
package and would fragment on any path between two buildings.

## 4. The five jobs, one by one

```text
  job                          verdict         preset
  ---------------------------  --------------  ------------
  cloud sync                   FITS            cloud-sync
  simplistic blockchain        FITS, scoped    chain
  decentralized hosting        FITS to ~78 MB  host
  position streaming           FITS on a LAN   live
  video streaming              DOES NOT FIT    --
  bulk files > several GB      DOES NOT FIT    bulk (local only)
```

### Cloud sync — fits

This is the job Geist was built around and it shows. `qoSync` carries a
log position and the server's epoch; a follower that has been away asks
from its cursor and is told what it missed. An epoch change means the
log was rewritten and the follower restarts from zero. `qoSubscribe` and
`qoPoll` do the same with the cursor kept on the server. Rows carry
their identity, so a change travels as that row.

What to know: ceiling 3. Catching up is many round trips of ~28 KB each,
and each one blocks. A million-row backlog is not a single transfer.

### Simplistic blockchain — fits, if scoped honestly

```text
  what you get                        what you do NOT get
  ----------------------------------  ----------------------------------
  hash-chained checkpoints            per-ROW chaining (rows are covered
  (parentHash links each to the        by their batch's Merkle root, not
   one before)                         by a chain of their own)
  a Merkle root per sealed batch      a proof API -- merkleProof lives in
                                       crypto/mac.nim and no session-level
                                       call hands you a path for a row
  replication by log position         consensus, fork choice, or any rule
                                       for picking between two divergent
                                       logs. There is none, anywhere.
  pinned-peer identity per writer     anonymous or permissionless writers
```

So: right for a tamper-evident shared record among machines that already
hold each other's pins. Wrong for anything that must survive a
participant lying, because nothing here adjudicates that.

### Decentralized hosting — fits up to ~78 MB an object

The sidecar is content-addressed: a value at or above the threshold
becomes a file named by its own hash, two machines holding the same
object agree on its name without coordinating, and a corrupted copy is
caught by hashing it. The router forwards on a third party's behalf and
narrows rights to the intersection of the router's and the subject's.

Two gaps. Ceiling 4 caps an object at ~78 MB over the wire. And
`discoversPeers` is a field on `GeistConfig` that **nothing reads** --
there is no peer discovery; peers are pinned by an operator, by hand.

### Position streaming — fits on a LAN; video does not

Ceiling 5 is the whole story. `send` blocks for a reply, so the update
rate is bounded by the round trip:

```text
  round trip   updates/second   good for
  -----------  ---------------  ------------------------------------
  1 ms         ~1000            same machine
  5 ms         ~200             same building -- comfortable at 50 Hz
  20 ms        ~50              same country -- marginal
  80 ms        ~12              intercontinental -- no
```

Video is a different answer, and it is no. A 1080p stream is megabytes
per second that must not wait for an acknowledgement per frame; this
transport waits for one per message and caps a reply at 28 KB. Carry the
video on a transport built for it and keep the metadata in Geist.

### Bulk files over several GB — does not fit yet

Three independent blockers, none of them a setting:

```text
  1. putSidecar / getSidecar hold the whole object in RAM (ceiling 6)
  2. one transfer tops out at ~78 MB (ceiling 4)
  3. a save rewrites the whole store (ceiling 7)
```

`bulkConfig` is still worth having: it is correct for many-megabyte
objects on ONE machine, and it configures the store the way a
future streaming path would want it. It does not make a 5 GB transfer
work, and its doc comment says so.

## 5. What would have to change

In the order that unlocks the most per unit of work:

```text
  1  Streaming sidecar I/O. putSidecarStream / getSidecarStream over a
     File with incremental hashing. Unblocks ceiling 6, and is contained
     to sidecar.nim. This is the single highest-value change here.

  2  Multi-package transfers. A name, a part count, and a part index
     above the DAC package layer, so an object larger than ~78 MB is a
     sequence of packages that reassemble. Unblocks ceiling 4.

  3  One-way send. A `push` that does not wait for a reply, for updates
     whose value expires before an acknowledgement is worth having.
     Unblocks ceiling 5 for position streaming; does NOT make video
     viable on its own.

  4  Leaf imports instead of the `tyr` umbrella, then build-time
     primitive gating (section 2). Does not unlock a workload -- it
     shrinks the binary, which is what matters on a small part. The leaf
     imports alone are cheap and should drop Falcon, and probably more,
     out of a storage-only build on their own.

  5  A session-level Merkle proof call. `proofFor(session, rowId)` and
     its verifier, so the roots the store already computes are reachable
     without going through crypto/mac.nim by hand.

  6  Incremental save. The largest change on this list by far, and the
     one that lifts ceiling 7. Probably its own project.
```
