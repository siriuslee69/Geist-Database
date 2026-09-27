## ---------------------------------------------------------------------
## Config <- composable presets for storage, crypto, sidecar and backup
## ---------------------------------------------------------------------
##
##   named preset -> ordinary GeistConfig -> optional caller overrides
##                                      `-> openGeist / connect / serve
##
## The preset -> normalize -> validate shape is carried over deliberately:
## it was the best-designed part of the previous implementation. What is
## new are the knobs the rearchitecture introduced -- column policy, batch
## geometry, cipher/mac selection, sidecar threshold, backup rotation.
##
## Two independent questions, and a preset normally answers both:
##
##   WHERE a value lives   -> per column, via `columnPolicy` + `autoCollapse`
##   WHEN state is flushed -> per database, via `writeMode`
##
## Neither is decided per table any more. There used to be a `cellLayout`
## here answering the first question for every column at once; it was
## removed once columns could answer it individually.

import std/strutils

import runePragmas
import ./types
import ./backup
import ./crypto/batch
import ./crypto/hashing

export hashing

type
  WriteMode* {.role: configurator, tag: "config|db|types".} = enum
    ## When pending state reaches disk. Orthogonal to column policy.
    ## `Session.maybeFlush` is what acts on this, after every mutation.
    ##
    ##   wmOnChange  every mutation is flushed immediately
    ##   wmInterval  flushed once `writeIntervalSeconds` have passed
    ##   wmManual    only an explicit `save`, plus one on `close`
    ##   wmVolatile  never automatically, and `close` discards
    ##
    ## A flush rewrites the WHOLE file, so wmOnChange is quadratic in the
    ## row count over the life of a database. It is right for a handful of
    ## records that must survive a crash, and wrong for bulk loading --
    ## which is why it is not the default.
    wmOnChange, wmInterval, wmManual, wmVolatile

  TransposeMode* {.role: configurator, tag: "config|db|types".} = enum
    ## When the column-first copy of the entry rows is rebuilt.
    ##
    ##   tmNone      never; the store is row-major only
    ##   tmOnSave    with every save -- never stale, slowest writes
    ##   tmInterval  at most every `transposeEverySeconds`
    ##   tmManual    only when asked, so it may be stale and says so
    ##
    ## The copy is DERIVED and is rebuilt whole, never patched: a column
    ## file that tried to apply one row's worth of change would have to
    ## move every later value of every varying column. Rebuilding is also
    ## what makes "which one is newer" a comparison of two generation
    ## numbers rather than a merge.
    tmNone, tmOnSave, tmInterval, tmManual

  ColumnPolicy* {.role: configurator, tag: "appApi|config|db|types".} = object
    ## One column's storage override, named by field.
    ##
    ##   field:      dotted name, matching the schema's own naming
    ##   column:     colFixed / colCapped / colVariable
    ##   width:      required by colFixed and colCapped, ignored otherwise
    ##   onOverflow: colFixed only; opError unless stated
    ##
    ## Naming a column that the schema does not have is an ERROR rather
    ## than a no-op: a typo in a width is otherwise indistinguishable from
    ## a policy that silently did not apply.
    field*: FieldName
    column*: ColumnKind
    width*: uint32
    onOverflow*: OverflowPolicy

  GeistConfig* {.role: configurator, tag: "appApi|config|db|types".} = object
    name*: string
    ## ---- storage layout ----
    ## Storage is chosen per COLUMN, not per table. `columnPolicy` names
    ## the columns that want something other than the default derived from
    ## their Nim type, and `autoCollapse` turns on the null bitmap for the
    ## whole schema.
    autoCollapse*: bool
    columnPolicy*: seq[ColumnPolicy]
    sidecarThreshold*: uint32
    keepHistory*: bool
    ## rowIdentity: give every row two reserved leading columns, `__rowId`
    ## and `__flags`, so it can be replaced and removed by name instead of
    ## by position. 16 bytes per row.
    ##
    ## On for anything a person or a peer edits. Off for append-only
    ## streams -- telemetry is never updated, and 16 bytes on a 32-byte
    ## sensor row is half again as much disk for a feature that workload
    ## does not use. Without it `set`, `delete` and per-row sync are not
    ## available: there is nothing to name a row with. See rowid.nim.
    rowIdentity*: bool
    ## ---- write scheduling ----
    ## writeIntervalSeconds applies to wmInterval only, and is the LONGEST
    ## a write may go unflushed -- not a timer. Nothing runs in the
    ## background; the check happens on the next mutation, or whenever a
    ## caller invokes `maybeFlush` itself.
    writeMode*: WriteMode
    writeIntervalSeconds*: uint32
    ## ---- hashing ----
    ## Three call sites, selected independently because they need different
    ## properties. `contentHash` verifies (and in the own-file tier also
    ## addresses) overflow payloads; `treeHash` builds Merkle leaves and
    ## nodes; `chainHash` links cmChained journal rows.
    ## None of them may be an XOR combiner -- see crypto/hashing.nim.
    ##
    ## contentHashBytes applies to the PACKED tier only, where the address
    ## is an explicit (fileId, slot) pair and the hash therefore only has
    ## to resist second preimages. The own-file tier ignores it and always
    ## uses the full width, because there the hash IS the path: truncating
    ## it would make two different payloads landing on one file a 2^64
    ## search rather than 2^128.
    contentHash*: HashKind
    contentHashBytes*: uint8
    treeHash*: HashKind
    treeHashBytes*: uint8
    chainHash*: HashKind
    ## ---- encryption ----
    cipher*: CipherKind
    mac*: MacKind
    macBytes*: uint8
    batchRows*: uint32
    columnGroups*: seq[seq[FieldName]]
    rekeyAtEpoch*: uint64
    ## sealMeta/sealJournal: the entry cluster is always sealed when a
    ## cipher is selected. These extend that to the metadata and the
    ## hash-chained journal. Both default to true, because "encrypted"
    ## silently meaning "only your rows" is the kind of surprise that is
    ## discovered at the wrong moment -- a journal leaks checkpoint
    ## labels and timing, and metadata leaks node and app identity.
    ## Turn them off only when a reader must inspect those clusters
    ## without holding the key.
    sealMeta*: bool
    sealJournal*: bool
    ## ---- durability ----
    backup*: BackupPolicy
    ## ---- fast search ----
    ## transpose: keep a second, column-first copy of the entry rows beside
    ## the store, so a search over one column reads that column instead of
    ## every row. It is DERIVED: the row-major generation stays the truth,
    ## and losing the copy costs a rebuild rather than data. See
    ## transpose.nim for the file and what it excludes.
    ##
    ## The cost is on the write side, which is why this is off by default:
    ## `tmOnSave` rewrites the whole column file on every save.
    ##
    ##   tmNone      row-major only
    ##   tmOnSave    rebuilt with every save; never stale, slowest writes
    ##   tmInterval  rebuilt at most every transposeEverySeconds
    ##   tmManual    rebuilt only when asked; may be stale, and says so
    transpose*: TransposeMode
    transposeEverySeconds*: uint32
    ## ---- transport ----
    ##
    ## NEITHER OF THESE IS READ BY ANYTHING. They are set by `baseConfig`
    ## and no code in this repository ever looks at them, which Otter
    ## reports as two dead configurator fields. They are left in place,
    ## named and documented as inert, rather than deleted, because both
    ## name a decision Geist genuinely has to make eventually and a reader
    ## who finds them should know which:
    ##
    ##   transferTier   which AME strength a store's own traffic opens at.
    ##                  Today the tier comes from `[transport] startTier`
    ##                  in configs/default.toml, which is per PROCESS, not per
    ##                  store. A machine serving one public database and
    ##                  one private one cannot currently ask for different
    ##                  strengths for each.
    ##   discoversPeers whether a node looks for peers rather than being
    ##                  handed their pins by an operator. There is no
    ##                  discovery in Geist at all; every peer is pinned by
    ##                  hand. `docs/workloads.md` lists this under what
    ##                  decentralized hosting still lacks.
    ##
    ## Setting either of them today does nothing. If you are wiring one
    ## up, that is the right moment to delete this comment.
    transferTier*: uint8
    discoversPeers*: bool

proc fixedColumn*(field: FieldName, width: uint32 = defaultFixedWidth,
    onOverflow: OverflowPolicy = opError): ColumnPolicy {.role: configurator,
    tag: "appApi|config|db".} =
  ## field/width/onOverflow: an exact-width column that never externalises.
  ## Good for integers, timestamps, enums and identifiers that live outside
  ## Geist, where a ceiling is known and dense storage is wanted.
  result = ColumnPolicy(field: field, column: colFixed, width: width,
    onOverflow: onOverflow)

proc cappedColumn*(field: FieldName,
    width: uint32 = minCappedWidth): ColumnPolicy {.role: configurator,
    tag: "appApi|config|db".} =
  ## field/width: an exact-width column that keeps short values inline and
  ## sends long ones to the sidecar, storing the reference in the same
  ## space. Width is raised to `minCappedWidth` if a caller asks for less,
  ## because below that the reference would not fit.
  result = ColumnPolicy(field: field, column: colCapped,
    width: max(width, minCappedWidth), onOverflow: opError)

proc variableColumn*(field: FieldName): ColumnPolicy {.role: configurator,
    tag: "appApi|config|db".} =
  ## field: a length-prefixed column with no ceiling. The default for text
  ## and bytes, so this is only needed to override a narrower policy.
  result = ColumnPolicy(field: field, column: colVariable)

proc baseConfig(name: string, c: CipherKind): GeistConfig {.role: configurator,
    tag: "appApi|config|db".} =
  ## name: preset label retained for diagnostics.
  ## c: default cipher for this workload.
  result.name = name
  result.sidecarThreshold = defaultSidecarThreshold
  result.keepHistory = true
  # Identity on by default: a database whose rows cannot be changed or
  # removed is a log, and most callers want a database. Presets whose
  # workload really is a log turn it off and save the 16 bytes.
  result.rowIdentity = true
  # Manual by default. A flush rewrites the whole file, so flushing per
  # mutation is quadratic; a default that quietly does that would make
  # Geist look slow for the ordinary case of writing many rows and then
  # saving. Presets whose workload genuinely wants otherwise say so.
  result.writeMode = wmManual
  result.writeIntervalSeconds = 5'u32
  result.contentHash = hkBlake3
  result.contentHashBytes = uint8(shortDigestBytes)
  result.treeHash = hkBlake3
  result.treeHashBytes = uint8(fullDigestBytes)
  result.chainHash = hkBlake3
  result.cipher = c
  # Gimli is the default authenticator: measured 2147 ns/op against
  # BLAKE3's 2410 and the XOR combiner's 4608 (docs/STORAGE_PLAN.md 7b).
  # It is the fastest of the three on row-sized messages and the cheapest
  # on a constrained part, which is where a MAC pass is felt. Presets that
  # want two independent primitives opt into mkCombined explicitly.
  result.mac = mkGimli
  result.macBytes = uint8(fullDigestBytes)
  result.batchRows = defaultBatchRows
  result.rekeyAtEpoch = defaultRekeyAtEpoch
  result.sealMeta = c != ckNone
  result.sealJournal = c != ckNone
  result.backup = defaultBackupPolicy()
  result.transferTier = 2'u8
  result.discoversPeers = true

proc normalizeGeistConfig*(c: GeistConfig): GeistConfig {.role: configurator,
    tag: "appApi|config|db|read".} =
  ## c: caller-composed configuration normalized before use.
  result = c
  if result.name.len == 0:
    result.name = "custom"
  if result.sidecarThreshold == 0'u32:
    result.sidecarThreshold = defaultSidecarThreshold
  if result.writeIntervalSeconds == 0'u32:
    result.writeIntervalSeconds = 5'u32
  if result.batchRows == 0'u32:
    result.batchRows = defaultBatchRows
  if result.rekeyAtEpoch == 0'u64:
    result.rekeyAtEpoch = defaultRekeyAtEpoch
  if result.cipher == ckNone:
    result.sealMeta = false
    result.sealJournal = false
  if result.contentHashBytes == 0'u8:
    result.contentHashBytes = uint8(shortDigestBytes)
  if result.treeHashBytes == 0'u8:
    result.treeHashBytes = uint8(fullDigestBytes)
  if result.macBytes == 0'u8:
    result.macBytes = uint8(fullDigestBytes)

proc validateGeistConfig*(c: GeistConfig): tuple[ok: bool, err: string] {.
    role: sanitizer, tag: "appApi|config|db|read".} =
  ## c: configuration checked at the public API boundary.
  var
    n: GeistConfig = default(GeistConfig)
  n = normalizeGeistConfig(c)
  if n.batchRows == 1'u32 and n.cipher != ckNone:
    return (false, "batchRows = 1 is field-level encryption: it costs about " &
      "145 MiB of ledger per million rows on four column groups. Set it " &
      "explicitly above 1, or disable encryption.")
  if n.backup.enabled and n.backup.copies == 0'u8:
    return (false, "backup is enabled but keeps zero copies")
  # Volatile means the data is never written unless a caller asks. A backup
  # policy is a promise to write it on a schedule, so holding both is a
  # contradiction that would otherwise be discovered as "my volatile
  # database left files behind".
  if n.writeMode == wmVolatile and n.backup.enabled:
    return (false, "writeMode = wmVolatile never persists on its own, but " &
      "backups are enabled; disable one of the two")
  if n.writeMode == wmVolatile and n.keepHistory:
    return (false, "writeMode = wmVolatile discards on close, so a journal " &
      "of checkpoints would be discarded with it; set keepHistory = false")
  if n.cipher == ckNone and n.columnGroups.len > 0:
    return (false, "column groups are configured but no cipher is selected")
  # A transposed copy is plaintext columns beside a sealed file, which is
  # not a smaller leak than the file itself -- it is the same values with
  # the grouping made obvious. Refusing is the only honest answer until
  # the copy can be sealed with the batch geometry the store uses.
  if n.transpose != tmNone and n.cipher != ckNone:
    return (false, "transpose keeps a plaintext column copy beside the " &
      "store, so it cannot be combined with encryption at rest. Use " &
      "transpose = tmNone with a sealed preset, or an unsealed preset " &
      "for the search copy.")
  if n.transpose == tmInterval and n.transposeEverySeconds == 0'u32:
    return (false, "transpose = tmInterval needs transposeEverySeconds; " &
      "zero would rebuild the column copy on every save, which is tmOnSave")
  if not validDigestBytes(int(n.contentHashBytes)):
    return (false, "contentHashBytes must be " & $shortDigestBytes & " or " &
      $fullDigestBytes & ", got " & $n.contentHashBytes)
  if not validDigestBytes(int(n.treeHashBytes)):
    return (false, "treeHashBytes must be " & $shortDigestBytes & " or " &
      $fullDigestBytes & ", got " & $n.treeHashBytes)
  if not validDigestBytes(int(n.macBytes)):
    return (false, "macBytes must be " & $shortDigestBytes & " or " &
      $fullDigestBytes & ", got " & $n.macBytes)
  # Merkle leaves and journal links must resist collisions, not merely
  # second preimages: a 16-byte tree digest puts a birthday attack at 2^64.
  if int(n.treeHashBytes) != fullDigestBytes:
    return (false, "treeHashBytes must be " & $fullDigestBytes &
      ": a Merkle tree needs collision resistance, and 16 bytes puts that " &
      "at 2^64")
  result = (true, "")

proc appConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|db".} =
  ## Ordinary local application records, unencrypted.
  result = baseConfig("app", ckNone)
  result = normalizeGeistConfig(result)

proc collapsedConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|db".} =
  ## Rare-write records with collapsing on. Every zero or empty field
  ## costs one bit instead of its bytes, which is the right trade for a
  ## sparse or wide schema written rarely and read whole.
  ##
  ## Collapsing makes rows vary in length, so the cluster carries a
  ## `rowCount+1` offset table -- 4 bytes per row -- and loses arithmetic
  ## addressing. Worth it whenever more than a few columns are typically
  ## unset; not worth it for a dense narrow schema.
  result = baseConfig("collapsed", ckNone)
  result.autoCollapse = true
  result = normalizeGeistConfig(result)

proc secureCollapsedConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db".} =
  ## Collapsed records with the cascade at rest. Sealing covers the
  ## bitmaps as well as the values, so which columns were set does not
  ## leak.
  result = baseConfig("secure-collapsed", ckCascade)
  result.mac = mkCombined
  result.autoCollapse = true
  result.batchRows = 32'u32
  result.contentHashBytes = uint8(fullDigestBytes)
  result = normalizeGeistConfig(result)

proc secureAppConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db".} =
  ## Local application records with the full cascade at rest.
  result = baseConfig("secure-app", ckCascade)
  # Two structurally independent primitives, deliberately: this preset
  # exists for maximum assurance, and the 2.15x cost of the combiner is
  # the point rather than an oversight. The default is mkGimli.
  result.mac = mkCombined
  result.batchRows = 32'u32
  result.contentHashBytes = uint8(fullDigestBytes)
  result = normalizeGeistConfig(result)

proc chatConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|sync".} =
  ## Encrypted messaging. Random access by message id, so the batch stays
  ## small: a large N would decrypt many neighbours for every point read.
  result = baseConfig("chat", ckChaCha20)
  result.batchRows = 16'u32
  result.columnGroups = @[@["body"], @["authorId", "spaceId", "sentAt"]]
  result.keepHistory = true
  result = normalizeGeistConfig(result)

proc iotConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|db|stream".} =
  ## Fixed-width telemetry. Leave every column `colFixed` and collapsing
  ## off and the schema stays dense: rows are contiguous, addressable by
  ## arithmetic, and there is no offset table to carry.
  ##
  ## Flushed at most every 5 seconds rather than per reading, so a sensor
  ## writing at 10 Hz costs one file write per 50 samples instead of 50.
  ## The window is also the exposure: a crash loses up to 5 seconds.
  result = baseConfig("iot", ckChaCha20)
  result.batchRows = 256'u32
  # A reading is never edited or removed, so 16 bytes of identity per row
  # would buy nothing. This is what keeps a telemetry row dense.
  result.rowIdentity = false
  result.writeMode = wmInterval
  result.writeIntervalSeconds = 5'u32
  result.keepHistory = false
  result.backup.everyNWrites = 4096'u32
  result = normalizeGeistConfig(result)

proc archiveConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|storageIo".} =
  ## Scan-heavy long-term storage. Large batches are cheap here because
  ## reads are sequential and the Merkle path keeps point checks logarithmic.
  result = baseConfig("archive", ckCascade)
  result.mac = mkCombined
  result.batchRows = 1024'u32
  result.contentHashBytes = uint8(fullDigestBytes)
  result.sidecarThreshold = 512'u32
  result.backup.copies = 3'u8
  result.backup.everySeconds = 3600'u32
  result = normalizeGeistConfig(result)

proc streamConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|db|stream".} =
  ## Volatile low-latency chunks: rows live in RAM and are never written
  ## unless a caller explicitly calls `save`. `close` discards them.
  ##
  ## This is the relay's shape. A blob in flight is worth keeping only
  ## while it is in flight, and a disk write on the forwarding path is the
  ## one cost that workload cannot absorb.
  result = baseConfig("stream", ckChaCha20)
  result.writeMode = wmVolatile
  result.rowIdentity = false
  result.keepHistory = false
  result.batchRows = 8'u32
  result.backup.enabled = false
  result = normalizeGeistConfig(result)

proc ledgerConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|ledger".} =
  ## Append-only hash-chained records with aggressive durability.
  ##
  ## The only preset that flushes per write. A hash-linked record exists to
  ## be evidence, and a record still sitting in RAM when the process dies
  ## is not evidence -- so here the whole-file rewrite per append is the
  ## price of the guarantee rather than an oversight.
  result = baseConfig("ledger", ckCascade)
  result.writeMode = wmOnChange
  # Identity, but nothing may ever be superseded: `set` and `delete` append
  # like everything else, so the chain keeps both versions.
  result.rowIdentity = true
  # SHA3 throughout: a hash-linked record is meant to outlive the software
  # that wrote it, so it should not depend on a single hash family. SHA3's
  # sponge is structurally independent of BLAKE3's tree, so a break in one
  # construction does not imply a break in the other.
  result.mac = mkCombined
  result.contentHash = hkSha3
  result.contentHashBytes = uint8(fullDigestBytes)
  result.treeHash = hkSha3
  result.chainHash = hkSha3
  result.batchRows = 128'u32
  result.keepHistory = true
  result.backup.everyNWrites = 16'u32
  result.backup.everySeconds = 300'u32
  result = normalizeGeistConfig(result)

## ------------------------- workload presets -------------------------
##
## The nine presets above are named after a SHAPE OF DATA -- collapsed
## rows, fixed-width telemetry, a hash-chained log. The five below are
## named after a JOB somebody is trying to do, and each one is the
## shape-preset that job needs plus the settings that job's traffic
## pattern implies.
##
## Each states, in its own doc comment, the ceiling its workload runs into
## in THIS build. A preset cannot lift a ceiling -- it only picks numbers
## -- and a preset named after a job it cannot finish would be worse than
## no preset at all. `docs/workloads.md` has the measurements behind each
## figure and what would have to change to move it.

proc syncConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|sync".} =
  ## Records that several machines each hold a copy of and reconcile.
  ##
  ## The shape a follower needs: every row nameable (`rowIdentity`), so a
  ## change to one row travels as that row rather than as a whole file,
  ## and history kept, so a peer that has been away can be told what it
  ## missed instead of being handed everything again.
  ##
  ## Batches are small on purpose. A sync answer is a handful of rows
  ## scattered through the log, not a scan, and a large batch would
  ## decrypt many neighbours to return one row.
  ##
  ## CEILING: one answer stops at 28,000 bytes of rows and hands back a
  ## cursor, so catching up is many round trips, each one blocking. That
  ## is fine for records people edit and wrong for a firehose.
  result = baseConfig("cloud-sync", ckChaCha20)
  result.batchRows = 32'u32
  result.rowIdentity = true
  result.keepHistory = true
  ## Interval rather than per-change: a sync peer applies rows in bursts,
  ## and flushing per row would rewrite the whole file per row.
  result.writeMode = wmInterval
  result.writeIntervalSeconds = 2'u32
  result.backup.copies = 2'u8
  result.backup.everySeconds = 900'u32
  result = normalizeGeistConfig(result)

proc chainConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|ledger".} =
  ## A tamper-evident append-only log that pinned peers replicate and
  ## each verify for themselves.
  ##
  ## What Geist actually gives this workload, stated plainly so nobody
  ## expects the rest:
  ##
  ##   hash-chained checkpoints   yes -- `checkpoint()` links each to its
  ##                              predecessor by `parentHash`
  ##   Merkle root per batch      yes -- `Sealed.root`, so one row can be
  ##                              proved against it
  ##   replication to peers       yes -- `qoSync` by log position
  ##   per-ROW chaining           no  -- the chain covers checkpoints; a
  ##                              row is covered by its batch's root
  ##   consensus, fork choice     no  -- there is no such thing here, and
  ##                              nothing in Geist will pick between two
  ##                              divergent logs for you
  ##
  ## So this is the right preset for a tamper-evident record among machines
  ## that already trust each other's pins, and the wrong one for anything
  ## that has to survive a participant lying.
  ##
  ## SHA3 throughout and the combined MAC, for the reason `ledgerConfig`
  ## gives: evidence should not rest on one hash construction.
  result = ledgerConfig()
  result.name = "chain"
  ## Bigger batches than `ledger`. A verifier checks a Merkle path per
  ## batch, so fewer, larger batches mean fewer paths to ship -- and this
  ## workload reads whole ranges rather than single rows.
  result.batchRows = 256'u32
  ## Peers pull by log position, so the log must never be rewritten under
  ## them: compaction changes what a position means and forces every
  ## follower back to zero.
  result.keepHistory = true
  result = normalizeGeistConfig(result)

proc hostConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|storageIo|sync".} =
  ## Content served from several machines, addressed by what it IS rather
  ## than by where it sits.
  ##
  ## The sidecar is the whole point: at or above the threshold a value
  ## leaves the row and becomes a file named by its own hash, so two
  ## machines that hold the same object agree on its name without
  ## coordinating, and a reader detects a corrupted copy by hashing it.
  ## The threshold is dropped to 256 bytes because here almost everything
  ## is an object rather than a field.
  ##
  ## Reads dominate, so batches are large: an object is fetched by name
  ## and its neighbours in the batch are usually wanted next.
  ##
  ## NO COLUMN COPY, deliberately. The fast-search copy is plaintext, and
  ## Geist refuses to keep one beside a sealed store -- rightly, because a
  ## machine hosting other people's content is exactly where an index of
  ## it in the clear is worst. A deployment that wants the copy has to
  ## choose an unsealed preset and mean it.
  ##
  ## CEILING: an object is served over the wire in one DAC package, which
  ## tops out at 65,535 chunks of 1,200 bytes -- about 78 MB. Above that a
  ## caller must split the object itself. `bulkConfig` says the same thing
  ## at more length.
  result = baseConfig("host", ckChaCha20)
  result.sidecarThreshold = 256'u32
  result.batchRows = 256'u32
  result.rowIdentity = true
  result.keepHistory = true
  result.transpose = tmNone
  result.backup.copies = 2'u8
  result = normalizeGeistConfig(result)

proc liveConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|db|stream".} =
  ## Small updates arriving fast and mattering briefly: a position, a
  ## pose, a cursor, a reading somebody is watching live.
  ##
  ## Nothing is written unless a caller asks. A position that is three
  ## updates old is worthless, so paying a disk write for it is paying for
  ## nothing -- `wmVolatile` keeps rows in RAM and `close` discards them.
  ## Identity is off and history is off for the same reason: an update is
  ## never edited, only superseded.
  ##
  ## CEILING, and it is the one that decides whether this preset suits
  ## you. Every exchange is a REQUEST AND A REPLY -- `send` blocks until
  ## the answer arrives. There is no one-way push in Geist today. So the
  ## update rate is bounded by the round trip, not by the bandwidth:
  ##
  ##   round trip   updates per second, per link
  ##   ----------   ----------------------------
  ##   1 ms         ~1000     (same machine, loopback)
  ##   5 ms         ~200      (same building)
  ##   20 ms        ~50       (same country)
  ##   80 ms        ~12       (across an ocean)
  ##
  ## Positions at 50 Hz on a LAN: comfortable. VIDEO: no. A 1080p stream
  ## is several megabytes a second of payload that must not wait for an
  ## acknowledgement per frame, and both of those are the opposite of what
  ## this transport does. Carry video on its own transport and keep the
  ## metadata here.
  result = baseConfig("live", ckChaCha20)
  result.writeMode = wmVolatile
  result.rowIdentity = false
  result.keepHistory = false
  ## Tiny batches: an update is read the moment it lands, so a large batch
  ## would decrypt a group to reach the one row anybody wants.
  result.batchRows = 4'u32
  result.autoCollapse = false
  result.backup.enabled = false
  result = normalizeGeistConfig(result)

proc bulkConfig*(): GeistConfig {.role: configurator,
    tag: "appApi|config|cryptoBoundary|db|storageIo".} =
  ## Few objects, each very large: recordings, disk images, datasets.
  ##
  ## Everything here pushes bytes out of the row and into the sidecar as
  ## early as possible, and keeps the row table small enough that the
  ## whole-file rewrite on save stays cheap.
  ##
  ## CEILING -- read this before choosing it for multi-gigabyte files,
  ## because there are three separate limits and none of them is lifted by
  ## a setting:
  ##
  ##   1. `putSidecar` takes the whole object as one `openArray[uint8]`
  ##      and `getSidecar` returns the whole object as one `ByteSeq`. A
  ##      5 GB file therefore needs 5 GB of RAM to store and 5 GB to read,
  ##      plus a copy. There is no chunked or streaming path.
  ##
  ##   2. One DAC package carries at most 65,535 chunks, and Geist sends
  ##      1,200-byte chunks, so a single transfer tops out at about
  ##      78 MB. Anything larger must be split by the caller into several
  ##      transfers with their own names.
  ##
  ##   3. A save serialises the whole store and replaces the file
  ##      atomically. Keeping objects in the sidecar rather than in rows
  ##      is what keeps that affordable, which is why the threshold here
  ##      is 64 bytes.
  ##
  ## So: right preset for many-megabyte objects on one machine, and for
  ## anything up to ~78 MB over the wire. For files of several gigabytes
  ## it gives you the correct SETTINGS and Geist still lacks the streaming
  ## machinery -- see `docs/workloads.md`.
  result = baseConfig("bulk", ckChaCha20)
  ## Almost nothing stays inline. A row here is a name and a reference.
  result.sidecarThreshold = 64'u32
  ## Few rows, read whole, so a large batch costs nothing and saves MAC
  ## passes.
  result.batchRows = 512'u32
  result.rowIdentity = true
  result.keepHistory = false
  ## Every mutation is expensive and rare, so flush when one happens
  ## rather than risk losing an hour of upload to a crash.
  result.writeMode = wmOnChange
  result.contentHashBytes = uint8(fullDigestBytes)
  result.backup.copies = 2'u8
  result = normalizeGeistConfig(result)

proc geistConfigPresets*(): seq[tuple[name, purpose: string]] {.
    role: configurator, tag: "appApi|config|db|read".} =
  ## The public preset catalog, for CLIs and diagnostics.
  ##
  ## Two groups. The first nine are named after the SHAPE of the data; the
  ## last five after the JOB. A caller who knows their access pattern
  ## wants the first list; a caller who knows what they are building wants
  ## the second.
  result = @[
    (name: "app", purpose: "ordinary local application records"),
    (name: "collapsed", purpose: "omit zero/empty fields via a null bitmap"),
    (name: "secure-collapsed", purpose: "collapsed with cascade at rest"),
    (name: "secure-app", purpose: "local records with cascade at rest"),
    (name: "chat", purpose: "encrypted messaging, small batches"),
    (name: "iot", purpose: "fixed-width telemetry, no overflow region"),
    (name: "archive", purpose: "scan-heavy long-term encrypted storage"),
    (name: "stream", purpose: "volatile low-latency chunks"),
    (name: "ledger", purpose: "append-only hash-chained records"),
    (name: "cloud-sync", purpose: "records several machines reconcile"),
    (name: "chain", purpose: "tamper-evident log peers each verify"),
    (name: "host", purpose: "content addressed by its own hash"),
    (name: "live", purpose: "fast small updates, round-trip bound"),
    (name: "bulk", purpose: "few very large objects, ~78 MB per transfer")]

proc knownPresetNames*(): string {.role: helper,
    tag: "appApi|config|db|read".} =
  ## Every canonical preset name, comma separated, for an error message.
  ## Built from the catalog so a preset can never be added without the
  ## message that names it being updated too.
  var
    i: int = 0
    A: seq[tuple[name, purpose: string]] = geistConfigPresets()
  while i < A.len:
    if i > 0:
      result = result & ", "
    result = result & A[i].name
    i = i + 1

proc geistConfigPreset*(name: string): GeistConfig {.role: configurator,
    tag: "appApi|config|db|read".} =
  ## name: canonical preset name or a documented alias.
  case name.strip().toLowerAscii()
  of "app", "local-app": result = appConfig()
  of "collapsed", "rare-write", "packed": result = collapsedConfig()
  of "secure-collapsed", "secure-packed": result = secureCollapsedConfig()
  of "secure-app", "secure": result = secureAppConfig()
  of "chat", "messaging", "message": result = chatConfig()
  of "iot", "telemetry", "sensor": result = iotConfig()
  of "archive", "archival", "backup": result = archiveConfig()
  of "stream", "media", "livestream": result = streamConfig()
  of "ledger", "journal", "append-only": result = ledgerConfig()
  # The five named after a job rather than a shape.
  of "cloud-sync", "sync", "replica": result = syncConfig()
  of "chain", "blockchain": result = chainConfig()
  of "host", "hosting", "content": result = hostConfig()
  of "live", "position", "realtime": result = liveConfig()
  of "bulk", "files", "large-files": result = bulkConfig()
  else:
    raise newException(ValueError, "unknown Geist config preset '" & name &
      "'; known: " & knownPresetNames())

proc applyColumnPolicy*(c: GeistConfig,
    s: Schema): tuple[ok: bool, s: Schema, err: string] {.role: configurator,
    tag: "appApi|config|db|types".} =
  ## c: configuration naming the columns that want a non-default policy.
  ## s: schema derived from the object type, with per-type defaults.
  ##
  ## Applied ONCE when a session opens, so the schema written to disk is
  ## the schema the policy asked for and a later reader needs no config to
  ## interpret it.
  var
    i: int = 0
    at: int = -1
    w: uint32 = 0'u32
  result.s = s
  result.s.autoCollapse = c.autoCollapse
  while i < c.columnPolicy.len:
    at = result.s.slotIndex(c.columnPolicy[i].field)
    if at < 0:
      return (false, s, "column policy names '" & c.columnPolicy[i].field &
        "', which is not a field of " & s.typeName &
        "; check the spelling, because an unmatched policy would " &
        "otherwise apply to nothing and look like it worked")
    result.s.slots[at].column = c.columnPolicy[i].column
    result.s.slots[at].onOverflow = c.columnPolicy[i].onOverflow
    case c.columnPolicy[i].column
    of colFixed:
      w = c.columnPolicy[i].width
      if w == 0'u32:
        w = defaultFixedWidth
      result.s.slots[at].width = w
    of colCapped:
      # A caller who states a width too small for a reference gets an
      # error, not a silent widening. Quietly raising it would mean the
      # stored schema disagreed with the policy that was written down --
      # the exact failure this proc's error path exists to prevent.
      if c.columnPolicy[i].width < minCappedWidth:
        return (false, s, "column '" & c.columnPolicy[i].field &
          "' is capped at " & $c.columnPolicy[i].width &
          " B but a reference needs " & $minCappedWidth &
          " B; widen it or use colVariable")
      result.s.slots[at].width = c.columnPolicy[i].width
    of colVariable:
      result.s.slots[at].width = 0'u32
    i = i + 1
  # A capped column too narrow for a reference cannot honour its contract,
  # so it is rejected here rather than at the first oversized write.
  i = 0
  while i < result.s.slots.len:
    if result.s.slots[i].column == colCapped and
        result.s.slots[i].width < minCappedWidth:
      return (false, s, "column '" &
        result.s.nameOf(result.s.slots[i].nameId) & "' is capped at " &
        $result.s.slots[i].width & " B but a reference needs " &
        $minCappedWidth & " B")
    if result.s.slots[i].column == colFixed and
        result.s.slots[i].width == 0'u32:
      return (false, s, "column '" &
        result.s.nameOf(result.s.slots[i].nameId) & "' is colFixed with " &
        "no width")
    i = i + 1
  result.ok = true

proc columnGroupsFor*(c: GeistConfig, s: Schema): seq[ColumnGroup] {.
    role: truthBuilder, tag: "batch|config|cryptoBoundary".} =
  ## c: configuration naming groups by field name.
  ## s: schema resolving those names to slot indices.
  ## Field names that do not exist in this schema are skipped rather than
  ## failing: a preset is allowed to name columns a given object lacks.
  ## When a cipher is selected but no groups are named, EVERY slot forms a
  ## single group -- "encrypted" must never silently mean "some columns".
  var
    i: int = 0
    j: int = 0
    g: ColumnGroup = default(ColumnGroup)
    idx: int = 0
  if c.cipher != ckNone and c.columnGroups.len == 0:
    g = ColumnGroup(groupId: 0'u16, slots: @[])
    while i < s.slots.len:
      g.slots.add i
      i = i + 1
    if g.slots.len > 0:
      result.add g
    return
  while i < c.columnGroups.len:
    g = ColumnGroup(groupId: uint16(i), slots: @[])
    j = 0
    while j < c.columnGroups[i].len:
      idx = s.slotIndex(c.columnGroups[i][j])
      if idx >= 0:
        g.slots.add idx
      j = j + 1
    if g.slots.len > 0:
      result.add g
    i = i + 1
  # The reserved identity columns were never named by the caller, so named
  # groups would leave them in clear -- and an unsealed `__flags` publishes
  # exactly which rows were edited and which were deleted. They join the
  # first group, so "encrypted" keeps meaning the whole row.
  if c.cipher != ckNone and s.hasIdentityColumns() and result.len > 0:
    j = 0
    while j < identityColumnCount:
      if not (j in result[0].slots):
        result[0].slots.add j
      j = j + 1
