## ---------------------------------------------------------------------
## Geist Types <- the complete model. One codec type, the rest are free.
## ---------------------------------------------------------------------
##
##   app object  ->  Row (packed tuple)  ->  Cluster  ->  file
##                        `-> Sealed rides in a slot when a policy seals it
##
## Rule that decided every type here:
##   same shape, different meaning  -> one type with an enum   (Record)
##   different invariants           -> separate structs        (Ref, Sealed)
##
## `Row` is the ONLY type the on-disk codec knows. Every other struct
## reaches disk through `toRow[T]`, so adding a model type costs no codec.

import runePragmas
import ./secret
import ./crypto/hashwidths

export secret
export hashwidths

type
  ByteSeq* = seq[uint8]
  EntryId* = uint64
  RowId* = uint64
    ## A row's stable name, allocated once and never reused, so it keeps
    ## meaning after other rows are added, replaced or removed. Zero means
    ## "no row": allocation starts at one. See rowid.nim.
  KeyId* = uint64
  NameId* = uint16
  Timestamp* = uint64
  FieldName* = string

  ## ------------------------------ schema ------------------------------

  SlotKind* {.role: truthState, tag: "appApi|db|types".} = enum
    ## How to read a slot. Fixed slots hold the value; variable slots hold
    ## an (u32 start, u32 len) pair into the cluster's overflow region.
    skNull, skInt, skFloat, skText, skBytes, skSealed, skRef

  ColumnKind* {.role: configurator, tag: "appApi|config|db|types".} = enum
    ## HOW a column is stored, chosen per column rather than per table.
    ## This is what used to be `CellLayout`, moved down one level: a table
    ## no longer picks one storage strategy for all of its columns.
    colFixed,     ## exact width, never overflows; too-long writes follow
                  ## `onOverflow`. Dense and arithmetically addressable.
    colCapped,    ## exact width with a sidecar escape: a value that fits
                  ## is stored inline, one that does not becomes a
                  ## reference in the same space. Needs `minCappedWidth`.
    colVariable   ## u32 length prefix then the payload; no ceiling.

  OverflowPolicy* {.role: configurator, tag: "appApi|config|db|types".} = enum
    ## What a `colFixed` column does with a value wider than its width.
    ## There is no silent default: truncation loses data and rejection
    ## loses the write, so the schema has to say which is intended.
    opError,      ## refuse the write and say which column and by how much
    opTruncate    ## cut at width and count it; never chosen implicitly

  Slot* {.role: truthState, tag: "appApi|db|types".} = object
    ## A column's declaration: what it MEANS (`kind`) and how it is STORED
    ## (`column`, `width`, `onOverflow`).
    ##
    ## `width` is stored, `offset` is not: offsets are a prefix sum over
    ## widths, recomputed when the schema is decoded. Width is genuine
    ## configuration; an offset would be a cached derivation, which is the
    ## reason `Slot.offset` was removed in the first place.
    nameId*: NameId
    kind*: SlotKind
    column*: ColumnKind
    width*: uint32          ## colFixed / colCapped only
    onOverflow*: OverflowPolicy

  Schema* {.role: truthState, tag: "appApi|db|types".} = object
    ## Derived from T at compile time, stored once per cluster.
    ## names: interned field names. Cold path only (migration/inspection);
    ## the pack/unpack hot path addresses slots positionally.
    ## autoCollapse: omit zero and empty fields, recording absence in a
    ## null bitmap at the head of each row. Independent of column kind --
    ## an all-`colFixed` table can collapse too, trading its arithmetic
    ## addressing for the space. Nim has no null distinct from a zero
    ## value, so this is lossless compression rather than a semantic
    ## change.
    typeName*: string
    names*: seq[string]
    slots*: seq[Slot]
    aliases*: seq[tuple[old, current: string]]
    autoCollapse*: bool

  Row* {.role: truthState, tag: "appApi|db|types".} = object
    ## The runtime packed tuple. One allocation per stored object.
    schemaId*: uint16
    data*: ByteSeq

  ## ---------------------------- cluster -------------------------------

  ClusterRole* {.role: truthState, tag: "appApi|db|types".} = enum
    crMeta, crSchema, crKeyLedger, crJournal, crVersion, crEntry

  ClusterMode* {.role: truthState, tag: "appApi|db|types".} = enum
    ## cmMutable: rewritten in place.
    ## cmAppend:  rows only ever appended.
    ## cmChained: appended AND each row carries its predecessor's hash.
    cmMutable, cmAppend, cmChained

  ## A `Cluster` type used to sit here, duplicating `ClusterBuild` in
  ## store.nim minus the parts that make one usable. One of them had to be
  ## the cluster; `ClusterBuild` is, because it is the one that can be
  ## written, read back and appended to.

  ## ---------------------------- crypto --------------------------------

  CipherKind* {.role: truthState, tag: "appApi|cryptoBoundary|types".} = enum
    ## Seekability is a declared property: a seekable cipher decrypts one
    ## row out of a batch, a non-seekable one must decrypt the whole batch.
    ckNone,
    ckChaCha20,      ## seekable via block counter
    ckAesCtr,        ## seekable via counter pre-advance
    ckCascade        ## ChaCha20 keystream XOR AES-CTR keystream

  MacKind* {.role: truthState, tag: "appApi|cryptoBoundary|types".} = enum
    mkBlake3,        ## BLAKE3 keyed HMAC
    mkGimli,         ## Gimli keyed HMAC
    mkCombined       ## BLAKE3 HMAC XOR Gimli HMAC (sound PRF combiner)

  Sealed* {.role: truthState, tag: "appApi|cryptoBoundary|db|types".} = object
    ## The encrypted object. Nonce is never stored: it derives from
    ## (keyRef, groupId, batchIndex, epoch) so reuse is structurally
    ## impossible. `root` is a Merkle root, enabling single-row proofs.
    cipher*: CipherKind
    mac*: MacKind
    keyRef*: KeyId
    epoch*: uint64
    root*: ByteSeq
    payload*: ByteSeq

  ## `Secret` (move-only, self-zeroing key material) comes from ./secret,
  ## which owns it so its `=destroy` / `=copy` hooks stay in the defining
  ## module and `data` can remain unexported.

  ## ---------------------------- model ---------------------------------

  RefTarget* {.role: truthState, tag: "appApi|db|types".} = enum
    rtSidecar,     ## own file; the hash IS the path, so it must be full width
    rtPacked,      ## a row of a shared sidecar cluster, at (fileId, slot)
    rtEntry,       ## another entry, possibly in another database
    rtExternal     ## hash-bound target outside Geist

  Ref* {.role: truthState, tag: "appApi|db|types".} = object
    ## The reference cell. Two addressing modes, because the filesystem
    ## makes one file per value uneconomical below about one block:
    ##
    ##   rtSidecar  hash addresses AND verifies -> needs collision
    ##              resistance -> 32 B
    ##   rtPacked   (fileId, slot) addresses, hash only verifies -> needs
    ##              second-preimage resistance only -> 16 B
    ##
    ## `locator` is NOT stored: for rtSidecar it is `hex(hash)` with
    ## two-level fan-out, a pure function of `hash`, and caching it cost
    ## 66 of the old encoding's 118 bytes. `size` is not stored either --
    ## the file or the slot row knows it.
    ##
    ## Invariant a generic carrier cannot enforce: a reference always has
    ## a hash, and an rtSidecar reference resolves to a path. Validate with
    ## `validRef` at every boundary.
    target*: RefTarget
    hash*: ByteSeq
    fileId*: uint16      ## rtPacked only
    slot*: uint32        ## rtPacked only: row index in the sidecar cluster
    entryId*: EntryId    ## rtEntry only
    databaseId*: string  ## rtEntry / rtExternal only

  RecordKind* {.role: truthState, tag: "appApi|db|types".} = enum
    ## Same shape, different meaning: this is where a discriminant earns
    ## its place. Journal, version commits, evidence and checkpoints all
    ## carry (kind, target, time, status, label, payload).
    rkJournal, rkVersion, rkEvidence, rkCheckpoint

  Record* {.role: truthState, tag: "appApi|db|types".} = object
    kind*: RecordKind
    targetId*: uint64
    at*: Timestamp
    status*: uint16
    label*: string
    parentHash*: ByteSeq
    payload*: ByteSeq

  KeyRecord* {.role: truthState, tag: "appApi|cryptoBoundary|ledger|types".} = object
    ## The key ledger row. Public material only; the private half lives
    ## sealed in the separate key file.
    keyId*: KeyId
    label*: string
    purpose*: uint16
    createdAt*: Timestamp
    retiredAt*: Timestamp
    publicPart*: ByteSeq

  Peer* {.role: truthState, tag: "appApi|networkSurface|peerDirectory|types".} = object
    nodeId*: string
    endpoint*: string
    capabilities*: seq[string]
    lastSeenAt*: Timestamp

  ## ---------------------------- asking ---------------------------------

  PeerRight* {.role: configurator, tag: "ame|networkSurface|server|types".} = enum
    ## What a trusted peer may ask for. A right is granted by the operator
    ## alongside the pin, so a peer cannot request its own privileges.
    ##
    ##   prRead   list, get, find, sync, subscribe, poll
    ##   prWrite  put and delete -- rows this peer sends are stored
    ##   prAdmin  reserved for operations that change the database's shape
    prRead, prWrite, prAdmin

  PeerContext* {.role: truthState, tag: "ame|networkSurface|server|types".} = object
    ## What a handler is told about WHO is asking. A handler that decided
    ## by subject alone would be trusting a name; these rights come from
    ## the pin the handshake actually verified.
    ##
    ## This lives with the types rather than with the transport because
    ## every handler takes one and not every handler owns a socket: the
    ## relay decides what a message may do from exactly this object, and
    ## it must be able to do so without compiling a handshake.
    subject*: string
    address*: string
    rights*: set[PeerRight]

  ## ---------------------------- query ---------------------------------

  QueryOp* {.role: truthState, tag: "appApi|db|networkSurface|types".} = enum
    ## Doubles as the wire message kind: a serialized Query IS the request
    ## body, which is why there is no separate exchange-kind enum.
    qoGet, qoPut, qoFind, qoDelete, qoSync, qoFetch, qoSubscribe, qoPoll

  Predicate* {.role: truthState, tag: "appApi|db|types".} = object
    field*: FieldName
    text*: string
    num*: int64
    isText*: bool

  Query* {.role: truthState, tag: "appApi|db|networkSurface|types".} = object
    op*: QueryOp
    collection*: string
    where*: seq[Predicate]
    limit*: uint32
    cursor*: uint64
    subscriptionId*: string
    payload*: ByteSeq

  Reply* {.role: truthState, tag: "appApi|db|networkSurface|types".} = object
    ## cursor: for a sync or poll, the log position the follower has now
    ##   reached -- what it sends back next time.
    ## matched: rows answered, or for a sync the total the server holds, so
    ##   a follower can tell whether it is caught up.
    ## epoch: the server's log epoch. A follower that sees this CHANGE must
    ##   start again from zero: its cursor counts positions, and the log
    ##   was rewritten under it (see Session.logEpoch).
    ok*: bool
    err*: string
    rows*: seq[Row]
    schema*: Schema
    cursor*: uint64
    matched*: uint32
    epoch*: uint64

  ## ---------------------------- stats ---------------------------------

  LengthHistogram* {.role: truthState, tag: "appApi|db|types".} = object
    ## 16 buckets, O(1) update, enough to compute cost(w) for any candidate
    ## width without retaining individual lengths.
    buckets*: array[16, uint32]
    rows*: uint32
    totalLen*: uint64
    maxLen*: uint32

  FieldStats* {.role: truthState, tag: "appApi|db|types".} = object
    field*: FieldName
    width*: uint32
    hist*: LengthHistogram

const
  slotBytes* = 8'u32
    ## Every slot is 8 bytes, so field i lives at i*8 and no offset is stored.
  defaultSidecarThreshold* = 1024'u32
    ## Values at or above this leave the row for the sidecar, and the row
    ## keeps a reference. Only `colCapped` columns can take that exit.
  defaultBatchRows* = 64'u32
    ## N=1 is field-level encryption and costs ~145 MiB of ledger per million
    ## rows on four columns. Never a default.
  defaultRekeyAtEpoch* = 0x8000_0000'u64
    ## High-water mark forcing a rekey well before a u64 epoch could wrap.

const
  rowIdColumn* = "__rowId"
    ## The two reserved columns every identified row carries, ahead of the
    ## caller's own fields. The double underscore is what makes them
    ## reserved: a caller schema may not declare a name starting with it.
    ##
    ## They live here, at the bottom of the module graph, so the codec, the
    ## configuration and the identity layer all read the same two strings
    ## instead of each spelling them out. See rowid.nim for what they mean.
  rowFlagsColumn* = "__flags"
  identityColumnCount* = 2
  tombstoneFlag* = 1'u64
    ## Bit 0 of `__flags`: this version removes the row. Bits 1..63 are
    ## unassigned, and a reader must ignore what it does not recognise
    ## rather than treat the word as a boolean.

const
  minCappedWidth* = 33'u32
    ## Floor for a `colCapped` column: the size of the reference it may
    ## have to hold in the SAME space as an inline value.
    ##
    ## That is `ownFileRefBytes` (tag | hash32), because the sidecar
    ## currently writes own-file references. It is NOT the 23-byte packed
    ## reference -- that tier encodes and decodes but nothing produces one
    ## yet, so sizing a column for it would let a column accept a policy it
    ## could not honour at the first oversized write. Revisit together with
    ## the packed tier, not before.
    ##
    ## An inline value in a capped column gets `width - 2` bytes, the two
    ## being its length prefix.
  defaultFixedWidth* = 8'u32
    ## What an integer, float, bool or enum needs. Also the default for a
    ## `colFixed` column whose width the caller did not state.

  refTagBytes* = 1
    ## Discriminant byte. Kept explicit rather than stolen from a spare bit
    ## of `fileId`: one byte is cheaper than a decoding rule nobody expects.
  packedRefBytes* = refTagBytes + shortDigestBytes + 2 + 4
    ## 23 B: tag | hash16 | fileId | slot
  ownFileRefBytes* = refTagBytes + fullDigestBytes
    ## 33 B: tag | hash32

proc validRef*(r: Ref): bool {.role: sanitizer,
    tag: "appApi|db|read".} =
  ## r: reference whose invariant is checked at an API boundary.
  ## An rtSidecar reference needs a full-width hash because that hash is
  ## its address; an rtPacked one needs a hash and nothing more, because
  ## (fileId, slot) already addresses it.
  case r.target
  of rtSidecar: result = r.hash.len == fullDigestBytes
  of rtPacked: result = r.hash.len > 0
  of rtEntry: result = r.entryId != 0'u64 or r.databaseId.len > 0
  of rtExternal: result = r.hash.len > 0 and r.databaseId.len > 0

proc nullBitmapBytes*(slots: int): int {.role: helper, inline,
    tag: "appApi|db|read".} =
  ## slots: column count whose bitmap width is returned.
  result = (slots + 7) div 8

proc hasCapped*(s: Schema): bool {.role: parser,
    tag: "appApi|db|read".} =
  ## s: schema holding at least one column that may externalise.
  ## Decides whether rows carry a second bitmap saying which values took
  ## the sidecar escape -- schemas without such a column never pay for it.
  var
    i: int = 0
  while i < s.slots.len:
    if s.slots[i].column == colCapped:
      return true
    i = i + 1

proc isDense*(s: Schema): bool {.role: parser,
    tag: "appApi|db|read".} =
  ## s: schema every row of which has the same byte width.
  ##
  ## True only when every column is `colFixed` AND collapsing is off. Then
  ## row i is at `i * rowBytes` with no indirection, which is what an IoT
  ## reader needs to stream from an SD card without an allocator.
  ##
  ## A single `colVariable` or `colCapped` column, or `autoCollapse`, makes
  ## rows vary and the cluster carries an offset table instead. That is the
  ## whole cost of those features and it is one u32 per row.
  var
    i: int = 0
  if s.autoCollapse:
    return false
  while i < s.slots.len:
    if s.slots[i].column != colFixed:
      return false
    i = i + 1
  result = true

proc headerBytesOf*(s: Schema): int {.role: helper,
    tag: "appApi|db|read".} =
  ## s: schema whose per-row bitmap prefix width is returned.
  ## Each bitmap is emitted only when the schema can use it.
  if s.autoCollapse:
    result = result + nullBitmapBytes(s.slots.len)
  if s.hasCapped():
    result = result + nullBitmapBytes(s.slots.len)

proc rowBytes*(s: Schema): uint32 {.role: helper,
    tag: "appApi|db|read".} =
  ## s: schema whose row width is returned when rows are dense.
  ## Zero for a schema whose rows vary -- callers must consult the offset
  ## table instead, and a zero here is what tells them so.
  var
    i: int = 0
  if not s.isDense():
    return 0'u32
  while i < s.slots.len:
    result = result + s.slots[i].width
    i = i + 1

proc slotAt*(s: Schema, i: int): uint32 {.role: helper,
    tag: "appApi|db|read".} =
  ## s/i: schema and column whose byte offset inside a DENSE row is
  ## returned. Prefix sum over widths, so a non-uniform dense schema still
  ## addresses arithmetically.
  var
    j: int = 0
  while j < i and j < s.slots.len:
    result = result + s.slots[j].width
    j = j + 1

proc intern*(S: var Schema, n: string): NameId {.role: actor,
    tag: "appApi|db|write".} =
  ## S: schema whose name table receives the field name.
  ## n: field name, dotted for nested structs (`attachment.locator`).
  var
    i: int = 0
  while i < S.names.len:
    if S.names[i] == n:
      return NameId(i)
    i = i + 1
  S.names.add n
  result = NameId(S.names.len - 1)

proc nameOf*(s: Schema, id: NameId): string {.role: parser,
    tag: "appApi|db|read".} =
  ## s: schema holding the name table.
  ## id: interned name identifier.
  result = ""
  if int(id) < s.names.len:
    result = s.names[int(id)]

proc hasIdentityColumns*(s: Schema): bool {.role: parser,
    tag: "appApi|db|read".} =
  ## s: schema asked whether its rows carry identity.
  ##
  ## DERIVED from the columns themselves, never stored as a separate flag:
  ## a file that claims identity while its columns say otherwise is a
  ## contradiction that cannot arise if nothing can write it down.
  result = s.slots.len >= identityColumnCount and
    s.nameOf(s.slots[0].nameId) == rowIdColumn and
    s.nameOf(s.slots[1].nameId) == rowFlagsColumn

proc slotIndex*(s: Schema, n: string): int {.role: parser,
    tag: "appApi|db|read".} =
  ## s: schema to search.
  ## n: field name, possibly matched through the alias table.
  var
    i: int = 0
    target: string = n
  while i < s.aliases.len:
    if s.aliases[i].old == n:
      target = s.aliases[i].current
      break
    i = i + 1
  i = 0
  while i < s.slots.len:
    if s.nameOf(s.slots[i].nameId) == target:
      return i
    i = i + 1
  result = -1

proc keepFirst*(err: var string, msg: string) {.role: helper, inline,
    tag: "status".} =
  ## err/msg: remember msg only when nothing went wrong before it. A loop
  ## that carries on past a failure reports the FIRST one; later ones are
  ## usually its consequences.
  if err.len == 0:
    err = msg

proc textBytes*(s: string): ByteSeq {.role: parser, inline,
    tag: "codecBoundary".} =
  ## s: text -> the same bytes, unchanged. "hé" -> 68 C3 A9.
  var
    i: int = 0
  result = newSeq[uint8](s.len)
  while i < s.len:
    result[i] = uint8(s[i])
    i = i + 1

proc bytesText*(A: openArray[uint8]): string {.role: parser, inline,
    tag: "codecBoundary".} =
  ## A: bytes -> the same bytes as text. The reverse of `textBytes`.
  var
    i: int = 0
  result = newString(A.len)
  while i < A.len:
    result[i] = char(A[i])
    i = i + 1
