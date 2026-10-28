# Geist

A packed-row, cluster-addressed encrypted database for one machine. Rows
are stored in files, read and written through a `Session`, sealed at rest,
backed up by rotation, and searched through an optional column copy.

Talking to other machines (links, sync, relays, daemons, the device monitor)
is in [Nebel-DecentralizedDB](https://github.com/siriuslee69/Nebel-DecentralizedDB),
which imports this library. Nothing in Geist opens a socket.

## Installation

Clone, then fetch the pinned submodules. One level only -- not `--recursive`:

```sh
git clone https://github.com/siriuslee69/Geist-Database.git
cd Geist-Database
git submodule update --init
```

### ❄ NixOS -- the CLI

```sh
nix-build nix/default.nix        # builds build/result/bin/geist
./result/bin/geist help
```

### ❄ NixOS -- as a library in your own Nim program

```nim
# config.nims of your program
if dirExists(thisDir() & "/submodules/Geist-Database/src"):
  switch("path", thisDir() & "/submodules/Geist-Database/src")
```

### 🪟 Windows 11 -- the CLI

```sh
nimble buildAll                  # build/geist_database_cli.exe
```

### ✅ Check it works

```sh
nimble checkAll && nimble checkModular
nimble test
```

### ⚙ Where settings live

```text
  configs/default.toml     library defaults: [runtime.storage], [runtime.backup]
  configs/<preset>.toml    a build preset laid over default.toml
  userconfig.toml          this machine's database: [database]
                           Template: userconfig.toml.template
```

An unknown key in any of these stops the program that reads it, and names
the key. Network sections ([daemon], [client], [runtime.transport]) belong
to Nebel-DecentralizedDB and are read there.

## Terms

Everything below is spelled out before it is used. Skip it and come back
when a word is doing work you did not expect.

### How bytes are written

Every number in every Geist file and every Geist packet follows these
three rules. There are no others.

```text
  integers    little-endian, fixed width, unsigned unless stated
              u8 = 1 byte   u16 = 2   u32 = 4   u64 = 8

  text        u32 length, then exactly that many raw bytes
              +----+----+----+----+----+----+----+
              | 05 | 00 | 00 | 00 | 6E | 6F | .. |   "notes"
              +----+----+----+----+----+----+----+
                \___ length = 5 ___/ \__ bytes __/

  list        u32 count, then that many items back to back
```

Nothing is aligned, padded or self-describing beyond this. A reader that
knows the schema knows every offset.

### The words

```text
  ON DISK
  -------
  store root      a FOLDER. The unit you back up, copy or delete.
  generation      one complete, immutable version of the store, numbered.
                  Saving writes generation N+1 and never touches N.
  manifest        the file named `current`. Its whole content is the live
                  generation number in decimal, e.g. "4\n".
  artifact set    the files of one generation that must travel together:
                  .ge1st always, plus .keys and .ledger when sealed.
  cluster         one region of a generation file holding rows of ONE
                  kind. A file has several; only crEntry holds your rows.
  cluster index   a fixed-size table at the front of the file, one 76-byte
                  entry per cluster. Readable without a password.
  aux region      a cluster's trailing offset table. Present only when
                  rows vary in length.
  sidecar         `.geist-sidecar/`, a content-addressed folder for values
                  too big to sit inside a row.
  reference       the 33 bytes a row keeps in place of an externalised
                  value: 1 tag byte + a 32-byte content hash.
  lease           `.geist-lock`. One line: `<pid> <host> <unix-seconds>`.
  cursor file     `.geist-cursors`. One line per peer:
                  `<remote> <epoch> <cursor>`.

  IN A ROW
  --------
  schema          the ordered list of columns, stored in the cluster.
  slot            one column's declaration: name id, kind, column kind,
                  overflow policy, width. Nine bytes on disk.
  kind            what a value MEANS: int, float, text, bytes, ref, ...
  column kind     how a value is STORED: fixed, capped or variable.
  width           a fixed or capped column's exact byte count. Zero for
                  variable columns, whose length is written per value.
  row header      the per-row bitmap prefix. Zero bytes unless the schema
                  collapses nulls or has a capped column.
  __rowId         reserved column 0. u64 = 24-bit node tag | 40-bit counter.
  __flags         reserved column 1. u64; bit 0 set means tombstone.
  packed row      the bytes actually stored: row header, then every
                  present column's bytes end to end, in schema order.

  WHAT YOU SEE
  ------------
  log             every row ever appended, including old versions and
                  tombstones. It only grows.
  live view       the newest version of each id, tombstones excluded.
                  `entryCount` counts these; `logCount` counts the log.
  log position    an index into the log. What a peer's cursor counts.
  @position       an index into the live view, as `list` prints it.
  epoch           a counter bumped when the log is REWRITTEN (compaction).
                  A peer whose epoch changed must start again from zero.
  tombstone       a row appended to say an id is gone. Nothing is erased
                  in place, so the removal replicates like any other row.

  SEALING
  -------
  column group    a set of columns sealed together.
  batch           the unit that is sealed: one column group crossed with
                  one range of `batchRows` rows.
  ledger          the PUBLIC table of which key and epoch each batch used,
                  and its two checks (Gimli digest, keyed BLAKE3 tag).
                  Lose it and the data cannot be opened, by design.
  key file        the sealed secret material, `.keys`.

  ON THE WIRE
  -----------
  identity        a signing key file. Private; never leaves its machine.
  pin             the public half of an identity, in a `.pin` file. Handed
                  to a peer out of band. That exchange IS the trust.
  subject         the name on an identity, as peers see it.
  strength        which algorithms a session uses. Six named levels.
  Query / Reply   the request and answer. One shape for every operation.
  frame           one AME/DAC datagram. At most 65,507 bytes.
  envelope        the first byte of a frame's payload: 0 whole,
                  1 package manifest, 2 package chunk.
  package         a payload split across frames because it exceeded
                  32,000 bytes, reassembled and digest-checked on arrival.

  THE RELAY
  ---------
  stream          a name a message is sent under. Not a schema.
  message         bytes, plus who sent them and when, both stamped locally.
  spool           a bounded in-memory ring of messages per stream.
```

---

## Five minutes

Everything below this point is one of the three parts in more detail.
This is the shortest complete round trip through part 1.

### In Nim

```nim
import geist

type
  Note = object
    noteId: int
    title: string
    body: string

var
  db = openGeist[Note]("data/notes", appConfig())
  id = db.put(Note(noteId: 1, title: "first", body: "hello"))

discard db.set(id, Note(noteId: 1, title: "corrected", body: "hello"))
discard db.save()
db.close()

# a fresh open, from the file this time
db = openGeist[Note]("data/notes", appConfig())
echo byId[Note](db, id).value.title      # corrected
db.close()
```

The reopen is the part worth keeping in the example: it is what shows the
row survived the process, under the id `put` handed back.

```text
nim c -r examples/geist_quickstart.nim     # or: nimble runExamples, for all five
```

The other four sit beside it in `examples/`: `geist_encrypted`,
`geist_observe`, `geist_fast_search` and `geist_buffers` -- that last one is two Geist instances passing rows
to each other with no database on either side ([2.0](#20-a-link-does-not-need-a-database)).

### From the shell

The same store, the same file, no Nim:

```text
$ geist --path data/notes init --schema "noteId:int,title:text,body:text"
created data/notes with preset 'app'
schema: noteId:int,title:text,body:text

$ geist --path data/notes put noteId=1 title=first body=hello
stored row id 16970053778118017025

$ geist --path data/notes list
@  __rowId               __flags  noteId  title  body
-----------------------------------------------------
0  16970053778118017025  0        1       first  hello

1 of 1 rows
```

```text
nimble demoCli
```

---

# Part 1 — The store

## 1.1 Opening one

```nim
var db = openGeist[Note]("data/notes", appConfig())
```

Three arguments, and they answer three different questions:

```text
  "data/notes"    a FOLDER, not a file (the store root)
  appConfig()     the preset: shape of the rows        -> 1.11
  (a password)    only for a sealed preset             -> 1.9
```

The folder is the unit. Look inside one after a few writes:

```text
$ ls -a data/notes
current            <- names the live generation
main.ge1st.g4      <- generation 4: the data
main.ge1st.g3      <- generation 3: kept until 4 has survived a clean cycle
main.ge1st.b1      <- backup rotation slots
main.ge1st.b2
.geist-lock        <- who may write (only while a writer is open)
.geist-sidecar/    <- values too big to sit in a row
.geist-cursors     <- where peers left off (only after a sync)
```

Nothing here is a hidden index that can drift: everything except the data
files is either a pointer (`current`), a lock, or a payload store.

## 1.2 Rows have ids

`put` gives you back a name for the row that means the same thing forever
and everywhere:

```nim
var id = db.put(Note(noteId: 1, title: "first", body: "hello"))
discard db.set(id, Note(noteId: 1, title: "corrected", body: "hello"))
echo byId[Note](db, id).value.title      # corrected
discard db.delete(id)
echo byId[Note](db, id).found            # false — gone from the view
```

The CLI prints both the id and a position:

```text
$ geist --path data/notes list
@  __rowId               __flags  noteId  title   body
------------------------------------------------------
0  16970053778118017025  0        1       first   hello
1  16970053778118017026  0        2       second  world
```

```text
  @0                     true on THIS machine, in THIS list, right now
  16970053778118017025   true on every machine that ever held the row
```

So:

```text
  editing what you just listed   ->  @0 is fine and shorter
  talking to another machine     ->  always the id
  remote delete                  ->  id only; positions may already have moved
```

An id is a small machine tag plus a counter, so two machines minting rows
at the same moment cannot collide.

Identity costs 16 bytes per row (`__rowId` + `__flags`) and buys `set`,
`delete`, `byId` and row-level exchange with a peer. Two presets turn it
off on purpose — see [1.11](#111-configuring).

## 1.3 Looking at it

`echo` a store and you get the table, not the object's fields:

```nim
echo db
```

```text
@    __rowId               __flags  noteId  title     body
----------------------------------------------------------
0    16970053778118017025  0        1       first     hello
1    16970053778118017026  0        2       second    world
2    16970053778118017027  0        3       title3    body3
...
9    16970053778118017034  0        10      title10   body10
...  ...                   ...      ...     ...       ...
90   16970053778118017115  0        91      title91   body91
...
99   16970053778118017124  0        100     title100  body100

100 rows x 5 columns (showing 20 x 5)
```

**A big table is elided the way a big matrix is written** — the corners,
with the middle marked. That is the default because `echo` on a
500,000-row store is not a printout, it is an accident. Both axes elide,
so a wide schema loses its middle columns the same way:

```text
@    __rowId               __flags  a    b    c    ...  j    k    l    m    n
-----------------------------------------------------------------------------
0    17349218163933315073  0        1    2    3    ...  1    1    1    1    99
...  ...                   ...      ...  ...  ...  ...  ...  ...  ...  ...  ...
29   17349218163933315102  0        30   60   90   ...  30   30   30   30   2970

30 rows x 16 columns (showing 20 x 10)
```

The elided rows are **never rendered** — not rendered and then dropped.
Printing twenty lines of a million-row store costs twenty rows, because
`show` asks the style which positions it needs and fetches only those.

Turn any of it up or down:

```nim
var style = defaultShowStyle()   # 20 rows, 10 columns, 42-char cells
style.maxRows = 6
echo db.show(style)
echo db.show(everything())       # no eliding at all
```

Same rows with the axes swapped — one line per field, which is what fits
a terminal when the schema is wide and the answer is short:

```nim
echo db.showTransposed()
```

```text
field    @0                    @1                    @2
--------------------------------------------------------------------
__rowId  16970053778118017025  16970053778118017026  16970053778118017027
__flags  0                     0                     0
noteId   1                     2                     3
title    first                 second                title3
body     hello                 world                 body3
```

From the shell it is the same renderer — `list`, `get` and `find` all
take `--transposed`, and `--json` is never elided, because a program
cannot see the dots:

```text
$ geist --path data/notes --transposed get 0
$ geist --path data/notes --json list
```

## 1.4 Saving

```nim
discard db.save()
```

Nothing is ever overwritten in place. A save publishes a whole new
generation and switches one pointer:

```text
  readers still on generation N

  1. write notes.ge1st.g(N+1)
     write notes.keys.g(N+1)      (if sealed)
     write notes.ledger.g(N+1)    (if sealed)
  2. flush to disk
  3. open the new files and check they read back
  4. rename  current  ->  "N+1"        <--- only this step is the switch
  5. keep generation N until N+1 has survived one clean cycle
```

A crash at any step costs at most the rows since the last save. A reader
holding N never sees a half-written N+1.

**One writer per folder.** The lock file answers "is another program
writing?"; an in-process list answers "is another open handle in this
program?". A write-open that loses the race becomes read-only and tells
you who holds the lease:

```text
$ geist --path data/notes put noteId=3 title=nope
geist: database is already open for writing: held by pid 4127 on desktop-a, 12s ago
```

Readers are never blocked. A crashed holder's lease breaks after 120 s.

## 1.5 The log, and what you actually see

A store is a log. What you see is a view over the newest version of each
id — so one row you have edited once is one row and two log entries:

```nim
discard db.set(id, Note(noteId: 1, title: "corrected", body: "hello"))
echo db.entryCount(), " visible / ", db.logCount(), " stored"
# 1 visible / 2 stored
```

```text
  log (what is stored)                 live view (what you see)
  --------------------                 ------------------------
  add id=1 v1                          id=1 -> v2
  add id=2 v1                          id=2 -> v1
  set id=1 v2                          (id=3 gone — tombstone)
  del id=3
```

That is also why a peer can catch up by asking for "everything after
position N" — the log only grows, so a position keeps its meaning.

Two commands trim it, in this order:

```text
$ geist --path data/notes compact    # drop versions the live view no longer needs
$ geist --path data/notes sweep      # drop big values no remaining row points at
```

`compact` first, `sweep` second: a superseded version still in the log is
a live reference to its payload.

## 1.6 Inside a row

Ask the store what it made of your object:

```text
$ geist --path data/notes schema
type:   Note
spec:   noteId:int,title:text,body:text
rowBytes: 0
identity: yes (__rowId, __flags -- rows can be set and deleted)

  0   __rowId             int       colFixed    8 B     per row
  1   __flags             int       colFixed    8 B     per row
  2   noteId              int       colFixed    8 B     per row
  3   title               text      colVariable 0 B     per row
  4   body                text      colVariable 0 B     per row
```

Each column is stored one of three ways:

```text
  column kind     bytes in the row                      good for
  -----------     ----------------                      --------
  fixed           exactly `width`, always present       ints, times, enums
  capped          exactly `width`; a value too big is   titles, short bodies
                  replaced by a 33-byte reference and
                  the bytes move to the sidecar
  variable        u32 length, then that many bytes      free text, blobs
```

### A row, byte for byte

Take `Note(noteId: 7, title: "hi")` under `appConfig()` — the schema
above without `body`, so four slots. This is the row that lands on disk,
thirty bytes, every one of them accounted for:

```text
  offset  bytes                      what
  ------  -------------------------  ----------------------------------
       0  01 00 00 00 00 B8 7A 4A    __rowId  u64 = 0x4A7AB80000000001
       8  00 00 00 00 00 00 00 00    __flags  u64 = 0  (not a tombstone)
      16  07 00 00 00 00 00 00 00    noteId   u64 = 7
      24  02 00 00 00                title    u32 length = 2
      28  68 69                      title    'h' 'i'
                                     -------------------------------
                                     30 bytes total
```

```text
  byte  0         8         16        24    28    30
        |         |         |         |     |     |
        +---------+---------+---------+-----+-----+
        | __rowId | __flags |  noteId | len | "hi"|
        +---------+---------+---------+-----+-----+
          fixed     fixed     fixed     variable
          8 B       8 B       8 B       u32 len + that many bytes
```

There is **no row header here** — `appConfig` does not collapse nulls and
has no capped column, so the bitmap prefix is zero bytes wide. Turn
either on and the row gains a prefix, one bit per column, rounded up to
whole bytes:

```text
  headerBytesOf(schema)
    = (slots + 7) / 8   if autoCollapse     null bitmap: which are omitted
    + (slots + 7) / 8   if any capped       capped bitmap: which went out

  4 slots, collapsing, one capped  ->  1 + 1  =  2 byte prefix
```

That prefix is the only thing between a stored row and a plain
concatenation of its columns. It is why a row can be taken apart and put
back together without knowing what any column means — which is exactly
what the column copy in [1.8](#18-fast-search-the-same-rows-turned-on-their-side)
does.

The id in that dump is worth splitting open:

```text
  0x4A7AB8_0000000001
    \____/ \_________/
     24-bit  40-bit counter
     node tag
```

Two machines minting rows at the same instant differ in the top 24 bits,
so they cannot collide — see [1.2](#12-rows-have-ids).

### Where a row lives: the cluster

```text
  cluster = schema block | rows back to back | (aux region)

  +----------------+-------------------------------+------------------+
  |  schema block  |  row 0 | row 1 | row 2 | ...   |  offset table    |
  +----------------+-------------------------------+------------------+
   typeName, names,   packed rows, no padding,       u32 count, then
   slots, aliases     no separators                  count u32 offsets
```

The **aux region is written only when rows vary in length**. For a schema
where every column is fixed, `rowBytes` is a real number and row *i*
starts at `i * rowBytes` — arithmetic, no table, no search. `rowBytes: 0`
in `schema` output is the declaration that the table is in use instead.

```text
  dense schema                  varying schema
  ------------                  --------------
  rowBytes = 24                 rowBytes = 0
  row i at i * 24               row i at offsets[i] .. offsets[i+1]
  no aux region                 aux region = 4 + 4*(rowCount+1) bytes
```

### Where clusters live: the file

```text
  offset                      what
  --------------------------  --------------------------------------
  0                           file header, 32 bytes
  32                          cluster index: 76 bytes per cluster
  32 + 76*clusterCount        cluster 0 body, then its aux region
                              cluster 1 body, then its aux region
                              ...
```

The header, from a real file — three clusters, generation 2:

```text
  offset  bytes                      what
  ------  -------------------------  ----------------------------------
       0  47 45 31 53 54             magic "GE1ST"
       5  00 00 00                   unused
       8  04 00                      format version u16 = 4
      10  03 00 00 00                clusterCount u32 = 3
      14  02 00 00 00 00 00 00 00    generation u64 = 2
      22  00 x10                     unused, to 32 bytes
```

One index entry, the same file's entry cluster:

```text
  offset  bytes                      what
  ------  -------------------------  ----------------------------------
       0  05                         role u8 = crEntry
       1  01                         mode u8 = cmAppend
       2  00 00                      schemaId u16
       4  01 00 00 00                rowCount u32 = 1
       8  00 00 00 00                rowBytes u32 = 0 -> use the offsets
      12  EC 02 00 00 00 00 00 00    at     u64 = 748   (cluster body)
      20  80 00 00 00 00 00 00 00    len    u64 = 128
      28  6C 03 00 00 00 00 00 00    auxAt  u64 = 876   (offset table)
      36  0C 00 00 00 00 00 00 00    auxLen u64 = 12
      44  71 58 A5 BE ... (32 B)     content hash of the cluster body
                                     -------------------------------
                                     76 bytes total
```

Five roles exist, and only one of them holds your rows:

```text
  0 crMeta       counters, the log epoch, the id allocator
  1 crSchema     reserved
  2 crKeyLedger  reserved
  3 crJournal    the hash-chained trail, when history is kept
  4 crVersion    reserved
  5 crEntry      YOUR ROWS
```

That last hash is what makes observation cheap: `changedClusters`
compares the hashes of two index reads and says which clusters moved,
having read nothing but the index.

```text
  index read cost = 32 + 76 * clusterCount

  3 clusters -> 260 bytes, whether the file is 1 KB or 1 GB
```

### The trail: a journal row carries its predecessor

A `cmChained` cluster — the journal — links every row to the one before
it, so a removed or edited entry cannot pass unnoticed:

```text
  chain(0) = 0
  chain(n) = H( chain(n-1) || rowBytes(n) )        H = the chain hash,
                                                   always full width

  row 0        row 1        row 2
    |            |            |
    v            v            v
  chain0 ----> chain1 ----> chain2      each link folds in the whole row
```

`geist checkpoint "message"` appends one. Full width on purpose: a link
that only resisted preimages could be forked by a birthday collision.

### What the index says, from the outside

`inspect` needs no password and no lease:

```text
$ geist --path data/notes inspect
file:        data/notes/main.ge1st.g4
size:        964 B
index cost:  260 B  (read to produce this output)
format:      v4
generation:  4
clusters:    3

role        mode       rows    rowBytes  addressing  offsets
--------------------------------------------------------------
crMeta      cmMutable  3       0         offsets     20 B
crJournal   cmChained  0       0         offsets     0 B
crEntry     cmAppend   2       0         offsets     16 B
```

Every column of that table is read straight out of the index entries
above: `rows` is `rowCount`, `addressing` is whether `rowBytes` is zero,
`offsets` is `auxLen`. Nothing was decoded to produce it.

Why it is shaped this way, with the measurements that decided it:
[docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md).

## 1.7 What it costs

```text
nimble runBenchmarks
```

Message-shaped schema, five columns, ~120-byte body, not sealed, one
machine:

```text
  rows      write     open      RAM      byId     find      disk
  ------    ------    ------    -----    ----     ------    -----
   50,000   0.23 s     58 ms    17 MiB   1 us     14 ms     16 MB
  200,000   0.77 s    200 ms    66 MiB   1 us     57 ms     64 MB
  500,000   1.63 s    453 ms   164 MiB   1 us    144 ms    159 MB
```

```text
  byId   constant — a hash into the live view
  find   walks every live row, unless there is a column copy (1.8)
  RAM    ~= file size (a session loads clusters; seek.nim can read a
         slice, the session API does not use it yet)
  write  ~= 300k rows/s, linear
```

A store that stays open has to fit in memory today. That is the size
ceiling, and it is the honest one.

## 1.8 Fast search: the same rows, turned on their side

`find` above walks every row, and most of every row belongs to columns
nobody asked about. Turning the table on its side fixes exactly that:

```text
  row-major (the store)             transposed (a copy)
  ---------------------             -------------------
  [id|flags|noteId|title|body]      [id id id ...]
  [id|flags|noteId|title|body]      [flags flags flags ...]
  [id|flags|noteId|title|body]      [noteId noteId noteId ...]
                                    [title title title ...]
                                    [body body body ...]

  find over title:                  find over title:
    reads every row                   reads the title region
```

Ask for it in the config, and every save writes the copy:

```nim
var c = appConfig()
c.transpose = tmOnSave
var db = openGeist[Note]("data/notes", c)
```

```toml
[storage]
transpose = "onSave"
```

Measured on 20,000 rows of a four-column schema, searching a tag column:

```text
  row-major file   2,018,475 B
  column copy      2,177,909 B

  find over tag    bytes read     time
  --------------   -----------    -------
  row scan          2,018,475     3.24 ms
  column scan         239,804     0.43 ms
  (both answered 200 rows)
```

The copy is **slightly bigger** than the store, and that is the honest
trade: a column whose values vary carries its own offset table, so the
saving is in what a search *reads*, not in what the disk holds.

### The copy, byte for byte

`name.getr.gN`, and it is the row layout of [1.6](#16-inside-a-row) taken
apart along the other axis:

```text
  offset  what
  ------  ----------------------------------------------------------
       0  magic "GETR1"                                       5 bytes
       5  version u16
       7  generation u64      which .ge1st generation this mirrors
      15  rowCount u32
      19  headerBytes u32     the row prefix width, 0 when there is none
      23  columnCount u32
      27  schemaLen u32, then the schema block
          directory: (columnCount + 1) entries of 21 bytes:
              at u64 | len u64 | dense u8 | width u32
              entry 0      the row prefixes
              entry 1..n   one per column, in schema order
          regions, in directory order
```

A region is one of two shapes, and the `dense` byte says which:

```text
  dense = 1                        dense = 0
  ---------                        ---------
  +------+------+------+           +---------------+---------------+
  | v[0] | v[1] | v[2] |           | rowCount+1    |  values, end  |
  +------+------+------+           | u32 offsets   |  to end       |
   width  width  width             +---------------+---------------+

  value i at  at + i*width         value i at  at + 4*(rowCount+1)
                                                  + offsets[i]
```

A column is dense when every row spends the same bytes on it — fixed and
capped columns of a schema that does not collapse. Anything else, and
anything at all under `autoCollapse`, gets offsets.

Rebuilding row *i* is then the row picture of 1.6 read right to left:

```text
  prefix[i]  +  column0[i]  +  column1[i]  +  ...  =  the original row
   \______/     \________________________________/
   entry 0        entries 1..n, in schema order
```

Byte for byte the row that was stored — which is why `fromRowBytes[T]`
works on it unchanged, and why the copy can be checked against the store
row by row rather than trusted.

### It is a copy, never the truth

```text
  the row-major generation      the column copy
  ------------------------      ---------------
  rows, metadata, journal,      the entry rows only
  key ledger, id allocator      rebuilt whole, never patched
  in artifactSet(); backed up   not backed up: losing it costs a rebuild
```

Metadata, the journal, the key ledger and the sidecar are **excluded on
purpose** — a column store of a hash-chained journal would be a chain
nobody can walk.

Reading it gives back exactly what was stored, so objects still come out
as objects:

```nim
var view = db.transposedView()
let hit = view.t.transposedFind("tag", "hit")   # row positions, and what it cost
let note = fromRowBytes[Note](view.t.transposedRow(hit.rows[0]).data,
                              view.t.schema)
```

### Keeping the two in step

Four modes, which are the four answers to "when is the copy rewritten":

```text
  mode        when                                    can it be stale?
  ---------   -------------------------------------   ----------------
  tmNone      never; there is no copy                  n/a
  tmOnSave    every save                               no
  tmInterval  at most every transposeEverySeconds      briefly
  tmManual    only when asked                          yes, until you ask
```

```nim
c.transpose = tmInterval        # a daemon that saves often
c.transposeEverySeconds = 300
```

```text
$ geist --path data/notes transpose          # rebuild now
$ geist --path data/notes transpose status   # just tell me
column copy:   current (built from generation 10)
mode:          tmOnSave
  main.getr.g10  690 B   (rows: main.ge1st.g10  1249 B)
```

**Which one is newer is not tracked anywhere.** The copy's header records
the generation it was built from, the manifest records the generation
that is live, and comparing them is the answer — a tracker file would be
a second copy of a fact already on disk, and the two would eventually
disagree.

```text
  absent    no copy; searches scan rows
  current   built from the live generation
  stale     built from an older one — refused, and searches fall back
  orphaned  built from a NEWER one; a save was rolled back under it
```

A stale copy is **refused rather than searched**: yesterday's rows would
look like the database being wrong, and a slow answer today is better
than a fast wrong one.

```text
$ geist --path data/notes find title title6
1 match(es)  (read 116 B of the column copy, not 1249 B of rows)
```

Two limits worth knowing before you turn it on: it **cannot be combined
with a sealed preset** (the copy would be plaintext columns beside an
encrypted file, and the config refuses rather than doing it), and
rebuilding is whole-file, so `tmOnSave` on a large store makes every save
cost a second write.

## 1.9 Sealing

Same call, a sealed preset, and a password:

```nim
var db = openGeist[Note]("data/notes", secureAppConfig(), "password")
```

```text
$ geist --path data/notes --preset secure-app --password-file pw list
$ grep -r --binary-files=text "hello" data/notes     # finds nothing
```

```text
nim c -r examples/geist_encrypted.nim
```

The unit that gets sealed is a **batch**: a row range crossed with a
column group.

```text
  column group  x  row range  =  one batch
       |                |
       v                v
  "body" alone     rows 0..31
  "title,tags"     rows 0..31   <- a second batch, same rows, other columns

  ledger row = floor(rowIndex / batchRows)      plain arithmetic, no search
```

```text
  plaintext bytes
        |
        |  two independent key-streams, XOR'd together
        |  (ChaCha20 and AES-CTR — both can jump to any offset)
        v
  sealed bytes
        |
        |  digest    = Gimli over the sealed bytes          (no key: "is this what was written?")
        |  tag       = keyed BLAKE3 over the same           (key:    "did a key holder write it?")
        |  tree root = proof a single row still belongs
        |  both checks are bound to: WHERE the batch sits, its row lengths,
        |  the cluster's schema and total row count
        v
  stored batch
```

Opening a batch checks the digest, then the tag, and refuses before a single
byte is decrypted:

```text
  digest wrong   -> "sealed data is damaged"            a broken disk, a cut file
  tag wrong      -> "sealed data failed authentication" a deliberate change (even
                                                        with a recomputed digest),
                                                        or the wrong key
```

The digest needs no password, so anyone can check a sealed store (or a
keyring folder) without opening it:

```text
$ geist verify --path data/notes
intact: 5 sealed batch(es) checked
```

```nim
let r = verifyStoreIntegrity("data/notes")   # r.ok, r.batches, r.problems
```

It also checks each cluster against the index hash and that no sealed
cluster is missing. What it cannot tell is WHO changed a file: anyone can
recompute a digest, which is why opening also checks the tag. Layout fields
a reader never uses (header padding, `rowBytes`) are not covered; changing
one never changes what is read.

Rules that matter day to day:

```text
  - no stored random number for the stream start; it is derived from
    (key id, group, batch index, epoch)
  - every rewrite bumps the epoch, so a stream start never repeats
  - a batch moved somewhere else, re-cut at other row boundaries, or cut
    short through the index fails its check
  - one row can be opened without opening its whole batch
  - a fresh key id per batch avoids rewriting the file when a counter
    climbs
```

A sealed generation is **three files that travel together**:

```text
  +-- generation N ------------------------+
  |  name.ge1st.gN     the data            |
  |  name.keys.gN      secret material     |
  |  name.ledger.gN    public epochs/checks|
  +----------------------------------------+
        ^
        |  "current" points at the set, not at a file
        |  lose the ledger -> the data cannot be opened, by design
        |  artifactSet() names the set; backup refuses an incomplete one
```

Meta and journal clusters are sealed too, under the same rules and with
their own ledger rows. Turn that off only when a tool must read those
clusters without the password.

### Keyrings: parts that open with different passwords

A store has ONE password. A **keyring set** is several sealed stores in one
folder, each with its own password, opened one at a time. A ring that was
never unlocked is never read and never written.

```text
  vault/
    rings          public list of ring names, one per line
    stage1/        a sealed store   (password A)
    stage2/        a sealed store   (password B)

  unlocked   stage1             locked   stage2
  changed    yes                         --
  on save    written                     untouched, byte for byte
```

```nim
var K = createKeyrings("vault", ["stage1", "stage2"], ["A", "B"])
K.upsert("stage1", RingRow(rowKey: "card-7", kind: "accounts", body: "..."))
discard K.save()                # writes only rings that changed
K.close()

K = openKeyrings("vault")       # every ring locked
discard K.unlock("stage1", "A") # stage2 stays closed
echo K.rows("stage1").len
```

Rows are `(rowKey, kind, body)`; the body is the caller's and Geist never
reads it. Why separate stores rather than one key per column group: a
store with text columns seals whole rows (section 1.9), so a column group
cannot split a row between two passwords. Separate stores can, and need
nothing new in the sealing code. `changePassword` re-seals one ring's key
file on the next save; its rows and master secret stay as they are.
Android reaches the same rings through `android/geistvault` (`GeistVault`,
`GeistProfiles`).

**Seeing a locked row without opening it.** Every save also writes a small
public **row map** beside the ring: which row key sits at which row
position in the file. With it, a locked ring can hand out one row's stored
bytes exactly as they are on disk -- still sealed, so they show THAT
something is stored, never what.

```text
  vault/stage4/rowmap        (plain text, no secrets but the row keys)
    7                        <- generation the map belongs to
    card-9<TAB>0             <- row key, row position
    card-3<TAB>1

  sealedRow(K, "stage4", "card-9")
    rowmap generation == live generation?   no  -> empty (map is stale)
    find card-9 -> position 0
    read the entry cluster, cut out row 0   -> its sealed bytes
```

```nim
echo K.sealedRow("stage4", "card-9").len   # works while stage4 is locked
```

The map reveals the row keys and how many rows a ring has. Both were
already guessable from the file sizes; the row contents stay sealed.

## 1.10 Watching a store you do not own

No password, no lease, no row bodies — only "which blocks moved":

```nim
var
  seen = observeStore("data/notes")
  step = followStore(seen.f, "data/notes")
echo step.changed        # cluster numbers that differ
```

```text
nim c -r examples/geist_observe.nim
```

```text
  one read = 32 byte header + 76 bytes per cluster
  three clusters -> 260 bytes, whether the file is 1 MB or 1 GB
```

This is how `geistd` notices that a local `geist put` moved the file
underneath it ([2.3](#23-who-may-do-what)) without reopening anything.

## 1.11 Configuring

Start from a preset. That is one call, and it decides the on-disk shape:

```nim
var db = openGeist[Note]("data/notes", chatConfig())
```

```text
$ geist --path data/notes --preset chat init --schema "..."
$ geist presets                      # the same list, from the CLI
```

```text
  code name                 CLI names                         id?  batch  seal      for
  -----------------------   --------------------------------  ---  -----  --------  ----
  appConfig                 app, local-app                    yes   64    none      normal local records
  collapsedConfig           collapsed, rare-write, packed     yes   64    none      wide / sparse, rare writes
  secureCollapsedConfig     secure-collapsed, secure-packed   yes   32    cascade   same, sealed
  secureAppConfig           secure-app, secure                yes   32    cascade   sealed local records
  chatConfig                chat, messaging, message          yes   16    ChaCha20  messaging by id
  iotConfig                 iot, telemetry, sensor            no   256    ChaCha20  fixed sensor rows
  archiveConfig             archive, archival, backup         yes 1024    cascade   long-term scan
  streamConfig              stream, media, livestream         no     8    ChaCha20  short-lived chunks
  ledgerConfig              ledger, journal, append-only      yes  128    cascade   append-only chain
```

`iot` and `stream` are the two with `id?  no`: telemetry never edits a
reading, so paying 16 bytes a row for `set`/`delete`/`byId` would be
waste.

Those nine are named after the SHAPE of the data. Five more are named
after the JOB, for a caller who knows what they are building rather than
how it is accessed:

```text
  code name                 CLI names                         id?  batch  seal      for
  -----------------------   --------------------------------  ---  -----  --------  ----
  syncConfig                cloud-sync, sync, replica         yes   32    ChaCha20  machines reconciling copies
  chainConfig               chain, blockchain                 yes  256    cascade   tamper-evident shared log
  hostConfig                host, hosting, content            yes  256    ChaCha20  content addressed by hash
  liveConfig                live, position, realtime          no     4    ChaCha20  fast small updates, RAM only
  bulkConfig                bulk, files, large-files          yes  512    ChaCha20  few very large objects
```

**Each of the five carries a ceiling, and a preset cannot lift one.**
They are worth reading before you pick:

```text
  preset      works for                       runs into
  ----------  -----------------------------   ---------------------------
  cloud-sync  records people edit             a reply stops at 28 KB, so
                                              a big backlog is many
                                              blocking round trips
  chain       a shared record among peers     no consensus and no fork
              who hold each other's pins      choice exist anywhere in
                                              Geist; rows are covered by
                                              a batch root, not chained
                                              one by one
  host        objects up to ~78 MB            one transfer is 65,535
                                              chunks x 1,200 B; peer
                                              DISCOVERY does not exist,
                                              pins are placed by hand
  live        50 Hz positions on a LAN        every send waits for a
                                              reply, so the rate is
                                              1/RTT. VIDEO DOES NOT WORK
  bulk        many-MB objects on ONE machine  sidecar reads and writes
                                              whole objects in RAM, so
                                              multi-GB files need a
                                              streaming path that is not
                                              written yet
```

`docs/workloads.md` has the measurements behind every number above, and
what would have to change to move each one.

Adjust a preset in code when a specific store needs it:

```nim
var c = archiveConfig()
c.sidecarThreshold = 4096'u32
c.columnPolicy = @[cappedColumn("title", 128'u32)]
c.columnGroups = @[@["body"], @["authorId", "spaceId"]]
c.backup.everyNWrites = 32'u32
```

### The layers, and which of them may touch what

Five things get called "config". They are not a pile — they sit on
different sides of the store/link/machine walls, and only the first two
can change what lands on disk:

```text
  +-- SHAPE (part 1 only) -----------------------------------------+
  |  1  preset            appConfig() / --preset app               |
  |                       columns, id on/off, seal, batch,         |
  |                       write mode, backup policy                |
  |                       scope: ONE database                      |
  |                                                                |
  |  2  library defaults  configs/default.toml [runtime.storage]   |
  |                       and [runtime.backup]                     |
  |                       a few nudges over the preset             |
  |                       scope: every database in the project     |
  +----------------------------------------------------------------+

  +-- LINK (part 2 and 3) -----------------------------------------+
  |  3  link policy       configs/default.toml [runtime.transport] |
  |                       where a link starts, when it climbs      |
  |                       scope: every peer session                |
  |                       does NOT choose algorithms — those are   |
  |                       fixed in code                            |
  +----------------------------------------------------------------+

  +-- MACHINE (binaries only; never touches on-disk shape) --------+
  |  4  this machine      userconfig.toml                          |
  |                       paths, pins, listen address, sinks       |
  |                                                                |
  |  5  this run          CLI flags / NixOS services               |
  |                       one-off overrides of 4                   |
  +----------------------------------------------------------------+
```

```text
  who reads which layer
  ---------------------
  import geist            1 + 2
  import geist/wire       3        (+ [relay] machine keys from 4/5)
  import geist/network    1 + 2 + 3
  geist-relayd            3 + [relay]; never compiles the reader for [storage]
```

`configs/default.toml` is one file with three kinds of reader. Its build
tables (`[project]`, `[nim]`, `[define]`, `[passC]`, `[passL]`) are read by
the compiler through `config.nims`. Of its `[runtime]` tables,
`storage`/`backup` never reach the wire half, `transport` never reaches
the disk half, and neither parses the other's keys.

### How shape layers stack

Later wins, and a key a file does not mention is **silence**, not an
override:

```text
  builtinDefaults()
        |
        |  full starting table
        v
  named preset  (app / secure / iot / ...)
        |
        |  only keys ACTUALLY written in configs/default.toml [runtime],
        |  then in the build preset's file (configs/<preset>.toml)
        v
  fields you set on GeistConfig in code
        |
        v
  openGeist receives this final value
```

```nim
discard initGeistDefaults()            # part 1 only
discard initGeistNetworkDefaults()     # parts 1 + 2
var db = openGeist[Note]("data/notes", defaultGeistConfig())
```

The machine layers stack more simply, and separately: a CLI flag always
beats `userconfig.toml`. An unknown key in either file is an **error** —
a typo must not look like success.

### `configs/default.toml` — the project file

Not required; a missing file means the built-ins. It is read from the
working directory when the program starts. This is the whole `[runtime]`
surface:

```text
  section               key                 default      meaning
  -------------------   ------------------  -----------  -------
  [runtime.storage]     preset              "app"        starting preset name
  [runtime.storage]     sidecarThreshold    1024         bytes before a value moves out
  [runtime.storage]     rowIdentity         (unset)      force id on/off; unset keeps the preset
  [runtime.storage]     transpose           "none"       column copy: none / onSave / interval / manual
  [runtime.storage]     transposeEverySeconds  0         rebuild window for "interval", in seconds
  [runtime.backup]      copies              2            rotation slots .b1 .b2 .b3
  [runtime.backup]      everySeconds        0            also rotate on a timer
  [runtime.transport]   startTier           "standard"   strength a link opens at
  [runtime.transport]   secretAtMiB         64           climb to secret after this many MiB
  [runtime.transport]   archiveAtMiB        1024         climb to archive after this many MiB
  [runtime.transport]   requireCookie       true         challenge a first hello before doing key work
```

You may change *when* a link climbs. You may not change *what algorithms*
a strength uses — see [2.5](#25-strength-levels).

### `configs/<preset>.toml` — build presets

Def. 1: a **build preset** is a file in `configs/` that holds only what
differs from `default.toml`. It changes how a program is compiled and what
its `[runtime]` starts with. It is not a storage preset (`app`, `iot`, ...):
a storage preset is a shape of database; a build preset is a shape of
*program*.

```text
  nim c -d:preset=server src/server/geistd.nim
  nimble buildServer -d:preset=server        # the shared tasks pass it on

  configs/default.toml  -->  configs/server.toml  -->  command line
  (every switch)             (what server changes)     (wins over both)
```

```text
  file          compiled with          starts with
  ------------  ---------------------  ------------------------------------
  default.toml  --mm:orc --threads:on  storage preset app, tier standard
                -d:hasLibsodium
  server.toml   + --opt:speed          tier secret, 3 backups, hourly
  iot.toml      + --opt:size, gc-      storage preset iot, no row ids,
                sections               1 backup, tier telemetry
  android.toml  no -d:hasLibsodium     (same as default)
```

A program built with `-d:preset=server` reads `configs/default.toml` and
then `configs/server.toml` from its working directory when it starts, so
the file on disk can still be edited after the build.

### `userconfig.toml` — this machine

Saves typing, nothing else. Every key has a flag, and the flag always
wins. Looked for in the working directory, then
`~/.config/geist/userconfig.toml`. Passwords are named by *file*, so the
config itself stays shareable.

```text
$ cat userconfig.toml
[database]
path = "data/notes"
preset = "app"

$ geist list          # no --path, no --preset
```

```text
  section         key                      flag                         sets
  -------------   -----------------------  ---------------------------  ----
  [database]      path                     --path                       store folder
  [database]      preset                   --preset                     preset name
  [database]      passwordFile             --password-file              seal password file
  [daemon]        listen                   --listen                     geistd bind (dac://host:port)
  [daemon]        identity                 --identity                   this side's key file
  [daemon]        identityPasswordFile     --identity-password-file     seals that key
  [daemon]        trust                    --trust (repeat)             pins allowed to read
  [daemon]        allowWrite               --allow-write (repeat)       pins allowed to send rows
  [client]        remote                   --remote                     daemon to call
  [client]        peerPin                  --peer-pin                   pin checked on that daemon
  [client]        limit                    --limit                      default list/find limit
  [relay]         listen                   --listen                     geist-relayd bind (port 47656)
  [relay]         subject                  --subject                    relay name on its pin
  [relay]         identity                 --identity                   relay key file
  [relay]         identityPasswordFile     --identity-password-file     seals that key
  [relay]         trust                    --trust (repeat)             pins that may collect
  [relay]         allowWrite               --allow-write (repeat)       pins that may send
  [relay]         to                       --to                         spool | stdout | file | exec
  [relay]         file                     --file                       log path when to=file
  [relay]         format                   --format                     lines | json | raw
  [relay]         exec                     --exec                       command when to=exec
  [relay]         execTimeoutMs            --exec-timeout-ms            kill after N ms (0 = no wait)
  [relay]         stream                   --stream (repeat)            accepted stream names
  [relay]         spool                    --spool                      in-memory messages per stream
  [relayClient]   remote / peerPin / ...   same flags                   client side of a relay
```

`[daemon]` vs `[client]`, and `[relay]` vs `[relayClient]`, stay separate
so a machine can run both ends without anyone guessing which side a key
belongs to.

On NixOS these files are generated:

```nix
services.geistd = { enable = true; path = "/var/lib/geist/notes"; ... };
services.geist-relay = { enable = true; to = "exec"; ... };
programs.geist-client = { enable = true; settings.database.path = "..."; };
```

See [docs/nix.md](docs/nix.md).

## 1.12 Converting JSON and TOML

```nim
var toml = convertDoc(jsonText, dfJson, dfToml)      # text -> text
discard convertFile("settings.json", "settings.toml")   # by extension
echo toDocText(mySettings, dfToml)                   # object -> text
var back = fromDocText(text, dfJson, defaults())     # text -> object
```

```text
geist convert settings.json settings.toml
```

Nothing is dropped quietly. TOML has no `null`, no document that is a
list, and no list that mixes tables with plain values; a conversion that
meets one refuses and names the place (`server.host is null, and TOML has
no null`) rather than writing a file that is missing it. A failed
`convertFile` writes nothing.

## 1.13 Sealing one object

For an object that is not going into a Geist store -- one password entry
kept by another program, a game save, a record inside a message:

```nim
var key = newSealKey()                       # keep it in the OS keystore
var blob = sealObject(entry, key, aad = "vault/alice")
# ... write blob.data wherever you like ...
var back = openObject[Entry](blob.data, key, aad = "vault/alice")
```

```text
  | "GSK1" | 24 | nonce (24) | t | tag (t) | sealed JSON of the object |
```

The object travels as JSON inside the seal, so lists and tables are
fine and a field added later keeps its default when an older blob is
opened. `aad` is context the blob is bound to: sealed for `vault/alice`,
it will not open as `vault/bob`. A wrong key, a changed byte and a wrong
context are one answer, never garbage. `sealObjectWithPassword` does the
key step per call (Argon2) -- right for one object, wrong for thousands.

## 1.14 A whole table as JSON or TOML

To hand the rows to another program, keep a copy in git, or fix one
value in an editor, a store is written out as an ordinary file and read
back in:

```nim
discard db.exportTable("notes.toml")                  # one block per row
var style = defaultTableTextStyle()
style.shape = shColumns                               # turned on its side
style.binary = bfEscaped                              # bytes as \u00HH
style.sealed = @["body"]                              # body encrypted
discard db.exportTable("notes.json", style, key)      # key: newSealKey()
discard db.exportTable("notes.json", style, "pw")     # ... or a password
var done = copy.importTable("notes.json", key)        # (ok, added, err)
```

```text
geist --path data/notes export notes.toml
geist --path data/notes export notes.json --transposed
geist --path data/notes export notes.toml --seal body --seal-key notes --binary escaped
geist --path data/copy  import notes.toml --seal-key notes
```

**Def. 14.1 — shape.** Which way round the table is written. `shRows`
is one block per row, the way `geist list` shows it. `shColumns` is the
**transposed** form: one list per column, rows and columns swapped.

```text
  shRows (TOML)                    shColumns (TOML)
  ------------------------------   ---------------------------------
  [[rows]]                         [columns]
  __rowId = "17"                   __rowId = ["17", "18"]
  __flags = "0"                    __flags = ["0", "0"]
  title = "groceries"              title = ["groceries", "diary"]
  body = "milk, eggs"              body = ["milk, eggs", "dear ..."]
  stars = 2                        stars = [2, 5]

  [[rows]]
  __rowId = "18"
  ...
```

In JSON the same two shapes are `"rows": [ {...}, {...} ]` and
`"columns": { "title": [...], ... }`.

**Def. 14.2 — binary form.** JSON and TOML hold text. A `bytes` column,
and every sealed value (Def. 14.3), is bytes from 00 to FF, so it is
written one of two ways:

```text
  the bytes   48 69 00 FF

  bfHex       "486900ff"            two letters per byte
  bfEscaped   "Hi\u0000ÿ"      a readable byte stays itself; every
                                    other byte HH becomes \u00HH
```

`\u00HH` is an escape JSON and TOML both already have, so any reader
opens the file. Geist turns the character U+00HH back into the byte HH.
A character above U+00FF in an escaped field is refused, because it
cannot be a byte.

**Def. 14.3 — sealed column.** Each value of the column is encrypted on
its own (1.13's `GSK1` blob), then written in the binary form:

```text
  "dear diary"  --seal(key, context "geist-table/body")-->  GSK1 | 24 |
                                         nonce | t | tag | ciphertext
                --bfHex-->  body = "47534b3118..."
```

The context ties a value to its column: a sealed `body` pasted into
`title` will not open. A password is turned into a key once per file,
and its salt is written into the file (`salt = "..."`), so the same
password opens it again. `__rowId` and `__flags` cannot be sealed: a
reader needs them to tell the rows apart.

**The file, top to bottom:**

```text
  geist = "table"         marks a table file
  version = 1             this layout
  type = "Note"           the schema's type name
  shape = "rows"          Def. 14.1
  binary = "hex"          Def. 14.2
  collapse = false        the schema's autoCollapse
  sealed = ["body"]       Def. 14.3; [] when nothing is sealed
  salt = "..."            only when a password sealed it

  [[schema]]              one per column, in order
  name = "title"
  kind = "text"           int | float | text | bytes | sealed | ref
  column = "variable"     fixed | capped | variable
  width = 0
  overflow = "error"      error | truncate

  [[rows]] ...  or  [columns] ...
```

`__rowId` and `__flags` are written as quoted numbers: an id carries the
machine's tag in its high bits and is often bigger than the largest
integer TOML can hold.

**Reading back.** A missing cell is the column's zero, like a collapsed
value in the store. An unknown field, a value of the wrong kind, or
columns of different lengths are refused, naming the row and the field.
A value that left its row for the sidecar is written as the value
itself, not as a reference into this machine's folder.

**Importing.** A row keeps the id the file gives it, so importing the
same file twice replaces the rows instead of doubling them;
`freshIds = true` (`--fresh-ids`) gives them new ids instead. Every row
is checked before any is stored: one bad cell stops the import with
nothing written. `geist import` into a path with no database creates one
from the file's schema.

```text
  file __rowId   database has ids   freshIds   stored as
  ------------   ----------------   --------   ------------------------
  "17"           yes                no         row 17 (new or replaced)
  "17"           yes                yes        the next free id
  (none)         yes                either     the next free id
  any            no                 either     appended, no id
```

See `examples/geist_tables.nim`, and `src/geist/tabletext.nim` for the
full definitions.

---

## For contributors

## Where the walls are

```text
  src/geist.nim          the facade: rows, files, keys, backups, sessions
  src/geist/             the storage library
  src/clients/geist_cli.nim   the `geist` command line (local --path only)
  src/clients/cli/       common, direct, keys, tables
```

`nimble checkModular` compiles a program that imports `geist` with Bifrost
REMOVED from the search path. A storage change that starts importing the
network fails that check. Bifrost is not a dependency of this repository.

## Source layout

```text
  src/geist.nim             facade
  src/geist/                storage modules (types, config, session*, store,
                            rowid, sidecar, keys, keyring, keystore, crypto/,
                            tabletext, transpose, layout, settings, ...)
  src/clients/geist_cli.nim the `geist` entry point
  src/clients/cli/          common, direct, keys, tables
  evaluation/tests/         storage tests; modular/storage_only.nim
  examples/                 quickstart, encrypted, observe, tables, convert, ...
  configs/                  default.toml, iot.toml, android.toml
  android/geistkeystore/    the Android keystore companion
  android/geistvault/       the Android keyring app
```

## Tasks

```text
  nimble buildAll            the `geist` CLI, for release
  nimble checkAll            compile-check every storage module
  nimble checkModular        the storage half builds with no network stack
  nimble test                the whole suite
  nimble runExamples         every example
  nimble demoCli             a scratch database driven through the CLI
```

## Issue playbook

```text
  problem                                              what to do
  ---------------------------------------------------  ------------------------------------------
  "already open for writing: held by pid N on HOST"    another process holds the write lease.
                                                       Open read-only, or stop that process. A
                                                       lock left by a dead process is taken over
                                                       after its staleness window
  "transpose status: stale" or a refused fast search   the column copy is older than the rows.
                                                       `geist transpose` rebuilds it; a stale
                                                       copy is refused on purpose
  "unknown key" from a settings file                   a typo. The error names the key and the
                                                       section; an unknown key is never ignored
  "a password is needed" on keys                       the key folder is sealed with the password;
                                                       pass --password-file
```

## Maintainer conventions

The house style lives in the workspace `Agent-Conventions` repo, not in
a copy here -- a copy drifts. The parts you hit first:

```text
  area              rule
  ----------------  ----------------------------------------------------
  language          Nim unless stated otherwise
  flow              take data in -> clean it -> build truth -> act
  modules           order by dependency; types first; keep them small
  declarations      var / const in indented blocks; avoid let
  nesting           no nested loops or nested ifs — extract a helper
  pragmas           {.role: ..., tag: "a|b".} on procs, from runePragmas
  promises          needs / gives / keeps (var_invariants) where a sentence
                    about a routine would otherwise rot in a comment
  unfinished code   a placeholder routine is named ph_<name>
  settings          one file, configs/default.toml; presets hold only the
                    difference; never repeat a value in .nimble or nix
  tasks             generic ones come from Nimble-Tasks; write only what
                    it cannot cover
  evaluation        tests in evaluation/tests with a # {.testKind: ...}
                    line; benchmarks and statistics beside them
  parameter names   A arrays, S mutated state, i/j/k index, l/m/n length,
                    t temporary; first letter of the thing otherwise
  docs on params    ## lines under the declaration
  comments          say why, never restate the code
  artifacts         builds go under build/; never into src/
  tests             a public behaviour change needs a test in the same commit
  decisions         a format / wire / on-disk change needs DESIGN_RATIONALE.md
  git               commit after each change; no secrets in the tree
```

Two rules that are not style:

```text
  do not store what can be derived
  do not acknowledge what is not durable yet
```
