# Geist

Stores your Nim objects on disk as packed rows. Can seal them. Can let
another machine follow the same store — or write into it — without owning
the files.

```text
  your object (Note, Message, Reading, ...)
           |
           |  one mapper at compile time
           v
  +---------------- packed row ----------------+
  | id | flags | field | field | field | ...   |
  +--------------------------------------------+
           |
           |  many rows share one cluster
           v
  +------------- store root (a folder) -------------+
  |  notes.ge1st.g3     the live data               |
  |  notes.keys.g3      secrets (only if sealed)    |
  |  notes.ledger.g3    public open-table           |
  |  current            points at generation 3      |
  |  .geist-lock        who may write               |
  |  .geist-sidecar/    big values live here        |
  +-------------------------------------------------+
```

---

## The whole thing, top down

Geist is three parts. Each one is the part above it with something added
or taken away, so you can stop reading at whichever one you need.

```text
  +-- PART 1: THE STORE -------------------+   import geist
  |  rows on disk, sealed or not           |   binary: geist
  |  one writer, many readers              |
  +----------------------------------------+
                    |
                    |  add a pinned link, and the same rows
                    |  live on two machines
                    v
  +-- PART 2: THE LINK --------------------+   import geist/network
  |  catch up, push rows, serve a store    |   binary: geistd   (port 47655)
  |  everything from part 1, plus peers    |
  +----------------------------------------+
                    |
                    |  now take the store back OUT and keep
                    |  only the link
                    v
  +-- PART 3: THE PIPE --------------------+   import geist/wire
  |  messages between machines             |   binary: geist-relayd (47656)
  |  nothing is kept                       |
  +----------------------------------------+
```

The imports are real walls, not naming. Part 1 does not compile a socket;
part 3 does not compile a database. Two tasks prove it, and they are the
first thing to run if you ever suspect an import crept across:

```text
nimble checkModular    # build part 1 with the network stack removed from the path
nimble checkRelay      # build part 3 and fail if any database module reaches the C output
```

One line of each part, so the rest of this file has somewhere to hang:

```nim
# part 1 — a store
var db = openGeist[Note]("data/notes", appConfig())
```

```text
# part 2 — a store another machine may read
geistd --path data/notes --listen dac://0.0.0.0:47655 \
       --identity daemon.key --trust laptop.pin
```

```text
# part 3 — a pipe with no store behind it
geist-relayd --listen dac://0.0.0.0:47656 \
             --identity relay.key --allow-write phone.pin --to exec \
             --exec 'whisper-cpp -'
```

Four binaries come out of the build, two per side of the store/no-store
line:

```text
  geist           client   talks to a folder, or to a geistd
  geistd          daemon   serves a store                     47655
  geist-relay     client   sends and collects messages
  geist-relayd    daemon   moves messages, stores nothing     47656
```

---

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
  ledger          the PUBLIC table of which key and epoch each batch used.
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
nimble exampleQuickstart
```

The other four: `exampleEncrypted`, `exampleObserve`, `exampleFastSearch`,
and `exampleBuffers` -- that last one is two Geist instances passing rows
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
nimble bench
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
nimble exampleEncrypted
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
        |  tag       = keyed check (two checks XOR'd)
        |  tree root = proof a single row still belongs
        |  + public bytes binding WHERE this batch sits
        v
  stored batch
```

Rules that matter day to day:

```text
  - no stored random number for the stream start; it is derived from
    (key id, group, batch index, epoch)
  - every rewrite bumps the epoch, so a stream start never repeats
  - a batch moved somewhere else fails its check
  - one row can be opened without opening its whole batch
  - a fresh key id per batch avoids rewriting the file when a counter
    climbs
```

A sealed generation is **three files that travel together**:

```text
  +-- generation N ------------------------+
  |  name.ge1st.gN     the data            |
  |  name.keys.gN      secret material     |
  |  name.ledger.gN    public epochs/roots |
  +----------------------------------------+
        ^
        |  "current" points at the set, not at a file
        |  lose the ledger -> the data cannot be opened, by design
        |  artifactSet() names the set; backup refuses an incomplete one
```

Meta and journal clusters are sealed too, under the same rules and with
their own ledger rows. Turn that off only when a tool must read those
clusters without the password.

## 1.10 Watching a store you do not own

No password, no lease, no row bodies — only "which blocks moved":

```nim
var
  seen = observeStore("data/notes")
  step = followStore(seen.f, "data/notes")
echo step.changed        # cluster numbers that differ
```

```text
nimble exampleObserve
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
  |  2  library defaults  config.toml [storage] [backup]           |
  |                       a few nudges over the preset             |
  |                       scope: every database in the project     |
  +----------------------------------------------------------------+

  +-- LINK (part 2 and 3) -----------------------------------------+
  |  3  link policy       config.toml [transport]                  |
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

`config.toml` is one file with two readers. `[storage]`/`[backup]` never
reach the wire half, `[transport]` never reaches the disk half, and
neither parses the other's keys.

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
        |  only keys ACTUALLY written in config.toml
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

### `config.toml` — the project file

Not required; a missing file means the built-ins. This is the whole
surface:

```text
  section       key                 default      meaning
  -----------   ------------------  -----------  -------
  [storage]     preset              "app"        starting preset name
  [storage]     sidecarThreshold    1024         bytes before a value moves out
  [storage]     rowIdentity         (unset)      force id on/off; unset keeps the preset
  [storage]     transpose           "none"       column copy: none / onSave / interval / manual
  [storage]     transposeEverySeconds  0         rebuild window for "interval", in seconds
  [backup]      copies              2            rotation slots .b1 .b2 .b3
  [backup]      everySeconds        0            also rotate on a timer
  [transport]   startTier           "standard"   strength a link opens at
  [transport]   secretAtMiB         64           climb to secret after this many MiB
  [transport]   archiveAtMiB        1024         climb to archive after this many MiB
  [transport]   requireCookie       true         challenge a first hello before doing key work
```

You may change *when* a link climbs. You may not change *what algorithms*
a strength uses — see [2.5](#25-strength-levels).

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

---

# Part 2 — The link

Everything in part 1, plus other machines. Same rows, same ids, one
writer at a time.

## 2.0 A link does not need a database

This is the part people expect to be harder than it is, so it is stated
before anything else in part 2.

**Def.: a Geist endpoint is a function, not a file.** `initGeistServer`
takes a local identity and a list of peers it trusts. It does *not* take
a `Session`. What it serves is a `ServedHandler`:

```nim
ServedHandler* = proc (q: Query, p: PeerContext): Reply {.gcsafe.}
```

Whatever that function closes over IS the storage. Three programs in this
repository are the same program with a different handler:

```text
  program          the handler closes over        touches disk?
  ---------------  -----------------------------  -------------
  geistd           a Session                      yes
  geist-relayd     a bounded ring in memory       no
  examples/        a plain `seq[Row]`             no
   geist_buffers
```

So two instances that only want to pass rows between their buffers need
three things and nothing else:

```text
  where the other is   dac://host:port
  who the other is     its pin -- the public half of its signing keys
  who this one is      its own identity
```

Neither side needs a store, a path, or a shared schema at compile time —
the schema travels on the wire. `nimble exampleBuffers` runs it:

```text
identities: sender=sender  receiver=receiver  (in memory, no files)
receiver: listening on dac://127.0.0.1:47901 with nothing on disk
sender:   handshake done, session open
sender:   schema from the wire -> noteId:int,title:text,body:text
sender:   pushed 3 row(s)
sender:   receiver now holds 3 row(s):
            1  row-1  in memory only
```

Identities there are minted with `geistIdentity("name")` and never
written down, which is why the example touches no path at all. A real
deployment persists them with `loadOrCreateIdentity` and `savePin`, so a
restart is the same peer rather than a stranger.

**Authentication is public-key only.** A pin is a name plus public
signing keys, and that is the one mode Geist wires up. Bifrost underneath
also implements a shared-secret mode (AM1M, `initAmePskAuthentication`),
and Geist does not expose it — `connectGeist` and `initGeistServer` both
hard-code the pinned-key path. If you want symmetric keys, that is the
change to make, and it is contained to `transport.nim`.

## 2.1 Two desktops, from nothing

Trust here is **pinned**: each side must already hold the other's public
name card before a handshake will complete. That exchange is the trust
decision, and Geist does not make it for you.

```text
  # 1. each side mints a key and publishes the public half, once
  geist  keygen --identity client.key --pin-out client.pin --password-file pw
  geistd --path data/notes --identity daemon.key \
         --identity-password-file pw --pin-out daemon.pin

  # 2. hand the .pin files over by any means you like (they are public)

  # 3. serve, naming the pin you now hold
  geistd --path data/notes --listen dac://127.0.0.1:47655 \
         --identity daemon.key --identity-password-file pw \
         --trust client.pin

  # 4. call it
  geist --remote dac://127.0.0.1:47655 \
        --identity client.key --password-file pw \
        --peer-pin daemon.pin list
```

A daemon with no pin refuses to start: with nobody to trust, every
handshake would be rejected anyway.

In Nim the same conversation is four calls (identities and cursors come
from the steps above):

```nim
import geist/network

var
  link = connectGeist(peer, myIdentity, theirPin, defaultTierPolicy())
  caught = link.link.syncRemote(myCursor)

discard mine.applyRows(caught.reply.rows)
discard link.link.pushRemote(mine.rowsSince(theirCursor))
```

## 2.2 Push and pull

Two directions, and they are not the same command:

```text
  push   a peer sends rows INTO your store     -> needs --allow-write there
  pull   you ask a peer for rows you lack      -> `geist sync`, needs nothing there
                                                  beyond being trusted to read
```

```text
$ geist sync --path data/notes --remote dac://192.168.1.20:47655 \
      --identity me.key --peer-pin them.pin --password-file pw
applied 2 row(s) in 1 request(s); now at log position 2
```

```text
  position remembered in .geist-cursors beside the store
  a second call with nothing new is one empty request
  an empty store adopts the peer's schema from the first answer
```

Because a caught-up store is an ordinary store and a served one is an
ordinary daemon, machines chain with no forwarding code at all:

```text
  origin  --sync-->  middle  --sync-->  tail
```

Same command at every hop. The id minted at `origin` survives both, so a
later update from `origin` lands **on** that row at `tail` rather than
beside it. A node that only applies what it pulls should be `--trust`
only — `--allow-write` would take the write lease the catch-up itself
needs.

## 2.3 Who may do what

Rights come from the pin list the operator wrote, never from the request:

```text
  --trust pin.file          may read
  --allow-write pin.file    may read AND send rows
```

```text
$ geist --remote dac://192.168.1.20:47655 ... put noteId=3 title=nope
geist: 'alpha' may read but not write; the operator grants that with
--allow-write <pin>
```

`--allow-write` has one consequence worth planning around: serving a
write means *being* the writer, so such a daemon takes the store's write
lease, and a direct `geist put` on that machine is refused while it runs.

```text
  --trust only        no lease   -> local `geist put` keeps working, and the
                                    daemon notices the file moved (1.8) and
                                    re-reads a few hundred bytes of index
  --allow-write       lease held -> local writes refused by name
```

## 2.4 What the wire carries

One request type, one reply type, eight meanings. The operation is the
**first byte of the request**, and that is the only place the kind of
message is written down:

```text
  0 qoGet    one row by @position      4 qoSync       log rows after a cursor
  1 qoPut    rows from a peer          5 qoFetch      one row by id
  2 qoFind   exact text match          6 qoSubscribe  name a cursor
  3 qoDelete remove one row by id      7 qoPoll       drain a named cursor
```

### A request, byte for byte

`find title "hi"` in collection `notes`, limit 20. Fifty-eight bytes,
using only the three rules from [Terms](#how-bytes-are-written):

```text
  offset  bytes                      what
  ------  -------------------------  ----------------------------------
       0  02                         op u8 = qoFind
       1  05 00 00 00                collection length = 5
       5  6E 6F 74 65 73             "notes"
      10  01 00 00 00                predicate count = 1
      14  05 00 00 00                field length = 5
      18  74 69 74 6C 65             "title"
      23  01                         isText u8 = 1
      24  02 00 00 00                text length = 2
      28  68 69                      "hi"
      30  00 00 00 00 00 00 00 00    num i64 = 0 (unused for text)
      38  14 00 00 00                limit u32 = 20
      42  00 00 00 00 00 00 00 00    cursor u64 = 0
      50  00 00 00 00                subscriptionId length = 0
      54  00 00 00 00                payload length = 0
                                     -------------------------------
                                     58 bytes total
```

Every operation uses this one layout; the unused fields are simply zero.
That is why there is no second codec for the network, and why a `qoPut`
is the same shape as a `qoFind` with rows in `payload`.

### The answer, byte for byte

One row back, cursor 3, epoch 7. Fifty-four bytes:

```text
  offset  bytes                      what
  ------  -------------------------  ----------------------------------
       0  01                         ok u8 = true
       1  00 00 00 00                err length = 0
       5  03 00 00 00 00 00 00 00    cursor u64 = 3
      13  01 00 00 00                matched u32 = 1
      17  07 00 00 00 00 00 00 00    epoch u64 = 7
      25  ..                         schema block (see 1.6)
                                     rows:
      42  01 00 00 00                row count = 1
      46  00 00                      schemaId u16
      48  02 00 00 00                row length = 2
      52  68 69                      the packed row bytes
```

**Every reply carries the schema.** That is what lets a client build a
row for a store it has never opened, and it is why a remote `put` needs
no local copy of the database.

The rows in a reply are the same bytes [1.6](#16-inside-a-row) describes,
untouched — no projection, no re-encoding. A row that travels arrives as
the sender stored it, identity included.

### Frames, envelopes and packages

A datagram has a ceiling and a database does not, so every payload
travels under a one-byte envelope:

```text
  fits in a frame                 too big for a frame
  ---------------                 -------------------
  +----+---------------+          +----+---------------+
  | 00 |   payload     |          | 01 |   manifest    |  chunk count,
  +----+---------------+          +----+---------------+  length, digest
   whole                          +----+---------------+
                                  | 02 |   chunk 0     |
                                  +----+---------------+
                                  | 02 |   chunk 1     |  ... until the
                                  +----+---------------+  digest checks out
```

```text
  payload <= 32,000 bytes   -> one frame, envelope 0
  payload  > 32,000 bytes   -> manifest + chunks, envelopes 1 and 2
  one frame                 <= 65,507 bytes, ceiling of a DAC datagram
```

Chunks are MTU-sized and each one rides inside an ordinary sealed frame,
so the slow path is slower by design — it is the fallback, not the norm.
The server avoids it by answering with fewer rows: a reply stops at about
28,000 bytes of rows and hands back a cursor to resume from.

### The order of a conversation

```text
  client                                   server
  ------                                   ------
  open ONE socket
  client hello        ------------------>  who is this? NOBODY KNOWS YET
                      <------------------  hello retry: prove you can
                                           receive here (a cookie)
  client hello again  ------------------>  cookie checks out; now spend
   (+ the cookie)                          the key exchange
                      <------------------  server hello: the key answer in
                                           the clear, WHO WE ARE sealed
                                           under it
  client finish       ------------------>  open the seal, read who they
   (WHO WE ARE sealed)                     are, find the pin that matches;
                                           session open, rights from that
                                           pin (same socket from here on)
  Query (envelope 0)  ------------------>  handler
                      <------------------  Reply (envelope 0)
  Query               ------------------>  ...
```

Three things in that picture are worth naming, because they are not how
most handshakes work.

**Nobody says who they are in the clear.** Def.: a *private handshake* is
one where each side's name and public keys travel inside a block only the
other side can open, after the key exchange. An observer on the wire sees
two machines agreeing on a key. It does not see which two.

**Which pin is used is decided last, not first.** The server holds a list
of trusted pins. It cannot look one up when the hello arrives, because the
hello names nobody — so it answers every hello the same way and, when the
sealed `client finish` opens, compares what it found against each pin in
turn. The first that matches decides both the name and the rights. A pin
that is not the caller costs a name-and-key comparison; only the pin that
matches pays for signature checking.

**A stranger cannot make the server do key work.** Def.: a *cookie* is a
short tag over the caller's address and the current time, computed with a
secret that never leaves the server. The server remembers nothing when it
sends one; when the cookie comes back it recomputes the tag and compares.
On a datagram socket nothing proves a source address, so without this a
flood of forged helloes would have the server doing post-quantum key
exchanges for packets that came from nowhere. The cost is one extra round
trip, paid once per session rather than once per question. It is on by
default and turned off with `initGeistServer(..., requireCookie = false)`
— which is only ever right on a socket strangers cannot reach.

One handshake per peer, then as many questions as you like. **The socket
must not change**: the server keys sessions by source address, so a
second socket arrives as a stranger.

Rows arriving from a peer go through the same rule as a local write —
one rule, two entry points:

```text
  unknown id   -> add
  known id     -> replace
  tombstone    -> remove
  same row again (a retry) -> no duplicate; applying it twice is a no-op
```

Two things a follower has to handle, and both are visible in the reply
bytes above:

```text
  epoch changed (offset 17)   -> the sender compacted under your cursor;
                                 start from zero (re-applying is harmless)
  fewer rows than --limit     -> the answer hit the 28 KB budget; resume
                                 from `cursor` (offset 5)
```

A remote `put` sends no id — the daemon names the row — and a remote
write is saved **before** it is acknowledged: a peer told "stored" will
not send it again.

## 2.5 Strength levels

Set where a link starts and when it climbs; you cannot set what it uses.

```text
$ cat config.toml
[transport]
startTier = "standard"
secretAtMiB = 64
```

```text
  strength      key-exchanges   signatures   fits in one frame?
  ----------    -------------   ----------   ------------------
  telemetry     1               1            yes
  userData      1               2            yes
  standard      2               2            yes   (default)
  secret        3               3            yes
  archive       5               3            no — needs package transfer
  recovery      6               3            no — needs package transfer
```

Large public keys only appear from `archive` up, so a small sensor never
pays for them. Which algorithms each strength selects is fixed in code: a
settings file able to weaken that would make the guarantee a deployment
detail.

## 2.6 Geist's share of the link

Geist did not write a transport. It picks masks and gives Query/Reply a
meaning; [Bifrost](docs/submodules.md) does the cryptography and the
plumbing:

```text
  Geist owns                         Bifrost owns
  ----------------------------       ---------------------------------
  which algorithm slots exist        handshake bytes
  how many slots each strength has   certificate / pin verification
  Query / Reply meaning              framing, packaging, replay defence
  (for rows, or for a relay pipe)    live session and epoch state
```

On the server side, one socket carries every peer:

```text
  one bound socket
       |
       +-- peer A session   (keyed by source address)
       +-- peer B session
       +-- peer C session

  handshake once per peer, then many questions on that SAME socket
  a second socket from the same client arrives as a stranger
```

## 2.7 What runs where

```text
  command                              local folder   remote daemon   password?
  -----------------------------------  ------------   -------------   ---------
  inspect, schema                      yes            via info        no
  list, get, find, info                yes            yes             if sealed
  put, delete                          yes            yes (write)     if sealed
  init, checkpoint, compact, sweep     yes            no              if sealed
  transpose                            yes            no              if sealed (refused)
  backup, restore, rekey               yes            no              if sealed
  keygen, presets, help                yes            n/a             keygen only
  sync                                 yes (writes here, reads there)
```

The local-only ones stay local on purpose: they touch key material and
file layout, and sending that to a daemon would widen the trust boundary
for nothing.

---

# Part 3 — The pipe

Part 2 with the store taken out. Same pinned handshake, same `.pin`
files, same Query/Reply bytes — a different handler behind them, and
nothing kept.

## 3.1 Phone to desktop, two commands

```text
# desktop
geist-relayd --listen dac://0.0.0.0:47656 \
             --identity relay.key --allow-write phone.pin \
             --to exec --exec 'whisper-cpp -'

# phone
arecord -f S16_LE -r 16000 -d 5 | \
  geist-relay send --remote dac://desktop:47656 --stream voice \
                   --identity phone.id --peer-pin relay.pin
```

The transcript is printed on the phone, by the command that sent the
audio:

```text
  phone                         desktop
  -----                         -------
  audio bytes ~~~~ geist-relay ~~~~> geist-relayd --to exec
                                          |  bytes on stdin
                                          v
                                     whisper-cpp
                                          |  transcript on stdout
  transcript  <~~~~~~~~~~~~~~~~~~~~~~~~~~ reply
```

## 3.2 What a message is, and where it goes

Inbound, a message is **raw**: the stream is `Query.collection` and the
body is `Query.payload`, so a client that can send bytes needs to know
nothing else.

```text
  a send is one qoPut          a collect is one qoPoll
  ------------------           -----------------------
  op          01               op          07
  collection  "voice"          collection  "voice"
  payload     the bytes        subscriptionId  reader name
                               -> Reply.rows, one per message
```

Outbound it gains an envelope, because a message being handed on has left
its sender behind:

```text
  +--------+--------+--------+---------+--------+-----------+
  | stream | sender |   at   | ordinal | length |   body    |
  +--------+--------+--------+---------+--------+-----------+
    text     text     u64      u64       u32      bytes
                      unix     per-stream, from 1

  carried as a Row with schemaId 0xFFF1 -- far outside the range a
  database assigns, so an envelope can never be read as a stored row
```

`sender` is the subject on the certificate the handshake verified, and
`at` is when this relay accepted it. Those are the two facts a relay can
vouch for, so they are the two it stamps.

```text
  --to      what happens                                     reply carries
  ------    ----------------------------------------------   -------------
  spool     held in RAM; a peer collects it later            nothing
  stdout    written to the daemon's stdout, for a pipeline   nothing
  file      appended to --file                               nothing
  exec      fed to --exec on stdin                           that command's stdout
```

```text
  --format lines   one plain line per message
  --format json    one object per line (binary bodies as base64)
  --format raw     the bytes, nothing added (audio pipes)
```

```text
$ geist-relayd ... --to file --file inbox.jsonl --format json
$ tail -1 inbox.jsonl
{"at":"2026-08-09T12:04:11Z","from":"phone","stream":"notes","ordinal":3,
 "bytes":20,"body":"a note worth keeping"}
```

The spool is fed whatever the sink is, so a relay piping to a transcriber
can still be polled by somebody else.

## 3.3 Rights, and the safety that is easy to miss

```text
  flag                  may send   may collect
  -------------------   --------   -----------
  --trust pin           no         yes
  --allow-write pin     yes        yes
```

Same two flags as `geistd`, same meaning; only the object of the right
changes (messages instead of rows).

```text
  the body reaches --exec on STDIN only, never on its command line
  a hung command is killed (--exec-timeout-ms, default 30s; 0 = fire and forget)
  "who sent this" comes from the verified pin, never from the payload
  status lines go to stderr, so --to stdout stays a clean pipe
  --stream limits which stream names are accepted at all
```

The environment carries the rest, so a script needs no parser:

```sh
#!/bin/sh
printf '[%s/%s] ' "$GEIST_FROM" "$GEIST_STREAM"   # also GEIST_AT, GEIST_BYTES
tr a-z A-Z
```

## 3.4 Collecting instead of piping

```text
$ geist-relay poll --remote dac://desktop:47656 --stream notes \
                   --as laptop --format json --follow
```

Each reader name has its own position, so two readers of one stream each
see everything once instead of racing.

Log fan-in, one message per line, on one link:

```text
journalctl -f | geist-relay send --stream logs --split-lines \
    --remote dac://collector:47656 --identity me.id --peer-pin them.pin
```

```text
  spool is a ring in RAM (--spool N, default 256)
  a full ring drops the OLDEST and counts the drop
  every answer carries the stream total, so a reader can see it missed some
  nothing survives a restart
```

## 3.5 It is not a database, and says so

```text
$ geist --remote dac://desktop:47656 --identity me.id --peer-pin relay.pin list
geist: this endpoint is a relay, not a database: it forwards messages and
keeps 256 per stream in memory. Point qoFind at a geistd instead.
```

```text
  want durable rows?      -> geistd,       port 47655
  want a short message?   -> geist-relayd, port 47656
  want both on one host?  -> two processes, two ports, two config sections
```

More: [docs/relay.md](docs/relay.md).

---

# For contributors

## Where the walls are

The three parts are the border. Everything below is a consequence of it,
and if a change crosses one of these lines it belongs in the commit
message.

```text
  border                              left owns                     right owns
  ---------------------------------   ---------------------------   --------------------------
  part 1  |  part 3                   files, rows, seal, lease      pins, link, Query/Reply
  Geist   |  Bifrost                  masks + suite layout          handshake, frames, replay
  sealed data | keys + ledger         ciphertext bytes              secret material | epochs
  writer  |  readers                  .geist-lock + in-process      open read-only anytime
  geistd  |  geist-relayd             durable rows                  RAM pipe only
  preset  |  userconfig               on-disk shape                 paths / pins / listen
  config.toml [storage] | [transport] part 1 reader                 part 2/3 reader
  id      |  @position                every machine, forever        one terminal, one list
```

Some things nest inside others on purpose:

```text
  fields, id and flags   inside  one row        (identity travels with the bytes)
  rows                   inside  one cluster
  clusters               inside  one generation file
  sealed batch           inside  a cluster slice (row range x column group)
  big value              inside  .geist-sidecar/ (row keeps a 33-byte pointer)
  AME session            inside  one Bifrost link (Geist does not rebuild it)
  relay spool            inside  process RAM only

  and these sit BESIDE, not inside:
  current, .geist-lock, .geist-cursors, .geist-sidecar/
```

And a few things are deliberately shared. Each of these looks like
duplication until you know it is not:

```text
  Query / Reply      one wire shape; answer.nim gives it a store meaning,
                     relay.nim gives it a pipe meaning
  config.toml        one file, two readers, neither parsing the other's keys
  PeerRight / peer   defined once in types.nim — every handler is told who is
    context          asking, and not every handler owns a socket
  row apply          one rule for local put and remote put
  pin flags          --trust / --allow-write mean the same on both daemons
```

Two that are easy to confuse and are **not** the same thing:

```text
  desktop sync chain   moves ROWS through ordinary geistd     (part 2)
  message relay        moves BYTES through geist-relayd       (part 3)

  observeStore   header + index only        openGeist   full rows
  compact        drops old row versions     sweep       drops orphan payloads
```

## Source layout

A module stays on one side of a border. Crossing means a new home, not a
quiet import.

```text
  +-- PART 1  import geist ----------------------------------------+
  |  src/geist.nim                 public disk facade              |
  |  src/geist/types.nim           small model (shared types only) |
  |  src/geist/secret.nim          move-only key bytes             |
  |  src/geist/durable.nim         flush + publish rename          |
  |  src/geist/lease.nim           one writer per folder           |
  |  src/geist/mapper.nim          object -> schema at compile time|
  |  src/geist/row.nim             the one row codec               |
  |  src/geist/rowid.nim           ids, deletes, live view         |
  |  src/geist/format.nim          header + cluster index          |
  |  src/geist/store.nim           clusters on disk                |
  |  src/geist/sidecar.nim         big values                      |
  |  src/geist/config.nim          presets                         |
  |  src/geist/toml_read.nim       shared TOML reader (no policy)  |
  |  src/geist/settings.nim        [storage] [backup] + disk keys  |
  |  src/geist/session.nim         open / put / set / save         |
  |  src/geist/keys.nim            key file, ledger, generations   |
  |  src/geist/backup.nim          .b1 / .b2 / .b3                 |
  |  src/geist/crypto/             seal, check, batch, column      |
  |  src/geist/collection.nim      seq-shaped API over a Session   |
  |  src/geist/seek.nim            partial cluster reads           |
  |  src/geist/dynamic.nim         rows without a compile-time type|
  |  src/geist/show.nim            rows as a table, elided         |
  |  src/geist/transpose.nim       the column-first search copy    |
  +----------------------------------------------------------------+

  +-- PART 3  import geist/wire -----------------------------------+
  |  src/geist/wire.nim            public wire facade              |
  |  src/geist/masks.nim           strength levels Geist owns      |
  |  src/geist/transport.nim       Query / Reply over Bifrost      |
  |  src/geist/identity.nim        key files and pins              |
  |  src/geist/relay.nim           Query meaning against a pipe    |
  |  src/geist/transport_settings.nim   [transport] only           |
  +----------------------------------------------------------------+

  +-- PART 2  import geist/network  (thin union, on purpose) ------+
  |  src/geist/network.nim         re-exports both halves          |
  |  src/geist/answer.nim          Query meaning against a Session |
  |  src/geist/need.nim            what this store is missing      |
  +----------------------------------------------------------------+

  +-- BINARIES (compose halves; never redefine a border) ----------+
  |  src/clients/geist_cli.nim     local folder or remote geistd   |
  |  src/server/geistd.nim         part 1 + part 3 + answer        |
  |  src/clients/geist_relay.nim   part 3 only                     |
  |  src/server/geist_relayd.nim   part 3 + relay handler          |
  +----------------------------------------------------------------+

  evaluation/tests/   evaluation/benchmarks/   examples/   nix/
```

## Tasks

```text
nimble test               all suites
nimble testCore           mapper + format
nimble testCrypto         seal + keys + backup
nimble testApi            session + masks + transport
nimble testDurability     generation swap + lease + restore
nimble testExchange       live sockets
nimble testApiSurface     collection + seek + hash agility
nimble examples           all four examples
nimble buildBins          four binaries into build/bin
nimble demoCli            scratch store through the CLI
nimble buildAll           compile every public module
nimble checkModular       part 1 with the network stack absent
nimble checkRelay         part 3 with no database in the C output
nimble bench              every benchmark group
nimble checkRouter        the router with no store in the C output
nimble stats              measure the tree, record evaluation/statistics/
nimble autopush           commit + push from agents/PROGRESS.md
```

Real-guest checks (need KVM):

```text
nix build .#checks.x86_64-linux.two-desktop-exchange -L
nix build .#checks.x86_64-linux.three-desktop-relay -L
nix build .#checks.x86_64-linux.relay-pipe -L
```

```text
  two-desktop-exchange   two machines set up differently (sealed vs plain)
  three-desktop-relay    an id survives two hops of sync
  relay-pipe             phone -> desktop transcript; laptop collects the spool
```

## Where to read next

```text
  file                         what it answers
  ---------------------------  ------------------------------------------
  CONTRIBUTING.md              how to change code without breaking it
  docs/layout.md               where every file lives, and why there
  docs/workloads.md            what Geist fits, with the ceilings
  docs/evaluation.md           the tests, benchmarks and statistics
  docs/DESIGN_RATIONALE.md     why each shape exists (with numbers)
  docs/STORAGE_PLAN.md         on-disk plan and generation rules
  docs/relay.md                part 3 in full
  docs/nix.md                  NixOS modules and VM checks
  docs/measurements/           the harnesses behind the numbers
  docs/submodules.md           which dependency owns which job
  agents/PROGRESS.md           commit message + recent change log
```

## Issue playbook

```text
  problem                                              what to do
  ---------------------------------------------------  ------------------------------------------
  recovery-strength handshake fails at Frodo           use archive strength or below; the Frodo
                                                       path in the pinned stack is known bad and
                                                       is excluded here on purpose
  handshake too big for one frame                      expected at archive/recovery; those levels
                                                       need package transfer
  lost .ledger, still have data + keys                 unrecoverable by design; always back up
                                                       artifactSet() as one unit
  compile error: Secret is move-only                   call clone() — copies of key bytes must
                                                       be explicit
  renamed a field, old rows no longer match            add the old name to Schema.aliases
  batchRows = 1 rejected                               field-level seal cost is huge at 1; raise
                                                       it or turn sealing off
  one wide column makes every row long                 cappedColumn("body", 128); lower
                                                       sidecarThreshold; archive preset uses 512
  whole cluster loaded on open / rewrite on save       true today; seek.nim can slice, the session
                                                       does not use it yet. avoid flush-per-row
                                                       for bulk loads
  find is slow on a big store                          build the column copy: [storage] transpose
                                                       = "onSave", or `geist transpose` (1.8)
  transpose refused: plaintext column copy             a sealed preset cannot keep one; choose
                                                       one of the two for that store
  "column copy is STALE"                               the store was saved after the copy was
                                                       built. `geist transpose` rebuilds it;
                                                       searches use rows until it does
  echo db printed only the corners                     working as intended: a big table elides
                                                       like a matrix. db.show(everything()) for
                                                       all of it
  --remote needs --identity and --peer-pin             exchange .pin files once; a fresh identity
                                                       every run can never be pinned
  "peer trust not established" after handshake         the trust result must ride into the session
                                                       (initAmeSession peerTrust)
  daemon served request, client times out              keep ONE socket for handshake + data;
                                                       a second socket looks like a stranger
  "database is already open for writing"               another process or Session holds the lease;
                                                       open read-only, or wait (a crashed lease
                                                       breaks after 120 s)
  iot/stream store has id columns                      made before the defaults fix; recreate it.
                                                       geist schema prints identity:
  two desktops overwrote each other's new rows         pre-tag ids; recreate the stores so ids
                                                       carry a machine tag
  follower keeps re-reading everything                 the sender compacted, so the epoch changed;
                                                       starting from zero is intended. compact
                                                       less often while followers are active
  sidecar folder keeps growing                         compact first, then sweep
  sweep: cannot read backup slot                       supply that slot's password, or remove the
                                                       unreadable slot on purpose
  large find returns fewer than --limit                answers stop near 28 KB; resume from the
                                                       reply cursor
  services.geistd will not start: no pin               publish pins, copy them, name trust /
                                                       allowWrite paths (see docs/nix.md)
  identityFile must be a writable path                 put it under stateDir, not in the store
  "this endpoint is a relay, not a database"           you reached port 47656; geistd is 47655
  relay messages gone after restart                    expected — the spool is RAM only
  --to exec silent while a command runs                one request at a time; give a busy stream
                                                       its own relay and port, or timeout 0
  --exec hangs until timeout on large stdout           answer with a path; keep stdout small
  --to stdout mixed with daemon chatter                status goes to stderr; check for a 2>&1
  need the old implementation                          .geist-legacy/ (gitignored), commit 047a776
  Otter reports ~1300 routines and 121 secrets          it walked .geist-legacy/ too. `nimble stats`
                                                       measures the TRACKED tree; the real numbers
                                                       are in evaluation/statistics/
  Otter says a proc is "never called"                   its call graph misses implicit calls; an
                                                       overloaded `$` reads as dead while four
                                                       places use it. Check before deleting
  handshake refused: no pinned peer matched             the caller's identity opened but matched no
                                                       .pin on this server. The hello names nobody,
                                                       so this is the FIRST point a name exists
  a flood of helloes does no key work                   working as intended: requireCookie = true
                                                       makes a first hello cost one small reply.
                                                       Only turn it off on an unreachable socket
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
