# Boxes <- places that keep items for somebody, decided and written by Geist

A box keeps items for somebody who is not always here: sealed keys, letters, the
records of a chat. Geist does every write, and decides every yes and no. It does
not know whether the caller sits on this machine or came over a network.

```text
  caller says       Geist does
  ───────────────   ─────────────────────────────────────────────────
  who is asking     checks the box's rule and lists: allowed?
  the key at rest   seals what it writes, opens what it reads
  what to write     numbers it, writes one record, checks it on reading
```

╭⟢ 1. Definitions 🌊
├⟢ 2. Using it 🍣
├⟢ 3. The four modes ✜
├⟢ 4. The file, byte by byte ❧
├⟢ 5. What a crash can do ⚠️
├⟢ 6. Signed boxes ◈
├⟢ 7. Accounts and grants ✧
├⟢ 8. Copying a box to another machine 🐦‍🔥
╰⟢ 9. Limits and open points 🔎

## 1. Definitions

```text
Def. 1 (box)      one folder: <root>/<kind>/<id>.
Def. 2 (kind)     the rule a box follows: owner, read, write, mode, blind, signed,
                  keep time, limits.
Def. 3 (subject)  who asks, as text. Geist compares it, and nothing more.
Def. 4 (number)   1, 2, 3, ... per box, in the order items were accepted.
Def. 5 (shelf)    every box below one folder. One program at a time.
```

## 2. Using it

```nim
import geist

var rule = defaultBoxRule("chat")
rule.owner = boSpace
rule.read = baMembers
rule.write = baMembers

var S = openShelf("data/boxes", [rule]).shelf
discard S.createBox("chat", "c0ffee", "alice")
discard S.setBoxPeople("chat", "c0ffee", "alice", ["bob"], [])
discard S.putBoxItem("chat", "c0ffee", "alice", "7:0", sealedBytes, 0, nowMs)

for item in S.fetchBoxItems("chat", "c0ffee", "bob", 0, 100, nowMs).items:
  echo item.number, " from ", item.writer

S.closeShelf()
```

Many writes, one trip to the disk. Nothing counts as done before `flushShelf` said ok:

```nim
for r in records:
  discard S.putBoxItem("chat", id, who, r.key, r.data, 0, nowMs, flush = false)
if S.flushShelf().ok: tellTheSender()
```

## 3. The four modes

```text
append     put "k1"  -> number 1          a key is WRITE-ONCE
           put "k1"  -> refused

overwrite  put "k" v0 -> version 1        a write names the version it replaces
           put "k" v0 -> "stale version: the newest is 1"

queue      bob puts "r1"                  only the owner reads, the owner says
           alice acks "r1" -> gone        "I have it"; acknowledging twice is fine

takeOnce   owner puts k1, k2              a reader TAKES the oldest; it is gone
           bob takes -> k1                durably before it is handed out
           carol takes -> k2
```

A refusal and a box that does not exist give the same words: `no such box, or not allowed`.

## 4. The file, byte by byte

```text
<root>/<kind>/<id>/box.log      the log
<root>/<kind>/<id>/blobs/<n>    the data of item n, when it is 64 KiB or more
```

All numbers little-endian.

```text
file     "GBX1" | logId u64 | record | record | ...

record   bodyLen u32 | kind u8 | body | check 16 B (BLAKE3 of all before it)

         kind 1 head   u16+kind | u16+id | u16+owner | u32+members | u32+whitelist
                       | counter u64 | u32+keys
         kind 2 item   u16+key | number u64 | version u64 | u16+writer | atMs u64
                       | u32+label
                       | 00 | u32+data               (data right here)
                       | 01 | size u64 | hash 32     (data in blobs/<number>)
         kind 3 gone   u16+key
```

With a key at rest the body is sealed; the check covers the sealed bytes, so
damage can be found without the key.

Example 1. A `gone` record for the key "ab", no key at rest:

```text
04 00 00 00 | 03 | 02 00 61 62 | <16 bytes of check>
```

## 5. What a crash can do

The number of an item is inside that item's record. The counter is what reading
the log back finds, so a number and its item are one write.

```text
state of the last record    after a restart
──────────────────────────  ─────────────────────────────────────────────
cut short                   cut off; that write never happened
complete, check wrong       the box refuses to open; repairBox cuts it there
complete, check right       it counts
```

A log that is more than half dead is written anew, and the new file replaces the
old in one rename. Numbers go on, and the log gets a new `logId`.

## 6. Signed boxes

Rule `signed = true`. Each item carries a label signed with a key the box holds.

```text
fields = boxEntryFields("archive", "alice", "phone", data, prev, sentAt)
label  = renderNote(fields, "dilithium65:" & hexText(signature of noteSignedText(fields)))
```

```text
checked                                 refused with
──────────────────────────────────────  ───────────────────────────────────
it is a label, for this very box        this label is not for this box
prev is the newest head                 stale head: the newest is <head>
it names the hash of these bytes        the label is for other data
the signature is by a key in the box    the signature does not belong to this box
```

This replaces the old blind store. Fetching needs no signed request: the caller
says who is asking, and the rule decides.

## 7. Accounts and grants

`accounts.nim`: a name, a random id, device keys, a login check. The password
never comes here: only a hash that proves it, and bytes that are never opened.
A wrong password and an unknown name give the same nothing, and an unknown name
gets a decoy id (`accountIdOf`).

`grants.nim`: subject + address prefix + rights, the longest prefix decides.

## 8. Copying a box to another machine

Geist hands out bytes "from this place on" and takes them in again. It does not
know what moves them.

```text
holder                                  copy
──────                                  ────
listBoxes             ─────────▶        what do I lack?
boxLogSince(id, off)  ─────────▶        records from there on, whole ones only
boxBlobBytes(n)       ─────────▶        putBoxBlob (large items first)
                                        applyBoxLog: every check, then appended
```

A holder that rewrote its log has a new `logId`. A copy asking with the old one is
sent the log from the start.

## 9. Limits and open points

- `maxBoxesPerOwner`, `maxBytesPerOwner` per shelf; `maxItems`, `maxItemBytes`,
  `keepMs`, `maxPerWriter` per kind. What sits in my mailbox counts against me, so
  a box that anyone may write to should set `maxPerWriter`: it is how many live
  items one writer other than the owner may have there.
- All live keys of a box are held in memory, about 150 bytes each. A million items
  in one box is about 150 MB while that box is open.
- A log is read once, whole, when its box opens.
- After a crash, usage counts dead bytes until the log is next rewritten.
