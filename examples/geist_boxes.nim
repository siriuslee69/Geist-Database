## ---------------------------------------------------------------------
## Boxes <- places that keep items for somebody, with rules Geist enforces
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/geist_boxes.nim
##
## A box has a KIND, and the kind's rule says who may read and write and what
## a write does. Whoever calls says who is asking; Geist says yes or no.

import std/os

import geist

const
  now = 1_800_000_000_000'u64

var
  dir: string = getTempDir() / "geist_boxes_example"
  chat: BoxRule = defaultBoxRule("chat")
  letters: BoxRule = defaultBoxRule("letters")
  S: BoxShelf = nil
  r: BoxResult = BoxResult()

# a chat: its members read and write, every key is written once
chat.owner = boSpace
chat.read = baMembers
chat.write = baMembers
# a posting box: anyone may leave a letter, only the owner reads; at most 2 each
letters.read = baOwner
letters.write = baAnyone
letters.mode = bmQueue
letters.maxPerWriter = 2

removeDir(dir)
S = openShelf(dir, [chat, letters]).shelf

discard S.createBox("chat", "c0ffee", "alice")
discard S.setBoxPeople("chat", "c0ffee", "alice", ["bob"], [])
echo "alice writes:   ", S.putBoxItem("chat", "c0ffee", "alice", "k1", textBytes("hi bob"), 0, now).ok
echo "bob reads:      ", S.fetchBoxItems("chat", "c0ffee", "bob", 0, 10, now).items.len, " item(s)"
echo "mallory reads:  ", S.fetchBoxItems("chat", "c0ffee", "mallory", 0, 10, now).err

discard S.createBox("letters", "alice", "alice")
for key in ["a", "b", "c"]:
  r = S.putBoxItem("letters", "alice", "stranger", key, textBytes("hello"), 0, now)
  echo "letter ", key, ":       ", (if r.ok: "kept" else: r.err)
echo "alice collects: ", S.fetchBoxItems("letters", "alice", "alice", 0, 10, now).items.len
discard S.ackBoxItems("letters", "alice", "alice", ["a", "b"])

S.closeShelf()
removeDir(dir)
