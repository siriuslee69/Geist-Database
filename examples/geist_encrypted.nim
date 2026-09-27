## ---------------------------------------------------------------
## Geist Encrypted <- column groups, batches, per-batch rekey
## ---------------------------------------------------------------
##
## Run from the repo root:
##   nimble exampleEncrypted

import std/[os, strutils]

import geist

type
  Message = object
    messageId: int
    spaceId: string
    authorId: string
    body: string

when isMainModule:
  var
    root: string = ""
    db: Session = default(Session)
    onDisk: string = ""
    needing: seq[tuple[batchIndex: uint32, groupId: uint16]] = @[]
    fresh: KeyId = 0'u64

  root = getTempDir() / "geist_encrypted_example"
  removeDir(root)

  # chatConfig puts `body` in its own column group and keeps the batch
  # small, because messages are read by id rather than scanned.
  db = openGeist[Message](root, chatConfig(), "example password")
  for i in 0 ..< 50:
    db.put(Message(messageId: i, spaceId: "space-1",
      authorId: "user-" & $(i mod 3),
      body: "PLAINTEXT-CANARY-" & $i))
  echo "stored:        ", db.entryCount()
  echo "column groups: ", db.ledger.groups.len
  echo "batch rows:    ", db.ledger.batchRows
  echo "ledger rows:   ", db.ledger.entries.len
  echo "save:          ", db.save()

  onDisk = readFile(db.dataPath())
  echo "canary on disk: ", onDisk.contains("PLAINTEXT-CANARY"),
    "   (must be false)"

  echo "artifact set -- ALL THREE are required to recover the data:"
  for p in db.artifactSet():
    echo "  ", extractFilename(p), "  ", getFileSize(p), " B"
  db.close()

  db = openGeist[Message](root, chatConfig(), "example password")
  echo "reopened row 42: ", get[Message](db, 42'u32).body

  # An epoch approaching its high-water mark needs ONE batch re-keyed,
  # not a global rewrite: a fresh keyRef is a fresh nonce space.
  db.ledger.entries[0].epoch = defaultRekeyAtEpoch
  needing = batchesNeedingRekey(db.ledger)
  echo "batches needing rekey: ", needing.len
  if needing.len > 0:
    fresh = rekeyBatch(db.keySet, db.ledger, needing[0].batchIndex,
      needing[0].groupId)
    echo "  rekeyed batch ", needing[0].batchIndex, " -> keyRef ", fresh,
      ", epoch reset to ", db.ledger.entries[0].epoch
  discard db.save()
  db.close()
