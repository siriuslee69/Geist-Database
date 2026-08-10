## Sidecar reclamation: deleting payloads nothing references, and only
## those.
##
## The dangerous half of a mark-and-sweep is the MARK. A sweep that misses
## a reference deletes data that a row still points at, and the failure
## does not show up until something reads that row -- possibly after a
## restore, weeks later. So every test here checks what SURVIVES at least
## as carefully as what goes.

import std/[os, strutils, unittest]
import geist

type
  Doc = object
    docId: int
    title: string
    blob: string        # capped, so a long value escapes to the sidecar

proc freshRoot(name: string): string =
  result = getTempDir() / name
  removeDir(result)

proc cappedConfig(): GeistConfig =
  ## A schema where `blob` is capped narrow enough that anything real
  ## escapes to the sidecar, which is what makes the sweep observable.
  result = appConfig()
  result.columnPolicy = @[cappedColumn("blob", 64'u32)]
  result.sidecarThreshold = 32'u32
  result.backup.enabled = false

proc sidecarFiles(root: string): int =
  ## root: store root whose sidecar payload count is returned.
  var
    dir = root / ".geist-sidecar"
  if not dirExists(dir):
    return 0
  for _ in walkDirRec(dir):
    result = result + 1

suite "sidecar sweep":
  test "a payload no row references is reclaimed":
    var root = freshRoot("geist_t_sw1")
    var db = openGeist[Doc](root, cappedConfig())
    var a = db.put(Doc(docId: 1, title: "keep", blob: repeat("K", 4096)))
    var b = db.put(Doc(docId: 2, title: "drop", blob: repeat("D", 4096)))
    check db.save().ok
    check sidecarFiles(root) == 2
    # Replacing the value orphans the OLD payload -- but only once the log
    # no longer carries the version that referenced it.
    check db.delete(b)
    check db.compact().ok
    check db.save().ok
    var swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 1
    check swept.bytes == 4096'u64
    check sidecarFiles(root) == 1
    # What remains is readable, which is the half that matters.
    check byId[Doc](db, a).value.blob == repeat("K", 4096)
    db.close()

  test "a superseded version still in the log keeps its payload":
    var root = freshRoot("geist_t_sw2")
    var db = openGeist[Doc](root, cappedConfig())
    var a = db.put(Doc(docId: 1, title: "v1", blob: repeat("A", 4096)))
    check db.set(a, Doc(docId: 1, title: "v2", blob: repeat("B", 4096)))
    check db.save().ok
    check sidecarFiles(root) == 2
    # Version 1 is superseded but NOT gone: a follower catching up will be
    # sent it, so its payload is still live.
    var swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 0
    check sidecarFiles(root) == 2
    # After compaction it really is gone, and only then.
    check db.compact().ok
    swept = db.sweepSidecar()
    check swept.removed == 1
    check byId[Doc](db, a).value.blob == repeat("B", 4096)
    db.close()

  test "a payload a backup slot references is not touched":
    var root = freshRoot("geist_t_sw3")
    var cfg = cappedConfig()
    cfg.backup.enabled = true
    cfg.backup.copies = 2'u8
    cfg.backup.everyNWrites = 1'u32
    var db = openGeist[Doc](root, cfg)
    var a = db.put(Doc(docId: 1, title: "backed up", blob: repeat("Z", 4096)))
    check db.save().ok
    # Slots hang off the generation-FREE stem, so they keep rotating as
    # the live file moves on.
    check fileExists(db.backupStems()[0] & ".b1")
    # Remove it from the LIVE database entirely.
    check db.delete(a)
    check db.compact().ok
    check db.save().ok
    check byId[Doc](db, a).found == false
    # The backup slot still holds a row that references the payload, and a
    # restore has to work. Nothing is reclaimed.
    var swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 0
    check sidecarFiles(root) > 0
    db.close()

  test "a read-only session refuses to sweep":
    var root = freshRoot("geist_t_sw4")
    var db = openGeist[Doc](root, cappedConfig())
    discard db.put(Doc(docId: 1, title: "x", blob: repeat("Q", 4096)))
    check db.save().ok
    var reader = openGeist[Doc](root, cappedConfig(), "", readOnly = true)
    var swept = reader.sweepSidecar()
    check not swept.ok
    check swept.err.contains("read-only")
    check sidecarFiles(root) == 1
    reader.close()
    db.close()

  test "a database with no sidecar sweeps to nothing and says so":
    var root = freshRoot("geist_t_sw5")
    var db = openGeist[Doc](root, appConfig())
    discard db.put(Doc(docId: 1, title: "small", blob: "short"))
    check db.save().ok
    var swept = db.sweepSidecar()
    check swept.ok
    check swept.removed == 0
    db.close()
