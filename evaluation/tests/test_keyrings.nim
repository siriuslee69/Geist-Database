## Keyrings: several sealed stores, one password each, saved only when changed.
import std/[os, strutils, unittest]
import geist

proc ringFiles(dir: string): seq[(string, string)] =
  ## dir: one ring's folder -> every file with its bytes, for "untouched" checks.
  for p in walkDirRec(dir):
    result.add (p, readFile(p))

suite "keyrings":
  # {.testKind: tkIntegration, covers: "createKeyrings|openKeyrings|unlock|rows|upsert|save".}
  test "rings open one by one, each only with its own password":
    var
      root = getTempDir() / "geist_t_rings_open"
      K = default(Keyrings)
    removeDir(root)
    K = createKeyrings(root, ["stage1", "stage2"], ["pw1", "pw1|pw2"])
    K.upsert("stage1", RingRow(rowKey: "card-1", kind: "accounts", body: "{\"title\":\"Mail\"}"))
    K.upsert("stage2", RingRow(rowKey: "card-1", kind: "accounts", body: "{\"pattern\":\"x\"}"))
    check K.save().ok
    K.close()
    K = openKeyrings(root)
    check K.rings.len == 2 and not K.rings[0].open and not K.rings[1].open
    check not K.unlock("stage2", "pw1").ok
    check not K.rings[1].open
    check K.unlock("stage1", "pw1").ok
    check K.rows("stage1") == @[RingRow(rowKey: "card-1", kind: "accounts", body: "{\"title\":\"Mail\"}")]
    expect ValueError:
      discard K.rows("stage2")
    check K.unlock("stage2", "pw1|pw2").ok
    check K.rows("stage2")[0].body == "{\"pattern\":\"x\"}"
    K.close()

  # {.testKind: tkRegression, covers: "save|replaceAll", pins: "a save with only some passwords must leave locked rings byte-identical".}
  test "saving with ring 1 unlocked leaves ring 2 byte-for-byte untouched":
    var
      root = getTempDir() / "geist_t_rings_partial"
      K = default(Keyrings)
      before: seq[(string, string)] = @[]
    removeDir(root)
    K = createKeyrings(root, ["stage1", "stage2"], ["a", "b"])
    K.upsert("stage2", RingRow(rowKey: "k", kind: "c", body: "secret-sentinel"))
    check K.save().ok
    K.close()
    before = ringFiles(root / "stage2")
    K = openKeyrings(root)
    check K.unlock("stage1", "a").ok
    K.replaceAll("stage1", [RingRow(rowKey: "p1", kind: "patterns", body: "new")])
    check K.save().ok
    K.close()
    check ringFiles(root / "stage2") == before
    K = openKeyrings(root)
    check K.unlock("stage1", "a").ok and K.unlock("stage2", "b").ok
    check K.rows("stage1").len == 1 and K.rows("stage2")[0].body == "secret-sentinel"
    for f in walkDirRec(root):
      check "secret-sentinel" notin readFile(f)
    K.close()

  # {.testKind: tkUnit, covers: "upsert|remove|replaceAll".}
  test "upsert replaces by rowKey, remove and replaceAll drop rows":
    var
      root = getTempDir() / "geist_t_rings_edit"
      K = default(Keyrings)
    removeDir(root)
    K = createKeyrings(root, ["r"], ["pw"])
    K.upsert("r", RingRow(rowKey: "a", body: "1"))
    K.upsert("r", RingRow(rowKey: "b", body: "2"))
    K.upsert("r", RingRow(rowKey: "a", body: "3"))
    check K.rows("r").len == 2
    check K.remove("r", "b")
    check not K.remove("r", "b")
    K.replaceAll("r", [RingRow(rowKey: "c", body: "4")])
    check K.rows("r") == @[RingRow(rowKey: "c", body: "4")]
    check K.save().ok
    K.close()

  # {.testKind: tkEdgeCase, covers: "changePassword".}
  test "a ring's password changes without touching its rows":
    var
      root = getTempDir() / "geist_t_rings_pw"
      K = default(Keyrings)
    removeDir(root)
    K = createKeyrings(root, ["r"], ["old"])
    K.upsert("r", RingRow(rowKey: "x", body: "kept"))
    K.changePassword("r", "new")
    check K.save().ok
    K.close()
    K = openKeyrings(root)
    check not K.unlock("r", "old").ok
    check K.unlock("r", "new").ok
    check K.rows("r")[0].body == "kept"
    K.close()

  # {.testKind: tkEdgeCase, covers: "createKeyrings|openKeyrings".}
  test "bad sets are refused instead of guessed":
    var root = getTempDir() / "geist_t_rings_bad"
    removeDir(root)
    expect ValueError:
      discard createKeyrings(root, ["a", "b"], ["only-one"])
    expect ValueError:
      discard createKeyrings(root, ["a/b"], ["pw"])
    expect IOError:
      discard openKeyrings(root / "missing")
    var K = createKeyrings(root, ["a"], ["pw"])
    K.close()
    expect IOError:
      discard createKeyrings(root, ["a"], ["pw"])

  # {.testKind: tkIntegration, covers: "sealedRow|writeRowMap".}
  test "a locked ring hands out a row's sealed bytes, never its content":
    var
      root = getTempDir() / "geist_t_rings_sealed"
      K = default(Keyrings)
      sealed: seq[uint8] = @[]
    removeDir(root)
    K = createKeyrings(root, ["s1", "s4"], ["a", "b"])
    K.upsert("s4", RingRow(rowKey: "card-9", kind: "accounts", body: "{\"pw\":\"hunter2-sentinel\"}"))
    K.upsert("s4", RingRow(rowKey: "card-3", kind: "accounts", body: "{\"pw\":\"other\"}"))
    check K.save().ok
    K.close()
    K = openKeyrings(root)                      # every ring locked
    sealed = K.sealedRow("s4", "card-9")
    check sealed.len > 20
    check "hunter2-sentinel" notin cast[string](sealed)
    check K.sealedRow("s4", "card-3") != sealed
    check K.sealedRow("s4", "no-such-card").len == 0
    check K.sealedRow("s1", "card-9").len == 0
