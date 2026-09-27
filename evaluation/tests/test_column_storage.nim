## P1 end to end: packed clusters through a session, sealed and plain.

import runePragmas
import std/[os, strutils, tables, unittest]

import geist

type
  Note = object
    id*: int
    score*: float
    title*: string
    body*: string

  Wide = object
    a*: int
    b*: string
    c*: int
    d*: string
    e*: int
    f*: string
    g*: int
    h*: string

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / name
  removeDir(result)

suite "packed storage":

  test "packed rows survive save and reopen":
    var
      root = scratch("geist_t_pk1")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
    c.add @[Note(id: 1, score: 1.5, title: "first", body: "alpha"),
            Note(id: 2, score: -2.5, title: "second", body: "beta"),
            Note(id: 3, title: "third")]
    check c.save().ok
    c.close()

    var re = openCollection[Note](root, "n", collapsedConfig(), "", false)
    check re.len == 3
    check re[0].title == "first"
    check re[1].score == -2.5
    check re[2].title == "third"
    check re[2].body == ""
    check re[2].score == 0.0
    re.close()
    removeDir(root)

  test "the index declares varying rows with rowBytes = 0":
    var
      root = scratch("geist_t_pk2")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
    c.add Note(id: 1, title: "x")
    check c.save().ok
    var path = c.session.dataPath()
    c.close()
    var idx = readIndex(path)
    check idx.ok
    var at = idx.f.findIndex(crEntry)
    check at >= 0
    # rowBytes = 0 is how the index declares "rows vary, consult the
    # offset table" -- derived from the schema, not a stored layout byte.
    check idx.f.index[at].rowBytes == 0'u32
    removeDir(root)

  test "a packed file is smaller than a fixed one for sparse data":
    var
      packedRoot = scratch("geist_t_pk3a")
      fixedRoot = scratch("geist_t_pk3b")
      rows: seq[Wide] = @[]
    for i in 0 ..< 300:
      # Only two of eight columns are ever set.
      rows.add Wide(a: i, e: i * 2)

    var p = openCollection[Wide](packedRoot, "w", collapsedConfig(), "", false)
    p.add rows
    check p.save().ok
    var pPath = p.session.dataPath()
    p.close()

    var f = openCollection[Wide](fixedRoot, "w", appConfig(), "", false)
    f.add rows
    check f.save().ok
    var fPath = f.session.dataPath()
    f.close()

    check getFileSize(pPath) < getFileSize(fPath)
    removeDir(packedRoot)
    removeDir(fixedRoot)

  test "collapsing costs one bitmap byte per row when nothing is empty":
    # The bitmap can only ADD bytes when every column is set. It pays for
    # itself on sparse data and nowhere else, which is why it is a choice
    # rather than the default.
    type AllSet = object
      a*, b*, c*, d*, e*, f*, g*, h*: int
    var
      onRoot = scratch("geist_t_cc_on")
      offRoot = scratch("geist_t_cc_off")
      rows: seq[AllSet] = @[]
    for i in 1 .. 400:
      rows.add AllSet(a: i, b: i, c: i, d: i, e: i, f: i, g: i, h: i)

    # Identity off on BOTH sides: this measures what collapsing costs, and
    # two reserved columns would change the bitmap width and the row size
    # without telling us anything about collapsing.
    var onCfg = collapsedConfig()
    onCfg.rowIdentity = false
    var offCfg = appConfig()
    offCfg.rowIdentity = false

    var on = openCollection[AllSet](onRoot, "w", onCfg, "", false)
    on.add rows
    check on.save().ok
    var onSize = getFileSize(on.session.dataPath())
    on.close()

    var off = openCollection[AllSet](offRoot, "w", offCfg, "", false)
    off.add rows
    check off.save().ok
    var offSize = getFileSize(off.session.dataPath())
    off.close()

    check onSize > offSize
    # 1 bitmap byte per row, plus the offset table collapsing forces:
    # 4*(N+1) + 4 bytes. The non-collapsed schema is all-fixed, so it
    # stays dense and needs no table at all.
    check onSize - offSize == 400 + 4 * 401 + 4
    removeDir(onRoot)
    removeDir(offRoot)

  test "collapsing pays for itself as soon as columns go unset":
    type AllSet = object
      a*, b*, c*, d*, e*, f*, g*, h*: int
    var
      onRoot = scratch("geist_t_cs_on")
      offRoot = scratch("geist_t_cs_off")
      rows: seq[AllSet] = @[]
    for i in 1 .. 400:
      rows.add AllSet(a: i, e: i)      # 2 of 8 set

    var on = openCollection[AllSet](onRoot, "w", collapsedConfig(), "", false)
    on.add rows
    check on.save().ok
    var onSize = getFileSize(on.session.dataPath())
    on.close()

    var off = openCollection[AllSet](offRoot, "w", appConfig(), "", false)
    off.add rows
    check off.save().ok
    var offSize = getFileSize(off.session.dataPath())
    off.close()

    check onSize < offSize
    removeDir(onRoot)
    removeDir(offRoot)

  test "find works on a packed cluster":
    var
      root = scratch("geist_t_pk4")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
    c.add @[Note(id: 1, title: "x"), Note(id: 2, title: "y"),
            Note(id: 3, title: "x")]
    check c.save().ok
    check c.find("title", "x").len == 2
    check c.find("title", "nope").len == 0
    c.close()
    removeDir(root)

  test "iteration and indexing agree with what was written":
    var
      root = scratch("geist_t_pk5")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
      want: seq[Note] = @[]
    for i in 0 ..< 120:
      want.add Note(id: i, score: float(i) / 4.0, title: "t" & $i,
        body: "b" & $i)
    c.add want
    check c.save().ok
    c.close()

    var re = openCollection[Note](root, "n", collapsedConfig(), "", false)
    check re.len == 120
    var got: seq[Note] = @[]
    for n in re.items:
      got.add n
    check got == want
    check re[119] == want[119]
    check re[0] == want[0]
    re.close()
    removeDir(root)

  test "an encrypted packed database seals whole rows and reopens":
    var
      root = scratch("geist_t_pk6")
      c = openCollection[Note](root, "n", secureCollapsedConfig(), "pw", false)
    c.add @[Note(id: 1, title: "SECRET-TITLE", body: "SECRET-BODY"),
            Note(id: 2, title: "other", body: "more")]
    check c.save().ok
    var path = c.session.dataPath()
    c.close()

    # Nothing recognisable on disk, including the field the bitmap covers.
    var raw = readFile(path)
    check not raw.contains("SECRET-TITLE")
    check not raw.contains("SECRET-BODY")

    var re = openCollection[Note](root, "n", secureCollapsedConfig(), "pw", false)
    check re.len == 2
    check re[0].title == "SECRET-TITLE"
    check re[1].body == "more"
    re.close()
    removeDir(root)

  test "a sealed packed database needs its ledger":
    var
      root = scratch("geist_t_pk7")
      c = openCollection[Note](root, "n", secureCollapsedConfig(), "pw", false)
    c.add Note(id: 1, title: "keep", body: "safe")
    check c.save().ok
    var ledger = c.session.ledgerPath()
    c.close()
    check fileExists(ledger)
    removeFile(ledger)
    # Without the ledger the batch coordinates are gone, so the rows cannot
    # be opened. Failing loudly is the point of keeping it separate.
    expect ValueError:
      var dead = openCollection[Note](root, "n", secureCollapsedConfig(), "pw",
        false)
      discard dead[0]
    removeDir(root)

  test "putRow takes a complete row, and only a complete one":
    var
      root = scratch("geist_t_pk8")
      s = openSession[Note](root, "n", collapsedConfig(), "")
    # A hand-made buffer is not a row: it agrees with no schema, so the
    # identity columns it would have to carry are not there.
    expect ValueError:
      s.putRow(Row(data: newSeq[uint8](32)))
    # A row built against the session's own schema is accepted, varying
    # widths and all -- this is the path `geist put` takes.
    var
      id = s.nextIdFor()
      built = buildRow(s.entries.schema,
        {"id": "1", "title": "hello"}.toTable, s.sidecarStore, id)
    check built.ok
    check s.putRow(Row(data: built.data)) == id
    check s.entryCount() == 1'u32
    s.close()
    removeDir(root)

  test "checkpoint still chains on a packed cluster":
    var
      root = scratch("geist_t_pk9")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
    c.add Note(id: 1, title: "x")
    discard c.checkpoint("first")
    discard c.checkpoint("second")
    check c.save().ok
    check c.session.journal.chainHash.len == fullDigestBytes
    c.close()
    removeDir(root)

  test "an empty packed collection saves and reopens":
    var
      root = scratch("geist_t_pk10")
      c = openCollection[Note](root, "n", collapsedConfig(), "", false)
    check c.save().ok
    c.close()
    var re = openCollection[Note](root, "n", collapsedConfig(), "", false)
    check re.len == 0
    re.close()
    removeDir(root)

  test "the preset catalog exposes both packed profiles":
    check geistConfigPreset("collapsed").autoCollapse
    check geistConfigPreset("secure-collapsed").autoCollapse
    check geistConfigPreset("secure-collapsed").cipher == ckCascade
    var names: seq[string] = @[]
    for p in geistConfigPresets():
      names.add p.name
    check "collapsed" in names
    check "secure-collapsed" in names

  test "gimli is the default authenticator":
    check appConfig().mac == mkGimli
    check collapsedConfig().mac == mkGimli
    check iotConfig().mac == mkGimli
    check chatConfig().mac == mkGimli
    # Presets wanting two independent primitives still opt in explicitly.
    check secureAppConfig().mac == mkCombined
    check ledgerConfig().mac == mkCombined
