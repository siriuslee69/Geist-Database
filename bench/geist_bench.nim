## ---------------------------------------------------------------------
## Geist benchmarks <- Otter's comparison harness over the storage paths
## ---------------------------------------------------------------------
##
##   nimble bench            everything
##   nimble bench crypto     hash families, digest widths, MAC combiners
##   nimble bench io         write throughput, point reads, column scans
##   nimble bench refs       reference cell encoding
##
## HARDWARE NOTE. These numbers are storage-bound in the io group, so the
## storage device and filesystem state affect the result. Treat io figures as
## a comparative measurement, not a universal performance guarantee.
##
## Otter supplies `BenchAlgo` / `compareAlgorithms` / `formatBenchResults`.
## Timings are monotonic ticks (nanoseconds on Linux); every group runs a
## warmup first, because the first touch of a fresh file pays for page
## cache and directory metadata that later calls do not.

import std/[os, strformat, strutils]

import otter_repo_evaluation

import ../src/geist

type
  Reading = object
    ## Fixed-width only: 4 slots, 32 B per row, no overflow region.
    sensor*: int
    value*: int
    at*: int
    flags*: int

  Note = object
    ## Text-bearing, so every row touches the overflow region.
    id*: int
    title*: string
    body*: string

const
  ioRows = 5_000
  scanRows = 20_000

proc benchRoot(name: string): string =
  result = getTempDir() / ("geist_bench_" & name)
  removeDir(result)

proc header() =
  echo "======================================================="
  echo "Geist benchmarks"
  echo "  time      ", isoTimestamp()
  echo "  storage   host filesystem (runtime-dependent)"
  echo "  note      io figures depend on the storage device and filesystem state."
  echo "  nim       ", NimVersion, "  mm:orc"
  echo "======================================================="
  echo ""

proc globalWarmup() =
  ## Otter warms each algorithm inside a group, but the FIRST group still
  ## pays one-time costs -- SIMD dispatch, lookup tables, the first heap
  ## growth -- and charges them to whichever entry happens to run first.
  ## Measured: BLAKE3 read 1683 ns/op as the first entry of the first group
  ## and 559 ns/op for the identical call two groups later. Exercising
  ## every primitive here removes that artifact rather than leaving a 3x
  ## error sitting in the first row of the output.
  var
    small = cast[ByteSeq]("warmup message of a plausible row length")
    key = initSecret(newSeq[uint8](32))
    i = 0
  while i < 2_000:
    discard geistHash(hkBlake3, small, 32)
    discard geistHash(hkSha3, small, 32)
    discard geistHash(hkGimli, small, 32)
    discard geistHash(hkBlake3, small, 16)
    discard geistHash(hkSha3, small, 16)
    discard geistMacOf(mkBlake3, key, small, 32)
    discard geistMacOf(mkGimli, key, small, 32)
    discard geistMacOf(mkCombined, key, small, 32)
    i = i + 1

proc report(title: string, results: seq[BenchResult]) =
  var
    fastest: int64 = 0
  echo "--- ", title
  if results.len == 0:
    echo "  (no results)"
    return
  fastest = results[0].avgTicks
  for r in results:
    if r.avgTicks < fastest and r.avgTicks > 0:
      fastest = r.avgTicks
  for r in results:
    var rel = ""
    if fastest > 0 and r.avgTicks > 0:
      rel = &"{float(r.avgTicks) / float(fastest):>6.2f}x"
    echo &"  {r.name:<44} {r.avgTicks:>10} ns/op  {rel}"
  echo ""

## ------------------------------ crypto -------------------------------

proc benchCrypto() =
  var
    small = cast[ByteSeq]("a short message, one row's worth of bytes")
    big = newSeq[uint8](64 * 1024)
    key = initSecret(newSeq[uint8](32))
    i = 0
  while i < big.len:
    big[i] = uint8(i and 0xFF)
    i = i + 1

  report("hash families, 32 B digest over 41 B", compareAlgorithms(@[
    BenchAlgo(name: "blake3", run: proc() =
      discard geistHash(hkBlake3, small, 32)),
    BenchAlgo(name: "sha3", run: proc() =
      discard geistHash(hkSha3, small, 32)),
    BenchAlgo(name: "gimli", run: proc() =
      discard geistHash(hkGimli, small, 32))], 20_000, 500))

  report("hash families, 32 B digest over 64 KiB", compareAlgorithms(@[
    BenchAlgo(name: "blake3", run: proc() =
      discard geistHash(hkBlake3, big, 32)),
    BenchAlgo(name: "sha3", run: proc() =
      discard geistHash(hkSha3, big, 32)),
    BenchAlgo(name: "gimli", run: proc() =
      discard geistHash(hkGimli, big, 32))], 300, 20))

  report("digest width: does 16 B cost less than 32 B", compareAlgorithms(@[
    BenchAlgo(name: "blake3 16 B", run: proc() =
      discard geistHash(hkBlake3, small, 16)),
    BenchAlgo(name: "blake3 32 B", run: proc() =
      discard geistHash(hkBlake3, small, 32)),
    BenchAlgo(name: "sha3 16 B (computed at 32, truncated)", run: proc() =
      discard geistHash(hkSha3, small, 16)),
    BenchAlgo(name: "sha3 32 B", run: proc() =
      discard geistHash(hkSha3, small, 32))], 20_000, 500))

  report("MAC: the price of the XOR combiner", compareAlgorithms(@[
    BenchAlgo(name: "mkBlake3", run: proc() =
      discard geistMacOf(mkBlake3, key, small, 32)),
    BenchAlgo(name: "mkGimli", run: proc() =
      discard geistMacOf(mkGimli, key, small, 32)),
    BenchAlgo(name: "mkCombined (blake3 XOR gimli)", run: proc() =
      discard geistMacOf(mkCombined, key, small, 32))], 20_000, 500))

## ------------------------------- refs --------------------------------

proc benchRefs() =
  var
    own = Ref(target: rtSidecar, hash: newSeq[uint8](fullDigestBytes))
    packed = Ref(target: rtPacked, hash: newSeq[uint8](shortDigestBytes),
      fileId: 7'u16, slot: 4211'u32)
    ownBytes = encodeRef(own)
    packedBytes = encodeRef(packed)

  echo "--- reference cell size"
  echo &"  legacy encoding (tag+locator+hash+size+entryId)   118 bytes"
  echo &"  own-file  (tag | hash32)                          {ownBytes.len} bytes" &
    &"   {118.0 / float(ownBytes.len):>5.2f}x smaller"
  echo &"  packed    (tag | hash16 | fileId | slot)          {packedBytes.len} bytes" &
    &"   {118.0 / float(packedBytes.len):>5.2f}x smaller"
  echo &"  per 1M externalised cells: {118 * 1_000_000 div (1024*1024)} MiB -> " &
    &"{ownBytes.len * 1_000_000 div (1024*1024)} MiB own-file, " &
    &"{packedBytes.len * 1_000_000 div (1024*1024)} MiB packed"
  echo ""

  report("reference codec", compareAlgorithms(@[
    BenchAlgo(name: "encodeRef own-file", run: proc() =
      discard encodeRef(own)),
    BenchAlgo(name: "encodeRef packed", run: proc() =
      discard encodeRef(packed)),
    BenchAlgo(name: "decodeRef own-file", run: proc() =
      discard decodeRef(ownBytes)),
    BenchAlgo(name: "decodeRef packed", run: proc() =
      discard decodeRef(packedBytes)),
    BenchAlgo(name: "derive path from hash", run: proc() =
      discard own.refLocator())], 50_000, 1000))

## -------------------------------- io ---------------------------------

proc buildFixture(root, name: string, n: int,
    c: GeistConfig, password: string): string =
  ## Writes `n` rows once and returns the data path. Not timed.
  var col = openCollection[Reading](root, name, c, password, false)
  var i = 0
  while i < n:
    col.add Reading(sensor: i mod 16, value: i, at: 1_700_000_000 + i,
      flags: i mod 3)
    i = i + 1
  doAssert col.save().ok
  result = col.session.dataPath()
  col.close()

proc benchWrite() =
  var
    plainRoot = benchRoot("wplain")
    encRoot = benchRoot("wenc")
    started: int64 = 0
    elapsed: int64 = 0

  echo "--- write throughput (", ioRows, " rows, one save at the end)"

  started = monotonicTick()
  block:
    var col = openCollection[Reading](plainRoot, "r", appConfig(), "", false)
    var i = 0
    while i < ioRows:
      col.add Reading(sensor: i mod 16, value: i, at: i, flags: 0)
      i = i + 1
    doAssert col.save().ok
    col.close()
  elapsed = monotonicTick() - started
  echo &"  plain            {elapsed div 1_000_000:>6} ms   " &
    &"{float(ioRows) / (float(elapsed) / 1e9):>12.0f} rows/s"

  started = monotonicTick()
  block:
    var col = openCollection[Reading](encRoot, "r", secureAppConfig(), "pw",
      false)
    var i = 0
    while i < ioRows:
      col.add Reading(sensor: i mod 16, value: i, at: i, flags: 0)
      i = i + 1
    doAssert col.save().ok
    col.close()
  elapsed = monotonicTick() - started
  echo &"  cascade+combined {elapsed div 1_000_000:>6} ms   " &
    &"{float(ioRows) / (float(elapsed) / 1e9):>12.0f} rows/s"

  # autoSave writes the whole file per row: this is the cost of NOT
  # batching, and it is why `add(openArray)` saves once at the end.
  started = monotonicTick()
  block:
    var root = benchRoot("wauto")
    var col = openCollection[Reading](root, "r", appConfig(), "", true)
    var i = 0
    while i < 200:
      col.add Reading(sensor: i, value: i, at: i, flags: 0)
      i = i + 1
    col.close()
    removeDir(root)
  elapsed = monotonicTick() - started
  echo &"  autoSave, 200 rows {elapsed div 1_000_000:>4} ms   " &
    &"{float(200) / (float(elapsed) / 1e9):>12.0f} rows/s   " &
    "(one full file write per row)"
  echo ""

  removeDir(plainRoot)
  removeDir(encRoot)

proc benchRead() =
  var
    root = benchRoot("read")
    path = buildFixture(root, "r", scanRows, appConfig(), "")
    handle = openSeek(path)
    valueSlot = 0
  doAssert handle.ok
  valueSlot = handle.h.schema.slotIndex("value")

  echo &"--- point read out of {scanRows} rows " &
    &"(file {getFileSize(path) div 1024} KiB, " &
    &"index {indexCostBytes(path)} B)"
  echo ""

  var h = handle.h
  report("one row", compareAlgorithms(@[
    BenchAlgo(name: "seekRow (index cached in handle)", run: proc() =
      discard h.seekRow(uint32(scanRows div 2))),
    BenchAlgo(name: "openSeek + seekRow (index re-read)", run: proc() =
      var f = openSeek(path)
      discard f.h.seekRow(uint32(scanRows div 2))),
    BenchAlgo(name: "seekObject -> Reading", run: proc() =
      discard h.seekObject[:Reading](uint32(scanRows div 2)))], 2_000, 100))

  report("scan", compareAlgorithms(@[
    BenchAlgo(name: "seekFixedColumn (stride one column)", run: proc() =
      discard h.seekFixedColumn(valueSlot)),
    BenchAlgo(name: "seekRange whole cluster (all columns)", run: proc() =
      discard h.seekRange(0'u32, uint32(scanRows))),
    BenchAlgo(name: "readCluster + unpack every object", run: proc() =
      var cl = readCluster(path, h.entry)
      var i = 0'u32
      while i < cl.rowCount:
        discard objectAt[Reading](cl, i)
        i = i + 1'u32)], 20, 3))

  report("window of 100 rows", compareAlgorithms(@[
    BenchAlgo(name: "seekRange 100 (one contiguous read)", run: proc() =
      discard h.seekRange(1000'u32, 100'u32)),
    BenchAlgo(name: "100 x seekRow (one read each)", run: proc() =
      var i = 0'u32
      while i < 100'u32:
        discard h.seekRow(1000'u32 + i)
        i = i + 1'u32)], 200, 20))

  removeDir(root)

proc benchText() =
  var root = benchRoot("text")
  block:
    var col = openCollection[Note](root, "n", appConfig(), "", false)
    var i = 0
    while i < ioRows:
      col.add Note(id: i, title: "title-" & $i,
        body: "a body of moderate length for row " & $i)
      i = i + 1
    doAssert col.save().ok
    col.close()
  var path = root / "n.ge1st.g1"
  var handle = openSeek(path)
  doAssert handle.ok
  var h = handle.h
  var titleSlot = h.schema.slotIndex("title")

  echo &"--- text column out of {ioRows} rows " &
    &"(file {getFileSize(path) div 1024} KiB)"
  echo ""

  report("one text field", compareAlgorithms(@[
    BenchAlgo(name: "seekText (slice only)", run: proc() =
      discard h.seekText(uint32(ioRows div 2), titleSlot)),
    BenchAlgo(name: "seekObject (row + whole overflow)", run: proc() =
      discard h.seekObject[:Note](uint32(ioRows div 2)))], 500, 50))

  report("whole text column", compareAlgorithms(@[
    BenchAlgo(name: "seekColumnBytes (two bulk reads)", run: proc() =
      discard h.seekColumnBytes(titleSlot)),
    BenchAlgo(name: "readCluster + unpack every object", run: proc() =
      var cl = readCluster(path, h.entry)
      var i = 0'u32
      while i < cl.rowCount:
        discard objectAt[Note](cl, i)
        i = i + 1'u32)], 20, 3))

  removeDir(root)

## ------------------------------ packed -------------------------------

type
  Wide = object
    ## Eight columns, of which a sparse workload sets two.
    a*: int
    b*: string
    c*: int
    d*: string
    e*: int
    f*: string
    g*: int
    h*: string

type
  AllInts = object
    ## No variable fields, so packed has nothing to save and pays its
    ## overhead bare. This is the case that falsifies "packed is always
    ## smaller".
    a*, b*, c*, d*, e*, f*, g*, h*: int

  AllText = object
    ## Variable fields only: the 8-byte (start, len) pointer of the fixed
    ## profile against packed's 4-byte length prefix, eight times over.
    a*, b*, c*, d*, e*, f*, g*, h*: string

proc fileSizeOf[T](root: string, c: GeistConfig, rows: seq[T]): int64 =
  removeDir(root)
  var col = openCollection[T](root, "w", c, "", false)
  col.add rows
  doAssert col.save().ok
  result = getFileSize(col.session.dataPath())
  col.close()
  removeDir(root)

proc benchLayoutCrossover() =
  ## Isolates WHY a packed row can be smaller than a fixed one even with
  ## nothing omitted. It is not the bitmap -- that only ever adds bytes.
  ## It is that a variable field costs an 8-byte pointer in the fixed
  ## profile and a 4-byte length prefix in the packed one.
  var
    ints: seq[AllInts] = @[]
    texts: seq[AllText] = @[]
    s = ""
    i = 1
  while i <= ioRows:
    ints.add AllInts(a: i, b: i, c: i, d: i, e: i, f: i, g: i, h: i)
    s = "v" & $i
    texts.add AllText(a: s, b: s, c: s, d: s, e: s, f: s, g: s, h: s)
    i = i + 1

  var
    ip = fileSizeOf(benchRoot("xip"), packedConfig(), ints)
    ifx = fileSizeOf(benchRoot("xif"), appConfig(), ints)
    tp = fileSizeOf(benchRoot("xtp"), packedConfig(), texts)
    tfx = fileSizeOf(benchRoot("xtf"), appConfig(), texts)

  echo &"--- layout crossover, {ioRows} rows of 8 columns"
  echo &"  0 variable columns  packed {float(ip)/float(ioRows):>6.1f} B/row   " &
    &"fixed {float(ifx)/float(ioRows):>6.1f} B/row   " &
    &"packed is {float(ip)/float(ifx):.3f}x"
  echo &"  8 variable columns  packed {float(tp)/float(ioRows):>6.1f} B/row   " &
    &"fixed {float(tfx)/float(ioRows):>6.1f} B/row   " &
    &"packed is {float(tp)/float(tfx):.3f}x"
  echo "  packed overhead: ceil(C/8) bitmap + 4 B offset entry, per row"
  echo "  packed saving:   4 B per VARIABLE column (8 B pointer -> 4 B length)"
  echo "  => packed is smaller iff 4*V > ceil(C/8) + 4;  for C<=8, V >= 2"
  echo ""

proc benchPacked() =
  var
    dense: seq[Wide] = @[]
    sparse: seq[Wide] = @[]
    i = 0
  while i < ioRows:
    dense.add Wide(a: i, b: "bb" & $i, c: i, d: "dd" & $i, e: i,
      f: "ff" & $i, g: i, h: "hh" & $i)
    sparse.add Wide(a: i, e: i * 2)
    i = i + 1

  proc writeWith(root: string, c: GeistConfig, rows: seq[Wide]): int64 =
    var col = openCollection[Wide](root, "w", c, "", false)
    col.add rows
    doAssert col.save().ok
    result = getFileSize(col.session.dataPath())
    col.close()

  var
    dpRoot = benchRoot("pkdp")
    dfRoot = benchRoot("pkdf")
    spRoot = benchRoot("pksp")
    sfRoot = benchRoot("pksf")
    densePacked = writeWith(dpRoot, packedConfig(), dense)
    denseFixed = writeWith(dfRoot, appConfig(), dense)
    sparsePacked = writeWith(spRoot, packedConfig(), sparse)
    sparseFixed = writeWith(sfRoot, appConfig(), sparse)

  echo &"--- file size, {ioRows} rows of an 8-column schema"
  echo &"  dense   packed {densePacked:>9} B   fixed {denseFixed:>9} B   " &
    &"{float(denseFixed) / float(densePacked):>5.2f}x"
  echo &"  sparse  packed {sparsePacked:>9} B   fixed {sparseFixed:>9} B   " &
    &"{float(sparseFixed) / float(sparsePacked):>5.2f}x"
  echo "  (dense wins on the pointer -> length-prefix swap; sparse adds"
  echo "   the bitmap on top. See the crossover group above.)"
  echo ""

  var
    pc = openCollection[Wide](spRoot, "w", packedConfig(), "", false)
    fc = openCollection[Wide](sfRoot, "w", appConfig(), "", false)

  report("read one row, sparse 8-column schema", compareAlgorithms(@[
    BenchAlgo(name: "packed (offset table + one pass)", run: proc() =
      discard pc[ioRows div 2]),
    BenchAlgo(name: "fixed (arithmetic + overflow region)", run: proc() =
      discard fc[ioRows div 2])], 5_000, 200))

  report("scan every row, sparse 8-column schema", compareAlgorithms(@[
    BenchAlgo(name: "packed", run: proc() =
      for x in pc.items: discard x),
    BenchAlgo(name: "fixed", run: proc() =
      for x in fc.items: discard x)], 20, 3))

  pc.close()
  fc.close()
  removeDir(dpRoot)
  removeDir(dfRoot)
  removeDir(spRoot)
  removeDir(sfRoot)

## ------------------------------- main --------------------------------

when isMainModule:
  var
    which = ""
  if paramCount() >= 1:
    which = paramStr(1).toLowerAscii()
  header()
  globalWarmup()
  if which.len == 0 or which == "crypto":
    benchCrypto()
  if which.len == 0 or which == "refs":
    benchRefs()
  if which.len == 0 or which == "packed":
    benchLayoutCrossover()
    benchPacked()
  if which.len == 0 or which == "io":
    benchWrite()
    benchRead()
    benchText()
  echo "done."
