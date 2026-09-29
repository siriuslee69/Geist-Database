## ---------------------------------------------------------------------
## Transpose <- the same rows, written column first
## ---------------------------------------------------------------------
##
##   name.ge1st.gN     rows, one after another          THE STORE
##   name.getr.gN      columns, one after another       a derived copy
##
## A row-major file answers "give me row 4" with one read and "which rows
## have title = x" by walking every byte of every row, most of which
## belong to columns nobody asked about. Turning the table on its side
## swaps those costs: a scan of one column reads that column and nothing
## else.
##
##   row-major                        transposed
##   ---------                        ----------
##   [id|flags|noteId|title|body]     [id id id ...]
##   [id|flags|noteId|title|body]     [flags flags flags ...]
##   [id|flags|noteId|title|body]     [noteId noteId noteId ...]
##                                    [title title title ...]
##                                    [body body body ...]
##
##   find over title:                 find over title:
##     reads every row                  reads the title region
##
## THIS FILE IS DERIVED, NEVER THE TRUTH. The row-major generation holds
## the metadata, the journal, the key ledger and the id allocator; those
## are excluded from transposition on purpose -- a column store of a
## hash-chained journal would be a chain nobody can walk. So this artifact
## carries the ENTRY rows only, it is rebuilt rather than repaired, and it
## is not part of `artifactSet()`: losing it costs a rebuild, not data.
##
## WHICH ONE IS NEWER is not tracked in a side file. The transposed header
## records the generation it was built from, and the manifest records the
## generation that is live; comparing them is the answer. A tracker file
## would be a second copy of a fact already on disk, and the two would
## eventually disagree.
##
## Layout:
##
##   magic "GETR1" | version | generation | rowCount | headerBytes
##   columnCount | schema
##   directory: (columnCount + 1) x (at, len, dense, width)
##     entry 0        the per-row bitmap prefix, or empty
##     entry 1..n     one per column, in schema order
##   regions
##
## A column is DENSE when every row spends the same number of bytes on it
## (fixed and capped columns of a schema that does not collapse), and its
## region is then `rowCount * width` with no addressing overhead at all.
## Anything else gets `rowCount + 1` offsets in front of its values, the
##
## This module WRITES the copy and says whether it is current. Reading it
## is ./transposed, which this module re-exports.

import std/[os, strutils]

import runePragmas
import ./types
import ./format
import ./row
import ./store
import ./keys
import ./transposed

export transposed

## ----------------------------- writing ------------------------------
##
##   rows -----> addRow, once per row -----> ColumnRegions
##                                            header | col 0 | col 1 | ...
##   ColumnRegions --> prologue + directory + regions --> the file

type
  ColumnRegions {.role: truthBuilder, expectedCount: 1,
      lifeCycle: lcScratch.} = object
    ## The table taken apart while it is written: every row's bitmap
    ## prefix one after another, and every column's values one after
    ## another. A varying column also keeps where each value ends.
    header: ByteSeq
    region: seq[ByteSeq]
    ends: seq[seq[uint32]]
    dense: seq[bool]

proc initRegions(s: Schema): ColumnRegions {.role: configurator,
    tag: "db|write".} =
  ## s: one empty region per column; a varying one starts its offset
  ## table at 0.
  for j in 0 ..< s.slots.len:
    result.region.add @[]
    result.dense.add isDenseColumn(s, j)
    result.ends.add (if result.dense[j]: @[] else: @[0'u32])

proc addRow(R: var ColumnRegions, s: Schema, row: openArray[uint8],
    headerBytes: int) {.role: truthBuilder, tag: "db|write".} =
  ## R/s/row/headerBytes: one row's bitmap prefix and each of its columns
  ## appended to the matching region.
  var
    offsets: seq[int] = fieldOffsets(s, row)
    span: tuple[at, len: int] = (0, 0)
    j: int = 0
  R.header.addBytes row[0 ..< headerBytes]
  while j < s.slots.len:
    span = columnSpan(s, row, offsets, j)
    R.region[j].addBytes row[span.at ..< span.at + span.len]
    if not R.dense[j]:
      R.ends[j].add uint32(R.region[j].len)
    j = j + 1

proc regionBytes(R: ColumnRegions, j: int): ByteSeq {.role: truthBuilder,
    tag: "db|write".} =
  ## R/j: column j as it is stored -- its offset table first when varying.
  for o in R.ends[j]:
    result.addU32 o
  result.addBytes R.region[j]

proc prologue(s: Schema, rowCount: uint32, headerBytes: int,
    generation: uint64): ByteSeq {.role: truthBuilder, tag: "db|write".} =
  ## s/rowCount/headerBytes/generation: everything before the directory.
  ##
  ##   "GETR1" | u16 version | u64 generation | u32 rowCount
  ##   | u32 headerBytes | u32 columnCount | u32 schema length | schema
  var
    schemaBytes: ByteSeq = encodeSchema(s)
  for c in transposedMagic:
    result.add uint8(c)
  result.addU16 transposedVersion
  result.addU64 generation
  result.addU32 rowCount
  result.addU32 uint32(headerBytes)
  result.addU32 uint32(s.slots.len)
  result.addU32 uint32(schemaBytes.len)
  result.addBytes schemaBytes

proc addDirectoryEntry(A: var ByteSeq, at: uint64, len: int, dense: bool,
    width: uint32) {.role: dataWriter, inline, tag: "db|write".} =
  ## A/at/len/dense/width: one directory entry, 21 bytes:
  ##
  ##   | u64 at | u64 len | u8 dense | u32 width |
  A.addU64 at
  A.addU64 uint64(len)
  A.add (if dense: 1'u8 else: 0'u8)
  A.addU32 width

proc writeTransposed*(path: string, C: ClusterBuild,
    generation: uint64): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "db|storageIo|write".} =
  ## path: where the transposed copy is written.
  ## C: the ENTRY cluster, the only one that is ever transposed.
  ## generation: the row-major generation this mirrors, stored in the
  ##   header so staleness is a comparison rather than a guess.
  ##
  ## Written whole and renamed into place by the caller's discipline: this
  ## is a derived file, so a half-written one is rebuilt rather than
  ## recovered. That is the one way it is allowed to be simpler than the
  ## store it mirrors.
  var
    s: Schema = C.schema
    headerBytes: int = s.headerBytesOf()
    R: ColumnRegions = initRegions(s)
    bodies: seq[ByteSeq] = @[]
    blob: ByteSeq = @[]
    at: uint64 = 0'u64
    i: uint32 = 0'u32
  if s.slots.len == 0:
    return (false, "a transposed file needs a schema")
  while i < C.rowCount:
    R.addRow(s, C.rowBytesAt(i), headerBytes)
    i = i + 1'u32
  for j in 0 ..< s.slots.len:
    bodies.add R.regionBytes(j)
  # Header, then the directory, then the regions. The directory can only
  # be written once every region's length is known, so the regions are
  # built first and their offsets computed against a fixed prologue.
  blob = prologue(s, C.rowCount, headerBytes, generation)
  at = uint64(blob.len + (s.slots.len + 1) * directoryEntryBytes)
  # Entry 0 is the per-row bitmap prefix; entries 1..n are the columns.
  blob.addDirectoryEntry(at, R.header.len, true, uint32(headerBytes))
  at = at + uint64(R.header.len)
  for j in 0 ..< s.slots.len:
    blob.addDirectoryEntry(at, bodies[j].len, R.dense[j], s.slots[j].width)
    at = at + uint64(bodies[j].len)
  blob.addBytes R.header
  for body in bodies:
    blob.addBytes body
  try:
    if path.parentDir().len > 0:
      createDir(path.parentDir())
    writeFile(path, blob)
    result = (true, "")
  except CatchableError as exc:
    result = (false, "could not write " & path & ": " & exc.msg)

## ---------------------------- freshness -----------------------------

proc transposeState*(baseDir: string,
    baseName: string = "main"): TransposeStatus {.role: parser,
    tag: "db|read|status".} =
  ## baseDir/baseName: which of the two artifacts is ahead, and by how far.
  ##
  ## Both numbers come off disk: `live` from the manifest, `built` from
  ## the transposed file's own header. Nothing is remembered between calls,
  ## so there is no third place for the answer to be wrong.
  var
    found: tuple[path: string, generation: uint64] = existingTransposed(
      baseDir, baseName)
  result.live = liveGeneration(baseDir)
  result.path = found.path
  result.built = found.generation
  if found.path.len == 0:
    return (tsAbsent, result.live, 0'u64, "")
  if found.generation == result.live:
    result.state = tsCurrent
  elif found.generation < result.live:
    result.state = tsStale
  else:
    result.state = tsOrphan

proc describeTransposeState*(s: TransposeState, live, built: uint64): string {.
    role: helper, tag: "db|status".} =
  ## s/live/built: one line an operator can act on.
  case s
  of tsAbsent:
    result = "absent (row-major only; `geist transpose` builds it)"
  of tsCurrent:
    result = "current (built from generation " & $built & ")"
  of tsStale:
    result = "STALE: built from generation " & $built & ", live is " &
      $live & " -- searches fall back to the row scan until rebuilt"
  of tsOrphan:
    result = "orphaned: built from generation " & $built &
      ", which is newer than the live " & $live & " -- a save was rolled " &
      "back under it; rebuild"

proc retireTransposed*(baseDir, baseName: string, keep: uint64) {.
    role: actor, tag: "db|lifecycle|storageIo".} =
  ## baseDir/baseName/keep: delete every transposed file except one.
  ##
  ## Generations of the store are retired one at a time because a reader
  ## may still hold the previous one. Nobody reads an old transposed file:
  ## it is derived, and a reader that wants one asks whether it is current
  ## before it reads a byte.
  if not dirExists(baseDir):
    return
  var
    stem: string = baseName & transposedSuffix & ".g"
    keepName: string = baseName & transposedSuffix & generationSuffix(keep)
  for kind, path in walkDir(baseDir):
    if kind != pcFile:
      continue
    var name = path.extractFilename()
    if not name.startsWith(stem) or name == keepName:
      continue
    try:
      removeFile(path)
    except CatchableError:
      discard
