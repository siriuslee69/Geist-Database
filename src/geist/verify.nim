## ---------------------------------------------------------------------
## Verify <- check a sealed store's integrity WITHOUT its password
## ---------------------------------------------------------------------
##
## Every sealed batch has an unkeyed Gimli digest in the ledger
## (crypto/batch.nim). This walks the live generation and recomputes each
## one, so a backup tool, a relay or a person without the password can
## tell an intact store from a damaged one:
##
##   ledger (public) --> each batch: position + sealed bytes --> Gimli digest
##                                                                 == ledger?
##
## It CANNOT tell a deliberate change from an intact store -- anyone can
## recompute an unkeyed digest. That is the keyed BLAKE3 tag's job, and the
## tag is checked every time the store is opened with its password.
##
##   verifyStoreIntegrity("data/notes")   one store
##   verifyStoreIntegrity("vault")        a keyring folder: every ring
##
## Large values kept outside the row file (sidecars) are not covered here;
## they carry their own content hash.

import std/os

import runePragmas
import ./types
import ./keys
import ./format
import ./store
import ./keyring
import ./crypto/batch
import ./crypto/column
import ./crypto/hashing

type
  IntegrityReport* {.role: truthState.} = object
    ## ok: every batch matched. batches: how many were checked.
    ## problems: one readable line per failure.
    ok*: bool
    batches*: int
    problems*: seq[string]

proc clusterHashOk(dataPath: string, e: IndexEntry): bool {.role: sanitizer,
    tag: "cryptoBoundary|read|storageIo".} =
  ## dataPath/e: a cluster and its index entry. True when its stored body
  ## (schema block and rows) still hashes to the index hash. The index does
  ## not say which family made that hash (presets differ), so any matches.
  var
    body: ByteSeq = readAt(dataPath, e.at, int(e.len))
  for k in HashKind:
    if geistHash(k, body, 32) == e.hash:
      return true

proc checkCluster(R: var IntegrityReport, dataPath: string, f: GeistFile,
    role: ClusterRole, L: Ledger, label: string) {.role: sanitizer,
    tag: "cryptoBoundary|read|storageIo".} =
  ## R: report extended. dataPath/f: the data file and its index.
  ## role/L: one sealed cluster and its ledger. label: name in messages.
  var
    at: int = f.findIndex(role)
    C: ClusterBuild = default(ClusterBuild)
  if at < 0:
    # A ledger that lists sealed batches for a cluster the file no longer
    # has is a dropped cluster (a changed role or cluster count), not an
    # empty store.
    if L.entries.len > 0:
      R.problems.add label & ": missing, though the ledger lists " & $L.entries.len & " sealed batch(es)"
    return
  if not clusterHashOk(dataPath, f.index[at]):
    R.problems.add label & ": schema or rows do not match the index hash"
  if L.entries.len == 0:
    return
  C = readCluster(dataPath, f.index[at])
  for b in sealedBatches(L, C.schema, C.rows, C.rowOffsets, C.rowCount, C.varyingRows()):
    R.batches = R.batches + 1
    if not checkBatch(b.e, L.databaseId, geistFormatVersion, b.sealed, b.lens, clusterBinding(C.schema, C.rowCount)):
      R.problems.add label & " batch " & $b.e.batchIndex & ", column group " &
        $b.e.groupId & ": bytes do not match the integrity digest"

proc checkStore(R: var IntegrityReport, dir, name, label: string) {.
    role: orchestrator, tag: "cryptoBoundary|read|storageIo".} =
  ## R: report extended. dir/name: one store's folder and stem.
  var
    g: Generation = generationPaths(dir, name, liveGeneration(dir))
    led: tuple[ok: bool, ledgers: seq[Ledger], err: string] = (false, @[], "")
    idx: tuple[ok: bool, f: GeistFile, err: string] = (false, default(GeistFile), "")
    roles: array[3, (ClusterRole, string)] = [(crEntry, "entries"), (crMeta, "meta"), (crJournal, "journal")]
    i: int = 0
  if not fileExists(g.ledgerPath):
    R.problems.add label & ": not sealed (no ledger), nothing to verify"
    return
  try:
    led = readLedgerFile(g.ledgerPath)
    idx = readIndex(g.dataPath)
  except ValueError, IOError, IndexDefect:
    R.problems.add label & ": unreadable: " & getCurrentExceptionMsg()
    return
  if not led.ok or not idx.ok:
    R.problems.add label & ": " & (if led.ok: idx.err else: led.err)
    return
  if idx.f.header.generation != g.number:
    R.problems.add label & ": file header names generation " & $idx.f.header.generation &
      ", the manifest " & $g.number
  while i < min(roles.len, led.ledgers.len):
    try:
      checkCluster(R, g.dataPath, idx.f, roles[i][0], led.ledgers[i], label & " " & roles[i][1])
    except ValueError, IOError, IndexDefect:
      R.problems.add label & " " & roles[i][1] & ": unreadable: " & getCurrentExceptionMsg()
    i = i + 1

proc verifyStoreIntegrity*(path: string): IntegrityReport {.role: orchestrator,
    tag: "appApi|cryptoBoundary|read|storageIo".} =
  ## path: a store folder (or `<dir>/<name>.ext` stem), or a keyring folder.
  ## Needs no password and changes nothing.
  var
    dir: string = path
    name: string = "main"
  if path.splitFile().ext.len > 0:
    dir = path.parentDir()
    name = path.splitFile().name
  if ringNames(dir).len > 0:
    for ring in ringNames(dir):
      checkStore(result, dir / ring, "main", "ring " & ring)
  else:
    checkStore(result, dir, name, name)
  result.ok = result.problems.len == 0
