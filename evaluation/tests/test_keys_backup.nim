## Key lifecycle and backup rotation.
import std/[os, unittest]
import geist

suite "keys":
  # {.testKind: tkEdgeCase.}
  test "key file seals and unseals, wrong password rejected":
    var
      root = getTempDir() / "geist_t_keys"
      K = newKeySet()
    removeDir(root); createDir(root)
    discard K.allocKeyRef("g0")
    var g = generationPaths(root, "main", 1'u64)
    check writeKeyFile(g.keyPath, "pw", K).ok
    var r = readKeyFile(g.keyPath, "pw")
    check r.ok
    check r.keys.master.use() == K.master.use()
    check not readKeyFile(g.keyPath, "nope").ok

  # {.testKind: tkEdgeCase.}
  test "the ledger is integrity-checked, not encrypted":
    var
      root = getTempDir() / "geist_t_ledger"
      L = Ledger(databaseId: "db", batchRows: 8'u32,
                 groups: @[ColumnGroup(groupId: 0'u16, slots: @[0, 1])])
    removeDir(root); createDir(root)
    L.ensureCapacity(1'u32)
    var p = root / "main.ledger.g1"
    check writeLedgerFile(p, @[L]).ok
    check readLedgerFile(p).ok
    var raw = readFile(p)
    raw[10] = char(uint8(raw[10]) xor 0xFF'u8)
    writeFile(p, raw)
    check not readLedgerFile(p).ok

  # {.testKind: tkUnit.}
  test "the manifest is the single atomic swap point":
    var root = getTempDir() / "geist_t_man"
    removeDir(root); createDir(root)
    check commitManifest(root, 4'u64).ok
    var m = readManifest(root)
    check m.ok and m.n == 4'u64

  # {.testKind: tkUnit.}
  test "per-batch rekey resets the epoch without a global rewrite":
    var
      K = newKeySet()
      L = Ledger(databaseId: "db", batchRows: 8'u32,
                 groups: @[ColumnGroup(groupId: 0'u16, slots: @[0])])
    L.ensureCapacity(2'u32)
    L.entries[0].keyRef = 1'u64
    L.entries[0].epoch = 900'u64
    var fresh = rekeyBatch(K, L, 0'u32, 0'u16)
    check fresh != 1'u64
    check L.entries[0].keyRef == fresh
    check L.entries[0].epoch == 0'u64

  # {.testKind: tkUnit.}
  test "batches approaching the high-water mark are reported":
    var L = Ledger(databaseId: "db", batchRows: 8'u32,
                   groups: @[ColumnGroup(groupId: 0'u16, slots: @[0])])
    L.ensureCapacity(1'u32)
    L.entries[0].epoch = defaultRekeyAtEpoch
    L.entries[0].batchIndex = 0'u32
    check batchesNeedingRekey(L).len == 1

suite "backup":
  # {.testKind: tkUnit.}
  test "rotation shifts .b1 -> .b2 -> .b3 newest first":
    var
      root = getTempDir() / "geist_t_bak"
      p = root / "main.ge1st"
      policy = defaultBackupPolicy()
      st: BackupState = default(BackupState)
    removeDir(root); createDir(root)
    policy.everyNWrites = 1'u32
    for gen in 1 .. 3:
      writeFile(p, "generation-" & $gen)
      st.noteWrite()
      var r = runBackup(@[p], @[p], policy, st, int64(gen))
      check r.performed
    check readFile(slotPath(p, 1)) == "generation-3"
    check readFile(slotPath(p, 2)) == "generation-2"
    check readFile(slotPath(p, 3)) == "generation-1"
    check st.rotations == 3'u32

  # {.testKind: tkEdgeCase.}
  test "an incomplete artifact set is refused, not half-copied":
    var
      root = getTempDir() / "geist_t_bak2"
      data = root / "main.ge1st"
      keysF = root / "main.keys"
      policy = defaultBackupPolicy()
      st: BackupState = default(BackupState)
    removeDir(root); createDir(root)
    policy.everyNWrites = 1'u32
    writeFile(data, "data")
    st.noteWrite()
    var r = runBackup(@[data, keysF], @[data, keysF], policy, st, 1'i64)
    check not r.performed
    check r.err.len > 0
    check not fileExists(slotPath(data, 1))

  # {.testKind: tkEdgeCase.}
  test "restore refuses a partial set and restores a complete one":
    var
      root = getTempDir() / "geist_t_bak3"
      p = root / "main.ge1st"
      policy = defaultBackupPolicy()
      st: BackupState = default(BackupState)
    removeDir(root); createDir(root)
    policy.everyNWrites = 1'u32
    writeFile(p, "v1")
    st.noteWrite()
    check runBackup(@[p], @[p], policy, st, 1'i64).performed
    writeFile(p, "v2")
    check restoreFrom(@[p], 1).ok
    check readFile(p) == "v1"
    check not restoreFrom(@[p], 3).ok
