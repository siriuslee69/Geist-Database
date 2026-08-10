import std/[os, strutils]
import ./format, ./store

proc str(A: ByteSeq): string =
  result = newString(A.len)
  for i in 0 ..< A.len: result[i] = char(A[i])

proc bytes(s: string): ByteSeq =
  result = newSeq[uint8](s.len)
  for i in 0 ..< s.len: result[i] = uint8(s[i])

when isMainModule:
  var
    o: Overflow
    meta: ClusterBuild
    notes: ClusterBuild
    path = getTempDir() / "geist_proto4.ge1st"

  # ---- meta cluster: fixed order, first in the file ----
  meta.role = crMeta; meta.mode = cmMutable
  meta.schema.typeName = "Meta"
  meta.schema.names = @["nodeId", "appName", "entryCount", "updatedAt"]
  meta.schema.slots = @[
    Slot(nameId: 0, kind: skText), Slot(nameId: 1, kind: skText),
    Slot(nameId: 2, kind: skInt),  Slot(nameId: 3, kind: skInt)]
  meta.beginRow()
  meta.setVar(o, 0, 0, bytes("workstation-1"))
  meta.setVar(o, 0, 1, bytes("contacts"))
  meta.setInt(0, 2, 3'u64)
  meta.setInt(0, 3, 1785600000'u64)

  # ---- entry cluster: 3 ContactNote rows ----
  notes.role = crEntry; notes.mode = cmAppend
  notes.schema.typeName = "ContactNote"
  notes.schema.names = @["noteId", "title", "clearance", "body"]
  notes.schema.slots = @[
    Slot(nameId: 0, kind: skInt),  Slot(nameId: 1, kind: skText),
    Slot(nameId: 2, kind: skInt),  Slot(nameId: 3, kind: skText)]
  for i in 0'u32 ..< 3'u32:
    notes.beginRow()
    notes.setInt(i, 0, uint64(i))
    notes.setVar(o, i, 1, bytes("case-note-" & $i))
    notes.setInt(i, 2, uint64(40 + i))
    notes.setVar(o, i, 3, bytes("body text for note " & $i))

  writeFile(path, @[meta, notes], o)
  echo "wrote ", path, "  (", getFileSize(path), " B total, overflow = ",
    o.data.len, " B)"

  # ================= PARTIAL READ 1: what geistd needs =================
  var (idx, overflowAt, overflowLen, headerBytes) = readIndex(path)
  echo "\n=== read header + index only: ", headerBytes, " B of ",
    getFileSize(path), " B ==="
  for e in idx:
    echo "  ", alignLeft($e.role, 9), "mode=", alignLeft($e.mode, 10),
      "rows=", align($e.rowCount, 3), "  at=", align($e.at, 5),
      " len=", e.len

  # ================= PARTIAL READ 2: one row, no cluster load ==========
  var
    ne = idx[1]
    schemaBytes = 4 + 11 + 4 + (4+6)+(4+5)+(4+9)+(4+4) + 4 + 4*5
    rowW = notes.schema.rowBytes()
    raw = readOneRow(path, ne, uint64(schemaBytes), rowW, 2'u32)
  echo "\n=== read ONLY row 2 (", rowW, " B) ==="
  echo "  noteId    = ", raw.getU64(int(slotAt(0)))
  echo "  clearance = ", raw.getU64(int(slotAt(2)))
  var
    ts = raw.getU32(int(slotAt(1)))
    tn = raw.getU32(int(slotAt(1)) + 4)
  echo "  title     -> overflow[", ts, " ..< ", ts+tn, "] = \"",
    str(readOverflowSlice(path, overflowAt, ts, tn)), "\""

  # ================= random access check =================
  echo "\n=== row i is at base + i*", rowW, " -- addressable, no scan ==="
  for i in 0'u32 ..< 3'u32:
    var r = readOneRow(path, ne, uint64(schemaBytes), rowW, i)
    var s = r.getU32(int(slotAt(1)))
    var n = r.getU32(int(slotAt(1)) + 4)
    echo "  row ", i, ": noteId=", r.getU64(0), " title=\"",
      str(readOverflowSlice(path, overflowAt, s, n)), "\""
