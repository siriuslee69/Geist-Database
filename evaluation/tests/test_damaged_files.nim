## A damaged file is an ANSWER, never a crash.
##
## Every offset and length a reader uses came out of the file, so a file
## cut short by a full disk, or with a flipped byte, can ask for anything.
## These tests damage real files and check that each reader says what is
## wrong -- and allocates nothing a bad length claims.
##
##   damage                              reader         answer
##   ----------------------------------  -------------  -------------------
##   file cut in half                    readIndex      past the end
##   header claims 2^32-1 clusters       readIndex      past the end, fast
##   a slot's kind byte set to 200       openSeek       unknown kind
##   a column copy cut short             openTransposed an error, not zeros

import std/[os, strutils, unittest]

import runePragmas
import geist

type
  Note = object
    noteId: int
    title: string

proc freshStore(name: string): string {.role: dataWriter.} =
  ## name: a store under the temp folder with three rows; returns its root.
  var
    db: Session = default(Session)
    i: int = 1
  result = getTempDir() / name
  removeDir(result)
  createDir(result)
  db = openGeist[Note](result, appConfig())
  while i <= 3:
    discard db.put(Note(noteId: i, title: "row " & $i))
    i = i + 1
  doAssert db.save().ok
  db.close()

proc bytesOf(path: string): seq[uint8] {.role: dataFetcher.} =
  ## path: the whole file.
  for c in readFile(path):
    result.add uint8(c)

proc writeBytes(path: string, A: openArray[uint8]) {.role: dataWriter.} =
  ## path/A: replace the file with these bytes.
  var
    s: string = newString(A.len)
  for i, b in A:
    s[i] = char(b)
  writeFile(path, s)

proc firstSlotAt(A: openArray[uint8], at: int): int {.role: parser.} =
  ## A/at: a schema block starting at `at` -> where its first slot record
  ## starts: past the type name, the field names, autoCollapse and the
  ## slot count (see `encodeSchema`).
  var
    o: int = at + 4 + int(A.getU32(at))
    names: int = int(A.getU32(o))
    i: int = 0
  o = o + 4
  while i < names:
    o = o + 4 + int(A.getU32(o))
    i = i + 1
  result = o + 1 + 4

suite "damaged data files":
  # {.testKind: tkEdgeCase, covers: "readIndex, readAt".}
  test "a file cut in half is refused, not read as zeros":
    var
      path: string = liveDataPath(freshStore("geist_t_dmg_cut"), "main")
      A: seq[uint8] = bytesOf(path)
      got: tuple[ok: bool, f: GeistFile, err: string] =
        (false, default(GeistFile), "")
    writeBytes(path, A[0 ..< 40])
    got = readIndex(path)
    check not got.ok
    check got.err.contains("past the end")

  # {.testKind: tkEdgeCase, covers: "readIndex, readAt".}
  test "a header claiming four billion clusters allocates nothing":
    var
      path: string = liveDataPath(freshStore("geist_t_dmg_count"), "main")
      A: seq[uint8] = bytesOf(path)
      got: tuple[ok: bool, f: GeistFile, err: string] =
        (false, default(GeistFile), "")
    A.putU32(10, 0xFFFF_FFFF'u32)
    writeBytes(path, A)
    got = readIndex(path)
    check not got.ok
    check got.err.contains("past the end")

  # {.testKind: tkEdgeCase, covers: "openSeek, schemaFrom".}
  test "a column kind that does not exist is named":
    var
      path: string = liveDataPath(freshStore("geist_t_dmg_kind"), "main")
      A: seq[uint8] = bytesOf(path)
      idx: tuple[ok: bool, f: GeistFile, err: string] = readIndex(path)
      at: int = 0
      got: tuple[ok: bool, h: SeekHandle, err: string] =
        (false, default(SeekHandle), "")
    check idx.ok
    at = firstSlotAt(A, int(idx.f.index[idx.f.findIndex(crEntry)].at))
    A[at + 2] = 200'u8
    writeBytes(path, A)
    got = openSeek(path)
    check not got.ok
    check got.err.contains("unknown kind")

  # {.testKind: tkEdgeCase, covers: "openGeist, readCluster".}
  test "opening a damaged store raises an error a program can catch":
    var
      root: string = freshStore("geist_t_dmg_open")
      path: string = liveDataPath(root, "main")
      A: seq[uint8] = bytesOf(path)
      idx: tuple[ok: bool, f: GeistFile, err: string] = readIndex(path)
      at: int = firstSlotAt(A, int(idx.f.index[idx.f.findIndex(crEntry)].at))
      db: Session = default(Session)
    A[at + 2] = 200'u8
    writeBytes(path, A)
    expect IOError:
      db = openGeist[Note](root, appConfig())
      db.close()

suite "a damaged column copy":
  # {.testKind: tkEdgeCase, covers: "openTransposed".}
  test "a column copy cut short is an error, not a crash":
    var
      dir: string = getTempDir() / "geist_t_dmg_transposed"
      path: string = dir / "cut.gt"
    removeDir(dir)
    createDir(dir)
    writeBytes(path, [1'u8, 2, 3])
    check not openTransposed(path).ok
