## Folder scan tests <- which files changed, and what is not a change.

import std/[os, times, unittest]

import runePragmas
import geist/folderscan

proc place(name: string): string {.role: helper.} =
  ## name: an empty folder.
  result = getTempDir() / "geist_scan" / name
  removeDir(result)
  createDir(result)

suite "folder scan":
  # {.testKind: tkUnit, covers: "scanFolder".}
  test "new, changed and removed files are told apart":
    var
      d = place("basic")
      a = scanFolder(d, [])
    writeFile(d / "x.txt", "one")
    createDir(d / "sub")
    writeFile(d / "sub" / "y.txt", "two")
    var b = scanFolder(d, a.entries)
    check b.changes.len == 2 and b.changes[0].kind == cfAdded
    check b.entries[0].path == "sub/y.txt"
    writeFile(d / "x.txt", "three!")
    removeFile(d / "sub" / "y.txt")
    var c = scanFolder(d, b.entries)
    check c.changes.len == 2
    check c.changes[0].kind == cfChanged and c.changes[1].kind == cfRemoved

  # {.testKind: tkEdgeCase, covers: "scanFolder".}
  test "a file touched with the same content is no change":
    var d = place("touch")
    writeFile(d / "x", "same")
    var a = scanFolder(d, [])
    setLastModificationTime(d / "x", getTime() + initDuration(seconds = 5))
    check scanFolder(d, a.entries).changes.len == 0

  # {.testKind: tkEdgeCase, covers: "scanFolder".}
  test "hidden names and temporary files are left out":
    var d = place("hidden")
    writeFile(d / ".secret", "x")
    writeFile(d / "a.tmp", "x")
    writeFile(d / "b.part", "x")
    createDir(d / ".git")
    writeFile(d / ".git" / "config", "x")
    writeFile(d / "real", "x")
    var a = scanFolder(d, [])
    check a.entries.len == 1 and a.entries[0].path == "real"

  # {.testKind: tkEdgeCase, covers: "scanFolder".}
  test "a link cannot take the scan out of the folder":
    var
      d = place("link")
      outside = place("outside")
    writeFile(outside / "private", "x")
    when defined(posix):
      createSymlink(outside, d / "out")
      check scanFolder(d, []).entries.len == 0
