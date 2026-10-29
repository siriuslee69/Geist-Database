## -------------------------------------------------------------------------
## Folder tests <- the hashed version and permission files, and the store parameters
## -------------------------------------------------------------------------
##
##   suite                                  what it holds down
##   -------------------------------------  ----------------------------------------
##   "the folder files"                     a fresh folder gets them; a changed one is refused
##   "permissions"                          deny-write reads but never writes
##   "parameters"                           a store made under another hash family reads
##   "force read and adoption"              the raw view works on a damaged folder

import std/[unittest, os, strutils]

import runePragmas
import geist
import geist/search
import geist/folder
import null_query_apis as nq

type
  Item = object
    id: int
    title: string
    body: string

proc freshDir(name: string): string {.role: helper.} =
  ## A new, empty folder under the test directory.
  result = getTempDir() / name
  removeDir(result)

proc itemConfig(): GeistConfig {.role: configurator.} =
  result = appConfig()
  result.backup.enabled = false

suite "the folder files":

  # {.testKind: tkIntegration, covers: "checkFolder|writeFolderFiles".}
  test "a fresh folder gets its two files on the first write, and both validate":
    var
      dir = freshDir("geist_folder_fresh")
    var
      db: Session = openGeist[Item](dir, itemConfig(), "")
    discard db.put(Item(id: 1, title: "a", body: "b"))
    check db.save().ok
    db.close()
    check fileExists(dir / folderVersionName)
    check fileExists(dir / folderPermissionsName)
    check checkFolder(dir, forWrite = true).ok
    removeDir(dir)

  # {.testKind: tkRegression, covers: "checkFolder|openSessionWithSchema|openStore".}
  test "a changed version file refuses reads and writes, and nothing in the folder changes":
    var
      dir = freshDir("geist_folder_tampered")
    var
      db: Session = openGeist[Item](dir, itemConfig(), "")
    discard db.put(Item(id: 1, title: "a", body: "b"))
    check db.save().ok
    db.close()
    var before = readFile(liveDataPath(dir, storeBaseName))
    writeFile(dir / folderVersionName, readFile(dir / folderVersionName) & "extra = 1\n")
    expect IOError:
      discard openGeist[Item](dir, itemConfig(), "")
    expect IOError:
      discard openSession[Item](dir, storeBaseName, itemConfig(), "", true)
    var
      q = nq.initNullQuery(@[nq.parsePredicateSpec("title:exact=a").p])
      found = searchStore(dir, q)
    check not found.ok
    check found.err.contains("digest")
    check readFile(liveDataPath(dir, storeBaseName)) == before
    removeDir(dir)

suite "permissions":

  # {.testKind: tkEdgeCase, covers: "checkFolder".}
  test "a folder that denies write still reads, and refuses a writable open":
    var
      dir = freshDir("geist_folder_readonly")
    var
      db: Session = openGeist[Item](dir, itemConfig(), "")
      rid = db.put(Item(id: 7, title: "kept", body: "x"))
    check db.save().ok
    db.close()
    removeFile(dir / folderPermissionsName)
    writeFolderFiles(dir, FolderPolicy(read: true, write: false, sidecars: true))
    expect IOError:
      discard openGeist[Item](dir, itemConfig(), "")
    var
      reader: Session = openSession[Item](dir, storeBaseName, itemConfig(), "", true)
    check byId[Item](reader, rid).found
    reader.close()
    removeDir(dir)

suite "parameters":

  # {.testKind: tkIntegration, covers: "applyParams|loadParams|openSessionWithSchema".}
  test "a store written with another hash family is read with the family it was written with":
    var
      dir = freshDir("geist_params_other_hash")
      written = itemConfig()
      big = "h".repeat(2000)
    written.contentHash = hkSha3
    written.sidecarThreshold = 512'u32
    var
      db: Session = openGeist[Item](dir, written, "")
      id = db.put(Item(id: 1, title: "t", body: big))
    check db.save().ok
    db.close()
    check fileExists(dir / (storeBaseName & paramsSuffix))
    var
      reader: Session = openSession[Item](dir, storeBaseName, itemConfig(), "", true)
    check reader.config.contentHash == hkSha3
    check byId[Item](reader, id).value.body == big
    reader.close()
    removeDir(dir)

suite "force read and adoption":

  # {.testKind: tkIntegration, covers: "inspectFolder|adoptFolder".}
  test "force read shows the rows of a folder that does not validate, and adoption makes it usable":
    var
      dir = freshDir("geist_folder_inspect")
    var
      db: Session = openGeist[Item](dir, itemConfig(), "")
      rid = db.put(Item(id: 3, title: "visible", body: "row"))
    check db.save().ok
    db.close()
    writeFile(dir / folderVersionName, "not a version file\n")
    var report = inspectFolder(dir, asJson = true)
    check report.contains("visible")
    check report.contains("\"rows\"")
    check report.contains(folderVersionName)
    var plain = inspectFolder(dir, asJson = false)
    check plain.contains("== data")
    removeFile(dir / folderVersionName)
    removeFile(dir / folderPermissionsName)
    check not checkFolder(dir, forWrite = false).ok
    check adoptFolder(dir).ok
    check checkFolder(dir, forWrite = true).ok
    var
      after: Session = openSession[Item](dir, storeBaseName, itemConfig(), "", true)
    check byId[Item](after, rid).found
    after.close()
    removeDir(dir)
