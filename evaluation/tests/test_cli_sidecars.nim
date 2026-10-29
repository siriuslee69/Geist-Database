## -------------------------------------------------------------------------
## CLI sidecar tests <- track, folder and storage, and the run options
## -------------------------------------------------------------------------
##
##   suite                            what it holds down
##   -------------------------------  ----------------------------------------------
##   "the run options"                --sidecars, --storage, --storage-policy, --mb
##                                    and the words they take are read exactly
##   "a reference column"             sidecar:<hash> is stored as a reference, and
##                                    anything else in that column is refused
##   "track through the CLI"          one row per file, refused with sidecars off
##   "folder through the CLI"         adopt once, and show what is there
##   "storage through the CLI"        bench records a speed that a later run reads

import runePragmas
import std/[os, unittest, strutils, tables]

import clients/geist_cli
import geist
import geist/sidecar
import geist/storage
import geist/dynamic
import geist/folder
import geist/crypto/hashwidths

proc scratch(name: string): string {.role: helper.} =
  ## name: a folder under the temp dir, emptied and created.
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc makeFiles(dir: string) {.role: dataWriter.} =
  ## dir: a.txt, b.md and sub/c.txt, so the suffix and the depth both matter.
  createDir(dir / "sub")
  writeFile(dir / "a.txt", "alpha text")
  writeFile(dir / "b.md", "beta text")
  writeFile(dir / "sub" / "c.txt", "gamma text")

suite "the run options":
  # {.testKind: tkUnit.}
  test "the sidecar, storage, policy, megabyte and track options are read":
    var
      o = parseOptions(["track", "files", "--top", "--suffix", ".txt",
        "--sidecars", "off", "--storage", "/mnt/a,/mnt/b",
        "--storage-policy", "speed", "--mb", "8"])
    check o.command == "track"
    check o.args == @["files"]
    check o.top
    check o.suffix == ".txt"
    check o.sidecars == "off"
    check o.storage == "/mnt/a,/mnt/b"
    check o.storagePolicy == "speed"
    check o.megabytes == 8

  # {.testKind: tkUnit.}
  test "the default megabyte count is 16, and nothing is set by default":
    var
      o = parseOptions(["storage", "list"])
    check o.megabytes == 16
    check not o.top
    check o.sidecars.len == 0

  # {.testKind: tkEdgeCase.}
  test "on and off are the only words for --sidecars, and a typo is refused":
    check onOffOf("on")
    check not onOffOf("off")
    expect GeistCliFailure:
      discard onOffOf("maybe")

  # {.testKind: tkUnit.}
  test "a storage list drops blanks, and the policy words are priority and speed":
    check listOf("a, b,,c") == @["a", "b", "c"]
    check policyOf("speed") == spSpeed
    check policyOf("priority") == spPriority
    expect GeistCliFailure:
      discard policyOf("fastest")

  # {.testKind: tkUnit.}
  test "typed run options are put over the configuration, and untyped ones are not":
    var
      base = defaultGeistConfig()
      o = parseOptions(["list", "--sidecars", "off", "--storage", "/mnt/x",
        "--storage-policy", "speed"])
      c = withRunOptions(o, base)
    check not c.sidecars
    check c.storagePaths == @["/mnt/x"]
    check c.storagePolicy == spSpeed
    c = withRunOptions(parseOptions(["list"]), base)
    check c.sidecars == base.sidecars
    check c.storagePaths == base.storagePaths

suite "a reference column":
  # {.testKind: tkUnit.}
  test "sidecar:<full hash> is stored as an own-file reference, and nothing else is":
    var
      hash = newString(fullDigestBytes * 2)
      r = refFromText("")
    for i in 0 ..< hash.len:
      hash[i] = 'a'
    r = refFromText("sidecar:" & hash)
    check r.ok
    check r.data.len == 33
    check decodeRef(r.data).target == rtSidecar
    check not refFromText("bogus").ok
    check not refFromText("sidecar:abcd").ok
    check refFromText("").ok
    check refFromText("").data.len == 0

suite "track through the CLI":
  # {.testKind: tkIntegration.}
  test "a folder becomes one row per file, and the files are not written":
    var
      base = scratch("geist_t_cli_track")
      db = base / "db"
      files = base / "files"
      before: string = ""
      after: string = ""
    makeFiles(files)
    before = readFile(files / "a.txt")
    check runGeistCli(@["--path", db, "init", "--schema",
      "name:text,path:text,size:int,file:ref", "--type", "Tracked"]) == 0
    check runGeistCli(@["--path", db, "track", files, "--suffix", ".txt"]) == 0
    var
      s = openSessionWithSchema(db, "main", Schema(), defaultGeistConfig(), "")
    check s.entryCount() == 2'u32
    s.close()
    after = readFile(files / "a.txt")
    check before == after

  # {.testKind: tkEdgeCase.}
  test "with sidecars off a track is refused, and a folder without the columns is named":
    var
      base = scratch("geist_t_cli_track_off")
      db = base / "db"
      files = base / "files"
    makeFiles(files)
    check runGeistCli(@["--path", db, "init", "--schema",
      "name:text,path:text,size:int,file:ref", "--type", "Tracked"]) == 0
    check runGeistCli(@["--path", db, "--sidecars", "off", "track",
      files / "a.txt"]) == 1
    check runGeistCli(@["--path", base / "plain", "init", "--schema",
      "title:text", "--type", "Plain"]) == 0
    check runGeistCli(@["--path", base / "plain", "track", files / "a.txt"]) == 1

suite "folder through the CLI":
  # {.testKind: tkIntegration.}
  test "adopt gives a bare folder its files once, and refuses a second time":
    var
      dir = scratch("geist_t_cli_folder")
    check runGeistCli(@["folder", "adopt", dir]) == 0
    check fileExists(dir / folderVersionName)
    check fileExists(dir / folderPermissionsName)
    check runGeistCli(@["folder", "adopt", dir]) == 1
    check runGeistCli(@["folder", "show", dir]) == 0
    check runGeistCli(@["folder", "show", dir, "--json"]) == 0

suite "storage through the CLI":
  # {.testKind: tkIntegration.}
  test "bench records a speed, and a later run reads it back":
    var
      dir = scratch("geist_t_cli_storage")
    check runGeistCli(@["storage", "bench", dir, "--mb", "1"]) == 0
    check fileExists(dir / speedFileName)
    gSpeeds.del(absolutePath(dir))
    check measuredSpeedOf(dir) > 0.0
    check runGeistCli(@["storage", "list"]) == 0
    check runGeistCli(@["storage", "fastest"]) == 1
