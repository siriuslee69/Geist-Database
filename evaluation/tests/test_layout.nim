## One folder per machine.
##
## The property under test is that the path on disk and the address on the
## wire are the same shape: a store reached as
## `geist://fjord/mail/alice/inbox` lives at `db/fjord/mail/alice/inbox`,
## so an operator holding one can find the other without a lookup table.
##
## And that `..` cannot get through, because this is the function that
## turns an address into a filesystem path.

import runePragmas
import std/[os, strutils, unittest]

import geist/address
import geist/layout

proc scratch(name: string): string {.role: helper.} =
  result = getTempDir() / "geist_layout_test" / name
  removeDir(result)

suite "where the folder is":

  # {.testKind: tkUnit.}
  test "an explicit base wins and is marked explicit":
    var h = openHome("/tmp/somewhere", nrClient)
    check h.ok
    check h.home.base == "/tmp/somewhere"
    check h.home.explicit

  # {.testKind: tkEdgeCase.}
  test "a relative base is made absolute, so a chdir cannot move a store":
    var h = openHome("relative/place", nrClient)
    check h.ok
    check h.home.base.isAbsolute()

  # {.testKind: tkEdgeCase.}
  test "the environment is used when nothing was passed":
    putEnv(geistHomeEnv, "/tmp/from-the-env")
    var h = openHome("", nrClient)
    check h.ok
    check h.home.base == "/tmp/from-the-env"
    check h.home.explicit
    delEnv(geistHomeEnv)

  # {.testKind: tkUnit.}
  test "and the platform default when neither was":
    delEnv(geistHomeEnv)
    var h = openHome("", nrClient)
    check h.ok
    check not h.home.explicit
    check h.home.base.len > 0

  # {.testKind: tkUnit.}
  test "a server and a client default to different places":
    delEnv(geistHomeEnv)
    check defaultHomeFor(nrServer) != defaultHomeFor(nrClient)
    when not defined(windows) and not defined(android):
      check defaultHomeFor(nrServer) == "/var/lib/geist"

  # {.testKind: tkEdgeCase.}
  test "opening creates nothing":
    var p = scratch("untouched")
    discard openHome(p, nrClient)
    check not dirExists(p)

suite "the six subdirectories":

  setup:
    var
      p = scratch("tree")
      h = openHome(p, nrClient).home

  # {.testKind: tkUnit.}
  test "are all under the one base":
    check h.configDir() == p / "config"
    check h.keysDir() == p / "keys"
    check h.keystoreDir() == p / "keys" / "keystore"
    check h.peersDir() == p / "peers"
    check h.dbDir() == p / "db"
    check h.spoolDir() == p / "spool"
    check h.logDir() == p / "logs"

  # {.testKind: tkUnit.}
  test "and ensureHome makes them":
    check h.ensureHome().ok
    check dirExists(h.configDir())
    check dirExists(h.keysDir())
    check dirExists(h.keystoreDir())
    check dirExists(h.peersDir())
    check dirExists(h.dbDir())
    check dirExists(h.spoolDir())
    check dirExists(h.logDir())

  # {.testKind: tkEdgeCase.}
  test "but not the app directories: db/ lists what is actually here":
    check h.ensureHome().ok
    check h.appNames().len == 0

  # {.testKind: tkEdgeCase.}
  test "ensureHome twice is fine":
    check h.ensureHome().ok
    check h.ensureHome().ok

suite "named files":

  setup:
    var h = openHome(scratch("named"), nrClient).home

  # {.testKind: tkEdgeCase.}
  test "a config gets .toml when the caller did not write it":
    check h.configPath("fjord").endsWith("config/fjord.toml")
    check h.configPath("fjord.toml").endsWith("config/fjord.toml")

  # {.testKind: tkUnit.}
  test "and json is left alone":
    check h.configPath("export.json").endsWith("config/export.json")

  # {.testKind: tkUnit.}
  test "an identity and a pin land in their own folders":
    check h.identityPath("vps-1").endsWith("keys/vps-1.id")
    check h.pinPath("vps-2").endsWith("peers/vps-2.pin")

suite "the path is the address":

  setup:
    var h = openHome(scratch("paths"), nrClient).home

  # {.testKind: tkUnit.}
  test "a target becomes the same shape underneath db/":
    var r = h.storePath("fjord", "", "mail/alice/inbox")
    check r.ok
    check r.path.endsWith("db/fjord/mail/alice/inbox")

  # {.testKind: tkUnit.}
  test "an instance sits beside its app rather than under it":
    var r = h.storePath("fjord", "staging", "accounts")
    check r.ok
    check r.path.endsWith("db/fjord.staging/accounts")

  # {.testKind: tkEdgeCase.}
  test "a whole address is taken apart rather than refused":
    var r = h.storePath("fjord", "", "geist://fjord/mail/alice/inbox")
    check r.ok
    check r.path.endsWith("db/fjord/mail/alice/inbox")

  # {.testKind: tkUnit.}
  test "storeFor reads the app out of the address itself":
    var
      a = parseAddress("geist://eris.games/games/alderreach").a
      r = h.storeFor(a)
    check r.ok
    check r.path.endsWith("db/eris.games/games/alderreach")

  # {.testKind: tkEdgeCase.}
  test "an address that names no app has no folder":
    var r = h.storeFor(parseAddress("notes").a)
    check not r.ok
    check "names no app" in r.err

  # {.testKind: tkEdgeCase.}
  test "two apps cannot collide on a shared target name":
    var
      a = h.storePath("fjord", "", "accounts")
      b = h.storePath("eris", "", "accounts")
    check a.path != b.path

suite "what cannot become a path":

  setup:
    var h = openHome(scratch("safe"), nrClient).home

  # {.testKind: tkEdgeCase.}
  test "'..' is refused where the path is made":
    var r = h.storePath("fjord", "", "mail/../../etc/passwd")
    check not r.ok
    check "'..'" in r.err

  # {.testKind: tkEdgeCase.}
  test "an absolute target is refused":
    check not h.storePath("fjord", "", "/etc/passwd").ok

  # {.testKind: tkEdgeCase.}
  test "an empty target is refused":
    var r = h.storePath("fjord", "", "")
    check not r.ok
    check "needs a target" in r.err

suite "what an operator is shown":

  # {.testKind: tkEdgeCase.}
  test "the tree, with what is missing marked":
    var
      h = openHome(scratch("described"), nrClient).home
      before = h.describeHome()
    check "-- missing" in before
    check h.ensureHome().ok
    var after = h.describeHome()
    check "-- missing" notin after
    check "no application has stored anything yet" in after
    check h.base in after

  # {.testKind: tkUnit.}
  test "and the apps that have stored something":
    var h = openHome(scratch("described2"), nrClient).home
    check h.ensureHome().ok
    createDir(h.appDir("fjord"))
    createDir(h.appDir("eris", "games"))
    var names = h.appNames()
    check "fjord" in names
    check "eris.games" in names
    check "fjord" in h.describeHome()

  # {.testKind: tkUnit.}
  test "an explicit base says so, and a default says which role":
    var h = openHome(scratch("d3"), nrServer).home
    check "(explicit)" in h.describeHome()
    delEnv(geistHomeEnv)
    var d = openHome("", nrServer).home
    check "a server" in d.describeHome()
