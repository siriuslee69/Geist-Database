## One folder per machine.
##
## The property under test is that the path on disk and the address on the
## wire are the same shape: a store reached as
## `geist://fjord/mail/alice/inbox` lives at `db/fjord/mail/alice/inbox`,
## so an operator holding one can find the other without a lookup table.
##
## And that `..` cannot get through, because this is the function that
## turns an address into a filesystem path.

import std/[os, strutils, unittest]

import geist/address
import geist/layout

proc scratch(name: string): string =
  result = getTempDir() / "geist_layout_test" / name
  removeDir(result)

suite "where the folder is":

  test "an explicit base wins and is marked explicit":
    var h = openHome("/tmp/somewhere", nrClient)
    check h.ok
    check h.home.base == "/tmp/somewhere"
    check h.home.explicit

  test "a relative base is made absolute, so a chdir cannot move a store":
    var h = openHome("relative/place", nrClient)
    check h.ok
    check h.home.base.isAbsolute()

  test "the environment is used when nothing was passed":
    putEnv(geistHomeEnv, "/tmp/from-the-env")
    var h = openHome("", nrClient)
    check h.ok
    check h.home.base == "/tmp/from-the-env"
    check h.home.explicit
    delEnv(geistHomeEnv)

  test "and the platform default when neither was":
    delEnv(geistHomeEnv)
    var h = openHome("", nrClient)
    check h.ok
    check not h.home.explicit
    check h.home.base.len > 0

  test "a server and a client default to different places":
    delEnv(geistHomeEnv)
    check defaultHomeFor(nrServer) != defaultHomeFor(nrClient)
    when not defined(windows) and not defined(android):
      check defaultHomeFor(nrServer) == "/var/lib/geist"

  test "opening creates nothing":
    var p = scratch("untouched")
    discard openHome(p, nrClient)
    check not dirExists(p)

suite "the six subdirectories":

  setup:
    var
      p = scratch("tree")
      h = openHome(p, nrClient).home

  test "are all under the one base":
    check h.configDir() == p / "config"
    check h.keysDir() == p / "keys"
    check h.keystoreDir() == p / "keys" / "keystore"
    check h.peersDir() == p / "peers"
    check h.dbDir() == p / "db"
    check h.spoolDir() == p / "spool"
    check h.logDir() == p / "logs"

  test "and ensureHome makes them":
    check h.ensureHome().ok
    check dirExists(h.configDir())
    check dirExists(h.keysDir())
    check dirExists(h.keystoreDir())
    check dirExists(h.peersDir())
    check dirExists(h.dbDir())
    check dirExists(h.spoolDir())
    check dirExists(h.logDir())

  test "but not the app directories: db/ lists what is actually here":
    check h.ensureHome().ok
    check h.appNames().len == 0

  test "ensureHome twice is fine":
    check h.ensureHome().ok
    check h.ensureHome().ok

suite "named files":

  setup:
    var h = openHome(scratch("named"), nrClient).home

  test "a config gets .toml when the caller did not write it":
    check h.configPath("fjord").endsWith("config/fjord.toml")
    check h.configPath("fjord.toml").endsWith("config/fjord.toml")

  test "and json is left alone":
    check h.configPath("export.json").endsWith("config/export.json")

  test "an identity and a pin land in their own folders":
    check h.identityPath("vps-1").endsWith("keys/vps-1.id")
    check h.pinPath("vps-2").endsWith("peers/vps-2.pin")

suite "the path is the address":

  setup:
    var h = openHome(scratch("paths"), nrClient).home

  test "a target becomes the same shape underneath db/":
    var r = h.storePath("fjord", "", "mail/alice/inbox")
    check r.ok
    check r.path.endsWith("db/fjord/mail/alice/inbox")

  test "an instance sits beside its app rather than under it":
    var r = h.storePath("fjord", "staging", "accounts")
    check r.ok
    check r.path.endsWith("db/fjord.staging/accounts")

  test "a whole address is taken apart rather than refused":
    var r = h.storePath("fjord", "", "geist://fjord/mail/alice/inbox")
    check r.ok
    check r.path.endsWith("db/fjord/mail/alice/inbox")

  test "storeFor reads the app out of the address itself":
    var
      a = parseAddress("geist://eris.games/games/alderreach").a
      r = h.storeFor(a)
    check r.ok
    check r.path.endsWith("db/eris.games/games/alderreach")

  test "an address that names no app has no folder":
    var r = h.storeFor(parseAddress("notes").a)
    check not r.ok
    check "names no app" in r.err

  test "two apps cannot collide on a shared target name":
    var
      a = h.storePath("fjord", "", "accounts")
      b = h.storePath("eris", "", "accounts")
    check a.path != b.path

suite "what cannot become a path":

  setup:
    var h = openHome(scratch("safe"), nrClient).home

  test "'..' is refused where the path is made":
    var r = h.storePath("fjord", "", "mail/../../etc/passwd")
    check not r.ok
    check "'..'" in r.err

  test "an absolute target is refused":
    check not h.storePath("fjord", "", "/etc/passwd").ok

  test "an empty target is refused":
    var r = h.storePath("fjord", "", "")
    check not r.ok
    check "needs a target" in r.err

suite "what an operator is shown":

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

  test "and the apps that have stored something":
    var h = openHome(scratch("described2"), nrClient).home
    check h.ensureHome().ok
    createDir(h.appDir("fjord"))
    createDir(h.appDir("eris", "games"))
    var names = h.appNames()
    check "fjord" in names
    check "eris.games" in names
    check "fjord" in h.describeHome()

  test "an explicit base says so, and a default says which role":
    var h = openHome(scratch("d3"), nrServer).home
    check "(explicit)" in h.describeHome()
    delEnv(geistHomeEnv)
    var d = openHome("", nrServer).home
    check "a server" in d.describeHome()
