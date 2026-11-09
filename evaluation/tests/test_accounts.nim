## Account tests <- names, device keys, and a login that reveals nothing.

import std/[os, unittest]

import runePragmas
import geist/types
import geist/accounts

proc fresh(name: string): Accounts {.role: helper.} =
  ## name: an empty store.
  var
    dir = getTempDir() / "geist_accounts" / name
  removeDir(dir)
  result = openAccounts(dir).accounts

proc h(v: uint8): seq[uint8] {.role: helper.} =
  ## v: a test login hash.
  result = newSeq[uint8](32)
  result[0] = v

suite "accounts":
  # {.testKind: tkIntegration, covers: "createAccount|accountOfKey|checkAccountLogin".}
  test "an account is made, found by its key, and logs in":
    var
      A = fresh("make")
      c = A.createAccount("alice", h(1), [9'u8], [8'u8], "key1", 5)
    check c.ok and c.id.len == 32
    check A.accountOfKey("key1") == c.id
    var l = A.checkAccountLogin("alice", h(1))
    check l.ok and l.id == c.id and l.settings == @[9'u8] and l.sealedMaster == @[8'u8]
    A.closeAccounts()

  # {.testKind: tkEdgeCase, covers: "createAccount".}
  test "names are checked, taken once, and a key serves one account":
    var A = fresh("names")
    check not A.createAccount("Alice", h(1), [], [], "k", 5).ok
    check not A.createAccount("../x", h(1), [], [], "k", 5).ok
    check not A.createAccount("", h(1), [], [], "k", 5).ok
    check not A.createAccount("alice", [1'u8], [], [], "k", 5).ok
    check A.createAccount("alice", h(1), [], [], "k", 5).ok
    check A.createAccount("alice", h(2), [], [], "k2", 5).err == "that name is taken"
    check not A.createAccount("bob", h(2), [], [], "k", 5).ok
    A.closeAccounts()

  # {.testKind: tkEdgeCase, covers: "checkAccountLogin".}
  test "a wrong password and an unknown name give the same nothing":
    var A = fresh("login")
    check A.createAccount("alice", h(1), [], [], "k", 5).ok
    check A.checkAccountLogin("alice", h(2)) == AccountLogin()
    check A.checkAccountLogin("ghost", h(1)) == AccountLogin()
    A.closeAccounts()

  # {.testKind: tkEdgeCase, covers: "accountIdOf".}
  test "asking for a name that does not exist looks like one that does":
    var
      A = fresh("decoy")
      real = A.createAccount("alice", h(1), [], [], "k", 5).id
    check A.accountIdOf("alice") == real
    check A.accountIdOf("ghost").len == real.len
    check A.accountIdOf("ghost") == A.accountIdOf("ghost")
    check A.accountIdOf("ghost") != A.accountIdOf("other")
    check A.accountOfKey("nothing") == ""
    A.closeAccounts()

  # {.testKind: tkIntegration, covers: "addAccountKey|removeAccountKey".}
  test "a new device logs in and joins; a lost one is removed":
    var
      A = fresh("dev")
      id = A.createAccount("alice", h(1), [], [], "phone", 5).id
    check not A.addAccountKey("alice", h(9), "laptop", 6).ok
    check A.accountOfKey("laptop") == ""
    check A.addAccountKey("alice", h(1), "laptop", 6).ok
    check A.accountOfKey("laptop") == id
    check A.addAccountKey("alice", h(1), "laptop", 6).ok
    check A.removeAccountKey(id, "phone", 7)
    check A.accountOfKey("phone") == ""
    check not A.removeAccountKey(id, "laptop", 7)
    A.closeAccounts()

  # {.testKind: tkEdgeCase, covers: "addAccountKey".}
  test "an account has a limited number of devices":
    var
      A = fresh("many")
      i = 1
    check A.createAccount("alice", h(1), [], [], "k0", 5).ok
    while i < accountMaxDevices:
      check A.addAccountKey("alice", h(1), "k" & $i, 5).ok
      i = i + 1
    check not A.addAccountKey("alice", h(1), "one-more", 5).ok
    A.closeAccounts()

  # {.testKind: tkIntegration, covers: "changeAccountPassword".}
  test "a new password replaces all three parts at once":
    var
      A = fresh("pw")
      id = A.createAccount("alice", h(1), [1'u8], [1'u8], "k", 5).id
    check A.changeAccountPassword(id, h(2), [2'u8], [2'u8], 6)
    check not A.checkAccountLogin("alice", h(1)).ok
    check A.checkAccountLogin("alice", h(2)).sealedMaster == @[2'u8]
    A.closeAccounts()

  # {.testKind: tkRegression, covers: "openAccounts".}
  test "everything comes back after a restart":
    var
      dir = getTempDir() / "geist_accounts" / "back"
    removeDir(dir)
    var
      A = openAccounts(dir).accounts
      id = A.createAccount("alice", h(1), [], [], "k", 5).id
      decoy = A.accountIdOf("ghost")
    check A.addAccountKey("alice", h(1), "k2", 6).ok
    A.closeAccounts()
    A = openAccounts(dir).accounts
    check A.accountOfKey("k2") == id
    check A.accountIdOf("ghost") == decoy
    check A.checkAccountLogin("alice", h(1)).ok
    A.closeAccounts()
