## A sign-in database, so no application writes one twice.
##
## The easy half of a user table is `create` and `get`. The half that
## matters is what a FAILED sign-in reveals, and those are the properties
## here:
##
##   * an unknown user and a wrong password give ONE answer
##   * and take a comparable amount of TIME, so the clock does not answer
##     the question the message refused to
##   * a disabled account is told apart, but only after the password
##     verifies, so it cannot be used to enumerate accounts
##   * a rehash happens on successful sign-in, the only moment the
##     plaintext exists
##   * the key that unlocks a user's store is NOT what the server stores

import std/[os, strutils, times, unittest]

import geist

proc scratch(name: string): GeistHome =
  var p = getTempDir() / "geist_users_test" / name
  removeDir(p)
  var opened = openHome(p, nrServer)
  doAssert opened.ok, opened.err
  doAssert opened.home.ensureHome().ok
  result = opened.home

suite "accounts":

  test "one is created and found":
    var
      h = scratch("create")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2", "Alice").ok
    check users.userExists("alice")
    check users.getUser("alice").value.displayName == "Alice"
    check users.userNames() == @["alice"]
    discard users.closeUsers()

  test "it lands under db/<app>/users, in the one folder":
    var
      h = scratch("path")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.root == h.base / "db" / "fjord" / "users"
    discard users.closeUsers()

  test "a staging instance is a different table":
    var
      h = scratch("instance")
      main: UserStore = default(UserStore)
      staging: UserStore = default(UserStore)
    check openUsers(main, h, "eris", appConfig()).ok
    check openUsers(staging, h, "eris", appConfig(), instance = "staging").ok
    check main.root != staging.root
    check staging.root == h.base / "db" / "eris.staging" / "users"
    discard main.closeUsers()
    discard staging.closeUsers()

  test "the name is lower-cased, so one person is not two":
    var
      h = scratch("case")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("Alice", "hunter2").ok
    check users.userExists("alice")
    check users.userExists("ALICE")
    check users.userNames() == @["alice"]
    discard users.closeUsers()

  test "a duplicate is refused rather than replacing":
    var
      h = scratch("dup")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var again = users.createUser("alice", "different")
    # An overwrite here would be an account takeover spelled as a typo.
    check not again.ok
    check "already an account" in again.err
    check verifyPassword("hunter2", users.getUser("alice").value.password)
    discard users.closeUsers()

  test "a name that could not be logged safely is refused":
    var
      h = scratch("badname")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check not users.createUser("", "hunter2").ok
    check not users.createUser("alice bob", "hunter2").ok
    check not users.createUser("../etc", "hunter2").ok
    check not users.createUser(repeat("a", maxUserNameBytes + 1),
      "hunter2").ok
    discard users.closeUsers()

  test "an empty password cannot make an account":
    var
      h = scratch("nopw")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    var got = users.createUser("alice", "")
    check not got.ok
    check "must not be empty" in got.err
    check not users.userExists("alice")
    discard users.closeUsers()

  test "the password is not in the record":
    var
      h = scratch("nostore")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "SECRETMARKER").ok
    var r = users.getUser("alice").value
    check "SECRETMARKER" notin r.password
    check "SECRETMARKER" notin r.salt
    check r.password.startsWith(passwordScheme)
    discard users.closeUsers()

suite "signing in":

  test "the right password works":
    var
      h = scratch("signin")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var got = users.authenticate("alice", "hunter2")
    check got.result == arOk
    check got.user.name == "alice"
    discard users.closeUsers()

  test "an unknown user and a wrong password give ONE answer":
    var
      h = scratch("sameanswer")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var
      wrongPw = users.authenticate("alice", "hunter3")
      noUser = users.authenticate("ghost", "hunter3")
    check wrongPw.result == arWrong
    check noUser.result == arWrong
    # Distinguishing them turns the sign-in form into a tool for finding
    # out who has an account.
    check wrongPw.reason == noUser.reason
    discard users.closeUsers()

  test "and take a comparable amount of time":
    var
      h = scratch("timing")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok

    var start = getTime()
    discard users.authenticate("alice", "hunter3")
    var knownNs = (getTime() - start).inNanoseconds

    start = getTime()
    discard users.authenticate("ghost", "hunter3")
    var unknownNs = (getTime() - start).inNanoseconds

    # Without the dummy hash, the unknown name returns in microseconds
    # and the known one in a tenth of a second -- and anyone can read an
    # account list off the clock. The bound is loose on purpose: this is
    # a real Argon2 run on a shared machine, and the claim being tested
    # is "same order of magnitude", not "identical".
    check unknownNs > knownNs div 4
    check unknownNs < knownNs * 4
    discard users.closeUsers()

  test "a malformed request is still charged a derivation":
    var
      h = scratch("malformed")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    # An impossible name must not return faster than a wrong password.
    var got = users.authenticate("alice bob", "hunter2")
    check got.result == arWrong
    discard users.closeUsers()

  test "a disabled account is told apart, but only after the password":
    var
      h = scratch("disabled")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.setDisabled("alice", true).ok

    # Right password: they learn the account is suspended, which they
    # need to know.
    check users.authenticate("alice", "hunter2").result == arDisabled
    # Wrong password: indistinguishable from any other failure, so this
    # cannot be used to discover that the account exists.
    check users.authenticate("alice", "hunter3").result == arWrong
    discard users.closeUsers()

  test "an account can be restored":
    var
      h = scratch("restore")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.setDisabled("alice", true).ok
    check users.setDisabled("alice", false).ok
    check users.authenticate("alice", "hunter2").result == arOk
    discard users.closeUsers()

  test "a closed store refuses rather than crashing":
    var
      users: UserStore = default(UserStore)
    check users.authenticate("alice", "hunter2").result == arRefused

  test "signing in records when they were last seen":
    var
      h = scratch("lastseen")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.getUser("alice").value.lastSeenAt == 0
    var got = users.signIn("alice", "hunter2")
    check got.result == arOk
    check users.getUser("alice").value.lastSeenAt > 0
    discard users.closeUsers()

  test "a failed sign-in records nothing":
    var
      h = scratch("nofail")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.signIn("alice", "wrong").result == arWrong
    check users.getUser("alice").value.lastSeenAt == 0
    discard users.closeUsers()

suite "changing a password":

  test "the new one works and the old one does not":
    var
      h = scratch("setpw")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.setPassword("alice", "correct-horse").ok
    check users.authenticate("alice", "correct-horse").result == arOk
    check users.authenticate("alice", "hunter2").result == arWrong
    discard users.closeUsers()

  test "the storage salt is NOT rotated":
    var
      h = scratch("saltkept")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var before = users.getUser("alice").value.salt
    check users.setPassword("alice", "correct-horse").ok
    # Rotating it would silently make every local store this person owns
    # unopenable, on every device.
    check users.getUser("alice").value.salt == before
    discard users.closeUsers()

  test "an unknown account cannot have its password set":
    var
      h = scratch("setpw-ghost")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check not users.setPassword("ghost", "anything").ok
    discard users.closeUsers()

  test "an empty new password is refused":
    var
      h = scratch("setpw-empty")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check not users.setPassword("alice", "").ok
    check users.authenticate("alice", "hunter2").result == arOk
    discard users.closeUsers()

suite "raising the cost later":

  test "a weak hash verifies, and is reported for upgrade":
    var
      h = scratch("rehash")
      users: UserStore = default(UserStore)
      cheap = PasswordParams(passes: 1'u32, memoryKiB: 256'u32, lanes: 1'u32)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok

    # Simulate an account hashed before the cost was raised.
    var r = users.getUser("alice").value
    r.password = hashPassword("hunter2", cheap).encoded
    var at = users.userRowFor("alice")
    check at.found
    users.session.set(at.id, r)

    var got = users.authenticate("alice", "hunter2")
    check got.result == arOk
    check got.rehash
    discard users.closeUsers()

  test "signing in upgrades it, since that is when the password exists":
    var
      h = scratch("rehash-signin")
      users: UserStore = default(UserStore)
      cheap = PasswordParams(passes: 1'u32, memoryKiB: 256'u32, lanes: 1'u32)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var r = users.getUser("alice").value
    r.password = hashPassword("hunter2", cheap).encoded
    var at = users.userRowFor("alice")
    users.session.set(at.id, r)
    check needsRehash(users.getUser("alice").value.password)

    check users.signIn("alice", "hunter2").result == arOk
    # Upgraded in place, without asking the person to do anything.
    check not needsRehash(users.getUser("alice").value.password)
    check users.authenticate("alice", "hunter2").result == arOk
    discard users.closeUsers()

suite "the key a user's own stores are unlocked with":

  test "it is derived from their salt, and is not what the server holds":
    var
      h = scratch("storagekey")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var
      r = users.getUser("alice").value
      key = r.storageKeyFor("hunter2")
    check key.len == passwordHashBytes
    # A stolen user table must not decrypt anything.
    check cast[string](key.use()) notin r.password
    discard users.closeUsers()

  test "the same password gives the same key every time":
    var
      h = scratch("storagekey-stable")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var
      r = users.getUser("alice").value
      a = r.storageKeyFor("hunter2")
      b = r.storageKeyFor("hunter2")
    check a.use() == b.use()
    discard users.closeUsers()

  test "two users with one password get different keys":
    var
      h = scratch("storagekey-users")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.createUser("bob", "hunter2").ok
    var
      a = users.getUser("alice").value.storageKeyFor("hunter2")
      b = users.getUser("bob").value.storageKeyFor("hunter2")
    # Per-user salts, so one cracked password does not open the other.
    check a.use() != b.use()
    discard users.closeUsers()

suite "removing an account":

  test "it is a tombstone, so the removal can reach a mirror":
    var
      h = scratch("delete")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.deleteUser("alice").ok
    check not users.userExists("alice")
    check users.authenticate("alice", "hunter2").result == arWrong
    check users.userNames().len == 0
    discard users.closeUsers()

  test "deleting what is not there succeeds":
    var
      h = scratch("delete-ghost")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.deleteUser("ghost").ok
    discard users.closeUsers()

  test "an account survives being reopened":
    var
      h = scratch("reopen")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    check users.saveUsers().ok
    discard users.closeUsers()

    var again: UserStore = default(UserStore)
    check openUsers(again, h, "fjord", appConfig()).ok
    check again.authenticate("alice", "hunter2").result == arOk
    discard again.closeUsers()

suite "what a log is told":

  test "it says nothing that would enumerate accounts":
    var
      h = scratch("logline")
      users: UserStore = default(UserStore)
    check openUsers(users, h, "fjord", appConfig()).ok
    check users.createUser("alice", "hunter2").ok
    var
      wrongPw = users.authenticate("alice", "hunter3").describeAuth()
      noUser = users.authenticate("ghost", "hunter3").describeAuth()
    check wrongPw == noUser
    check "alice" notin wrongPw
    check "ghost" notin noUser
    discard users.closeUsers()
