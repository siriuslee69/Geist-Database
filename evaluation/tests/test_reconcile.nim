## The misspelt friend: what a hand-edited settings table does when the
## names in it stop matching the names the server knows.
##
## The rule under test is that NOTHING IS DELETED. A person typed `alcie`
## and meant `alice`; the entry they typed stays exactly where it is, the
## friend they meant gets an entry of their own, and the report says which
## is which.

import std/[os, strutils, tables, unittest]

import geist/doc
import geist/reconcile

type
  FriendRule = object
    notify*: bool
    blocked*: bool
    nickname*: string

  Cfg = object
    account*: string
    friend*: OrderedTable[string, FriendRule]

proc defaultRule(): FriendRule =
  result.notify = true

proc withFriends(names: varargs[string]): OrderedTable[string, FriendRule] =
  result = initOrderedTable[string, FriendRule]()
  for n in names:
    result[n] = defaultRule()

suite "a name the roster knows":

  test "is matched and left alone":
    var t = withFriends("alice", "bob")
    t["alice"].nickname = "Al"
    var r = t.reconcile(@["alice", "bob"], defaultRule())
    check r.matched == @["alice", "bob"]
    check r.added.len == 0
    check r.orphan.len == 0
    check t["alice"].nickname == "Al"

  test "keeps the settings the file gave it":
    var t = withFriends("alice")
    t["alice"].notify = false
    t["alice"].blocked = true
    discard t.reconcile(@["alice"], defaultRule())
    check not t["alice"].notify
    check t["alice"].blocked

suite "a roster name with no entry":

  test "gets one, with every option at its default":
    var
      t = withFriends("alice")
      r = t.reconcile(@["alice", "bob"], defaultRule())
    check r.added == @["bob"]
    check t.hasKey("bob")
    check t["bob"].notify
    check not t["bob"].blocked
    check t["bob"].nickname == ""

  test "is appended, so the file only ever grows downward":
    var t = withFriends("zoe", "alice")
    discard t.reconcile(@["alice", "bob", "zoe"], defaultRule())
    check t.rosterOf() == @["zoe", "alice", "bob"]

  test "and reconciling twice adds nothing the second time":
    var t = withFriends("alice")
    discard t.reconcile(@["alice", "bob"], defaultRule())
    var r = t.reconcile(@["alice", "bob"], defaultRule())
    check r.added.len == 0
    check not r.changed()

suite "a name the roster does not know":

  test "is an orphan: kept, never deleted":
    var t = withFriends("alice", "alcie")
    t["alcie"].blocked = true
    var r = t.reconcile(@["alice"], defaultRule())
    check r.orphan.len == 1
    check r.orphan[0].name == "alcie"
    check t.hasKey("alcie")
    check t["alcie"].blocked

  test "and the name that was meant is added beside it":
    var
      t = withFriends("alcie")
      r = t.reconcile(@["alice"], defaultRule())
    check r.added == @["alice"]
    check t.hasKey("alcie")
    check t.hasKey("alice")
    check t.len == 2

  test "is never applied":
    var t = withFriends("alice", "alcie")
    t["alcie"].blocked = true
    discard t.reconcile(@["alice"], defaultRule())
    var live = t.applied(@["alice"])
    check live.len == 1
    check not live.hasKey("alcie")

  test "and the report says what was probably meant":
    var
      t = withFriends("alcie")
      r = t.reconcile(@["alice", "bob"], defaultRule())
    check r.orphan[0].nearest == "alice"
    check "did you mean alice?" in r.describe("friend")

  test "with no suggestion when nothing is close":
    var
      t = withFriends("qqqqqqqq")
      r = t.reconcile(@["alice", "bob"], defaultRule())
    check r.orphan[0].nearest == ""
    check "did you mean" notin r.describe("friend")

  test "and none at all for a name too short to guess at":
    check suggest("ab", @["ac", "ad"]) == ""

suite "reading one entry":

  test "an absent name is the defaults, and inserts nothing":
    var t = withFriends("alice")
    check t.settingsFor("nobody", defaultRule()).notify
    check t.len == 1

  test "a present name is what the file said":
    var t = withFriends("alice")
    t["alice"].notify = false
    check not t.settingsFor("alice", defaultRule()).notify

suite "a roster arriving in a different order every sync":

  test "is sorted once, so the file stops reshuffling":
    check sortedRoster(@["zoe", "alice", "bob"]) == @["alice", "bob", "zoe"]
    check sortedRoster(@["bob", "alice", "bob"]) == @["alice", "bob"]

suite "the whole path: file, edit, reconcile, save":

  test "a typo survives a full round trip and is reported":
    var p = getTempDir() / "geist_reconcile_test" / "userconfig.toml"
    createDir(p.parentDir())
    removeFile(p)
    # what a person wrote by hand, with one name misspelt
    writeFile(p, """
account = "me"

[friend.alice]
notify = false

[friend.alcie]
blocked = true
nickname = "typo"
""")
    var fallback: Cfg = default(Cfg)
    fallback.account = ""
    fallback.friend = initOrderedTable[string, FriendRule]()
    var loaded = readDoc(p, fallback)
    check loaded.report.ok
    check loaded.value.friend.len == 2

    # the server says who really exists
    var
      cfg = loaded.value
      report = cfg.friend.reconcile(@["alice", "bob"], defaultRule())
    check report.matched == @["alice"]
    check report.added == @["bob"]
    check report.orphan[0].name == "alcie"

    check writeDoc(p, cfg, defaultDocStyle(), loaded.node).ok
    var text = readFile(p)
    check "[friend.alice]" in text
    check "[friend.alcie]" in text     # the typo is still there
    check "[friend.bob]" in text       # and the real friend was added
    check "nickname = \"typo\"" in text

    # and the second pass changes nothing
    var again = readDoc(p, fallback)
    check again.value.friend.len == 3
    check not again.value.friend.reconcile(@["alice", "bob"],
      defaultRule()).changed()
