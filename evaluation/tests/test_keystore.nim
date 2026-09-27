## Where a key lives, and what happens when the platform cannot hold it.
##
## The file and memory providers are exercised end to end. The Android
## provider is a JNI seam: on a desktop build it must REFUSE rather than
## pretend, and `openKeystore` must fall back and SAY SO -- an app that
## wants to warn "your keys are not in hardware" can only do that if the
## downgrade is a value it can read.

import std/[os, strutils, unittest]

import geist/keystore
import geist/secret

proc scratch(name: string): string =
  result = getTempDir() / "geist_keystore_test" / name
  removeDir(result)
  createDir(result)

proc bytes(s: string): seq[uint8] =
  result = newSeq[uint8](s.len)
  var i = 0
  while i < s.len:
    result[i] = uint8(s[i])
    i = i + 1

proc text(s: Secret): string =
  result = ""
  var i = 0
  while i < s.len:
    result = result & char(s.use()[i])
    i = i + 1

suite "a name that would escape the keystore":

  test "is refused before anything touches the disk":
    check checkName("../../.ssh/id_ed25519").len > 0
    check checkName("a/b").len > 0
    check checkName("a\\b").len > 0
    check checkName("").len > 0

  test "an ordinary name is fine":
    check checkName("master") == ""
    check checkName("account-3.vault") == ""

suite "the memory provider":

  setup:
    var k = openKeystore(scratch("mem"), "", kpMemory)

  test "round-trips":
    check k.put("master", bytes("hunter2")).ok
    var got = k.get("master")
    check got.ok
    check got.status == ksPresent
    check got.value.text() == "hunter2"

  test "an absent name is absent, and says which":
    var got = k.get("nothing")
    check not got.ok
    check got.status == ksAbsent
    check "no key called 'nothing'" in got.err

  test "writes nothing to disk":
    check k.put("master", bytes("hunter2")).ok
    var found = 0
    for kind, path in walkDir(k.dir):
      found = found + 1
    check found == 0

  test "and dropping forgets it":
    check k.put("master", bytes("x")).ok
    check k.drop("master").ok
    check k.status("master") == ksAbsent

suite "the file provider":

  setup:
    var k = openKeystore(scratch("file"), "a-good-password", kpFile)

  test "round-trips through a sealed file":
    check k.put("master", bytes("hunter2")).ok
    check fileExists(k.dir / "master" & keystoreSuffix)
    var got = k.get("master")
    check got.ok
    check got.value.text() == "hunter2"

  test "the file does not contain the secret in the clear":
    check k.put("master", bytes("SECRETMARKER")).ok
    check "SECRETMARKER" notin readFile(k.dir / "master" & keystoreSuffix)

  test "a wrong password fails as PRESENT, not as absent":
    check k.put("master", bytes("hunter2")).ok
    var
      other = openKeystore(k.dir, "the-wrong-password", kpFile)
      got = other.get("master")
    check not got.ok
    check got.status == ksPresent
    check got.err.len > 0

  test "with no password at all it refuses to write":
    var
      bare = openKeystore(scratch("nopass"), "", kpFile)
      r = bare.put("master", bytes("x"))
    check not r.ok
    check "needs a password" in r.err

  test "one entry per file, so dropping one leaves the rest":
    check k.put("a", bytes("1")).ok
    check k.put("b", bytes("2")).ok
    check k.drop("a").ok
    check k.get("a").status == ksAbsent
    check k.get("b").ok

  test "dropping something that was never there is a success":
    check k.drop("never").ok

  test "names lists what is stored":
    check k.put("a", bytes("1")).ok
    check k.put("b", bytes("2")).ok
    var n = k.names()
    check n.len == 2
    check "a" in n
    check "b" in n

  test "a replacement replaces":
    check k.put("a", bytes("first")).ok
    check k.put("a", bytes("second")).ok
    check k.get("a").value.text() == "second"

  test "status does not need the password":
    check k.put("a", bytes("1")).ok
    var blind = openKeystore(k.dir, "", kpFile)
    check blind.status("a") == ksPresent
    check blind.status("b") == ksAbsent

suite "what is too big to be a key":

  test "is refused with the limit named":
    var
      k = openKeystore(scratch("big"), "pw", kpMemory)
      r = k.put("blob", newSeq[uint8](maxSecretBytes + 1))
    check not r.ok
    check "the limit is" in r.err

  test "and an empty secret is refused too":
    var k = openKeystore(scratch("empty"), "pw", kpMemory)
    check not k.put("nothing", @[]).ok

suite "asking for hardware that is not there":

  test "falls back rather than failing to open":
    var k = openKeystore(scratch("droid"), "pw", kpAndroid)
    check k.requested == kpAndroid
    check k.provider == kpFile
    check k.downgraded()
    check "not available on this device" in k.note

  test "and the fallback works":
    var k = openKeystore(scratch("droid2"), "pw", kpAndroid)
    check k.put("master", bytes("hunter2")).ok
    check k.get("master").value.text() == "hunter2"

  test "a keystore that got what it asked for is not downgraded":
    var k = openKeystore(scratch("plain"), "pw", kpFile)
    check not k.downgraded()

  test "the Android provider refuses outright when selected by hand":
    # openKeystore would have downgraded it; this is the provider itself,
    # which must never pretend to have stored something it did not.
    var k = openKeystore(scratch("forced"), "pw", kpFile)
    k.provider = kpAndroid
    var r = k.put("master", bytes("x"))
    check not r.ok
    check "no Android Keystore" in r.err
    check k.get("master").status == ksUnavailable

suite "what a person is told":

  test "every provider describes itself":
    check "file" in describeProvider(kpFile)
    check "hardware" in describeProvider(kpAndroid)
    check "nothing is saved" in describeProvider(kpMemory)

  test "an invalidated key says it cannot be recovered":
    check "again" in describeStatus(ksInvalidated)
    check "unreadable" in describeStatus(ksInvalidated)

  test "an unavailable one says to retry":
    check "try again" in describeStatus(ksUnavailable)
