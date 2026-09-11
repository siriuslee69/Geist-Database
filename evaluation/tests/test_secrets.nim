## The one crypto surface an application gets.
##
## Everything here is a property an application would otherwise have had
## to get right itself, which is the whole reason the module exists:
##
##   * two users with one password do NOT share a hash
##   * the cost is stored IN the hash, so it can be raised later without
##     locking anybody out
##   * a malformed record verifies as false rather than raising
##   * the key that unlocks a store is NOT the value a server stores
##   * a wrong password and a tampered blob give the SAME answer
##
## The costs are lowered in this file. A test suite that spent a tenth of
## a second per hash at the real setting would spend a minute here and
## nobody would run it.

import std/[strutils, unittest]

import geist

proc cheap(): PasswordParams =
  ## The real parameters, divided by enough to keep the suite quick. The
  ## properties under test do not depend on the cost -- only on it being
  ## recorded and honoured.
  result.passes = 1'u32
  result.memoryKiB = 256'u32
  result.lanes = 1'u32

suite "a password becomes a line a database can hold":

  test "the encoding says what made it":
    var got = hashPassword("hunter2", cheap())
    check got.ok
    check got.encoded.startsWith(passwordScheme)
    check "m=256,t=1,p=1" in got.encoded
    # Six fields: geist, argon2id, v=1, params, salt, hash.
    check got.encoded.split('$').len == 6

  test "it verifies":
    var got = hashPassword("hunter2", cheap())
    check verifyPassword("hunter2", got.encoded)
    check not verifyPassword("hunter3", got.encoded)
    check not verifyPassword("", got.encoded)

  test "two users with the same password do not share a hash":
    var
      a = hashPassword("hunter2", cheap())
      b = hashPassword("hunter2", cheap())
    # The salt is generated inside, and cannot be supplied. This is the
    # property that stops one stolen rainbow table opening every account.
    check a.encoded != b.encoded
    check a.salt != b.salt
    check verifyPassword("hunter2", a.encoded)
    check verifyPassword("hunter2", b.encoded)

  test "an empty password is refused rather than hashed":
    var got = hashPassword("", cheap())
    check not got.ok
    check "must not be empty" in got.err
    check got.encoded.len == 0

  test "an absurdly long password is refused before the KDF runs":
    var got = hashPassword(repeat("x", maxPasswordBytes + 1), cheap())
    check not got.ok
    check "refused" in got.err

  test "a long-but-allowed password works":
    var
      long = repeat("correct horse ", 60)
      got = hashPassword(long, cheap())
    check got.ok
    check verifyPassword(long, got.encoded)

suite "a stored hash carries its own cost":

  test "it is parsed back out":
    var
      made = hashPassword("hunter2", cheap())
      back = parsePasswordHash(made.encoded)
    check back.ok
    check back.params.passes == 1'u32
    check back.params.memoryKiB == 256'u32
    check back.params.lanes == 1'u32
    check back.salt == made.salt
    check back.hash == made.hash

  test "a hash made cheaply still verifies when policy is dearer":
    var made = hashPassword("hunter2", cheap())
    # The cost comes from the record, not from today's constants. Reading
    # today's would lock out everybody hashed before the last raise.
    check verifyPassword("hunter2", made.encoded)
    check needsRehash(made.encoded)

  test "a hash at current policy does not need rehashing":
    var made = hashPassword("hunter2")
    check not needsRehash(made.encoded)
    check verifyPassword("hunter2", made.encoded)

  test "an unreadable record needs rehashing":
    check needsRehash("")
    check needsRehash("not-a-hash")

suite "nothing here raises on a bad row":

  test "a malformed record verifies as false":
    check not verifyPassword("hunter2", "")
    check not verifyPassword("hunter2", "nonsense")
    check not verifyPassword("hunter2", "geist$argon2id$v=1$m=1$a$b")
    check not verifyPassword("hunter2",
      "geist$argon2id$v=9$m=256,t=1,p=1$AAAA$AAAA")

  test "a truncated record is refused with a reason":
    var got = parsePasswordHash("geist$argon2id$v=1$m=256,t=1,p=1")
    check not got.ok
    check "not a Geist password hash" in got.err

  test "a zero cost is refused, not treated as a cheap hash":
    # This is the one corrupted shape that must not verify: zeroes would
    # make the derivation instant.
    var got = parsePasswordHash("geist$argon2id$v=1$m=0,t=0,p=0$AAAA$AAAA")
    check not got.ok
    check "unreadable cost" in got.err

  test "a foreign scheme is named rather than guessed at":
    var got = parsePasswordHash("argon2$argon2id$v=1$m=256,t=1,p=1$AA$AA")
    check not got.ok
    check "unknown password scheme" in got.err

  test "salt or hash that is not base64 is refused":
    var got = parsePasswordHash("geist$argon2id$v=1$m=256,t=1,p=1$!!!$!!!")
    check not got.ok

suite "authentication and encryption are not the same derivation":

  test "the storage key is not the stored hash":
    var
      salt = randomSalt()
      key = deriveKey("hunter2", salt, cheap())
      auth = hashPassword("hunter2", cheap())
    # Different domains. A stolen user database must not decrypt anything.
    check key.use() != auth.hash
    check key.len == passwordHashBytes

  test "the same password and salt still derive one key":
    var
      salt = randomSalt()
      a = deriveKey("hunter2", salt, cheap())
      b = deriveKey("hunter2", salt, cheap())
    check a.use() == b.use()

  test "a different salt is a different key":
    var
      a = deriveKey("hunter2", randomSalt(), cheap())
      b = deriveKey("hunter2", randomSalt(), cheap())
    check a.use() != b.use()

suite "sealing something that is not a store":

  test "it round-trips":
    var
      sealed = sealWithPassword("hunter2", cast[seq[uint8]]("a secret"),
        [], cheap())
    check sealed.ok
    var opened = openWithPassword("hunter2", sealed.data, [], cheap())
    check opened.ok
    check cast[string](opened.data) == "a secret"

  test "the plaintext is not in the blob":
    var sealed = sealWithPassword("hunter2",
      cast[seq[uint8]]("MARKER-DO-NOT-FIND"), [], cheap())
    check sealed.ok
    check "MARKER" notin cast[string](sealed.data)

  test "the salt travels with it, so nothing has to be kept beside it":
    var
      first = sealWithPassword("hunter2", cast[seq[uint8]]("x"), [], cheap())
      second = sealWithPassword("hunter2", cast[seq[uint8]]("x"), [], cheap())
    # Two seals of one plaintext under one password differ, because the
    # salt is fresh each time.
    check first.data != second.data
    check openWithPassword("hunter2", first.data, [], cheap()).ok
    check openWithPassword("hunter2", second.data, [], cheap()).ok

  test "a wrong password and a tampered blob give the same answer":
    var
      sealed = sealWithPassword("hunter2", cast[seq[uint8]]("a secret"),
        [], cheap())
      wrongPw = openWithPassword("hunter3", sealed.data, [], cheap())
    var torn = sealed.data
    torn[^1] = torn[^1] xor 0xFF'u8
    var tampered = openWithPassword("hunter2", torn, [], cheap())
    check not wrongPw.ok
    check not tampered.ok
    # Telling them apart would tell an attacker which of the two they
    # achieved.
    check wrongPw.err == tampered.err

  test "context is bound in, so a blob cannot be moved":
    var
      sealed = sealWithPassword("hunter2", cast[seq[uint8]]("alice's"),
        cast[seq[uint8]]("alice"), cheap())
    check sealed.ok
    check openWithPassword("hunter2", sealed.data,
      cast[seq[uint8]]("alice"), cheap()).ok
    # The same blob, claimed to be bob's, does not open.
    check not openWithPassword("hunter2", sealed.data,
      cast[seq[uint8]]("bob"), cheap()).ok

  test "something that is not a blob is refused by its shape":
    check not openWithPassword("hunter2", cast[seq[uint8]]("nope"), [],
      cheap()).ok
    check "not a sealed blob" in
      openWithPassword("hunter2", cast[seq[uint8]]("nope"), [], cheap()).err
    check not openWithPassword("hunter2", @[], [], cheap()).ok

  test "an empty password cannot seal":
    var got = sealWithPassword("", cast[seq[uint8]]("x"), [], cheap())
    check not got.ok

  test "empty plaintext round-trips":
    var sealed = sealWithPassword("hunter2", @[], [], cheap())
    check sealed.ok
    var opened = openWithPassword("hunter2", sealed.data, [], cheap())
    check opened.ok
    check opened.data.len == 0
