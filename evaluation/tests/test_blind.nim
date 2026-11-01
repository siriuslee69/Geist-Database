## -------------------------------------------------------------------------
## Blind store tests <- sealed entries kept for one owner, read back only by that owner
## -------------------------------------------------------------------------
##
## The signatures are real: Dilithium keys and signatures from Tyr. The "blobs" are
## plain bytes standing in for data the owner sealed; Geist never reads them, so
## their content does not matter. Every refusal of docs/BLIND_STORE.md sections 5
## and 6 has a test that names it.
##
##   suite                              what it holds down
##   ---------------------------------  ------------------------------------------
##   "making and opening a store"       one owner file, bad owners refused, reopen
##   "handing in an entry"              stamp, store, kind, hash, chain, read-only
##   "asking for entries back"          stamp, kind, clock window, ranges, budget
##   "limits"                           hard refuses and writes nothing, soft warns
##   "two clocks"                       receivedAt never goes back, far sentAt warns

import std/[os, strutils, unittest]

import runePragmas
import geist/types
import geist/trust
import geist/textfile
import geist/blind
import tyr/signatures

proc bytesOf(s: string): ByteSeq {.role: helper.} =
  ## s: text as the bytes of a blob.
  result = cast[ByteSeq](s)

proc scratch(name: string): string {.role: helper.} =
  ## name: an emptied folder of its own below the temp folder.
  result = getTempDir() / "geist_blind_test" / name
  removeDir(result)

proc ownerOf(kp: SigKeypair): BlindOwner {.role: helper.} =
  ## kp: one Dilithium-65 key pair -> an owner named alice with its public key.
  result = BlindOwner(signer: "alice", keys: @[TrustedKey(signer: "alice",
    algorithm: "dilithium65", publicKey: kp.public)])

proc sealWith(fields: Fields, kp: SigKeypair): string {.role: helper.} =
  ## fields/kp: a signed text the way the owner's program makes one (one key).
  var
    sig: ByteSeq = sign(dilithium65, textBytes(noteSignedText(fields)), kp.secret)
  result = renderNote(fields, "dilithium65:" & hexText(sig))

proc labelFor(S: BlindStore, blob: ByteSeq, kp: SigKeypair, prev: string,
    sentAt: int64 = 1000): string {.role: helper.} =
  ## S/blob/kp/prev/sentAt: the signed label for a blob.
  result = sealWith(entryFields(S.id, "alice", blob, prev, sentAt), kp)

proc askFor(S: BlindStore, kp: SigKeypair, since: int64 = 0, until: int64 = 0,
    limit: int = 100, asked: int64 = 5000): string {.role: helper.} =
  ## S/kp/...: the signed request for entries.
  result = sealWith(fetchFields(S.id, "alice", since, until, limit, asked), kp)

proc put(S: var BlindStore, text: string, kp: SigKeypair, at: int64,
    sentAt: int64 = 1000): BlindResult {.role: helper.} =
  ## S/text/kp/at: signs a label for `text` after the current head and appends it,
  ## with our clock at `at`.
  var
    blob: ByteSeq = bytesOf(text)
  result = S.append(labelFor(S, blob, kp, S.head, sentAt), blob, at)

suite "making and opening a store":
  # {.testKind: tkUnit.}
  test "a store is made, found again, and keeps its owner":
    var
      dir: string = scratch("make")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check S.id.len == 64
    check fileExists(ownerPath(dir, "alice-main"))
    S.closeBlind()
    check T.openBlind(dir, "alice-main").ok
    check T.id == S.id
    check T.head == zeroHead
    T.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a second createBlind of the same name is refused":
    var
      dir: string = scratch("again")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    r = T.createBlind(dir, "alice-main", ownerOf(kp))
    check not r.ok
    check "already" in r.err
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "an owner with no key, or a key of an unknown algorithm, is refused":
    var
      dir: string = scratch("badowner")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      o: BlindOwner = ownerOf(kp)
    check not S.createBlind(dir, "a", BlindOwner(signer: "alice")).ok
    o.keys[0].algorithm = "rot13"
    check not S.createBlind(dir, "b", o).ok
    check not fileExists(ownerPath(dir, "a"))
    check not fileExists(ownerPath(dir, "b"))

  # {.testKind: tkEdgeCase.}
  test "opening a name with no owner file says to make it":
    var
      S: BlindStore = default(BlindStore)
      r: BlindResult = S.openBlind(scratch("none"), "ghost")
    check not r.ok
    check "createBlind" in r.err

  # {.testKind: tkEdgeCase.}
  test "a damaged owner file is refused":
    var
      dir: string = scratch("damaged")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    S.closeBlind()
    writeFile(ownerPath(dir, "alice-main"),
      readFile(ownerPath(dir, "alice-main")).replace("alice", "mallory"))
    check not T.openBlind(dir, "alice-main").ok

suite "handing in an entry":
  # {.testKind: tkUnit.}
  test "a signed entry is kept, and the next one follows it":
    var
      dir: string = scratch("append")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      a: BlindResult = default(BlindResult)
      b: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    a = put(S, "first sealed thing", kp, 2000)
    b = put(S, "second sealed thing", kp, 2001)
    check a.ok and b.ok
    check a.seqNo == 0 and b.seqNo == 1
    check S.entryCount == 2
    check S.head != zeroHead
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a label signed by someone else is refused and nothing is written":
    var
      dir: string = scratch("stranger")
      kp: SigKeypair = keypair(dilithium65)
      other: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    r = put(S, "forged", other, 2000)
    check not r.ok
    check "owner" in r.err
    check S.entryCount == 0
    check S.head == zeroHead
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a blob that is not the one the label names is refused":
    var
      dir: string = scratch("swapped")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    r = S.append(labelFor(S, bytesOf("the real one"), kp, S.head),
      bytesOf("a swapped one"), 2000)
    check not r.ok
    check "hash" in r.err
    check S.entryCount == 0
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a label made for another store is refused":
    var
      dir: string = scratch("otherstore")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("sealed")
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "one", ownerOf(kp)).ok
    check T.createBlind(dir, "two", ownerOf(kp)).ok
    r = T.append(labelFor(S, blob, kp, zeroHead), blob, 2000)
    check not r.ok
    check "this store" in r.err
    S.closeBlind()
    T.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a request cannot be handed in as an entry, even one that carries a hash":
    var
      dir: string = scratch("kindswap")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("x")
      f: Fields = default(Fields)
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    # a plain request has no hash, so it is unreadable as an entry
    check not S.append(askFor(S, kp), blob, 2000).ok
    # a correctly signed text with a hash, but of kind fetch, is stopped by the kind
    f = entryFields(S.id, "alice", blob, zeroHead, 1000)
    for kv in f.mitems:
      if kv.key == "kind":
        kv.value = kindFetch
    r = S.append(sealWith(f, kp), blob, 2000)
    check not r.ok
    check "not entry text" in r.err
    check S.entryCount == 0
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "an entry that does not follow the head is refused as stale":
    var
      dir: string = scratch("stale")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("late")
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "first", kp, 2000).ok
    r = S.append(labelFor(S, blob, kp, zeroHead), blob, 2001)
    check not r.ok
    check "stale head" in r.err
    check S.entryCount == 1
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "with two owner keys, one signature is not enough":
    var
      dir: string = scratch("hybrid")
      kp65: SigKeypair = keypair(dilithium65)
      kp44: SigKeypair = keypair(dilithium44)
      o: BlindOwner = ownerOf(kp65)
      S: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("sealed")
      f: Fields = default(Fields)
      sig65: ByteSeq = @[]
      sig44: ByteSeq = @[]
    o.keys.add TrustedKey(signer: "alice", algorithm: "dilithium44", publicKey: kp44.public)
    check S.createBlind(dir, "alice-main", o).ok
    f = entryFields(S.id, "alice", blob, zeroHead, 1000)
    sig65 = sign(dilithium65, textBytes(noteSignedText(f)), kp65.secret)
    sig44 = sign(dilithium44, textBytes(noteSignedText(f)), kp44.secret)
    check not S.append(renderNote(f, "dilithium65:" & hexText(sig65)), blob, 2000).ok
    check S.append(renderNote(f, "dilithium65:" & hexText(sig65) & ",dilithium44:" &
      hexText(sig44)), blob, 2000).ok
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a store opened read-only refuses to append":
    var
      dir: string = scratch("readonly")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("x")
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    S.closeBlind()
    check T.openBlind(dir, "alice-main", readOnly = true).ok
    check not T.append(labelFor(T, blob, kp, T.head), blob, 2000).ok
    T.closeBlind()

  # {.testKind: tkIntegration.}
  test "after a reopen the head, the counters and the chain carry on":
    var
      dir: string = scratch("reopen")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      T: BlindStore = default(BlindStore)
      head: string = ""
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "one", kp, 2000).ok
    check put(S, "two", kp, 2001).ok
    head = S.head
    S.closeBlind()
    check T.openBlind(dir, "alice-main").ok
    check T.head == head
    check T.entryCount == 2
    check T.nextSeq == 2
    check put(T, "three", kp, 2002).seqNo == 2
    T.closeBlind()

suite "asking for entries back":
  # {.testKind: tkIntegration.}
  test "the owner gets the labels and blobs back, unchanged and in order":
    var
      dir: string = scratch("fetch")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "alpha", kp, 2000).ok
    check put(S, "beta", kp, 2001).ok
    F = S.fetch(askFor(S, kp), now = 5000)
    check F.ok
    check F.entries.len == 2
    check F.entries[0].blob == bytesOf("alpha")
    check F.entries[1].blob == bytesOf("beta")
    check F.entries[0].seqNo == 0 and F.entries[1].seqNo == 1
    check parseNote(F.entries[1].note).ok
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a request signed by someone else gets the same refusal as a wrong store":
    var
      dir: string = scratch("fetchstranger")
      kp: SigKeypair = keypair(dilithium65)
      other: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "secret-ish", kp, 2000).ok
    F = S.fetch(askFor(S, other), now = 5000)
    check not F.ok
    check F.entries.len == 0
    check "owner" in F.err
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a label cannot be used as a request":
    var
      dir: string = scratch("fetchkind")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      blob: ByteSeq = bytesOf("x")
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    F = S.fetch(labelFor(S, blob, kp, zeroHead), now = 5000)
    check not F.ok
    check "not fetch text" in F.err
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a request outside the clock window is refused and says by how much":
    var
      dir: string = scratch("window")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    F = S.fetch(askFor(S, kp, asked = 5000), now = 5000 + fetchWindowMs + 1000)
    check not F.ok
    check "301 s" in F.err
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "since, until and limit pick the range":
    var
      dir: string = scratch("range")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "a", kp, 2000).ok
    check put(S, "b", kp, 3000).ok
    check put(S, "c", kp, 4000).ok
    F = S.fetch(askFor(S, kp, since = 3000), now = 5000)
    check F.entries.len == 2 and F.entries[0].blob == bytesOf("b")
    F = S.fetch(askFor(S, kp, since = 3000, until = 4000), now = 5000)
    check F.entries.len == 1 and F.entries[0].blob == bytesOf("b")
    F = S.fetch(askFor(S, kp, limit = 1), now = 5000)
    check F.entries.len == 1 and F.entries[0].blob == bytesOf("a")
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a byte budget stops after the first entry that reaches it, and the first always comes":
    var
      dir: string = scratch("budget")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    check put(S, "0123456789", kp, 2000).ok
    check put(S, "0123456789", kp, 2001).ok
    F = S.fetch(askFor(S, kp), byteBudget = 1, now = 5000)
    check F.ok and F.entries.len == 1
    S.closeBlind()

  # {.testKind: tkRegression.}
  test "a blob file that went missing makes the fetch fail loudly, not return less":
    var
      dir: string = scratch("missing")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      F: FetchResult = default(FetchResult)
      r: BlindResult = default(BlindResult)
      f: string = ""
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    r = put(S, "will vanish", kp, 2000)
    check r.ok
    for p in walkDirRec(dir / "alice-main.blobs"):
      f = p
    check f.len > 0
    removeFile(f)
    F = S.fetch(askFor(S, kp), now = 5000)
    check not F.ok
    check F.entries.len == 0
    S.closeBlind()

suite "limits":
  # {.testKind: tkEdgeCase.}
  test "a blob over the hard limit is refused and leaves no file":
    var
      dir: string = scratch("hardblob")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      L: BlindLimits = defaultBlindLimits()
      r: BlindResult = default(BlindResult)
    L.maxBlobBytes = 10
    check S.createBlind(dir, "alice-main", ownerOf(kp), L).ok
    r = put(S, "this is more than ten bytes", kp, 2000)
    check not r.ok
    check "maxBlobBytes" in r.err
    check S.entryCount == 0
    check not dirExists(dir / "alice-main.blobs")
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a store that would pass its hard size is refused":
    var
      dir: string = scratch("hardstore")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      L: BlindLimits = defaultBlindLimits()
    L.maxStoreBytes = 12
    check S.createBlind(dir, "alice-main", ownerOf(kp), L).ok
    check put(S, "123456", kp, 2000).ok
    check put(S, "123456", kp, 2001).ok
    check not put(S, "1", kp, 2002).ok
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "past a soft limit the entry is kept and a warning says so, every time":
    var
      dir: string = scratch("soft")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      L: BlindLimits = defaultBlindLimits()
      a: BlindResult = default(BlindResult)
      b: BlindResult = default(BlindResult)
    L.warnStoreBytes = 10
    check S.createBlind(dir, "alice-main", ownerOf(kp), L).ok
    a = put(S, "0123456789ab", kp, 2000)
    b = put(S, "0123456789ab", kp, 2001)
    check a.ok and b.ok
    check a.warnings.len == 1 and b.warnings.len == 1
    check "warnStoreBytes" in a.warnings[0]
    check S.entryCount == 2
    S.closeBlind()

suite "two clocks":
  # {.testKind: tkEdgeCase.}
  test "receivedAt never goes back when our clock does":
    var
      dir: string = scratch("clock")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      a: BlindResult = default(BlindResult)
      b: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    a = put(S, "one", kp, 9000)
    b = put(S, "two", kp, 100)
    check a.receivedAt == 9000
    check b.receivedAt == 9000
    S.closeBlind()

  # {.testKind: tkEdgeCase.}
  test "a sentAt far from our clock is kept with a warning":
    var
      dir: string = scratch("skew")
      kp: SigKeypair = keypair(dilithium65)
      S: BlindStore = default(BlindStore)
      r: BlindResult = default(BlindResult)
    check S.createBlind(dir, "alice-main", ownerOf(kp)).ok
    r = put(S, "far", kp, 2_000_000, sentAt = 1000)
    check r.ok
    check r.warnings.len == 1
    check "sentAt" in r.warnings[0]
    S.closeBlind()
