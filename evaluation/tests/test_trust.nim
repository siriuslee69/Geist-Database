## -------------------------------------------------------------------------
## Trust tests <- which notes Geist believes, and what it does with the rest
## -------------------------------------------------------------------------
##
## The signatures are real: Dilithium-65 keys and signatures from Tyr, the same
## library nebel signs with. Nothing here talks to a network; the provider is a
## fake that answers with the bytes it is given.
##
##   suite                                  what it holds down
##   -------------------------------------  -----------------------------------------
##   "the trusted keys file"                good lines are read, bad lines refused
##   "how far a note is trusted"            signed, tampered, unsigned, unknown and
##                                          partly signed notes each get their grade
##   "a payload with a note beside it"      a trusted note is used; an unsigned one
##                                          only when unsafe retrieval is allowed; a
##                                          bad one never; a broken trust file refuses
##   "versions and metadata of a folder"    the program's version and a note of who
##                                          made it, kept with Geist's own lines

import std/[os, strutils, unittest]

import runePragmas
import geist/types
import geist/sidecar
import geist/trust
import geist/folder
import geist/textfile
import geist/crypto/hashwidths
import tyr/signatures

var
  gFakeBytes: ByteSeq = @[]
    ## What the fake provider answers with. A global, so the closure stays gcsafe.

proc fakeProvider(s: SidecarStore, hash: ByteSeq, note: SidecarNote,
    trust: NoteTrust): tuple[ok: bool, data: ByteSeq, err: string] {.
    gcsafe.} =
  {.cast(gcsafe).}:
    result = (true, gFakeBytes, "")

proc fullHash(c: char): ByteSeq {.role: helper.} =
  ## c: one byte repeated to the full digest width, a stand-in for a payload's hash.
  result = newSeq[uint8](fullDigestBytes)
  for i in 0 ..< fullDigestBytes:
    result[i] = uint8(ord(c))

proc bytesOf(s: string): ByteSeq {.role: helper.} =
  ## s: text as the bytes a payload is made of.
  result = cast[ByteSeq](s)

proc freshStore(name: string): SidecarStore {.role: helper.} =
  ## A store with a folder of its own, emptied first.
  var
    root = getTempDir() / name
  removeDir(root)
  createDir(root)
  result = initSidecarStore(root / ".geist-sidecar")

proc keyLine(signer: string, kp: SigKeypair): string {.role: helper.} =
  ## The line a trusted keys file keeps for one signer's Dilithium-65 key.
  result = signer & " dilithium65 " & hexText(kp.public)

proc signedNote(hash: ByteSeq, signer: string, kp: SigKeypair,
    holder: string): string {.role: helper.} =
  ## A note the way nebel writes one: fields, then the signature over the signed text.
  var
    fields = noteFields(hash, @[(key: "signer", value: signer),
      (key: "holder", value: holder)])
    sig = sign(dilithium65, textBytes(noteSignedText(fields)), kp.secret)
  result = renderNote(fields, "dilithium65:" & hexText(sig))

proc parsed(text: string): SidecarNote {.role: helper.} =
  ## The note a text reads as. The tests only parse what they wrote, so a failure
  ## here is a real failure.
  var
    got = parseNote(text)
  doAssert got.ok, got.err
  result = got.note

suite "the trusted keys file":
  # {.testKind: tkUnit.}
  test "good lines are read, and a comment or a blank line is skipped":
    var
      kp = keypair(dilithium65)
      got = parseTrustFile("# who we trust\n\n" & keyLine("phone", kp) & "\n")
    check got.ok
    check got.table.keys.len == 1
    check got.table.keys[0].signer == "phone"
    check got.table.keys[0].publicKey == kp.public

  # {.testKind: tkEdgeCase.}
  test "a line that is not understood is refused, and the error says which":
    check not parseTrustFile("phone rsa4096 00ff\n").ok
    check parseTrustFile("phone rsa4096 00ff\n").err.contains("line 1")
    check not parseTrustFile("phone dilithium65 zz\n").ok
    check not parseTrustFile("phone dilithium65\n").ok
    check loadTrustFile(getTempDir() / "geist_t_trust_none.keys").ok

suite "how far a note is trusted":
  # {.testKind: tkUnit.}
  test "a note signed by a trusted key is signed; the same note with a changed field is bad":
    var
      kp = keypair(dilithium65)
      table = parseTrustFile(keyLine("phone", kp) & "\n").table
      text = signedNote(fullHash('a'), "phone", kp, "nas")
      note = parsed(text)
    check trustOf(note, table) == ntSigned
    note.fields[0].value = "a changed field"
    check trustOf(note, table) == ntBad

  # {.testKind: tkEdgeCase.}
  test "an unsigned note, or one from a signer nobody trusts, is unsigned":
    var
      kp = keypair(dilithium65)
      other = keypair(dilithium65)
      table = parseTrustFile(keyLine("phone", kp) & "\n").table
      unsigned = parsed(renderNote(noteFields(fullHash('h'), @[(key: "signer",
        value: "phone")]), ""))
      stranger = parsed(signedNote(fullHash('h'), "eris", other, "nas"))
    check trustOf(unsigned, table) == ntUnsigned
    check trustOf(stranger, table) == ntUnsigned

  # {.testKind: tkEdgeCase.}
  test "a trusted signer with a missing or unknown part is bad, not unsigned":
    var
      kp = keypair(dilithium65)
      twoKeys = parseTrustFile(keyLine("phone", kp) & "\nphone ed25519 00\n").table
      oneKey = parseTrustFile(keyLine("phone", kp) & "\n").table
      text = signedNote(fullHash('h'), "phone", kp, "nas")
      note = parsed(text)
    check trustOf(note, oneKey) == ntSigned
    check trustOf(note, twoKeys) == ntBad
    var
      wrongAlg = parsed(renderNote(note.fields, "falcon512:00"))
    check trustOf(wrongAlg, oneKey) == ntBad

suite "a payload with a note beside it":
  # {.testKind: tkIntegration.}
  test "a trusted note is used, and the provider is given the note and its grade":
    var
      kp = keypair(dilithium65)
      store = freshStore("geist_t_trust_trusted")
      payload = bytesOf("held by a trusted holder")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(payload)
    store.trust = parseTrustFile(keyLine("phone", kp) & "\n").table
    check store.leaveNote(rf.hash, signedNote(rf.hash, "phone", kp, "nas")).ok
    gFakeBytes = payload
    gSidecarProvider = fakeProvider
    got = store.getSidecar(rf)
    check got.ok
    check got.data == payload
    gSidecarProvider = nil

  # {.testKind: tkEdgeCase.}
  test "an unsigned note is refused unless unsafe retrieval is allowed, and then it is counted":
    var
      store = freshStore("geist_t_trust_unsigned")
      payload = bytesOf("fetched by hash alone")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
      before: uint32 = gUnsafeReads
    rf = store.putSidecar(payload)
    check store.leaveNote(rf.hash, renderNote(noteFields(rf.hash, @[(key: "signer",
      value: "phone")]), "")).ok
    gFakeBytes = payload
    gSidecarProvider = fakeProvider
    store.trustUnsigned = false
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("unsafe retrieval is off")
    store.trustUnsigned = true
    got = store.getSidecar(rf)
    check got.ok
    check got.data == payload
    check gUnsafeReads == before + 1'u32
    gSidecarProvider = nil

  # {.testKind: tkEdgeCase.}
  test "a note whose signature does not verify is refused even when unsafe retrieval is allowed":
    var
      kp = keypair(dilithium65)
      store = freshStore("geist_t_trust_bad")
      payload = bytesOf("the note lies about its holder")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
      text: string = ""
    rf = store.putSidecar(payload)
    store.trust = parseTrustFile(keyLine("phone", kp) & "\n").table
    store.trustUnsigned = true
    var
      signed = noteFields(rf.hash, @[(key: "signer", value: "phone"),
        (key: "holder", value: "nas")])
      sig = sign(dilithium65, textBytes(noteSignedText(signed)), kp.secret)
      forged = renderNote(noteFields(rf.hash, @[(key: "signer", value: "phone"),
        (key: "holder", value: "eris")]), "dilithium65:" & hexText(sig))
    check store.leaveNote(rf.hash, forged).ok
    gFakeBytes = payload
    gSidecarProvider = fakeProvider
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("does not verify")
    gSidecarProvider = nil

  # {.testKind: tkEdgeCase.}
  test "a trusted note with no provider says the payload is held elsewhere":
    var
      kp = keypair(dilithium65)
      store = freshStore("geist_t_trust_noprovider")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(bytesOf("held elsewhere"))
    store.trust = parseTrustFile(keyLine("phone", kp) & "\n").table
    check store.leaveNote(rf.hash, signedNote(rf.hash, "phone", kp, "nas")).ok
    gSidecarProvider = nil
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("held elsewhere")
    check got.err.contains("no provider")

  # {.testKind: tkEdgeCase.}
  test "a trusted keys file that cannot be read refuses every note":
    var
      kp = keypair(dilithium65)
      store = freshStore("geist_t_trust_broken")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(bytesOf("notes cannot be checked"))
    store.trust = parseTrustFile(keyLine("phone", kp) & "\n").table
    store.trustErr = "trusted keys, line 3: unknown algorithm 'rsa4096'"
    check store.leaveNote(rf.hash, signedNote(rf.hash, "phone", kp, "nas")).ok
    gFakeBytes = bytesOf("notes cannot be checked")
    gSidecarProvider = fakeProvider
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("cannot be checked")
    gSidecarProvider = nil

suite "versions and metadata of a folder":
  # {.testKind: tkIntegration.}
  test "a program's version and a note of who made the folder are kept with Geist's lines":
    var
      dir = getTempDir() / "geist_t_trust_folder"
    removeDir(dir)
    check setFolderVersion(dir, "nebel", 1).ok
    check setFolderMeta(dir, "made-by", "nebel").ok
    check folderVersionOf(dir, "nebel").version == 1
    check folderVersionOf(dir, "other").version == 0
    check folderMetaOf(dir, "made-by").found
    check folderMetaOf(dir, "made-by").value == "nebel"
    check setFolderVersion(dir, "nebel", 2).ok
    check folderVersionOf(dir, "nebel").version == 2
    check checkFolder(dir, false).ok

  # {.testKind: tkEdgeCase.}
  test "a version name that is not a plain word is refused, and a changed folder file is not believed":
    var
      dir = getTempDir() / "geist_t_trust_folder_bad"
      version = dir / folderVersionName
    removeDir(dir)
    check setFolderVersion(dir, "nebel", 1).ok
    check not setFolderVersion(dir, "Nebel", 1).ok
    check not setFolderMeta(dir, "two\nlines", "x").ok
    writeFile(version, readFile(version).replace("version.nebel = 1",
      "version.nebel = 9"))
    check not folderVersionOf(dir, "nebel").ok
