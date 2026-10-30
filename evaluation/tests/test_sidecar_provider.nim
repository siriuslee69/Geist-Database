## -------------------------------------------------------------------------
## Provider tests <- a payload with no file here, supplied by a program above Geist
## -------------------------------------------------------------------------
##
## Geist knows nothing about where a payload went. A program leaves a note in its
## place (leaveNote) and may install a provider (gSidecarProvider) that supplies the
## bytes. The grading of the note's signature is tested in test_trust.nim; here the
## stores allow unsigned retrieval, so the provider's part is what is tested.
##
##   suite                                  what it holds down
##   -------------------------------------  -----------------------------------------
##   "a note takes the payload's place"     the payload file goes, the note stays,
##                                          and a payload with no file cannot leave
##                                          a note
##   "a payload with no file here"          the provider is asked, and its bytes are
##                                          checked against the row's hash
##   "the provider is asked only then"      a payload that has a file never asks
##   "a note knows its payload"             the name of a note leads to its payload

import std/[os, strutils, unittest]

import runePragmas
import geist/types
import geist/sidecar
import geist/trust
import geist/textfile
import geist/crypto/hashwidths

proc bytesOf(s: string): ByteSeq {.role: helper.} =
  ## s: text as the bytes a payload is made of.
  result = cast[ByteSeq](s)

proc providerReturning(bytes: ByteSeq): SidecarProvider {.role: helper.} =
  ## bytes: what the fake provider answers with, whatever is asked.
  result = proc (s: SidecarStore, hash: ByteSeq, note: SidecarNote,
      trust: NoteTrust): tuple[ok: bool, data: ByteSeq, err: string] {.closure,
      gcsafe.} =
    result = (true, bytes, "")

proc providerRefusing(why: string): SidecarProvider {.role: helper.} =
  ## why: the reason the fake provider gives for having nothing.
  result = proc (s: SidecarStore, hash: ByteSeq, note: SidecarNote,
      trust: NoteTrust): tuple[ok: bool, data: ByteSeq, err: string] {.closure,
      gcsafe.} =
    result = (false, @[], why)

proc unsignedNote(hash: ByteSeq): string {.role: helper.} =
  ## A note with no signature, as a program may leave when it has nothing to sign.
  result = renderNote(noteFields(hash, @[(key: "signer", value: "phone"),
    (key: "holder", value: "nas")]), "")

proc freshStore(name: string): SidecarStore {.role: helper.} =
  ## A store with a folder of its own, emptied first, that allows unsigned retrieval.
  var
    root = getTempDir() / name
  removeDir(root)
  createDir(root)
  result = initSidecarStore(root / ".geist-sidecar")
  result.trustUnsigned = true

suite "a note takes the payload's place":
  # {.testKind: tkUnit.}
  test "the payload goes, and the note keeps what it said":
    var
      store = freshStore("geist_t_provider_note")
      payload = bytesOf("a payload that leaves for a while")
      rf: Ref = Ref()
      left: tuple[ok: bool, err: string] = (false, "")
      note = unsignedNote(newSeq[uint8](fullDigestBytes))
    rf = store.putSidecar(payload)
    note = unsignedNote(rf.hash)
    left = store.leaveNote(rf.hash, note)
    check left.ok
    check store.storedAt(refLocator(rf)).len == 0
    check store.storedAt(refLocator(rf) & noteSuffix).len > 0
    check readFile(store.storedAt(refLocator(rf) & noteSuffix)) == note

  # {.testKind: tkEdgeCase.}
  test "a note is refused for a payload that is not stored here":
    var
      store = freshStore("geist_t_provider_refuse")
      rf: Ref = Ref()
    rf = store.putSidecar(bytesOf("stored once"))
    check store.leaveNote(rf.hash, unsignedNote(rf.hash)).ok
    check not store.leaveNote(rf.hash, unsignedNote(rf.hash)).ok

suite "a payload with no file here":
  # {.testKind: tkIntegration.}
  test "the provider supplies the bytes, and they must hash to the row":
    var
      store = freshStore("geist_t_provider_read")
      payload = bytesOf("held by a provider, not here")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(payload)
    check store.leaveNote(rf.hash, unsignedNote(rf.hash)).ok
    gSidecarProvider = providerReturning(payload)
    got = store.getSidecar(rf)
    check got.ok
    check got.data == payload
    # A provider that answers with other bytes is refused, whatever it claims.
    gSidecarProvider = providerReturning(bytesOf("something else entirely"))
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("hash verification")
    gSidecarProvider = nil

  # {.testKind: tkEdgeCase.}
  test "without a provider a missing payload says so, and a refusal is passed on":
    var
      store = freshStore("geist_t_provider_none")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(bytesOf("nobody holds this"))
    check store.leaveNote(rf.hash, unsignedNote(rf.hash)).ok
    gSidecarProvider = nil
    got = store.getSidecar(rf)
    check not got.ok
    check got.err.contains("held elsewhere")
    gSidecarProvider = providerRefusing("the holder has no such payload")
    got = store.getSidecar(rf)
    check not got.ok
    check got.err == "the holder has no such payload"
    gSidecarProvider = nil

suite "the provider is asked only then":
  # {.testKind: tkUnit.}
  test "a payload that has a file here is read from it, whatever a provider says":
    var
      store = freshStore("geist_t_provider_local")
      payload = bytesOf("the file is here")
      rf: Ref = Ref()
      got: tuple[ok: bool, data: ByteSeq, err: string] = (false, @[], "")
    rf = store.putSidecar(payload)
    gSidecarProvider = providerReturning(bytesOf("a provider that should not be asked"))
    got = store.getSidecar(rf)
    check got.ok
    check got.data == payload
    gSidecarProvider = nil

suite "a note knows its payload":
  # {.testKind: tkUnit.}
  test "a note's name leads to the payload it belongs to":
    var
      hex: string = repeat("ab", 32)
    check noteOfPayload("ab/ab/" & hex) == "ab/ab/" & hex
    check noteOfPayload("ab/ab/" & hex & ".note") == "ab/ab/" & hex
    check noteOfPayload("ab/ab/" & hex & ".note.tmp") == "ab/ab/" & hex
    check noteOfPayload("ab/ab/" & hex & ".locator") == "ab/ab/" & hex
