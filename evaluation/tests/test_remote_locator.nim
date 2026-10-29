## -------------------------------------------------------------------------
## Remote locator tests <- a payload another machine holds, read through a hook
## -------------------------------------------------------------------------
##
## Geist never talks to the network. A remote locator names a holder, and the
## hook (gRemoteFetch, installed by nebel) fetches the bytes. These tests use a
## fake hook, so what they hold down is the storage half's share of the job:
##
##   suite                                 what it holds down
##   ------------------------------------  -----------------------------------------
##   "a remote locator"                    holder, signer and signature survive a
##                                         round trip; the signed text leaves them out
##   "a payload held elsewhere"            read through the hook, checked against the
##                                         row's hash whatever the hook returned
##   "dropping a local payload"            only once a locator names it

import std/[os, strutils, unittest]

import runePragmas
import geist/types
import geist/sidecar
import geist/crypto/hashwidths
import geist/crypto/hashing

proc bytesOf(s: string): ByteSeq {.role: helper.} =
  ## s: text as the bytes a payload is made of.
  result = cast[ByteSeq](s)

proc holderReturning(bytes: ByteSeq): RemoteFetch {.role: helper.} =
  ## bytes: what the fake holder answers with, whatever is asked.
  result = proc (loc: SidecarLocator): tuple[ok: bool, data: ByteSeq,
      err: string] {.closure, gcsafe.} =
    result = (true, bytes, "")

proc remoteLocatorFor(hash: ByteSeq): SidecarLocator {.role: helper.} =
  ## hash: the row's hash. A locator that says the payload is held by "nas".
  result = SidecarLocator(kind: remoteKind, hash: hash, size: 5, name: "held",
    target: "dac://10.0.0.5:47655", peer: "nas", signer: "phone",
    sig: "aa11,bb22")

suite "a remote locator":
  # {.testKind: tkUnit.}
  test "holder, signer and signatures survive a round trip":
    var
      hash = newSeq[uint8](fullDigestBytes)
      loc = remoteLocatorFor(hash)
      back = parseLocator(locatorText(loc))
    check back.ok
    check back.loc.kind == remoteKind
    check back.loc.target == loc.target
    check back.loc.peer == "nas"
    check back.loc.signer == "phone"
    check back.loc.sig == "aa11,bb22"

  # {.testKind: tkUnit.}
  test "the signed text covers every field but the signature":
    var
      loc = remoteLocatorFor(newSeq[uint8](fullDigestBytes))
      signed = locatorSigned(loc)
    check signed.contains("signer = phone")
    check signed.contains("peer = nas")
    check not signed.contains("sig = ")
    # Changing the holder changes what was signed, so the signature stops matching.
    loc.peer = "eris"
    check locatorSigned(loc) != signed

suite "a payload held elsewhere":
  # {.testKind: tkIntegration.}
  test "a payload is read through the hook, and the bytes must hash to the row":
    var
      root = getTempDir() / "geist_t_remote_read"
      payload = bytesOf("held on the nas, not here")
      store: SidecarStore = SidecarStore()
      rf: Ref = Ref()
    removeDir(root)
    createDir(root)
    store = initSidecarStore(root / ".geist-sidecar")
    rf = store.putSidecar(payload)
    # Replace the local payload with a remote locator that names it.
    check putLocator(store, remoteLocatorFor(rf.hash)).ok
    check dropSidecar(store, rf.hash).ok
    gRemoteFetch = holderReturning(payload)
    check store.getSidecar(rf).ok
    check store.getSidecar(rf).data == payload
    # A holder that answers with other bytes is refused, whatever it claims.
    gRemoteFetch = holderReturning(bytesOf("something else entirely"))
    var refused = store.getSidecar(rf)
    check not refused.ok
    check refused.err.contains("hash verification")
    gRemoteFetch = nil

  # {.testKind: tkEdgeCase.}
  test "without a hook a remote payload is named, not read":
    var
      root = getTempDir() / "geist_t_remote_nohook"
      payload = bytesOf("held elsewhere")
      store: SidecarStore = SidecarStore()
      rf: Ref = Ref()
    removeDir(root)
    createDir(root)
    store = initSidecarStore(root / ".geist-sidecar")
    rf = store.putSidecar(payload)
    check putLocator(store, remoteLocatorFor(rf.hash)).ok
    check dropSidecar(store, rf.hash).ok
    gRemoteFetch = nil
    var named = store.getSidecar(rf)
    check not named.ok
    check named.err.contains("needs nebel")
    check named.err.contains("dac://10.0.0.5:47655")

suite "dropping a local payload":
  # {.testKind: tkEdgeCase.}
  test "a payload no locator names is kept; once one names it, the payload goes":
    var
      root = getTempDir() / "geist_t_remote_drop"
      payload = bytesOf("kept until a locator names it")
      store: SidecarStore = SidecarStore()
      rf: Ref = Ref()
      dropped: tuple[ok: bool, err: string] = (false, "")
    removeDir(root)
    createDir(root)
    store = initSidecarStore(root / ".geist-sidecar")
    rf = store.putSidecar(payload)
    dropped = dropSidecar(store, rf.hash)
    check not dropped.ok
    check fileExists(store.storedAt(refLocator(rf)))
    check putLocator(store, remoteLocatorFor(rf.hash)).ok
    check dropSidecar(store, rf.hash).ok
    check store.storedAt(refLocator(rf)).len == 0
