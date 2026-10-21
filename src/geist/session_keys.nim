## ---------------------------------------------------------------------
## Session keys <- the second key a pre-shared link carries to its next one
## ---------------------------------------------------------------------
##
## A link made with a shared key (AM1P+S) hands out a SESSION KEY (SK): 32
## bytes both ends hold, which the NEXT handshake between the same two
## takes next to the shared key (Bifrost README, "The session key"). With it,
## a copy of the shared key alone no longer opens a hello: the machine that
## ran the last session is needed too.
##
## Bifrost derives the SK; it does not keep it. This file keeps it, one
## entry per PEER -- not per shared key, because every device of a Geist
## group shares ONE shared key, and one SK for all of them would be moved on
## by whichever device connected last.
##
## ╭─ ❧ When a new SK counts 🌊
##
## A datagram can be lost at the worst moment: the server accepted a
## session, the client never heard back. If both sides switched to the new
## SK at once, the next hello would carry a key the other side does not
## hold, and the device would be locked out. So a new SK is only CONFIRMED
## once the other side has shown it holds it:
##
##   client                                server (per peer)
##   ------                                -----------------
##   hello with C                ───────▶  opens with C ......... or P
##   session works                         P := new SK            (C := P,
##   first reply arrives  ◀───────────────                         P := new)
##   C := new SK
##   next hello with C (= P)     ───────▶  opens with P, so C := P
##
##   C  confirmed: what the client sends, what the server accepts
##   P  pending:   handed out by the newest session, not yet seen in use
##
## The server accepts C or P, never anything older. A copy of a device
## taken before its last two sessions is refused.
##
## ╭─ ❧ On disk 🐦‍🔥
##
##   <dir>/<subject as hex>.sk      one file per peer, mode 0600
##
##   offset  size  field
##   0       4     "GSK1"
##   4       1     1 when C follows, else 0
##   5       32    C (only when present)
##   ..      1     1 when P follows, else 0
##   ..      32    P (only when present)
##
## Written to a temporary file and moved into place, so a crash leaves the
## old pair or the new one, never half of each.
##
## ╭─ ❧ Starting over ⌜guide⌟
##
## A device that lost its SK (reinstalled, restored from an old backup) is
## refused while `required` is on, once that peer has a confirmed key.
## Delete that peer's file on the server (`forgetSessionKey`, or remove
## `<dir>/<hex>.sk`); the next session starts a new chain.

import std/[os, strutils, tables]

import runePragmas
import ./types

const
  sessionKeyBytes* = 32
  sessionKeyMagic = "GSK1"

type
  SessionKeySlot* = enum
    sksNone, sksConfirmed, sksPending

  SessionKeyPair* {.role: memory, expectedCount: [0, 256],
      lifeCycle: lcSession.} = object
    ## What one side holds for one peer (see the module note).
    confirmed*: ByteSeq
    pending*: ByteSeq

  SessionKeyStore* {.role: truthState, expectedCount: 1,
      lifeCycle: lcForever.} = ref object
    ## dir: where the pairs live; "" keeps them in memory only (tests).
    ## required: a peer with a pair on file must use it (server side).
    dir*: string
    required*: bool
    cache: Table[string, SessionKeyPair]

proc initSessionKeyStore*(dir: string,
    required: bool = true): SessionKeyStore {.role: configurator,
    tag: "appApi".} =
  ## dir: a private folder for the pairs ("" = memory only).
  ## required: refuse a peer that has a pair on file but does not use it.
  ##   Leave it on; turn it off only while a device may have lost its SK.
  result = SessionKeyStore(dir: dir, required: required,
    cache: initTable[string, SessionKeyPair]())
  if dir.len > 0:
    createDir(dir)
    when defined(posix):
      setFilePermissions(dir, {fpUserRead, fpUserWrite, fpUserExec})

proc pairPath(S: SessionKeyStore, subject: string): string {.role: helper.} =
  ## S/subject: the file one peer's pair lives in. Hex, so no subject can
  ## climb out of the folder.
  result = S.dir / (toHex(subject) & ".sk")

proc readKey(A: string, o: var int): ByteSeq {.role: parser.} =
  ## A/o: one optional 32-byte key at o, behind its presence byte.
  var
    i: int = 0
  if o >= A.len:
    raise newException(ValueError, "session key file is truncated")
  o = o + 1
  if A[o - 1] == '\0':
    return @[]
  if A[o - 1] != '\1' or o + sessionKeyBytes > A.len:
    raise newException(ValueError, "session key file is damaged")
  result = newSeq[uint8](sessionKeyBytes)
  while i < sessionKeyBytes:
    result[i] = uint8(ord(A[o + i]))
    i = i + 1
  o = o + sessionKeyBytes

proc decodePair(A: string): SessionKeyPair {.role: parser.} =
  ## A: one file's bytes (see "On disk").
  var
    o: int = sessionKeyMagic.len
  if not A.startsWith(sessionKeyMagic):
    raise newException(ValueError, "not a Geist session key file")
  result.confirmed = readKey(A, o)
  result.pending = readKey(A, o)
  if o != A.len:
    raise newException(ValueError, "session key file has trailing bytes")

proc appendKey(A: var string, K: ByteSeq) {.role: dataWriter.} =
  ## A/K: presence byte, then the key when there is one.
  if K.len == 0:
    A.add('\0')
    return
  A.add('\1')
  for b in K:
    A.add(char(b))

proc loadSessionKeys*(S: SessionKeyStore,
    subject: string): SessionKeyPair {.role: dataFetcher, tag: "appApi".} =
  ## S/subject: the pair held for one peer; empty when there is none. A
  ## damaged file raises rather than being read as "no key": quietly
  ## starting over would be a downgrade.
  if S.cache.hasKey(subject):
    return S.cache[subject]
  if S.dir.len > 0 and fileExists(pairPath(S, subject)):
    result = decodePair(readFile(pairPath(S, subject)))
  S.cache[subject] = result

proc saveSessionKeys(S: SessionKeyStore, subject: string,
    P: SessionKeyPair) {.role: dataWriter.} =
  ## S/subject/P: the pair kept in memory and, with a folder, on disk.
  var
    body: string = sessionKeyMagic
    path: string = ""
  S.cache[subject] = P
  if S.dir.len == 0:
    return
  appendKey(body, P.confirmed)
  appendKey(body, P.pending)
  path = pairPath(S, subject)
  writeFile(path & ".tmp", body)
  when defined(posix):
    setFilePermissions(path & ".tmp", {fpUserRead, fpUserWrite})
  moveFile(path & ".tmp", path)

proc sessionKeyCandidates*(S: SessionKeyStore,
    subject: string): seq[tuple[slot: SessionKeySlot, key: ByteSeq]] {.
    role: parser, tag: "appApi".} =
  ## S/subject: the keys a server accepts from this peer, newest first.
  var
    P: SessionKeyPair = loadSessionKeys(S, subject)
  if P.pending.len > 0:
    result.add((sksPending, P.pending))
  if P.confirmed.len > 0:
    result.add((sksConfirmed, P.confirmed))

proc holdsSessionKey*(S: SessionKeyStore, subject: string): bool {.
    role: parser, tag: "appApi".} =
  ## S/subject: true when any key is on file for this peer.
  result = sessionKeyCandidates(S, subject).len > 0

proc expectsSessionKey*(S: SessionKeyStore, subject: string): bool {.
    role: parser, tag: "appApi".} =
  ## S/subject: true when this peer has a CONFIRMED key on file -- it has
  ## shown it holds and uses an SK, so a hello without one is a downgrade.
  ##
  ## A pending key alone does not count. Every accepted session leaves one,
  ## including sessions with a peer on an older build that never sends an
  ## SK; requiring it there would lock that peer out after its first visit:
  ##
  ##   old build, session 1   PSK only -> accepted, P := new SK
  ##   old build, session 2   PSK only -> P only, not C: accepted
  ##   new build              uses P   -> C := P: from now on, required
  result = loadSessionKeys(S, subject).confirmed.len > 0

proc keepServerSessionKey*(S: SessionKeyStore, subject: string,
    used: SessionKeySlot, fresh: openArray[uint8]) {.role: actor,
    tag: "appApi".} =
  ## S/subject: server side, after a session with this peer started.
  ## used: which key its hello opened with. fresh: the new session's SK.
  ##
  ##   used pending   -> C := P, P := fresh   (the client had confirmed it)
  ##   used confirmed -> P := fresh           (C stays until P is seen)
  ##   used none      -> P := fresh           (first session, or a restart)
  var
    P: SessionKeyPair = loadSessionKeys(S, subject)
  if used == sksPending:
    P.confirmed = P.pending
  P.pending = @fresh
  saveSessionKeys(S, subject, P)

proc keepClientSessionKey*(S: SessionKeyStore, subject: string,
    fresh: openArray[uint8]) {.role: actor, tag: "appApi".} =
  ## S/subject: client side, once the server has answered on the session
  ## that handed out `fresh` -- proof that the server holds it too.
  saveSessionKeys(S, subject, SessionKeyPair(confirmed: @fresh))

proc forgetSessionKey*(S: SessionKeyStore, subject: string) {.role: actor,
    tag: "appApi".} =
  ## S/subject: start this peer's chain over (see "Starting over").
  S.cache.del(subject)
  if S.dir.len > 0 and fileExists(pairPath(S, subject)):
    removeFile(pairPath(S, subject))
