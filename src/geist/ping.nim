## ---------------------------------------------------------------------
## Ping <- the one datagram anybody may send to a Geist server
## ---------------------------------------------------------------------
##
##   forwarder (VPS)                          server (home)
##   ---------------                          -------------
##   "GEIST-FWD-PING"   -------------------->  answers at once, opens nothing
##                      <--------------------  "GEIST-FWD-PONG"
##
## A forwarder holds no key, so it cannot prove itself to a server. All it
## needs to know is "is the machine behind me still there, and where is it
## now". So the server knows two fixed words and nothing else:
##
##   ping -> pong        same length both ways: no gain for a sender who
##                       fakes the source address of somebody else
##
## Nothing is stored, nothing is decoded and no session is touched. A
## pong says the server is alive; it says nothing about WHO it is. Who
## it is stays the handshake's job.

import runePragmas
import ./types

const
  pingWord*: string = "GEIST-FWD-PING"
  pongWord*: string = "GEIST-FWD-PONG"

proc wordBytes(w: string): ByteSeq {.role: helper, tag: "wire|forward".} =
  ## w: a word as the bytes that travel.
  result = newSeq[uint8](w.len)
  for i in 0 ..< w.len:
    result[i] = uint8(w[i])

proc pingBytes*(): ByteSeq {.role: helper, tag: "wire|forward".} =
  ## The datagram a forwarder sends to see if the server is there.
  result = wordBytes(pingWord)

proc pongBytes*(): ByteSeq {.role: helper, tag: "wire|forward".} =
  ## The datagram a server answers a ping with.
  result = wordBytes(pongWord)

proc isWord(A: openArray[uint8], w: string): bool {.role: parser,
    tag: "wire|forward".} =
  ## A/w: whether the datagram is exactly this word.
  var
    i: int = 0
  result = A.len == w.len
  while result and i < w.len:
    result = A[i] == uint8(w[i])
    i = i + 1

proc isPing*(A: openArray[uint8]): bool {.role: parser,
    tag: "wire|forward".} =
  ## A: whether a datagram is a ping.
  result = isWord(A, pingWord)

proc isPong*(A: openArray[uint8]): bool {.role: parser,
    tag: "wire|forward".} =
  ## A: whether a datagram is a pong.
  result = isWord(A, pongWord)
