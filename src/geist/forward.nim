## ---------------------------------------------------------------------
## Forward <- Client -> VPS -> Home with ONE handshake, made end to end
## ---------------------------------------------------------------------
##
##   client                    VPS (this file)                 home server
##   ------                    ---------------                 -----------
##   hello ------------------> front socket --tag 1 socket ---> hello
##                                                              (handshake
##   <------------------------ front socket <-tag 1 socket ---   runs HERE)
##   Query ------------------> (same path, bytes untouched) --> Query
##
## The VPS opens no frame, holds no key and answers no handshake. It
## moves datagrams, so a link through it costs the same round trips as a
## link without it. A relay that shook hands in the middle would pay for
## two handshakes and read everything in between.
##
## All the decisions come from Bifrost (`UdpForwarder`, see its README,
## "Relaying through a VPS"). This file is the sockets around them:
##
##   front       the one public socket clients dial
##   tag n       one socket per client toward home; home sees a different
##               source port per client, which is how an answer finds its
##               way back
##   control     tag 0: the ping/pong that says home is still there
##
## WHAT A FORWARDER CHECKS, having no key to check anything else with:
##
##   an answer must come FROM home    another sender is dropped and counted
##   a pong must come FROM home       unless `followHome` is on
##   size, table size, idle time      Bifrost's bounds (ForwardOptions)
##
## `followHome` lets the forwarder chase a home address that changed (a
## line that reconnects). It also lets anyone who can reach the control
## socket move the forwarder, so it is OFF unless the operator asks.
##
## THE SERVER MUST BE REACHABLE FROM THE VPS: a VPN address, a forwarded
## port, or a public IPv6 address. A home behind a router that lets nothing
## in cannot be reached by ANY forwarder; that case wants the home server
## to dial OUT to a `geistd` on the VPS instead (README, "Two ways through
## a VPS").

import std/[nativesockets, net, tables, monotimes]

import bifrost_exchange_protocols as bfx except ByteSeq

import runePragmas
import ./ping

const
  forwardRecvBytes*: int = 4 * 1024 * 1024
    ## Kernel queue for the front socket; see Bifrost's README, "The one
    ## socket setting a server must set".
  forwardMaxDatagram*: int = 65_507

type
  ForwardOptions* {.role: configurator, tag: "config|forward|types".} = object
    ## The numbers that bound what an outsider can make the VPS spend.
    ## Seconds, not milliseconds, because that is what an operator thinks in.
    ## followHome: chase a home address that moved (see the top of the file).
    maxClients*: int
    clientIdleSeconds*: int
    pingSeconds*: int
    silentSeconds*: int
    bufferDatagrams*: int
    bufferBytes*: int
    followHome*: bool

  ForwardCounts* {.role: truthState, tag: "forward|types".} = tuple
    ## What a forwarder has done so far.
    clients: int
    forwarded: uint64
    dropped: uint64
    foreign: uint64
    buffered: int
    sockets: int

  Forwarder* {.role: truthState, tag: "forward|types",
    expectedCount: 1, lifeCycle: lcForever.} = object
    ## core: Bifrost's decisions. front/control/tagged: the sockets.
    ## home: where home is now, as the address it answers from.
    ## foreign: datagrams dropped for coming from the wrong sender.
    core: bfx.UdpForwarder
    front: bfx.DacSocket
    control: bfx.DacSocket
    tagged: Table[uint32, bfx.DacSocket]
    home: bfx.UdpAddress
    listened: bfx.DacAddress
    followHome: bool
    foreign: uint64
    open: bool

export bfx.DacAddress, bfx.parseDacAddress

proc forwardDefaults*(): ForwardOptions {.role: configurator,
    tag: "appApi|config|forward".} =
  ## Bifrost's own defaults, in seconds.
  result = ForwardOptions(maxClients: bfx.udpForwardMaxClients,
    clientIdleSeconds: int(bfx.udpForwardClientIdleMs div 1000'u64),
    pingSeconds: int(bfx.udpForwardNasKeepaliveMs div 1000'u64),
    silentSeconds: int(bfx.udpForwardNasSilentMs div 1000'u64),
    bufferDatagrams: bfx.udpForwardBufferDatagrams,
    bufferBytes: bfx.udpForwardBufferBytes, followHome: false)

proc nowMs(): uint64 {.role: helper, inline, tag: "forward".} =
  ## Milliseconds on a clock that only goes forward.
  result = uint64(getMonoTime().ticks div 1_000_000'i64)

proc resolveHome(a: bfx.DacAddress): tuple[ok: bool, a: bfx.UdpAddress,
    err: string] {.role: parser, tag: "forward|read".} =
  ## a: the address the operator wrote (a name or a number).
  ## The answer is the NUMBER, because replies arrive from a number and
  ## are compared with it.
  var
    info: ptr AddrInfo = nil
  result = (false, bfx.initUdpAddress(a.host, a.port), "")
  try:
    info = getAddrInfo(a.host, Port(a.port), AF_UNSPEC, SOCK_DGRAM,
      IPPROTO_UDP)
  except CatchableError as exc:
    result.err = "cannot find " & a.host & ": " & exc.msg
    return
  if info == nil:
    result.err = "cannot find " & a.host
    return
  result.a = bfx.initUdpAddress(getAddrString(info.ai_addr), a.port)
  result.ok = true
  freeAddrInfo(info)

proc initForwarder*(listen, home: bfx.DacAddress,
    o: ForwardOptions = forwardDefaults()): tuple[ok: bool, f: Forwarder,
    err: string] {.role: configurator, tag: "appApi|forward|networkSurface".} =
  ## listen: where clients dial (the VPS's public address).
  ## home: where the server is, from the VPS's point of view.
  ## o: the bounds. Refused, not corrected, if they make no sense.
  var
    found: tuple[ok: bool, a: bfx.UdpAddress, err: string] = resolveHome(home)
  result.ok = false
  if not found.ok:
    result.err = found.err
    return
  try:
    result.f.core = bfx.initUdpForwarder(found.a, bfx.initUdpForwardConfig(
      o.maxClients, uint64(o.clientIdleSeconds) * 1000'u64,
      uint64(o.pingSeconds) * 1000'u64, uint64(o.silentSeconds) * 1000'u64,
      o.bufferDatagrams, o.bufferBytes))
    result.f.front = bfx.openDacListener(listen, forwardRecvBytes)
    result.f.control = bfx.openDacListener(bfx.initDacAddress(
      bfx.wildcardUdpBindHost(found.a.host), 0'u16))
  except CatchableError as exc:
    result.err = exc.msg
    return
  result.f.tagged = initTable[uint32, bfx.DacSocket]()
  result.f.home = found.a
  result.f.listened = bfx.initDacAddress(listen.host, max(listen.port,
    bfx.dacLocalPort(result.f.front).port))
  result.f.followHome = o.followHome
  result.f.open = true
  result.ok = true

proc fromHome(F: Forwarder, remote: bfx.DacAddress): bool {.role: parser,
    tag: "forward", inline.} =
  ## F/remote: whether a datagram came from where home answers from.
  result = remote.host == F.home.host and remote.port == F.home.port

proc socketFor(F: var Forwarder, tag: uint32): bfx.DacSocket {.role: helper,
    tag: "forward|networkSurface".} =
  ## F/tag: the socket toward home that belongs to this client, made the
  ## first time it is needed. Tag 0 is the control socket.
  if tag == 0'u32:
    return F.control
  if not F.tagged.hasKey(tag):
    F.tagged[tag] = bfx.openDacListener(bfx.initDacAddress(
      bfx.wildcardUdpBindHost(F.home.host), 0'u16))
  result = F.tagged[tag]

proc emit(F: var Forwarder, S: bfx.UdpForwardStep, toClient: bool) {.
    role: dataWriter, tag: "forward|networkSurface".} =
  ## F/S: put on the wire what Bifrost decided. `toClient` says which way
  ## the datagrams go: out of the front socket, or toward home from the
  ## socket that belongs to their tag.
  for item in S.send:
    try:
      if toClient:
        bfx.sendDacFrameBytes(F.front, bfx.initDacAddress(item.peer.host,
          item.peer.port), item.payload)
      else:
        bfx.sendDacFrameBytes(F.socketFor(item.tag), bfx.initDacAddress(
          item.peer.host, item.peer.port), item.payload)
    except CatchableError:
      # UDP: a send that fails is a datagram lost, which the transport
      # above repairs. It must not stop the forwarder for everyone else.
      discard

proc closeSocket(sock: bfx.DacSocket) {.role: actor, tag: "forward", inline.} =
  ## sock: one socket, closed; a failed close changes nothing.
  try:
    bfx.closeDac(sock)
  except CatchableError:
    discard

proc releaseIdleSockets(F: var Forwarder) {.role: actor, tag: "forward".} =
  ## F: close the socket of every client whose place was given up.
  ## A client that returns gets a NEW socket, so home sees a new source
  ## port and starts a clean conversation instead of resuming a stale one.
  var
    gone: seq[uint32] = @[]
    inUse: seq[uint32] = @[]
  for slot in F.core.slots:
    if slot.inUse:
      inUse.add(slot.tag)
  for tag, sock in F.tagged:
    if tag notin inUse:
      gone.add(tag)
  for tag in gone:
    closeSocket(F.tagged[tag])
    F.tagged.del(tag)

proc fromClientSide(F: var Forwarder) {.role: orchestrator,
    tag: "forward|networkSurface".} =
  ## F: one datagram off the front socket, sent on toward home.
  var
    got: bfx.DacFrameBytesResult = bfx.recvDacFrameBytes(F.front,
      forwardMaxDatagram, 0)
  if not got.ok:
    return
  F.emit(bfx.fromClient(F.core, bfx.initUdpAddress(got.remote.host,
    got.remote.port), got.payload, nowMs()), false)

proc fromHomeSide(F: var Forwarder, tag: uint32) {.role: orchestrator,
    tag: "forward|networkSurface".} =
  ## F/tag: one datagram off a client's socket toward home, sent back to
  ## that client. Anyone but home is counted and dropped: those sockets
  ## have ports an outsider can guess.
  var
    sock: bfx.DacSocket = F.socketFor(tag)
    got: bfx.DacFrameBytesResult = bfx.recvDacFrameBytes(sock,
      forwardMaxDatagram, 0)
  if not got.ok:
    return
  if not F.fromHome(got.remote):
    F.foreign = F.foreign + 1'u64
    return
  F.emit(bfx.fromNas(F.core, tag, got.payload, nowMs()), true)

proc fromControlSide(F: var Forwarder) {.role: orchestrator,
    tag: "forward|networkSurface".} =
  ## F: one datagram off the control socket. Only a pong counts, and only
  ## from home -- or from anywhere, when the operator turned `followHome` on.
  var
    got: bfx.DacFrameBytesResult = bfx.recvDacFrameBytes(F.control,
      forwardMaxDatagram, 0)
    seen: bfx.UdpForwardStep = default(bfx.UdpForwardStep)
  if not got.ok:
    return
  if not isPong(got.payload) or not (F.followHome or F.fromHome(got.remote)):
    F.foreign = F.foreign + 1'u64
    return
  seen = bfx.noteNasSeen(F.core, bfx.initUdpAddress(got.remote.host,
    got.remote.port), nowMs())
  F.home = F.core.nas
  F.emit(seen, false)

proc readyTag(F: Forwarder, fd: SocketHandle): int64 {.role: parser,
    tag: "forward", inline.} =
  ## F/fd: which client a readable socket belongs to; -1 for the front
  ## socket, 0 for the control socket, and -2 for none of ours.
  result = -2'i64
  if fd == F.front.getFd():
    return -1'i64
  if fd == F.control.getFd():
    return 0'i64
  for tag, sock in F.tagged:
    if fd == sock.getFd():
      return int64(tag)

proc readableSockets(F: Forwarder): seq[SocketHandle] {.role: helper,
    tag: "forward".} =
  ## F: every socket a datagram might be waiting on.
  result = @[F.front.getFd(), F.control.getFd()]
  for tag, sock in F.tagged:
    result.add(sock.getFd())

proc forwardStep*(F: var Forwarder, timeoutMs: int = 200): tuple[ok: bool,
    moved: int, err: string] {.role: metaOrchestrator,
    tag: "appApi|forward|networkSurface".} =
  ## F: a bound forwarder.
  ## timeoutMs: how long to wait for anything at all. Waking with nothing
  ##   is the idle case, not a failure.
  ##
  ## One pass: read whatever is waiting on any socket, then do the
  ## housekeeping (free idle places, ping home). A caller loops on this.
  var
    fds: seq[SocketHandle] = F.readableSockets()
    which: int64 = 0
  result = (true, 0, "")
  if not F.open:
    return (false, 0, "forwarder is not open")
  try:
    if selectRead(fds, timeoutMs) > 0:
      for fd in fds:
        which = F.readyTag(fd)
        if which == -1:
          F.fromClientSide()
        elif which == 0:
          F.fromControlSide()
        elif which > 0:
          F.fromHomeSide(uint32(which))
        result.moved = result.moved + 1
  except CatchableError as exc:
    return (false, result.moved, exc.msg)
  F.emit(bfx.tickUdpForwarder(F.core, nowMs(), pingBytes()), false)
  F.releaseIdleSockets()

proc forwardCounts*(F: Forwarder): ForwardCounts {.role: parser,
    tag: "appApi|forward|read".} =
  ## F: what this forwarder has done so far.
  result = (bfx.udpForwardClients(F.core), F.core.forwardedTotal,
    F.core.droppedTotal, F.foreign, bfx.udpForwardBuffered(F.core), F.tagged.len)

proc forwardAddress*(F: Forwarder): bfx.DacAddress {.role: parser,
    tag: "appApi|forward|read".} =
  ## F: the address clients dial. Useful when the port asked for was 0.
  result = F.listened

proc closeForwarder*(F: var Forwarder) {.role: actor,
    tag: "appApi|forward|networkSurface".} =
  ## F: close every socket. Safe to call twice.
  if not F.open:
    return
  closeSocket(F.front)
  closeSocket(F.control)
  for tag, sock in F.tagged:
    closeSocket(sock)
  F.tagged.clear()
  F.open = false
