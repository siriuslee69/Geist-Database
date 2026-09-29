## Forward <- the VPS end of Client -> VPS -> Home, in ten lines
##
##   client ---> forwarder ---> home
##          <---           <---
##
## The forwarder holds no key and reads nothing: it carries the bytes and
## brings the answer back to whoever asked. Here "home" is a plain socket
## so the example needs no keys; a real home is `geistd` (docs/forwarding.md).
##
##   nim c -r examples/geist_forward.nim

import geist/forward
import bifrost_exchange_protocols as bfx except ByteSeq

var
  home: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress("127.0.0.1", 47971'u16))
  vps: tuple[ok: bool, f: Forwarder, err: string] = initForwarder(
    bfx.initDacAddress("127.0.0.1", 47972'u16),
    bfx.initDacAddress("127.0.0.1", 47971'u16))
  client: bfx.DacSocket = bfx.openDacListener(bfx.initDacAddress("127.0.0.1", 0'u16))
  atHome: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
  back: bfx.DacFrameBytesResult = default(bfx.DacFrameBytesResult)
  i: int = 0

doAssert vps.ok, vps.err
bfx.sendDacFrameBytes(client, bfx.initDacAddress("127.0.0.1", 47972'u16), @[104'u8, 105])
while i < 20 and not atHome.ok:
  discard vps.f.forwardStep(20)                        # the VPS moves the datagram
  atHome = bfx.recvDacFrameBytes(home, 2048, 10)
  i = i + 1
echo "home got:      ", atHome.payload                # [104, 105], untouched
bfx.sendDacFrameBytes(home, atHome.remote, @[111'u8, 107])
i = 0
while i < 20 and not back.ok:
  discard vps.f.forwardStep(20)                        # ... and carries the answer back
  back = bfx.recvDacFrameBytes(client, 2048, 10)
  i = i + 1
echo "client got:    ", back.payload                  # [111, 107]
echo "forwarder saw: ", vps.f.forwardCounts()
vps.f.closeForwarder()
bfx.closeDac(home)
bfx.closeDac(client)
