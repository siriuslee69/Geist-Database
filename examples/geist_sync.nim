## ---------------------------------------------------------------------
## Geist Sync <- keeping stores in step: same process, and over the wire
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/geist_sync.nim
##
## Two words do all of it:
##
##   need   "what do you have that I lack?"   rows come HERE    (pull)
##   offer  "here is what you lack"           rows go THERE     (push)
##
## Each remembers how far it got, per peer, in a small file beside the
## store, so the next call sends only what is new -- after a restart too.
##
##   where the other store is        pull                 push
##   ------------------------------  -------------------  -------------------
##   open in this same process       needLocal            offerLocal
##   another program or machine      needRemote (a link)  offerRemote (a link)
##   a named address, many hops      needVia (a client)   offerVia (a client)
##   several peers, on a timer       SyncAgent: syncOnce / tick
##
## The answering side of a network sync is one call per loop turn:
## `serveStore` -- what `geistd` does, for a program that wants to BE the
## server itself rather than run the daemon beside it.

import runePragmas
import std/os

import geist/network

type
  Note = object
    noteId: int
    title: string

  DeskArgs = object
    ## Handed to the desk thread. `ready`/`stop` are the only fields both
    ## threads touch, and each is written by one side only.
    root: string
    listen: string
    identity: AmeIdentityKey
    phonePin: AmePinnedPeerIdentity
    ready: bool
    stop: bool
    rows: int
    err: string

proc scratch(name: string): string {.role: helper.} =
  ## name: a fresh, empty store folder under the system temp folder.
  result = getTempDir() / "geist_example_sync" / name
  removeDir(result)
  createDir(result)

proc runDesk(a: ptr DeskArgs) {.role: orchestrator.} =
  ## a: the desk: its own store, served to one trusted phone.
  var
    desk: Session = openGeist[Note](a.root, appConfig())
    cursors: SyncCursors = initSyncCursors()
    server: tuple[ok: bool, server: GeistServer, err: string] =
      initGeistServer(parseDacAddress(a.listen).a, a.identity,
        [TrustedPeer(pin: a.phonePin, rights: {prRead, prWrite})],
        defaultTriggerPolicy())
  if not server.ok:
    a.err = server.err
    a.ready = true
    return
  a.ready = true
  while not a.stop:
    discard serveStore(desk, cursors, server.server, 200)
  a.rows = desk.entryCount().int
  server.server.closeServer()
  desk.close()

proc deskThread(a: ptr DeskArgs) {.role: orchestrator, thread.} =
  {.cast(gcsafe).}:
    runDesk(a)

when isMainModule:
  var
    laptop: Session = openGeist[Note](scratch("laptop"), appConfig())
    phone: Session = openGeist[Note](scratch("phone"), appConfig())
    pulled: NeedOutcome = default(NeedOutcome)
    pushed: OfferOutcome = default(OfferOutcome)
    phoneKey: AmeIdentityKey = geistIdentity("phone")
    deskKey: AmeIdentityKey = geistIdentity("desk")
    args: DeskArgs = default(DeskArgs)
    t: Thread[ptr DeskArgs] = default(Thread[ptr DeskArgs])
    agent: SyncAgent = default(SyncAgent)
    spins: int = 0

  ## ── 1. Same process: two stores, no socket ──
  discard laptop.put(Note(noteId: 1, title: "written on the laptop"))
  doAssert laptop.save().ok
  pulled = phone.needLocal(laptop, "laptop")
  echo "phone needed from laptop: ", pulled.applied, " row(s)"

  discard phone.put(Note(noteId: 2, title: "written on the phone"))
  doAssert phone.save().ok
  pushed = phone.offerLocal(laptop, "laptop")
  echo "phone offered to laptop:  ", pushed.sent, " row(s); laptop now has ",
    laptop.entryCount()

  ## ── 2. Over the network: the desk serves, the phone's agent syncs ──
  ##
  ## Loopback here; a real desk is another machine and the same code.
  args = DeskArgs(root: scratch("desk"), listen: "dac://127.0.0.1:47931",
    identity: deskKey, phonePin: geistPeerPin(phoneKey))
  createThread(t, deskThread, addr args)
  while not args.ready and spins < 500:
    sleep(10)
    spins = spins + 1
  doAssert args.err.len == 0, args.err

  agent = initSyncAgent(phoneKey, SyncPlan(everySeconds: 30,
    peers: @[SyncPeer(name: "desk", endpoint: args.listen,
      pin: geistPeerPin(deskKey), way: swBoth)]))
  for r in phone.syncOnce(agent):
    echo "phone <-> ", r.peer, ": pulled ", r.pulled, ", pushed ", r.pushed,
      (if r.ok: "" else: "  FAILED: " & r.err)

  ## In an application loop, `tick` runs the plan only when it is due:
  ##   while running:
  ##     for r in phone.tick(agent): log(r)
  ##     ...the rest of the loop...
  echo "due again right away? ", agent.syncDue(), " (every ",
    agent.plan.everySeconds, "s)"

  args.stop = true
  joinThread(t)
  echo "desk holds ", args.rows, " row(s)"
  laptop.close()
  phone.close()
