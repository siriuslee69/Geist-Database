## Monitor runtime <- one Nim worker owns all client state and periodic check-ins.
## UI/JNI callbacks pass plain strings across channels, never client object graphs.
import std/[locks, os]
import runePragmas
import ./client

var
  gate: Lock = default(Lock)
  commands: Channel[string] = default(Channel[string])
  answers: Channel[string] = default(Channel[string])
  worker: Thread[void] = default(Thread[void])
  started: bool = false

initLock(gate)

proc heartbeat(S: MonitorClient) {.role: orchestrator.} =
  ## S: a logging failure must not strand every UI caller behind a dead worker.
  try:
    S.monitorTick()
  except CatchableError as exc:
    stderr.writeLine("Geist heartbeat: " & exc.msg)

proc runMonitor() {.thread, role: orchestrator.} =
  ## This thread owns keys, closures, leases and every network session.
  {.cast(gcsafe).}:
    var
      monitor: MonitorClient = nil
      root: string = commands.recv()
      received: tuple[dataAvailable: bool, msg: string] = (false, "")
    try:
      monitor = openMonitor(root)
    except CatchableError as exc:
      answers.send(exc.msg)
      return
    answers.send("")
    while true:
      received = commands.tryRecv()
      if received.dataAvailable and received.msg == "\x00stop": break
      if received.dataAvailable:
        answers.send(monitor.monitorCall(received.msg))
      heartbeat(monitor)
      sleep(25)
    monitor.disconnect()

proc startMonitorRuntime*(root: string) {.role: orchestrator.} =
  ## root: one private device root per process, opened inside the worker.
  var
    error: string = ""
  acquire(gate)
  defer: release(gate)
  if started: return
  commands.open()
  answers.open()
  createThread(worker, runMonitor)
  commands.send(root)
  error = answers.recv()
  if error.len > 0:
    joinThread(worker)
    commands.close()
    answers.close()
    raise newException(IOError, error)
  started = true

proc monitorRuntimeCall*(request: string): string {.role: orchestrator.} =
  ## request: serialize callers while only strings move between runtime threads.
  acquire(gate)
  defer: release(gate)
  if not started: raise newException(IOError, "monitor runtime is closed")
  commands.send(request)
  result = answers.recv()

proc closeMonitorRuntime*() {.role: orchestrator.} =
  ## Stop and join before closing the channels; the worker closes its own sockets.
  acquire(gate)
  defer: release(gate)
  if not started: return
  commands.send("\x00stop")
  joinThread(worker)
  commands.close()
  answers.close()
  started = false
