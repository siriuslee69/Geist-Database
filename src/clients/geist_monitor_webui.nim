## Desktop monitor <- Nim WebUI renders the shared page; Geist carries messages.
import std/[os, locks]
import webui
from webui/bindings import WebuiBrowser
import runePragmas
import ./monitor/[client, page]

type
  WorkerArgs {.role: configurator.} = object
    root: string

var
  gate: Lock = default(Lock)
  commands: Channel[string] = default(Channel[string])
  answers: Channel[string] = default(Channel[string])
  stopping: bool = false

proc monitorWorker(A: ptr WorkerArgs) {.thread, role: orchestrator.} =
  ## A: this Nim thread owns the entire client, its closures and its key state.
  ## WebUI makes a new C thread per callback; managed client state never visits it.
  {.cast(gcsafe).}:
    var
      monitor: MonitorClient = nil
      command: string = ""
    try:
      monitor = openMonitor(A.root)
      answers.send("")
      while true:
        command = commands.recv()
        if command == "\x00stop": break
        answers.send(monitor.monitorCall(command))
      monitor.disconnect()
    except CatchableError as exc:
      answers.send(exc.msg)

proc request(e: Event) {.role: orchestrator.} =
  ## e: C-owned callback; only plain request/answer strings cross the channels.
  var
    answer: string = ""
  acquire(gate)
  defer: release(gate)
  if stopping:
    e.returnString("{\"ok\":false,\"error\":\"monitor is closing\"}")
    return
  commands.send(e.getString())
  answer = answers.recv()
  e.returnString(answer)

proc runMonitorWebui*() {.role: metaOrchestrator.} =
  ## Optional UI dependency; the headless database never imports WebUI.
  var
    root: string = if paramCount() > 0: paramStr(1) else: getConfigDir() / "geist-monitor"
    window: Window = newWindow()
    args: WorkerArgs = WorkerArgs(root: root)
    worker: Thread[ptr WorkerArgs] = default(Thread[ptr WorkerArgs])
    error: string = ""
  initLock(gate)
  commands.open()
  answers.open()
  createThread(worker, monitorWorker, addr args)
  error = answers.recv()
  if error.len > 0:
    joinThread(worker)
    raise newException(IOError, error)
  defer:
    acquire(gate)
    stopping = true
    commands.send("\x00stop")
    joinThread(worker)
    release(gate)
    commands.close()
    answers.close()
  createDir(root / "ui")
  window.rootFolder = root / "ui"
  window.public = false
  window.bind("geistRequest", request)
  window.setSize(1100, 760)
  if not window.show(monitorPage(desktop = true), WebuiBrowser.wbAnyBrowser):
    raise newException(IOError, "could not open Geist monitor window")
  webui.wait()

when isMainModule:
  runMonitorWebui()
