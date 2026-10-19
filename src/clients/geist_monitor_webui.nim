## Desktop monitor <- Nim WebUI renders the shared page; Geist carries messages.
import std/[os, locks]
import webui
from webui/bindings import WebuiBrowser
import runePragmas
import ./monitor/[client, page]

var
  gate: Lock = default(Lock)
  monitor: MonitorClient = nil

proc request(e: Event) {.role: orchestrator.} =
  ## e: a local WebUI callback serialized around the one Geist client.
  acquire(gate)
  defer: release(gate)
  e.returnString(monitor.monitorCall(e.getString()))

proc runMonitorWebui*() {.role: metaOrchestrator.} =
  ## Optional UI dependency; the headless database never imports WebUI.
  var
    root: string = if paramCount() > 0: paramStr(1) else: getConfigDir() / "geist-monitor"
    window: Window = newWindow()
  initLock(gate)
  monitor = openMonitor(root)
  createDir(root / "ui")
  window.rootFolder = root / "ui"
  window.public = false
  window.bind("geistRequest", request)
  window.setSize(1100, 760)
  if not window.show(monitorPage(desktop = true), WebuiBrowser.wbAnyBrowser):
    raise newException(IOError, "could not open Geist monitor window")
  webui.wait()
  monitor.disconnect()

when isMainModule:
  runMonitorWebui()
