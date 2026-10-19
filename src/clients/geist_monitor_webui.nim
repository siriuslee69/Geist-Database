## Desktop monitor <- Nim WebUI renders the shared page; Geist carries messages.
import std/[os, json]
import webui
from webui/bindings import WebuiBrowser
import runePragmas
import ./monitor/[runtime, page]

proc request(e: Event) {.role: orchestrator.} =
  ## e: C-owned callback; only plain request/answer strings cross the channels.
  var
    answer: string = ""
  try:
    answer = monitorRuntimeCall(e.getString())
  except CatchableError as exc:
    answer = $(%*{"ok": false, "error": exc.msg})
  e.returnString(answer)

proc runMonitorWebui*() {.role: metaOrchestrator.} =
  ## Optional UI dependency; the headless database never imports WebUI.
  var
    root: string = if paramCount() > 0: paramStr(1) else: getConfigDir() / "geist-monitor"
    window: Window = newWindow()
  startMonitorRuntime(root)
  defer: closeMonitorRuntime()
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
