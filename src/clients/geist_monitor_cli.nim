## Headless monitor <- provisioning and repeatable device checks via Geist.
import std/[os, json]
import runePragmas
import ./monitor/[provision, client]

proc runMonitorCli*(): int {.role: metaOrchestrator.} =
  ## Commands take a private root and keep all secret exports in files.
  var
    root: string = paramStr(1)
    op: string = paramStr(2)
    S: MonitorClient = nil
  case op
  of "provision": provisionDevice(root, paramStr(3))
  of "export-psk": exportSharedKey(root, paramStr(3))
  of "import-psk": importSharedKey(root, paramStr(3))
  of "request":
    S = openMonitor(root)
    echo S.monitorCall(paramStr(3))
    S.disconnect()
  else: raise newException(ValueError, "usage: geist-monitor-cli <root> provision|export-psk|import-psk|request <value>")
  result = 0

when isMainModule:
  try:
    quit(runMonitorCli())
  except CatchableError as exc:
    stderr.writeLine($(%*{"ok": false, "error": exc.msg}))
    quit(1)
