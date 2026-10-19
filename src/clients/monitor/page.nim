## Page <- one bundled HTML/CSS/JS UI shared by desktop and Android.
import std/strutils
import runePragmas

const
  monitorHtml = staticRead("../../../assets/monitor/index.html")
  monitorCss = staticRead("../../../assets/monitor/style.css")
  monitorJs = staticRead("../../../assets/monitor/app.js")

proc monitorPage*(desktop: bool = false): string {.role: helper.} =
  ## The complete local document. It loads no remote assets.
  result = monitorHtml.replace("/*MONITOR_CSS*/", monitorCss).replace(
    "/*MONITOR_JS*/", monitorJs)
  result = result.replace("<!--MONITOR_BRIDGE-->", if desktop:
    "<script src=\"/webui.js\"></script>" else: "")
