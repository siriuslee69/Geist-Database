## ---------------------------------------------------------------------
## Forward settings <- [runtime.forward] of configs/default.toml
## ---------------------------------------------------------------------
##
##   [runtime.forward]
##   maxClients        = 512
##   clientIdleSeconds = 120
##   ...
##
## The bounds a forwarder puts on what strangers can make it spend. They
## start at Bifrost's own defaults; an operator changes them in the file,
## and `geist-forwardd` flags win over the file.
##
## Kept apart from ./forward for the reason `transport_settings` is kept
## apart from ./transport: the forwarder needs no TOML reader to move
## datagrams, and a program that embeds one should not have to compile it.

import std/json

import runePragmas
import ./forward
import ./toml_read

proc loadForwardOptions*(path: string = libraryConfigName): tuple[ok: bool,
    options: ForwardOptions, err: string] {.role: configurator,
    tag: "config|forward|parsing|read".} =
  ## path: `configs/default.toml`; only `[runtime.forward]` is read.
  ## A missing file is success: Bifrost's defaults ARE the answer then.
  var
    doc: tuple[ok: bool, node: JsonNode, err: string] = (false, newJNull(), "")
    section: JsonNode = newJNull()
    complaint: string = ""
  result.options = forwardDefaults()
  doc = runtimeOf(path)
  if not doc.ok:
    return (false, result.options, doc.err)
  section = doc.node.section("forward")
  complaint = checkKeys(section, ["maxClients", "clientIdleSeconds",
    "pingSeconds", "silentSeconds", "bufferDatagrams", "bufferBytes",
    "followHome"], "[runtime.forward]")
  if complaint.len > 0:
    return (false, result.options, complaint)
  result.options.maxClients = section.setting("maxClients",
    result.options.maxClients)
  result.options.clientIdleSeconds = section.setting("clientIdleSeconds",
    result.options.clientIdleSeconds)
  result.options.pingSeconds = section.setting("pingSeconds",
    result.options.pingSeconds)
  result.options.silentSeconds = section.setting("silentSeconds",
    result.options.silentSeconds)
  result.options.bufferDatagrams = section.setting("bufferDatagrams",
    result.options.bufferDatagrams)
  result.options.bufferBytes = section.setting("bufferBytes",
    result.options.bufferBytes)
  result.options.followHome = section.setting("followHome",
    result.options.followHome)
  result.ok = true
