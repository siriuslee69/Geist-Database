## ---------------------------------------------------------------------
## Stop <- "please finish what you are doing and leave", for every daemon
## ---------------------------------------------------------------------
##
##   SIGTERM / SIGINT  ->  requestShutdown()  ->  shutdownWanted() is true
##                                                 the loop ends after the
##                                                 request in flight
##
## Four daemons (geistd, geist-relayd, geist-routed, geist-forwardd) each
## carried their own copy of this. One word for "stop", one place to
## change it. A test that runs a daemon on a thread calls `requestShutdown`
## to end it and `clearShutdown` before the next run.

import runePragmas

var
  wanted: bool = false

proc requestShutdown*() {.role: actor, tag: "entrypoint|lifecycle|server".} =
  ## Ask the serve loop to stop after the request in flight.
  wanted = true

proc clearShutdown*() {.role: actor, tag: "entrypoint|lifecycle|server".} =
  ## Forget an earlier request, at the start of a run.
  wanted = false

proc shutdownWanted*(): bool {.role: parser,
    tag: "entrypoint|lifecycle|server".} =
  ## Whether someone asked the daemon to stop.
  result = wanted

when defined(posix):
  import std/posix

  proc onSignal(sig: cint) {.role: actor, noconv.} =
    ## sig: SIGTERM or SIGINT; only used to leave the loop cleanly.
    requestShutdown()

proc installSignalHandlers*() {.role: orchestrator,
    tag: "entrypoint|lifecycle|server".} =
  ## Make SIGTERM and SIGINT request a graceful stop.
  when defined(posix):
    signal(SIGTERM, onSignal)
    signal(SIGINT, onSignal)
