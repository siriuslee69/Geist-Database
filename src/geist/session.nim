## ---------------------------------------------------------------------
## Session <- an open database: clusters, keys, ledger, backup, changefeed
## ---------------------------------------------------------------------
##
##   openSession -> put / find / save / checkpoint -> close
##                        `-> subscribe / poll for change following
##
## A session owns one artifact SET (data + keys + ledger) under one store
## root, plus the sidecar folder. Everything that must swap together is
## reachable from here, which is what makes the generation manifest the
## single atomic commit point.
##
## The Session is one type in five modules, gathered here so a caller
## imports one name:
##
##   sessioncore   open, put / set / delete, read, save, close, restore
##   replicate     rowsSince, applyRows, subscribe, poll
##   observe       observe, observeStore, followStore
##   sessionsweep  sweepSidecar, sidecarRefs
##   sessionview   show, visibleRow, the transposed search copy
##
## The core never calls the other four; they build on it.

import ./sessioncore
import ./replicate
import ./observe
import ./sessionsweep
import ./sessionview

export sessioncore, replicate, observe, sessionsweep, sessionview
