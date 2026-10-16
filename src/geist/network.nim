## ---------------------------------------------------------------------
## Geist network <- a database that other machines share
## ---------------------------------------------------------------------
##
##   import geist          storage only        rows on a disk
##   import geist/wire     the wire only       messages between machines
##   import geist/network  both                a database other machines share
##
## This module is the union: it re-exports `geist` and `geist/wire`, so
## one import is enough when a program wants a store AND peers. What it
## ADDS is the code that needs both at once:
##
##   answer    what a Query MEANS against a Session
##   need      what this database is missing, asked for
##   offer     what a peer is missing from here, sent
##   registry  which of MANY stores an address means
##
## WHY THE SPLIT EXISTS. Bifrost brings a post-quantum handshake with it --
## Falcon, ML-KEM, the DAC transport. A program that embeds Geist as a local
## disk backend and never speaks to anything was compiling all of it: 83 C
## modules where 45 would do. The line is drawn where the first socket is,
## which is also where the first algorithm choice is, so it is one line
## rather than an arbitrary one.
##
## The third door came later and for the mirror-image reason: a relay that
## moves a voice clip from a phone to a desktop has nothing to store, and
## `geist/wire` lets it say so.
##
## Nothing in the storage half imports the wire half, and nothing in the
## wire half imports the storage half. That is the property worth keeping:
## delete either one and the other still builds.

import runePragmas
import ../geist
import ./wire
import ./answer
import ./need
import ./offer
import ./registry
import ./agent

export geist, wire
export answer, need, offer, registry, agent

proc initGeistNetworkDefaults*(path: string = libraryConfigName): tuple[
    ok: bool, err: string] {.role: configurator,
    tag: "ame|config|lifecycle|read".} =
  ## path: configs/default.toml, adopted for BOTH halves in one call.
  ##
  ## A program that speaks to peers wants every section of that file
  ## validated, including `[transport]` -- a typo there should stop it just
  ## as surely as a typo in `[storage]`. A storage-only program calls
  ## `initGeistDefaults` and never learns `[transport]` exists; a relay
  ## calls `initGeistWireDefaults` and never learns `[storage]` does.
  result = initGeistDefaults(path)
  if not result.ok:
    return
  result = initGeistWireDefaults(path)
