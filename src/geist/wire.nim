## ---------------------------------------------------------------------
## Geist wire <- talking to another machine, with no database at all
## ---------------------------------------------------------------------
##
##   import geist          storage only        rows on a disk
##   import geist/wire     the wire only       messages between machines
##   import geist/network  both                a database other machines share
##
## Three doors, and this is the one for a program that has nothing to
## store. A relay moving a voice clip from a phone to a desktop, a daemon
## feeding a command line, a script fanning log lines at one machine --
## none of them wants a packed-row store, a write lease or a generation
## swap, and none of them should compile one.
##
## What this half contains:
##
##   address             what a request names, and where it has been
##   doc                 an object as an editable TOML or JSON file
##   reconcile           a settings table against a roster of real names
##   masks               which algorithms each tier selects
##   transport           Query/Reply over Bifrost AME/DAC, many peers
##   identity            signing identities and the pins peers exchange
##   relay               what a Query means against a PIPE
##   transport_settings  [runtime.transport] of configs/default.toml
##
## The trust model is the same one the database half uses, because it is
## the same handshake: peers are PINNED, the pin decides what a peer may
## do, and the identity in a reply was proved rather than claimed. A relay
## is not a lesser thing than a database daemon; it is the same daemon
## with a pipe where the store would be.
##
## Nothing here imports `geist`. That is the property worth keeping: if
## the storage half were deleted, every program built on this file would
## still build.

import runePragmas
import ./types
import ./format
import ./toml_read
import ./doc
import ./reconcile
import ./address
import ./route
import ./link
import ./layout
import ./masks
import ./transport
import ./identity
import ./relay
import ./transport_settings

import bifrost_exchange_protocols as bfx except ByteSeq

export types, format, toml_read, doc, reconcile, address, route, link, layout
export masks, transport, identity, relay, transport_settings

## The transport surface a CLI or daemon needs, re-exported so callers do
## not have to import Bifrost directly just to name an address or a key.
export bfx.DacAddress, bfx.parseDacAddress, bfx.formatDacAddress,
  bfx.AmeIdentityKey, bfx.AmePinnedPeerIdentity

type
  GeistDacAddress* = bfx.DacAddress

proc initGeistWireDefaults*(path: string = libraryConfigName): tuple[
    ok: bool, err: string] {.role: configurator,
    tag: "ame|config|lifecycle|read".} =
  ## path: configs/default.toml, of which only `[runtime.transport]` concerns this half.
  ##
  ## A relay has no storage settings to adopt, so it validates the one
  ## section it acts on and leaves the rest alone. A typo under
  ## `[transport]` still stops it, which is the whole reason a settings
  ## file is read at startup rather than consulted lazily.
  result = initTransportDefaults(path)
