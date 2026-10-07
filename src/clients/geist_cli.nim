## ---------------------------------------------------------------------
## geist <- command line client, direct or against a daemon
## ---------------------------------------------------------------------
##
##   direct:  geist --path data/notes list
##   daemon:  geist --remote dac://127.0.0.1:47655 list
##
## The same commands run either way. `--path` opens the database files in
## this process; `--remote` sends the identical `Query` to geistd over
## Bifrost AME/DAC. That works because a serialised Query IS the wire
## body, so the CLI has no second code path for the network.
##
## Commands that need the at-rest password or rewrite local files -- init,
## checkpoint, compact, sweep, backup, restore, rekey -- are direct only:
## sending key material to a daemon to have it do local file work would
## widen the trust boundary for no benefit.
##
##   inspect  -> works WITHOUT a password: reads only header + index
##   list/get -> needs the password when the database is encrypted
##
## A `userconfig.toml` fills in anything not typed, and `configs/default.toml`
## carries the library defaults a preset is adjusted by. An option on the
## command line always wins over either.
##
## The code is in three parts under src/clients/cli/:
##
##   common   options, userconfig, opening a store, printing rows
##   direct   commands that open the files in this process (--path)
##   remote   commands sent to a running geistd (--remote), and sync
##
## This file holds only the entry point: which part answers which command.

import std/os

import runePragmas
import ../geist/network
import ./cli/common
import ./cli/direct
import ./cli/remote
import ./cli/keys

export common

## ------------------------------ entry -------------------------------

proc dispatchCli(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name.
  var
    o: Options = default(Options)
  o = parseOptions(argv)
  if o.command.len == 0 or o.command == "help":
    echo usageText
    return 0
  # A userconfig.toml fills in what was not typed, and nothing more.
  o = withUserConfig(o)
  # configs/default.toml carries the library defaults every preset is adjusted by.
  var defaults = initGeistNetworkDefaults()
  if not defaults.ok:
    fail(defaults.err)
  if o.command == "convert":
    cmdConvert(o)
    return 0
  if o.command == "presets":
    cmdPresets()
    return 0
  if o.command == "keygen":
    cmdKeygen(o)
    return 0
  if o.command == "keys":
    cmdKeys(o)
    return 0
  # `sync` is the one command that is BOTH: it reads a peer and writes this
  # database, so it belongs to neither dispatch and is answered before the
  # mode decides anything.
  if o.command == "sync":
    cmdSync(o)
    return 0
  if o.mode == mRemote:
    runRemote(o, remoteQuery(o))
    return 0
  case o.command
  of "inspect": cmdInspect(o)
  of "verify": cmdVerify(o)
  of "schema": cmdSchema(o)
  of "info": cmdInfo(o)
  of "init": cmdInit(o)
  of "put": cmdPut(o)
  of "set": cmdSet(o)
  of "delete", "del", "rm": cmdDelete(o)
  of "compact": cmdCompact(o)
  of "sweep": cmdSweep(o)
  of "transpose": cmdTranspose(o)
  of "get": cmdGet(o)
  of "list": cmdList(o)
  of "find": cmdFind(o)
  of "checkpoint": cmdCheckpoint(o)
  of "backup": cmdBackup(o)
  of "restore": cmdRestore(o)
  of "rekey": cmdRekey(o)
  else:
    fail("unknown command '" & o.command & "'; try `geist help`")
  result = 0

proc runGeistCli*(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name -> the exit code.
  ##
  ##   dispatchCli  ->  0                  the command did its job
  ##                ->  GeistCliFailure    "geist: <why>" on stderr, 1
  try:
    result = dispatchCli(argv)
  except GeistCliFailure as e:
    stderr.writeLine("geist: " & e.msg)
    result = 1

when isMainModule:
  quit(runGeistCli(commandLineParams()))
