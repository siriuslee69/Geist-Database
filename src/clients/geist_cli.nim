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
## The code is in five parts under src/clients/cli/:
##
##   common   options, userconfig, opening a store, printing rows
##   direct   commands that open the files in this process (--path)
##   remote   commands sent to a running geistd (--remote), and sync
##   keys     the key folder (`geist keys ...`)
##   tables   export and import: the database as a JSON or TOML file
##
## This file holds only the entry point: which part answers which command.

import std/os

import runePragmas
import ../geist/network
import ./cli/common
import ./cli/direct
import ./cli/remote
import ./cli/keys
import ./cli/tables

export common

## ----------------------------- commands -----------------------------
##
##   anyMode     answered first, whatever --path / --remote say. `sync` is
##               here because it is BOTH: it reads a peer and writes this
##               database, so it belongs to neither of the other two.
##   remote      with --remote, every other command becomes a Query
##   directOnly  without it, the files are opened in this process

type
  Command {.role: configurator, tag: "cli|types".} = object
    ## One word typed after `geist`, and what answers it.
    name: string
    run: proc(o: Options) {.nimcall.}

const
  anyMode: array[5, Command] = [
    Command(name: "convert", run: cmdConvert),
    Command(name: "presets", run: cmdPresets),
    Command(name: "keygen", run: cmdKeygen),
    Command(name: "keys", run: cmdKeys),
    Command(name: "sync", run: cmdSync)]
  directOnly: array[22, Command] = [
    Command(name: "inspect", run: cmdInspect),
    Command(name: "verify", run: cmdVerify),
    Command(name: "schema", run: cmdSchema),
    Command(name: "info", run: cmdInfo),
    Command(name: "init", run: cmdInit),
    Command(name: "put", run: cmdPut),
    Command(name: "set", run: cmdSet),
    Command(name: "delete", run: cmdDelete),
    Command(name: "del", run: cmdDelete),
    Command(name: "rm", run: cmdDelete),
    Command(name: "compact", run: cmdCompact),
    Command(name: "sweep", run: cmdSweep),
    Command(name: "transpose", run: cmdTranspose),
    Command(name: "get", run: cmdGet),
    Command(name: "list", run: cmdList),
    Command(name: "find", run: cmdFind),
    Command(name: "checkpoint", run: cmdCheckpoint),
    Command(name: "backup", run: cmdBackup),
    Command(name: "restore", run: cmdRestore),
    Command(name: "rekey", run: cmdRekey),
    Command(name: "export", run: cmdExport),
    Command(name: "import", run: cmdImport)]

proc commandAt(C: openArray[Command], name: string): int {.role: parser,
    tag: "cli|parsing".} =
  ## C/name: where `name` is in the table, or -1.
  var
    i: int = 0
  while i < C.len:
    if C[i].name == name:
      return i
    i = i + 1
  result = -1

## ------------------------------ entry -------------------------------

proc dispatchCli(argv: seq[string]): int {.role: metaOrchestrator,
    tag: "cli|entrypoint|orchestrator".} =
  ## argv: command line without the executable name.
  var
    o: Options = parseOptions(argv)
    defaults: tuple[ok: bool, err: string] = (false, "")
    at: int = -1
  if o.command.len == 0 or o.command == "help":
    echo usageText
    return 0
  # A userconfig.toml fills in what was not typed, and nothing more.
  o = withUserConfig(o)
  # configs/default.toml carries the library defaults every preset is adjusted by.
  defaults = initGeistNetworkDefaults()
  if not defaults.ok:
    fail(defaults.err)
  at = anyMode.commandAt(o.command)
  if at >= 0:
    anyMode[at].run(o)
    return 0
  if o.mode == mRemote:
    runRemote(o, remoteQuery(o))
    return 0
  at = directOnly.commandAt(o.command)
  if at < 0:
    fail("unknown command '" & o.command & "'; try `geist help`")
  directOnly[at].run(o)
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
