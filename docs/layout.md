# Code layout

Geist is one library, `geist`, and one command line program, `geist`. This
file says where each piece lives and what it may import.

## 1. The shape of the repository

```text
  src/geist.nim               the facade: `import geist` gives the whole library
  src/geist/                  the modules, grouped below
  src/clients/geist_cli.nim   the `geist` entry point
  src/clients/cli/            common, direct, keys, tables (the CLI parts)
  evaluation/tests/           tests, one file per area (test_<area>.nim)
  evaluation/tests/modular/   storage_only.nim: proof of no network stack
  evaluation/benchmarks/      performance measurements
  examples/                   geist_<name>.nim, one idea each
  configs/                    default.toml, iot.toml, android.toml
  android/geistkeystore/      the Android keystore companion
  android/geistvault/        the Android keyring app
  docs/                       this folder
```

## 2. The one rule about imports

Storage modules import only storage modules and the pinned libraries in
docs/submodules.md. No storage module imports anything from the network
half, and `nimble checkModular` proves it: it compiles a program with
Bifrost removed from the search path. Within the library, the facade
`src/geist.nim` is the only file that lists the whole set.

## 3. What each module group is for

```text
  group            modules                        job
  ---------------  -----------------------------  -----------------------------
  data on disk     store, row, format, sidecar,   the packed-row file format,
                   durable, lease, backup         swapping generations safely
  rows by id       rowid, mapper, dynamic, row    identity and typed access
  encryption       keys, keystore, keyring,       sealed batches, key files,
                   crypto/*, secrets, seal        several stores with own keys
  reading          seek, collection, observe,     partial reads and watching
                   show, transpose                a store you do not own
  tables           tabletext, tableread,          JSON and TOML, round-trip
                   sessiontable, doc              safe
  settings         settings, config, layout       presets, defaults, folders
```

## 4. What is NOT here

The transport, peers, pins, relays, sync agents and daemons are in
Nebel-DecentralizedDB. A storage module that starts importing any of them
fails `nimble checkModular`.

## 5. A request, through the files

```text
  geist --path data/notes list
     |
     +-- cli/common     parse options, read userconfig [database]
     +-- cli/direct     cmdList: open the store
     |        |
     |        +-- session     open generation, check the lease
     |        +-- store       read the clusters
     |        +-- crypto/*    open sealed batches, if any
     |
     +-- cli/common     print rows (show)
```
