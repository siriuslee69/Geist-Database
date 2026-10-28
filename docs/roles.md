# What Geist Is For, and the Call for Each Job

Five jobs another program can hand to Geist, one call or one command each,
and where each one stops. Every row names a runnable example.

Jobs that cross a machine boundary -- sync, relays, daemons, forwarding --
are in the Nebel-DecentralizedDB repository, `docs/roles.md`.

## 1. The five roles

```text
  role                 import   the calls                       example
  -------------------  -------  -----------------------------  ---------------------
  write to disk        geist    openGeist, put, set,           geist_quickstart
                                delete, save
  read from disk       geist    byId, find, list, seek*;       geist_quickstart,
                                observeStore / followStore     geist_observe,
                                for a store you do not own     geist_fast_search
  convert data         geist    convertDoc, convertFile,       geist_convert;
                                toDocText, fromDocText         `geist convert`
  encrypt in memory    geist    sealObject / openObject,       geist_seal
                                sealWithKey / openWithKey,
                                ...WithPassword
  keep a table as a    geist    exportTable / importTable      geist_tables;
  file                          (JSON or TOML)                 `geist export`
```

**Def. 1 (a role).** A role is one kind of job with one entry point. A
program that needs two jobs calls two entry points; nothing else is
required.

**Def. 2 (the local CLI).** `geist` runs the same storage jobs from a
shell, on a database folder named by `--path`. It never opens a socket.

```text
  geist --path data/notes put title=hello
  geist --path data/notes list
  geist --path data/notes export notes.toml
```

## 2. Where it stops today

```text
  limit                    what it means
  -----------------------  ---------------------------------------------
  one writer per store     a second writer is refused by the write lease
                           (.geist-lock). Readers are never refused.
  nothing listens          Geist opens no socket. To let another machine
                           reach a store, use Nebel-DecentralizedDB.
  no streaming path        a single object is read and written whole
                           (sidecar). Multi-GB values wait for a streaming
                           path; see workloads.md.
  password, not hardware   at-rest keys are sealed with a password. The
                           Android keystore is a companion (keystore.md).
```
