# Code layout

Where every file lives, and why it lives there rather than next door.

╭⟢ 1. The shape of the repository 🌊
├⟢ 2. The three halves 🐦‍🔥
├⟢ 3. Dependency levels inside the library 🍣
├⟢ 4. What each dependency is for ⟡
╰⟢ 5. How a request moves through the files ❖

## 1. The shape of the repository

```text
  Geist-Database/
  |
  +-- src/
  |   +-- geist.nim              the storage half, one import
  |   +-- geist/                 the library's own modules
  |   |   +-- crypto/            cipher, mac, batch, column
  |   +-- clients/               programs a person runs
  |   +-- server/                programs a machine runs
  |
  +-- evaluation/
  |   +-- tests/                 unit, edge case, regression, integration
  |   |   +-- modular/           proofs about what does NOT get compiled
  |   +-- benchmarks/            the Otter timing harness
  |   +-- statistics/            recorded measurements of this tree
  |
  +-- examples/                  runnable, and run by `nimble examples`
  +-- docs/                      this file and its neighbours
  +-- agents/PROGRESS.md         project state and handoff notes
  +-- nix/                       NixOS package, modules and VM tests
  +-- android/                   the Kotlin keystore companion
  +-- submodules/                every dependency, pinned
```

Three rules decide that picture, and there are no others.

**Def. 1 (evaluation).** Anything that measures the code rather than
being the code goes under `evaluation/`. Tests, benchmarks and recorded
statistics are three kinds of measurement, so they are three folders
under one roof.

**Def. 2 (a program vs. a library).** `src/geist/` is a library: it is
imported and it returns values. `src/clients/` and `src/server/` are
programs: they parse arguments, print, and exit. A program may import the
library; the library may never import a program.

**Def. 3 (a dependency lives in one place).** Every dependency is a git
submodule under `submodules/`. Nothing is vendored into `src/`, and
nothing is fetched at build time except `nimsimd`, which the nix package
pins by hash.

## 2. The three halves

Geist is one repository holding three things that are deliberately
separable. The `nimble check*` tasks below are not documentation about
this -- they FAIL THE BUILD when it stops being true.

```text
  +----------------------------------------------------------------+
  | part 1  STORAGE      import geist                               |
  |         rows, clusters, columns, generations, the lease         |
  |         compiles NO network stack, NO post-quantum KEM          |
  |         proved by: nimble checkModular                          |
  +----------------------------------------------------------------+
  | part 2  TRANSPORT    import geist/network                       |
  |         Query/Reply over Bifrost AME/DAC; the handshake         |
  |         needs part 1 for the row types only                     |
  +----------------------------------------------------------------+
  | part 3  RELAY        import geist/wire                          |
  |         the same transport with a pipe where the database is    |
  |         compiles NO database module at all                      |
  |         proved by: nimble checkRelay, nimble checkRouter        |
  +----------------------------------------------------------------+
```

Why the proofs exist rather than a comment: a program that relays voice
clips between two phones has no store to serve, and the moment it can
open a database somebody will give it one to open. The check reads the
generated C file names and fails if a storage module appears in a relay
build.

## 3. Dependency levels inside the library

Modules are ordered so that a reader can start at the top and never meet
a name that has not been defined yet. Level `n` may import level `n-1`
and below, never sideways within its own level, and never upward.

```text
  level 0   types.nim  secret.nim  format.nim  rowid.nim
            |  the vocabulary: what a Row is, what a Query is,
            |  how an integer becomes bytes
            v
  level 1   mapper.nim  durable.nim  lease.nim  sidecar.nim
            |  one job each, on top of the vocabulary
            v
  level 2   store.nim  row.nim  keys.nim  crypto/*
            |  the store itself and what protects it
            v
  level 3   session.nim  collection.nim  seek.nim  backup.nim
            |  what a caller actually holds and asks
            v
  level 4   masks.nim -> transport.nim -> network.nim
            |  the wire, which is the only part that knows Bifrost
            v
  level 5   clients/  server/
               programs
```

`masks.nim` is worth naming separately. It is the ONLY file in the
repository that decides anything about the transport -- which algorithms
sit in which slot, and which slots each strength level turns on.
Everything else about the wire is a Bifrost call. That is a deliberate
boundary: it means "what protects a session" is one file a reader can
hold in their head, not a property spread across a protocol stack.

## 4. What each dependency is for

```text
  submodule                   what Geist uses it for
  --------------------------  --------------------------------------
  Bifrost-ExchangeProtocols   the whole wire: AME handshake and
                              sessions, DAC datagrams, packaging
  Tyr-Crypto                  the primitives Bifrost's slots name
  Eir-CompressionAndECC       Reed-Solomon repair inside DAC packages
  Fylgia-Utils                shared helpers used across the workspace
  SIMD-Nexus                  vectorised search over column bytes
  Rune-Pragmas                `runePragmas`: the role and tag pragmas
                              every routine in the workspace declares
  Otter-RepoEvaluation        the benchmark harness and the measurement
                              behind evaluation/statistics/
```

All seven are pinned at the commits Bifrost itself pins, where they
overlap. That is not a preference: Nim takes the LAST matching `--path`
entry, so two copies of one dependency on the path means one of them is
silently ignored, and the one that loses is whichever the ordering
happens to disfavour. One copy, one commit, no ordering question.

## 5. How a request moves through the files

A remote `find` from a person's terminal to the bytes on another
machine's disk and back:

```text
  geist --at dac://host:9000 find title=hello
     |
     |  src/clients/geist_cli.nim      parse the command line
     v
  connectGeist(remote, identity, pin, policy)
     |
     |  src/geist/transport.nim        the handshake (see the README)
     |  src/geist/masks.nim            which algorithms, which tier
     |  Bifrost                        every cryptographic step
     v
  send(Query(op: qoFind, ...))
     |
     |  src/geist/transport.nim        encodeQuery -> bytes
     |                                 one frame, or a DAC package
     v
  ~~~~~~~~~~~~~~~ the network ~~~~~~~~~~~~~~~
     |
     v
  serveOnce(handler)
     |
     |  src/server/geistd.nim          the loop
     |  src/geist/transport.nim        open the frame, decodeQuery,
     |                                 work out this peer's rights
     v
  answerQuery(session, cursors, q, peer)
     |
     |  src/geist/answer.nim           which op, and is it allowed
     |  src/geist/seek.nim             scan the clusters
     |  src/geist/row.nim              read the columns out of a row
     v
  Reply  ->  encodeReply  ->  frames  ->  back the way it came
```

Two things that picture makes visible. The CLI never touches a cluster:
it only ever holds a `Query` and a `Reply`. And the handler is told WHO
is asking as a separate argument, so no code path can answer a request
without having looked at the asker's rights.
