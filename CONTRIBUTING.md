# Contributing to Geist

## What this repository is

A Nim library (`src/geist.nim`), two command line clients (`geist`,
`geist-relay`) and three daemons (`geistd`, `geist-relayd`,
`geist-routed`). Nothing else. If you are looking for the browser
extension, the Koerper/Schatten/Spur records or the `protocols/` tree,
they belonged to the implementation replaced in commit `047a776` and are
not coming back.

```
src/geist.nim              public facade -- the only import an app needs
src/geist/                 the library, ordered by dependency depth
src/geist/crypto/          cipher, mac, batch, column
src/clients/geist_cli.nim  the geist client
src/server/geistd.nim      the geistd daemon
src/clients/geist_relay.nim   the geist-relay client
src/server/geist_relayd.nim   the geist-relayd message relay
src/server/geist_routed.nim   the geist-routed request router
configs/default.toml         the ONE settings file; presets beside it
evaluation/tests/test_*.nim   one file per area, found by `nimble test`
evaluation/benchmarks/       Otter benchmark harness
agents/PROGRESS.md           project state and handoff notes
examples/                  runnable, and run by `nimble runExamples`
```

`docs/layout.md` says where every file lives and why it lives there
rather than next door. `docs/evaluation.md` covers the tests, the
benchmarks and the recorded statistics, including how to declare what a
test is for.

`docs/DESIGN_RATIONALE.md` answers "why is it like this?" with the number
that drove each decision. Read it before proposing a change to the
format, the crypto or the transport — most of the obvious alternatives
are in there with the measurement that ruled them out.

## Before you push

```bash
nimble test          # every suite; must be green
nimble runExamples   # all five must run
nimble demoCli       # exercises the CLI end to end
nimble checkAll      # compile-check every public module
nimble buildAll      # build all five programs for release
nimble checkModular  # the storage half must build with no network stack
nimble checkRelay    # the wire half must build with no database in it
nimble checkRouter   # the router must build with no database in it
nimble checkForward  # the forwarder must build with no store and no handshake
```

Those two are the ones that fail silently in review otherwise, and they
guard the same line from opposite sides. `checkModular` compiles a
disk-only program with Bifrost removed from the search path, so adding a
network import to anything under the storage half breaks it. `checkRelay`
compiles a relay and then reads the C files the compiler emitted, so
adding a storage import to anything under the wire half breaks it — an
import three modules deep is exactly the kind that gets added without
anyone noticing. If you need a transport type in a storage module, or a
row in a wire module, the module belongs on the other side of the line —
see the headers of `src/geist/network.nim` and `src/geist/wire.nim`.

A change to a daemon, a NixOS module or anything two machines have to
agree on also needs the VM tests, which boot real guests and need KVM:

```bash
nix build .#checks.x86_64-linux.two-desktop-exchange -L
nix build .#checks.x86_64-linux.three-desktop-relay -L
nix build .#checks.x86_64-linux.relay-pipe -L
```

A change to public behaviour needs a test in the same commit. A change to
the format, the wire or the on-disk layout needs the reasoning added to
`docs/DESIGN_RATIONALE.md` — a decision without its "why" is a decision
someone will undo next year.

## House style

The full set lives in the workspace `Agent-Conventions` repo and is read
from there rather than copied here, because a copy drifts. The parts you
will hit immediately:

- **No `let`.** `var` or `const`, declared in an indented block at the
  top of the proc, one name per line with an explicit type.
- **No nested loops or nested `if`s.** Extract a helper instead.
- **Every proc carries `{.role: ..., tag: "...".}`** from `runePragmas`,
  the one shared module in the `Rune-Pragmas` repo (pinned here at
  `submodules/Rune-Pragmas`). Tags are plain strings separated by `|`.
  It is `tag`, not `tags`: Nim owns the plural for effect tracking.
- **Every parameter is doc-commented** on `##` lines under the
  declaration, by role: `A` for arrays, `S` for mutated state, `i,j,k`
  indices, `l,m,n` lengths, `t` temporary.
- **Modules are ordered by dependency level** and stay small. If a module
  is doing two jobs, split it.
- Comments say **why**, never what. A comment restating the code is
  worse than none.

## Two rules that are not style

**Do not store what can be derived.** A stored byte that duplicates a
derivable fact can disagree with it — that is why `Slot` has a width and
not an offset, why the index has no layout byte, and why row identity is
detected from the schema's own columns rather than from a flag.

**Do not acknowledge what is not durable.** A reply that leaves this
machine saying a row was stored must mean it: the peer will not send it
again. See `commitRemote` in `src/geist/answer.nim`.

## Dependencies

Everything lives in `submodules/` as a git submodule and is wired in
`config.nims`. Do not vendor, copy or reimplement a dependency — the
previous implementation rebuilt Bifrost's replay cache, framing and
packaging on top of Bifrost, and that is a large part of why it was
replaced.

```text
  where a thing goes             file
  -----------------------------  ------------------------------------------
  a new dependency               git submodule add ... submodules/<Name>,
                                 then one line in config.nims (pinnedDeps)
  a compiler flag or -d: switch  configs/default.toml [nim] / [define]
  a start value the program      configs/default.toml [runtime.<table>],
    reads                        plus its reader in src/geist/*settings.nim
  a build for one kind of        a new configs/<name>.toml holding ONLY
    machine                      what differs from default.toml
  a task every repo could use    Nimble-Tasks, not geist_database.nimble
  a task only Geist needs        geist_database.nimble
```

`docs/submodules.md` says which copy of each dependency the compiler sees
and how pins move.
