# Contributing to Geist

Geist is the storage library: rows, files, keys, backups, sealing and the
local `geist` command line. Anything that talks to another machine belongs
in [Nebel-DecentralizedDB](https://github.com/siriuslee69/Nebel-DecentralizedDB),
which imports this repository. Do not add a socket, a peer or a daemon here.

## Where code goes

```text
  a row, a file, a key, a backup, a seal         src/geist/
  a new public function for a caller             src/geist.nim (facade) + its module
  a local command                                src/clients/cli/  (common, direct, keys, tables)
  a storage test                                 evaluation/tests/test_<area>.nim
  a storage example                              examples/geist_<name>.nim
```

## Before you report a change done

```sh
nimble checkAll          every module compiles
nimble checkModular      the storage half still builds with no Bifrost on the path
nimble test              the whole suite, exit 0
```

`nimble checkModular` is the one that matters most. It fails when a storage
module starts importing anything from the network half.

## Rules that apply here

- Functions carry the custom pragmas (`role`, `tag`, `stage`, ...). Shared
  pragmas live in Rune-Pragmas, shared contracts in Var-Invariants.
- A settings key is part of a schema. An unknown key is an error, never a
  silent ignore. Add a key to the reader and to the template in the same change.
- Dependencies come from pinned submodules. Do not add a dependency on
  Bifrost or any network package to this repository.

## Commits

One change per commit, with a message that says what changed and why. Keep
`agents/PROGRESS.md` current in the same commit.
