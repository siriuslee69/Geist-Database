# Geist on NixOS

Geist builds as a library and one command line program, from the pinned
submodules. It has no NixOS service: the services (daemons, relays,
forwarders) are in Nebel-DecentralizedDB, which imports this repository.

## The package

```sh
nix-build nix/default.nix        # result/bin/geist
./result/bin/geist help
```

`nix/default.nix` copies the tree, links each submodule into it, and runs
`nim c` on `src/clients/geist_cli.nim`. Name and version come from
`configs/default.toml` `[project]`, the same table the nimble file reads.

Compiler flags are NOT in the Nix file. `config.nims` applies
`configs/default.toml` `[nim]` and `[define]` to every call, so a package
built here is built the same way the test suite runs.

## The development shell

```sh
nix develop                       # nim, gcc, libsodium and the rest
nimble test
```

## Checks

```text
  command                 what it proves
  ----------------------  --------------------------------------------------
  nimble checkAll         every storage module compiles
  nimble checkModular     a storage program builds with Bifrost not on the path
  nimble test             the whole suite
  nimble runExamples      every example runs
```

CI runs these on Windows and in a Nix shell (`.github/workflows/ci.yml`).
