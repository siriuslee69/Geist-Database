# Geist's Dependencies

Geist is a library and one CLI. Its dependencies are pinned submodules, one
level deep. There is no network dependency: Bifrost belongs to
Nebel-DecentralizedDB.

## 1. What each one is for

```text
  submodule                    what Geist uses it for
  ---------------------------  ------------------------------------------------
  Tyr-Crypto                   the cipher, MAC, hash and KDF families
  Fylgia-Utils                 TOML and JSON reading, shared helpers
  SIMD-Nexus                   vector helpers that Tyr's SIMD paths import
  nimsimd                      SIMD bindings, pinned at 1.3.2
  Eir-CompressionAndECC        compression at rest (kept; not yet imported)
  Rune-Pragmas                 the shared role/tag pragmas (sibling clone wins)
  Var-Invariants               needs / gives / keeps contracts (sibling wins)
  Nimble-Tasks                 the shared nimble tasks (sibling wins)
  Otter-RepoEvaluation         repository statistics, benchmarks
```

## 2. Which copy the compiler sees

`config.nims` puts one copy of each on the Nim path, and only that copy:

```text
  submodules/<name>/src     pinned, always used for code Geist runs
  ../Rune-Pragmas/meta      sibling clone if it exists, else the submodule
  ../Var-Invariants/src     sibling clone if it exists, else the submodule
```

Nim takes the LAST matching `--path`, so adding both copies would silently
reverse the preference. The file keeps exactly one.

## 3. How pins move

```sh
git submodule update --init        # one level, NOT --recursive
```

A pin moves in its own commit, with the reason in the message. A change in
Geist that needs a newer dependency is two commits: the dependency's pin,
then the code that uses it.

## 4. Nix

`nix/default.nix` takes each submodule's source as an argument and builds the
`geist` CLI from them. The same list is in `flake.nix`.
