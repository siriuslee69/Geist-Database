# Geist's Dependencies

Every dependency is a git submodule under `submodules/`, pinned to one
commit. A fresh clone needs one command and nothing from `nimble install`:

```sh
git clone https://github.com/siriuslee69/Geist-Database.git
cd Geist-Database
git submodule update --init          # ONE level. Not --recursive.
```

Not `--recursive`: several dependencies pin their own copies of each
other (Bifrost pins Tyr, Tyr pins SIMD-Nexus, ...). Geist never reads those
nested copies, and cloning them costs minutes and gigabytes for nothing.

╭⟢ 1. What each one is for 🌊
├⟢ 2. Which copy the compiler sees 🐦‍🔥
├⟢ 3. How pins move 🍣
╰⟢ 4. Nix ⟡

## 1. What each one is for

```text
  submodule                  kind      what Geist uses it for
  -------------------------  --------  ---------------------------------------
  Bifrost-ExchangeProtocols  code      AME handshake, DAC frames, sessions
  Tyr-Crypto                 code      ciphers, MACs, hashes, signatures, KEMs
  Eir-CompressionAndECC      code      Reed-Solomon (through Bifrost's DAC)
  SIMD-Nexus                 code      vector helpers under Tyr and Eir
  Fylgia-Utils               code      the TOML parser (parseTomlNode)
  nimsimd                    code      third-party; SIMD intrinsics for the
                                       two above. Pinned at release 1.3.2
  Otter-RepoEvaluation       code      otterBench timing in the benchmark;
                                       the statistics tasks
  Rune-Pragmas               tooling   {.role:, tag:, ...} -- every .nim file
                                       imports runePragmas
  Var-Invariants             tooling   needs / gives / keeps contracts
  Nimble-Tasks               tooling   shared nimble tasks + the reader for
                                       configs/*.toml
```

## 2. Which copy the compiler sees

`config.nims` puts exactly ONE copy of each on the Nim path. Nim takes the
LAST matching `--path` entry, so two copies of one module would silently
lose one of them, and which one loses depends on ordering nobody controls.

```text
  kind      first choice                     fallback
  --------  -------------------------------  ---------------------------
  code      submodules/<name>/src            (none -- a missing pin is
                                             an import error, on purpose)
  tooling   ../<name> beside this repo       submodules/<name>
```

Code comes ONLY from the pin, so the build on this machine is the build a
fresh clone gets. Tooling prefers a sibling clone, so an edit to a shared
pragma or task reaches every repository in the workspace at once.

To prove nothing leaks in from `~/.nimble`:

```sh
nim c --noNimblePath src/clients/geist_cli.nim
```

## 3. How pins move

```sh
nimble updateSubmodules      # every pin -> newest main, one commit
nimble submoduleStatus       # what each is pinned to now
```

`nimsimd` is listed in `frozenSubmodules` in `geist_database.nimble`, so
`updateSubmodules` leaves it at its release tag. It is someone else's
project; its master branch is not a release.

After moving pins, run the whole suite (`nimble test`). The pins do NOT
have to equal the ones Bifrost records for its own nested copies -- those
nested copies are never on Geist's path. What has to hold is that
Bifrost's code compiles and passes against the Tyr and Eir Geist pins,
and the suite is what checks that.

The last move (2026-09-27):

```text
  Bifrost  95a3ef2 -> 29915b7   Tyr    00590e2 -> 2f8d30c
  Eir      d8c8f45 -> ed3ba8a   Fylgia b049df1 -> 9dc379d
  SIMD     ba8db37 -> efee3b4   Otter  3a38b49 -> 939f066
  Rune     1ae792d -> 49d8868
  new:     Nimble-Tasks d0c09da, Var-Invariants 83361e4, nimsimd 1.3.2
```

Bifrost's old pin, 95a3ef2 (carrier pairing), was never pushed and is not
in Bifrost's history since. It is kept on a local branch named
`carrier-pairing` in `submodules/Bifrost-ExchangeProtocols` and in the
sibling Bifrost clone.

## 4. Nix

`nix/default.nix` defaults every source to `../submodules/<name>`, so a
package build uses the same commits as the checkout. Override the `*Src`
arguments only for a deliberate local experiment.
