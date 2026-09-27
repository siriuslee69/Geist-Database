# Third-Party Licenses

Geist's own code is covered by `LICENSE` (all rights reserved). This file
lists what a Geist build is made from that Geist did not write, and under
which terms. It records what was observed in the pinned submodules on
2026-09-27; the files inside each submodule are the authority.

## ╭⟢ What ends up inside a Geist program 🌊

```text
  component                   pinned at   license          how it gets in
  --------------------------  ----------  ---------------  -------------------------
  Bifrost-ExchangeProtocols   29915b7     all rights       compiled in (network half)
                                          reserved, same
                                          author as Geist
  Tyr-Crypto (its own code)   2f8d30c     Unlicense        compiled in
  Eir-CompressionAndECC       ed3ba8a     Unlicense        compiled in (via Bifrost)
  SIMD-Nexus                  efee3b4     Unlicense        compiled in
  Fylgia-Utils                9dc379d     Unlicense        compiled in (TOML reader)
  Rune-Pragmas                49d8868     Unlicense        compile time only
  Var-Invariants              83361e4     Unlicense        compile time only
  nimsimd                     1.3.2       MIT              compiled in
  Otter-RepoEvaluation        939f066     Unlicense        benchmarks and statistics
                                                           only; not in any program
  Nimble-Tasks                d0c09da     Unlicense        build tasks only
```

## ╭⟢ What a Geist program loads when it runs 🐦‍🔥

```text
  component   license   when
  ----------  --------  ----------------------------------------------------
  libsodium   ISC       loaded by Tyr at start-up when built with
                        -d:hasLibsodium (configs/default.toml). Not shipped
                        with Geist: the operating system provides it
                        (nix/default.nix wraps pkgs.libsodium; on Windows,
                        libsodium.dll beside the program).
```

## ╭⟢ What Geist does NOT compile ❖

Tyr-Crypto pins further submodules -- libsodium (ISC), liboqs (MIT, with
per-scheme licenses inside), OpenSSL (Apache-2.0), PQClean (CC0-1.0, with
per-scheme files). Geist builds only Tyr's own Nim code and none of those
trees. `submodules/Tyr-Crypto/THIRD_PARTY_LICENSES.md` describes them for
anyone who builds Tyr differently.

Geist clones its submodules ONE level deep (`git submodule update
--init`, not `--recursive`), so those nested trees are not even checked
out by a normal Geist clone.

## ╭⟢ nimsimd notice (MIT) 🍣

```text
Copyright (c) 2020 Ryan Oldenburg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

The full text, including the warranty disclaimer, is
`submodules/nimsimd/LICENSE`.
