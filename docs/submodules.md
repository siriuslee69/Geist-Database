# Geist Workspace Dependencies

The `submodules/` folder mirrors the shared sibling-repo workspace layout.
Each dependency entry is expected to be one of these local-development forms:

- Windows: NTFS junction
- Linux/NixOS/macOS: symlink
- release/provenance handoff: real git submodule checkout

## Direct Dependencies
- `Fylgia-Utils`
- `SIMD-Nexus`
- `Tyr-Crypto`
- `Eir-CompressionAndECC`
- `Bifrost-ExchangeProtocols`
- `Rune-Pragmas` -- the one shared pragma module. Every `.nim` file in
  this tree says `import runePragmas`, so a checkout without it compiles
  nothing at all.

## Notes
- The `.gitmodules` file exists so the dependency chain is visible at the repo root.
- Local development uses lightweight workspace links in `submodules/` to keep the workspace lightweight.
- `config.nims` resolves direct dependencies only through `submodules/`; local
  sibling checkouts must be linked or checked out there.
- `nix/default.nix` also defaults to `submodules/` so package builds use the
  same dependency revisions as the checked-out Geist repo.
- Production handoff should record every declared dependency as a gitlink.
- **Pins are aligned with Bifrost.** Where Geist and Bifrost both depend on
  something -- Tyr, Eir, Fylgia, SIMD, Otter, Rune-Pragmas -- both pin the
  SAME commit. This is not a preference. Nim takes the LAST matching
  `--path` entry, so two copies of one dependency on the path means one is
  silently ignored, and which one loses depends on ordering nobody
  controls. Geist's Eir once predated the `RsCodec` type Bifrost needed,
  and the symptom was Bifrost's own file failing to compile inside Geist's
  build. When bumping Bifrost, bump the shared pins to match it.
- Ariadne-style search/ranking delegation is a future integration idea, not a
  required dependency of the current Geist build.
- Geist does not keep `nimsimd` as a direct submodule. Tyr-Crypto and
  SIMD-Nexus own that Nimble package dependency; the Nix package pins it as a
  build-only transitive path because the Nix build does not run `nimble
  install`.
