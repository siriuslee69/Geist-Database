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

## Notes
- The `.gitmodules` file exists so the dependency chain is visible at the repo root.
- Local development uses lightweight workspace links in `submodules/` to keep the workspace lightweight.
- Run `nimble linkWorkspaceDeps` after cloning on NixOS/Linux if the placeholder links were created on Windows.
- `config.nims` resolves direct dependencies only through `submodules/`; local
  sibling checkouts must be linked or checked out there.
- `nix/default.nix` also defaults to `submodules/` so package builds use the
  same dependency revisions as the checked-out Geist repo.
- Production handoff should record every declared dependency as a gitlink.
- Ariadne-style search/ranking delegation is a future integration idea, not a
  required dependency of the current Geist build.
- Geist does not keep `nimsimd` as a direct submodule. Tyr-Crypto and
  SIMD-Nexus own that Nimble package dependency; the Nix package pins it as a
  build-only transitive path because the Nix build does not run `nimble
  install`.
