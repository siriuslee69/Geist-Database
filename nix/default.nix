{ pkgs ? import <nixpkgs> {}
, fylgiaUtilsSrc ? ../submodules/Fylgia-Utils
, simdNexusSrc ? ../submodules/SIMD-Nexus
, tyrCryptoSrc ? ../submodules/Tyr-Crypto
, eirCompressionAndEccSrc ? ../submodules/Eir-CompressionAndECC
, bifrostExchangeProtocolsSrc ? ../submodules/Bifrost-ExchangeProtocols
# The one shared pragma module for the whole workspace. Every `.nim` file
# in this tree and in its dependencies says `import runePragmas`, so a
# build without it does not compile a single module.
, runePragmasSrc ? ../submodules/Rune-Pragmas
# Shared nimble tasks and the build-preset reader config.nims includes.
, nimbleTasksSrc ? ../submodules/Nimble-Tasks
# needs/gives/keeps, the shared contract pragmas.
, varInvariantsSrc ? ../submodules/Var-Invariants
# Pinned at its 1.3.2 release tag, like the submodule.
, nimsimdSrc ? ../submodules/nimsimd
}:

let
  lib = pkgs.lib;
  filterRepoSource = src:
    let
      root = toString src;
      relPath = path:
        let
          pathStr = toString path;
        in
        if pathStr == root then
          ""
        else
          lib.removePrefix (root + "/") pathStr;
    in
    lib.cleanSourceWith {
      inherit src;
      filter = path: type:
        let
          rel = relPath path;
        in
        lib.cleanSourceFilter path type &&
        rel != "submodules" &&
        !(lib.hasPrefix "submodules/" rel) &&
        rel != "build" &&
        !(lib.hasPrefix "build/" rel) &&
        rel != "builds" &&
        !(lib.hasPrefix "builds/" rel) &&
        rel != "nimcache" &&
        !(lib.hasPrefix "nimcache/" rel) &&
        rel != "result";
    };

  filterDependencySource = src:
    let
      root = toString src;
      relPath = path:
        let
          pathStr = toString path;
        in
        if pathStr == root then "" else lib.removePrefix (root + "/") pathStr;
    in
    lib.cleanSourceWith {
      inherit src;
      filter = path: type:
        let
          rel = relPath path;
        in
        lib.cleanSourceFilter path type &&
        (rel == "" || rel == "src" || lib.hasPrefix "src/" rel ||
          rel == "meta" || lib.hasPrefix "meta/" rel);
    };

  filteredSrc = filterRepoSource ../.;
  filteredFylgiaUtilsSrc = filterDependencySource fylgiaUtilsSrc;
  filteredSimdNexusSrc = filterDependencySource simdNexusSrc;
  filteredTyrCryptoSrc = filterDependencySource tyrCryptoSrc;
  filteredEirCompressionAndEccSrc = filterDependencySource eirCompressionAndEccSrc;
  filteredBifrostExchangeProtocolsSrc =
    filterDependencySource bifrostExchangeProtocolsSrc;
  filteredRunePragmasSrc = filterDependencySource runePragmasSrc;
  filteredNimbleTasksSrc = filterDependencySource nimbleTasksSrc;
  filteredVarInvariantsSrc = filterDependencySource varInvariantsSrc;
  filteredNimsimdSrc = filterDependencySource nimsimdSrc;

  # Name and version come from ONE place, the same table the .nimble file
  # reads: [project] in configs/default.toml.
  project = (builtins.fromTOML (builtins.readFile ../configs/default.toml)).project;

  geistSrc = pkgs.runCommand "geistd-source" {} ''
    mkdir -p "$out"
    cp -R ${filteredSrc}/. "$out/"
    chmod -R u+w "$out"
    mkdir -p "$out/submodules"

    # Rebuild source-store links for declared dependencies after filtering the
    # root source tree's submodules/ directory.
    ln -s ${filteredFylgiaUtilsSrc} "$out/submodules/Fylgia-Utils"
    ln -s ${filteredSimdNexusSrc} "$out/submodules/SIMD-Nexus"
    ln -s ${filteredTyrCryptoSrc} "$out/submodules/Tyr-Crypto"
    ln -s ${filteredEirCompressionAndEccSrc} "$out/submodules/Eir-CompressionAndECC"
    ln -s ${filteredBifrostExchangeProtocolsSrc} "$out/submodules/Bifrost-ExchangeProtocols"
    ln -s ${filteredRunePragmasSrc} "$out/submodules/Rune-Pragmas"
    ln -s ${filteredNimbleTasksSrc} "$out/submodules/Nimble-Tasks"
    ln -s ${filteredVarInvariantsSrc} "$out/submodules/Var-Invariants"
    ln -s ${filteredNimsimdSrc} "$out/submodules/nimsimd"
  '';
in
pkgs.stdenv.mkDerivation {
  pname = project.name;
  version = project.version;
  src = geistSrc;

  nativeBuildInputs = [
    pkgs.nim
    pkgs.makeWrapper
  ];

  buildInputs = [
    pkgs.libsodium
  ];

  # No compiler flags here: config.nims applies configs/default.toml
  # ([nim] mm/threads, [define] hasLibsodium) to every call, exactly as it
  # does for the nimble tasks. A package built with different flags from the
  # ones the suite runs under is a package nothing has actually tested.
  buildPhase = ''
    export HOME=$TMPDIR
    nim c -d:release --hints:off --out:geistd src/server/geistd.nim
    nim c -d:release --hints:off --out:geist src/clients/geist_cli.nim
    # The relay pair: the same transport with a pipe where the database
    # would be. Separate binaries because they are a separate deployment --
    # a machine relaying voice clips has no store to serve.
    nim c -d:release --hints:off --out:geist-relayd src/server/geist_relayd.nim
    nim c -d:release --hints:off --out:geist-relay src/clients/geist_relay.nim
    nim c -d:release --hints:off --out:geist-routed src/server/geist_routed.nim
    nim c -d:release --hints:off --out:geist-forwardd src/server/geist_forwardd.nim
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp geistd $out/bin/geistd
    cp geist $out/bin/geist
    cp geist-relayd $out/bin/geist-relayd
    cp geist-relay $out/bin/geist-relay
    cp geist-routed $out/bin/geist-routed
    cp geist-forwardd $out/bin/geist-forwardd
    for prog in geistd geist geist-relayd geist-relay geist-routed geist-forwardd; do
      wrapProgram $out/bin/$prog \
        --set LIBSODIUM_LIB_DIRS ${pkgs.libsodium}/lib \
        --prefix LD_LIBRARY_PATH : ${pkgs.libsodium}/lib
    done
  '';

  meta = {
    description = project.description;
    mainProgram = "geist";
    platforms = lib.platforms.linux;
  };
}
