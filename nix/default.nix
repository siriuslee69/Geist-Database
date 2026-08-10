{ pkgs ? import <nixpkgs> {}
, fylgiaUtilsSrc ? ../submodules/Fylgia-Utils
, simdNexusSrc ? ../submodules/SIMD-Nexus
, tyrCryptoSrc ? ../submodules/Tyr-Crypto
, eirCompressionAndEccSrc ? ../submodules/Eir-CompressionAndECC
, bifrostExchangeProtocolsSrc ? ../submodules/Bifrost-ExchangeProtocols
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
          rel == ".iron" || rel == ".iron/meta" ||
          lib.hasPrefix ".iron/meta/" rel);
    };

  filteredSrc = filterRepoSource ../.;
  filteredFylgiaUtilsSrc = filterDependencySource fylgiaUtilsSrc;
  filteredSimdNexusSrc = filterDependencySource simdNexusSrc;
  filteredTyrCryptoSrc = filterDependencySource tyrCryptoSrc;
  filteredEirCompressionAndEccSrc = filterDependencySource eirCompressionAndEccSrc;
  filteredBifrostExchangeProtocolsSrc =
    filterDependencySource bifrostExchangeProtocolsSrc;
  nimsimdSrc = pkgs.fetchFromGitHub {
    owner = "guzba";
    repo = "nimsimd";
    rev = "3f6b2668ffb0867d0bf786a658b817763e611350";
    hash = "sha256-FO7ty/NIE/fNfGiiEaoAHLEb26fQCqai5V0ERYbEPTs=";
  };

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
    ln -s ${nimsimdSrc} "$out/submodules/nimsimd"
  '';
in
pkgs.stdenv.mkDerivation {
  pname = "geistd";
  version = "0.1.0";
  src = geistSrc;

  nativeBuildInputs = [
    pkgs.nim
    pkgs.makeWrapper
  ];

  buildInputs = [
    pkgs.libsodium
  ];

  # The SAME flags the nimble tasks use. A package built with a different
  # memory model from the one the suite runs under is a package nothing has
  # actually tested.
  buildPhase = ''
    export HOME=$TMPDIR
    nim c -d:release --mm:orc --threads:on --hints:off \
      --path:${nimsimdSrc}/src --out:geistd src/server/geistd.nim
    nim c -d:release --mm:orc --threads:on --hints:off \
      --path:${nimsimdSrc}/src --out:geist src/clients/geist_cli.nim
    # The relay pair: the same transport with a pipe where the database
    # would be. Separate binaries because they are a separate deployment --
    # a machine relaying voice clips has no store to serve.
    nim c -d:release --mm:orc --threads:on --hints:off \
      --path:${nimsimdSrc}/src --out:geist-relayd src/server/geist_relayd.nim
    nim c -d:release --mm:orc --threads:on --hints:off \
      --path:${nimsimdSrc}/src --out:geist-relay src/clients/geist_relay.nim
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp geistd $out/bin/geistd
    cp geist $out/bin/geist
    cp geist-relayd $out/bin/geist-relayd
    cp geist-relay $out/bin/geist-relay
    for prog in geistd geist geist-relayd geist-relay; do
      wrapProgram $out/bin/$prog \
        --set LIBSODIUM_LIB_DIRS ${pkgs.libsodium}/lib \
        --prefix LD_LIBRARY_PATH : ${pkgs.libsodium}/lib
    done
  '';

  meta = {
    description = "Packed-row, cluster-addressed encrypted database and its daemon";
    mainProgram = "geist";
    platforms = lib.platforms.linux;
  };
}
