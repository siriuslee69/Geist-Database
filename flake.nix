{
  description = "Geist Database";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/default.nix { };
        geist = pkgs.callPackage ./nix/default.nix { };
      });

      # All three run real NixOS guests over a real network.
      # `two-desktop-exchange` is the common case -- two machines swapping
      # rows; `three-desktop-relay` proves the middle machine of a chain is
      # not special; `relay-pipe` proves the other use of the same
      # transport, moving messages with no database anywhere in sight.
      checks = forAllSystems (pkgs:
        let
          geistPackage = pkgs.callPackage ./nix/default.nix { };
          args = { inherit geistPackage; module = ./nix/module.nix; };
        in
        {
          two-desktop-exchange =
            pkgs.callPackage ./nix/tests/two-desktop-exchange.nix args;
          three-desktop-relay =
            pkgs.callPackage ./nix/tests/three-desktop-relay.nix args;
          relay-pipe = pkgs.callPackage ./nix/tests/relay-pipe.nix {
            inherit geistPackage;
            relayModule = ./nix/relay-module.nix;
          };
        });

      devShells = forAllSystems (pkgs:
        let
          sodiumLibPath = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nim
              git
              gcc
              binutils
              gnumake
              pkg-config
              cmake
              autoconf
              automake
              libtool
              zig
              libsodium
            ];

            shellHook = ''
              export CC=${pkgs.gcc}/bin/gcc
              export AR=${pkgs.binutils}/bin/ar
              export LIBSODIUM_LIB_DIRS=${pkgs.libsodium}/lib
              export LD_LIBRARY_PATH=${sodiumLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
              echo "Geist Nix shell ready."
              echo "libsodium: $LIBSODIUM_LIB_DIRS"
            '';
          };
        });

      nixosModules.default = import ./nix/module.nix;
      nixosModules.geistd = import ./nix/module.nix;
      nixosModules.geist-client = import ./nix/module.nix;
      # The relay is its own module: a machine that only moves messages
      # has no database options to answer for.
      nixosModules.geist-relay = import ./nix/relay-module.nix;
    };
}
