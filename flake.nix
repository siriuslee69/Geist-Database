{
  description = "Geist: a packed-row, encrypted database on one machine";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # The storage library and its one CLI. Talking to other machines
      # (sync, relays, daemons, NixOS modules) is geist-sync's flake.
      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/default.nix { };
        geist = pkgs.callPackage ./nix/default.nix { };
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
    };
}
