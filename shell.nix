{ pkgs ? import <nixpkgs> {} }:

let
  sodiumLibPath = pkgs.lib.makeLibraryPath [ pkgs.libsodium ];
in
pkgs.mkShell {
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
    nodejs
    powershell
  ];

  shellHook = ''
    export CC=${pkgs.gcc}/bin/gcc
    export AR=${pkgs.binutils}/bin/ar
    export LIBSODIUM_LIB_DIRS=${pkgs.libsodium}/lib
    export LD_LIBRARY_PATH=${sodiumLibPath}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    echo "Geist Nix shell ready."
    echo "libsodium: $LIBSODIUM_LIB_DIRS"
  '';
}
