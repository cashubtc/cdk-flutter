{
  description = "CDK Flutter - Flutter bindings for the Cashu Development Kit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-analyzer-src.follows = "";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , rust-overlay
    , flake-utils
    , ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        lib = pkgs.lib;

        # Rust toolchain - latest stable with useful extensions
        stable_toolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
            "rust-analyzer"
          ];
        };

        # Build inputs shared across shells
        buildInputs = with pkgs; [
          # Rust toolchain
          stable_toolchain
          cargo-expand

          # Flutter SDK and Dart
          flutter

          # Flutter Rust Bridge codegen (v2.11.1 from nixpkgs)
          flutter_rust_bridge_codegen

          # Build tools
          just
          pkg-config
          cmake
          ninja
          clang

          # Rust crate native dependencies
          openssl
          sqlite
          zlib

          # Flutter Linux desktop dependencies (GTK3)
          gtk3
          glib
          pcre2
          util-linux
          libselinux
          libsepol
          libthai
          libdatrie
          libxkbcommon
          xorg.libXdmcp
          lerc
          libepoxy

          # Additional libraries for Flutter Linux runner
          at-spi2-atk
          dbus
        ];

      in
      {
        devShells = {
          default = pkgs.mkShell {
            inherit buildInputs;

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            shellHook = ''
              # Ensure pkg-config can find GTK and other system libraries
              export LD_LIBRARY_PATH=${
                lib.makeLibraryPath (with pkgs; [
                  gtk3
                  glib
                  zlib
                  openssl
                  sqlite
                  libepoxy
                ])
              }:$LD_LIBRARY_PATH

              echo ""
              echo "CDK Flutter development shell"
              echo "  Rust:    $(rustc --version)"
              echo "  Flutter: $(flutter --version --machine 2>/dev/null | head -1 || echo 'run flutter --version')"
              echo "  FRB:     $(flutter_rust_bridge_codegen --version 2>/dev/null || echo 'available')"
              echo ""
              echo "Common commands:"
              echo "  just setup     - Install deps and build Rust"
              echo "  just generate  - Regenerate FRB bindings"
              echo "  just build     - Build Rust library"
              echo "  just run       - Run example app (Linux)"
              echo "  just check     - Run all checks"
              echo ""
            '';

            # Environment variables
            NIX_PATH = "nixpkgs=${inputs.nixpkgs}";
          };
        };
      }
    );
}
