{
  description = "mips64rt — MIPS64r2 to AArch64 Linux user-mode translator dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        pkgs.mkShell {
          packages = [
            pkgs.gnumake
            pkgs.pkgsCross.aarch64-multiplatform-musl.stdenv.cc
          ];
          shellHook = ''
            echo "mips64rt dev shell (${system})";
            echo "  make build        # native bootstrap binary";
            echo "  nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c make build-cross";
          '';
        });
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            crossSystem = {
              config = "aarch64-unknown-linux-musl";
            };
          };
        in {
          mips64rt = pkgs.stdenv.mkDerivation {
            pname = "mips64rt";
            version = "0.0.0-phase0";
            src = ./.;
            enableParallelBuilding = true;
            makeFlags = [ "CC=${pkgs.stdenv.cc.targetPrefix}cc" ];
            installPhase = ''
              mkdir -p $out/bin
              cp _build/mips64rt $out/bin/
            '';
          };
          default = self.packages.${system}.mips64rt;
        });
    };
}
