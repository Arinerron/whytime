# whytime as a Nix flake for x86_64-linux and aarch64-linux; Nix 2.18 or newer with the
# `nix-command` and `flakes` features:
#   nix run github:Arinerron/whytime -- doctor
#   nix profile add github:Arinerron/whytime   # before Nix 2.30: nix profile install
#   nix build                                  # ./result/bin/whytime, man pages, completions
#   nix develop                                # cargo, clippy, rustfmt, clang, bpftool
{
  description = "Explains where a command's wall-clock time went: off-CPU and on-CPU attribution across its process tree, from eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # The tracekit submodule at the tag it pins: `github:` flake sources omit submodules,
    # `inputs.self.submodules` or not. The build always uses this copy. Bump the tag with the
    # submodule, then run `nix flake lock`.
    tracekit = {
      url = "github:Arinerron/tracekit/v0.1.0";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      tracekit,
    }:
    let
      inherit (nixpkgs) lib;
      perSystem =
        f:
        lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system};
          in
          f {
            inherit pkgs;
            # build.rs compiles the BPF objects with $CLANG and -Werror, which the cc wrapper's
            # host flags (--gcc-toolchain) fail.
            clang = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
          }
        );
    in
    {
      packages = perSystem (
        { pkgs, clang }:
        rec {
          default = whytime;
          whytime = pkgs.rustPlatform.buildRustPackage {
            pname = "whytime";
            inherit ((lib.importTOML ./Cargo.toml).workspace.package) version;
            src = self;
            postUnpack = ''
              rm -rf "$sourceRoot/tracekit"
              cp -r ${tracekit} "$sourceRoot/tracekit"
            '';
            cargoLock.lockFile = ./Cargo.lock;

            env.CLANG = clang;
            nativeBuildInputs = [ pkgs.installShellFiles ];
            # xtask writes the man pages.
            cargoBuildFlags = [
              "--package"
              "whytime"
              "--package"
              "xtask"
            ];
            # Tests always unwind: under the release profile (panic = "abort", fat LTO) they
            # would rebuild everything at full cost.
            checkType = "debug";
            postInstall = ''
              $out/bin/xtask man man
              rm $out/bin/xtask
              installManPage man/*.1
              installShellCompletion --cmd whytime \
                --bash <($out/bin/whytime completions bash) \
                --fish <($out/bin/whytime completions fish) \
                --zsh <($out/bin/whytime completions zsh)
            '';

            meta = {
              description = "Explains where a command's wall-clock time went, from eBPF";
              homepage = "https://github.com/Arinerron/whytime";
              license = lib.licenses.mit;
              mainProgram = "whytime";
              platforms = lib.platforms.linux;
            };
          };
        }
      );

      devShells = perSystem (
        { pkgs, clang }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.bpftools
            ];
            CLANG = clang;
            # nixpkgs' Rust ships no musl standard library: build for the host's glibc target
            # instead of the static musl default in .cargo/config.toml.
            CARGO_BUILD_TARGET = pkgs.stdenv.hostPlatform.rust.rustcTarget;
          };
        }
      );
    };
}
