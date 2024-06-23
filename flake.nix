{
  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    flake-utils = {
      url = "github:numtide/flake-utils";
      inputs.systems.follows = "systems";
    };
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        nixpkgs-stable.follows = "nixpkgs";
      };
    };
  };

  nixConfig = {
    extra-substituters = [
      "https://cachix.cachix.org"
      "https://aarch64-darwin.cachix.org"
      "https://helix.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cachix.cachix.org-1:eWNHQldwUO7G2VkjpnjDbWwy4KQ/HNxht7H4SSoMckM="
      "aarch64-darwin.cachix.org-1:mEz8A1jcJveehs/ZbZUEjXZ65Aukk9bg2kmb0zL9XDA="
      "helix.cachix.org-1:ejp9KQpR1FBI2onstMQ34yogDm4OgU2ru6lIwPvuCVs="
    ];
  };

  outputs =
    {
      flake-utils,
      nixpkgs,
      git-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config = {
            allowUnsupportedSystem = true;
            allowBroken = true;
            allowUnfree = true;
          };
        };

        pre-commit-check = import ./nix/pre-commit-check.nix { inherit pkgs git-hooks system; };
      in
      with pkgs;
      {
        checks = {
          inherit pre-commit-check;
        };

        devShells = {
          default = callPackage ./nix/shell.nix { inherit pre-commit-check; };

          install-hooks = mkShell.override { stdenv = stdenvNoCC; } {
            inherit system;
            shellHook =
              let
                inherit (pre-commit-check) shellHook;
              in
              ''
                ${shellHook}
                echo Done!
                exit
              '';
          };
        };

        formatter = nixfmt-rfc-style;

        packages = {
          aiml = callPackage ./nix/aiml.nix { };
          av = callPackage ./nix/av.nix { };
          dev = callPackage ./nix/dev.nix { };
          dev-jvm = callPackage ./nix/dev-jvm.nix { };
          system = callPackage ./nix/system.nix { };
          user = callPackage ./nix/user.nix { };
        };
      }
    );
}
