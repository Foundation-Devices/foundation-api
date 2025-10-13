# SPDX-FileCopyrightText: 2025 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "foudation-api dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = f: lib.genAttrs ["aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux"] f;
  in {
    devShells = forAllSystems (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };

        toolchain = fenix.packages.${system}.fromToolchainFile {
          file = self + "/rust-toolchain.toml";
          sha256 = "sha256-18J/HvJzns0BwRNsUNkCSoIw7MtAmppPu5jNzuzMvCc=";
        };
      in {
        default = pkgs.mkShellNoCC {
          packages = [toolchain];
        };
      }
    );
  };
}
