# SPDX-FileCopyrightText: 2025 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
{
  description = "foudation-api dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    keyos.url = "git+ssh://git@github.com/Foundation-Devices/KeyOS";
  };

  outputs = {
    self,
    nixpkgs,
    keyos,
  }: let
    inherit (nixpkgs) lib;
    forAllSystems = f: lib.genAttrs ["aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux"] f;
  in {
    devShells = forAllSystems (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
        keyosPackages = keyos.packages.${system};

        customPackages = with keyosPackages; [
          rust-analyzer
          rust-keyos
        ];
      in {
        default = pkgs.mkShellNoCC {
          packages = customPackages;
        };
      }
    );
  };
}
