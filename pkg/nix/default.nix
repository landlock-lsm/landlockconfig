# SPDX-License-Identifier: Apache-2.0 OR MIT
{
  pkgs ? import <nixpkgs> { },
}:
{
  landlockconfig = pkgs.callPackage ./landlockconfig.nix { };
  llconfig = pkgs.callPackage ./llconfig.nix { };
}
