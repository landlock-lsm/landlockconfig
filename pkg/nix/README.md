# Nix package

This directory includes a nix build script.

## Building

This will build the derivations and create symlinks `./llconfig` and
`./landlockconfig` that point into the Nix store.

```
make
```

## Testing

The `passthru.tests` attribute sets contain tests that can be run to validate
the package. These are run in CI, and can be run locally:

```
make test
```

## Installing

If you use flakes, you can import the package as a non-flake input:

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    landlockconfig = {
      url = "github:landlock-lsm/landlockconfig";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, landlockconfig }: let
      # ...
      pkgs = nixpkgs.legacyPackages.${system};
      llcPkgs = import "${landlockconfig}/pkg/nix" { inherit pkgs; };
      # llcPkgs.landlockconfig - the C library
      # llcPkgs.llconfig - the command-line tool
    in
    # ...
}
```

Otherwise, you can clone this repository and run one of the following:

```
$ nix-env --file ./pkg/nix --install --attr llconfig
$
$ # If you use `nix profile`, run this instead
$ nix profile add --file ./pkg/nix llconfig
```
