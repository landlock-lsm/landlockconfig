# Arch Linux package

This directory contains files for building an Arch Linux package of Landlock Config.

Built packages are only [meant for development and testing](https://github.com/landlock-lsm/landlockconfig/pull/52).

## Building the package

### Option 1: using Docker

On any Linux system with Docker installed:

```bash
make docker
```

### Option 2: native build

On Arch Linux systems with development tools installed:

```bash
make build
```

## Output

The build creates a package file: `landlockconfig-git-*.pkg.tar.zst`

Install with: `sudo pacman -U landlockconfig-git-*.pkg.tar.zst`
