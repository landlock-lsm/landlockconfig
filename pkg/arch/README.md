# Arch Linux package

This directory contains files for building the library-only Arch Linux package
of Landlock Policy.

Built packages are only [meant for development and
testing](https://github.com/landlock-lsm/landlock-policy/pull/52).

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

The build creates a library-only package file:
`landlock-policy-git-*.pkg.tar.zst`

Install with: `sudo pacman -U landlock-policy-git-*.pkg.tar.zst`
