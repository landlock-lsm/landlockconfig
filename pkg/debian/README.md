# Debian package

This directory contains files for building Debian packages of Landlock Config.

Built packages are only meant for development and testing.

## Building the packages

### Option 1: using Docker

On any Linux system with Docker installed:

```bash
make docker
```

### Option 2: native build

On Debian/Ubuntu systems with the required build tools:

```bash
make build
```

## Output

The build creates these packages:

- `liblandlock-policy-dev_*.deb` -- development files
- `liblandlock-policy0-dbgsym_*.deb` -- debug symbols for the shared library
- `liblandlock-policy0_*.deb` -- shared library
- `landlock-policy-dbgsym_*.deb` -- debug symbols for landlock-policy
- `landlock-policy_*.deb` -- command-line sandboxer tool

Install with:

```bash
sudo dpkg -i ../liblandlock-policy0_*.deb ../landlock-policy_*.deb
```
