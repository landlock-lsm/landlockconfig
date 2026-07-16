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

- `liblandlockconfig-dev_*.deb` -- development files
- `liblandlockconfig0-dbgsym_*.deb` -- debug symbols for the shared library
- `liblandlockconfig0_*.deb` -- shared library
- `llconfig-dbgsym_*.deb` -- debug symbols for llconfig
- `llconfig_*.deb` -- command-line sandboxer tool

Install with:

```bash
sudo dpkg -i ../liblandlockconfig0_*.deb ../llconfig_*.deb
```
