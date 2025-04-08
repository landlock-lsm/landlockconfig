# Landlock Config

> **Work in progress:**  The configuration specification is currently unstable.

See https://landlock.io

## Goal

The goal of Landlock Config is to define a simple and flexible configuration
specification for security policies using Landlock, and to provide a reference
implementation that can parse both [JSON](https://json.org/) and
[TOML](https://toml.io) formats.  These formats are designed to be easy to
write, read, and parse, leveraging libraries available in a wide variety of
programming languages.

For instance, JSON can serve as an intermediate representation leveraged by
higher-level configuration languages. In contrast, TOML is more user-friendly,
making it ideal for end users who need to document their configurations and
minimize errors due to its less strict format.  Both formats translate to the
same semantics, ensuring that the security policies defined are consistent
regardless of the format used.

The associated library is designed to be embeddable in various programs,
facilitating sandboxing and providing well-defined security and compatibility
guarantees.

## Configuration principles

### JSON specification

The JSON format is used to define a Landlock security policy as specified by the
related [JSON schema](schema/landlockconfig.json).

As the Landlock kernel maintainers, we can guarantee that the specification and
the library will be kept in sync with kernel changes.

### Backward and forward compatibilities

Because the Linux kernel and user space might be updated independently according
to the their own upstream and downstream release cycles, a launcher (e.g.,
service managers, container runtimes) might be newer or older than the running
kernel.

In the case of an older kernel and a newer user space, an up-to-date Landlock
configuration should be still compatible as much as possible with older kernels.
The default behavior should then be to following a best-effort approach to
protect users as much as possible.  See the "compatibility" modes in [the
specification](schema/landlockconfig.json).

**TODO:**
In the case of an older user space and a newer kernel, it should be possible for
users to still leverage a subset of the newer kernel features.  This means that
the Landlock configuration should be flexible enough to extend over the current
(soon old) specification.  Access rights are defined with meaningful keywords
(text), but to be able to protect users as much as possible, the configuration
should also handles numbers mapping to the kernel's UAPI bits. This should not
be seen as a replacement for the keyword representation of access rights, but as
a way to leverage some new features without being coupled too much with the
launcher's code.  The limit for supporting unknown features would be the
introduction of entirely new categories, such as new rule types or ruleset
properties. With the current fields, only unknown access rights would be
supported. However, if raw access rights are used, the library will not be able
to provide the same level of compatibility guarantees.  See
https://github.com/opencontainers/runtime-spec/pull/1241#pullrequestreview-2595870681

### Concise configuration

The configuration should ease conciseness (e.g., by handling arrays of paths).

The configuration should handle groups of access rights per [Landlock ABI
version](https://landlock.io/rust-landlock/landlock/enum.ABI.html).

### Flexible configuration

**TODO:**
The parser should limit error cases as much as possible. One way to achieve that
is to automatically complete the known properties (e.g., handled access rights
are automatically completed according to all used access rights).

## Reference implementation

### Shared Library

**TODO:**
This repository enables developers the build an ELF shared object library, which
can then be used by any program and most programming languages via a foreign
function interface (FFI).

### Resilient

The parser should be resilient against any input.

### Native Rust interface

Rust is used as the referenced implementation, which help build and maintain a
robust library while still being able to convert it to a shared object. This
Rust crate can be used as a standalone library.

## Testing

This repository contains the configuration specification and a test suite that
can be used to test the library implementation against a set of valid and
invalid samples. This could also be used to test Landlock libraries to make sure
the execution traces are similar.

## Example

Here are the steps to build and use the sandboxer example:
```bash
git clone https://github.com/landlock-lsm/landlockconfig
cd landlockconfig
cargo run --example sandboxer -- --json examples/mini-write-tmp.json sh
```

A new dedicated tool will be published soon.
