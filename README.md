# Landlock Policy

> **Work in progress:**  The policy specification is currently unstable.

See https://landlock.io

## Goal

The goal of Landlock Policy is to define a simple and flexible specification
for Landlock security policies, and to provide a reference implementation and
command-line tools that can parse both [JSON](https://json.org/) and
[TOML](https://toml.io) formats.  These formats are designed to be easy to
write, read, and parse, leveraging libraries available in a wide variety of
programming languages.

For instance, JSON can serve as an intermediate representation leveraged by
higher-level policy languages. In contrast, TOML is more user-friendly,
making it ideal for end users who need to document their policies and
minimize errors due to its less strict format.  Both formats translate to the
same semantics, ensuring that the security policies defined are consistent
regardless of the format used.

The associated library is designed to be embeddable in various programs,
facilitating sandboxing and providing well-defined security and compatibility
guarantees.

## Policy principles

### Policy composition and authority

A Landlock policy can be assembled by composing component compatibility policies
stored in separate files. Keeping these compatibility declarations separate
lets callers share and reuse them as policy snippets. It also lets ownership and
maintenance of a component's declarations be delegated to the party responsible
for that component, such as an application or library maintainer or a
distribution packager. Each policy describes the restrictions and resource
allowances under which its component is expected to work. Each owner is
responsible for maintaining and testing its component with the declarations in
that policy, and for retesting it after changing them.

For example, an application may depend on several libraries or plugins, each
delivered by a separate package and maintained by a different party. Each party
can own and maintain the compatibility policy for its component. A caller that
trusts all of these parties can compose their policies into one policy while
leaving each component owner responsible for its declarations.

Composing policies computes one policy intended to preserve the declared
compatibility requirements of every represented component. It does not combine
independent security requirements. Composition:

- intersects handled filesystem and network rights;
- intersects scoped rights;
- unions literal values declared for the same variable name; and
- unions path and port allowances, then limits them to the commonly handled
  rights.

Variable names share one composition-wide namespace. When multiple component
policies declare the same name, templates using that name expand over the union
of their literal values. Component owners must therefore coordinate shared names
or account for every resulting expansion in their compatibility tests.

This is intentionally compatibility-oriented. For ordinary access rights, the
composed policy only enforces a restriction if every selected policy declares
that its component tolerates that restriction. When every component handles a
right, the composed policy retains the resource allowances requested by all of
them.

A policy can therefore weaken the resulting confinement by leaving rights out
of an explicit handled array or requesting broad allowances. The caller must
trust every selected policy to state its component's compatibility requirements
accurately. Composition provides confinement only to the extent implied by the
selected compatibility declarations. It is not a security boundary between
mutually distrusting policy authors. It cannot prove that a component was tested
correctly.

When restrictions come from independent security authorities and must not be
weakened by a component policy, apply separate Landlock ruleset layers instead
of composing the policies. Landlock makes denials from stacked layers
cumulative: for rights restricted by multiple layers, an operation must satisfy
every relevant layer, and an allowance in one layer cannot override another
layer's denial. For example, an application and its libraries may compose their
compatibility policies, while a service manager or system administrator applies
another layer containing mandatory site restrictions.

In short:

```text
policy composition          = preserve declared component compatibility by
                              enforcing only common handled restrictions and
                              retaining requested allowances for commonly
                              handled rights
stacked Landlock rulesets   = enforce every independent authority's restrictions
```

### JSON specification

The JSON format is used to define a Landlock security policy as specified by the
related [JSON schema](schema/landlock-policy.json).

As the Landlock kernel maintainers, we can guarantee that the specification and
the library will be kept in sync with kernel changes.

### Backward and forward compatibilities

Because the Linux kernel and user space might be updated independently according
to the their own upstream and downstream release cycles, a launcher (e.g.,
service managers, container runtimes) might be newer or older than the running
kernel.

In the case of an older kernel and a newer user space, an up-to-date Landlock
policy should be still compatible as much as possible with older kernels.
The default behavior should then be to following a best-effort approach to
protect users as much as possible.  See the "compatibility" modes in [the
specification](schema/landlock-policy.json).

**TODO:**
In the case of an older user space and a newer kernel, it should be possible for
users to still leverage a subset of the newer kernel features.  This means that
the Landlock policy should be flexible enough to extend over the current
(soon old) specification.  Access rights are defined with meaningful keywords
(text), but to be able to protect users as much as possible, the policy format
should also handle numbers mapping to the kernel's UAPI bits. This should not
be seen as a replacement for the keyword representation of access rights, but as
a way to leverage some new features without being coupled too much with the
launcher's code.  The limit for supporting unknown features would be the
introduction of entirely new categories, such as new rule types or ruleset
properties. With the current fields, only unknown access rights would be
supported. However, if raw access rights are used, the library will not be able
to provide the same level of compatibility guarantees.  See
https://github.com/opencontainers/runtime-spec/pull/1241#pullrequestreview-2595870681

### Concise policies

The policy format should ease conciseness (e.g., by handling arrays of paths).

The policy format should handle groups of access rights per [Landlock ABI
version](https://landlock.io/rust-landlock/landlock/enum.ABI.html).

### Flexible policies

The parser should limit error cases as much as possible. One way to achieve that
is to automatically complete the known properties (e.g., handled access rights
are automatically completed according to all used access rights).

## Reference implementation

### Shared Library

This repository enables developers to build an ELF shared object library, which
can then be used by any program and most programming languages via a foreign
function interface (FFI) and a [C API](c/landlock-policy.h).

To install this library, first install
[cargo-c](https://github.com/lu-zero/cargo-c) using your package manager or with
`cargo install cargo-c`, and then run these commands:

```sh
cargo cinstall --package=landlock-policy-ffi --release --prefix=/usr/local --destdir=out
sudo cp -dr out/usr/local/* /usr/local/
```

The library is then usable via `pkg-config` as `landlock-policy`. See the [C
example](c/examples/sandboxer.c) and its [Makefile](c/examples/Makefile).

### Resilient

The parser should be resilient against any input.

### Native Rust interface

Rust is used as the referenced implementation, which help build and maintain a
robust library while still being able to convert it to a shared object. This
Rust crate can be used as a standalone library.

## Testing

This repository contains the policy specification and a test suite that
can be used to test the library implementation against a set of valid and
invalid samples. This could also be used to test Landlock libraries to make sure
the execution traces are similar.

The test suite uses an in-process JSON schema validator by default.  To also
validate every inline JSON snippet with `check-jsonschema`, install it and run:

```sh
LANDLOCK_POLICY_TEST_JSON_SCHEMA=1 cargo test --locked --all
```

When set, `LANDLOCK_POLICY_TEST_JSON_SCHEMA` accepts `0` or `1`.  Enabling it
requires the `check-jsonschema` executable to be available in `PATH`.

## Command-line tools

### landlock-policy

`landlock-policy` is the policy development, inspection, and transformation
tool. It currently prints the canonical JSON schema and is intended to grow
operations for debugging, linting, formatting, updating, merging, and
translating policy inputs:

```sh
git clone https://github.com/landlock-lsm/landlock-policy
cd landlock-policy
cargo install --path landlock-policy-cli
landlock-policy schema
```

### landlock-exec

`landlock-exec` is the policy enforcement and execution wrapper. It applies
one effective policy composed from JSON or TOML policy inputs and replaces
itself with the confined command. It is an intentionally minimal reference
wrapper; end users looking for a full-featured sandboxing tool should use
[Island](https://github.com/landlock-lsm/island) instead.

```sh
git clone https://github.com/landlock-lsm/landlock-policy
cd landlock-policy
cargo install --path landlock-exec
landlock-exec --json examples/mini-write-tmp.json sh
```

Component compatibility policies can be composed by specifying `--json` or
`--toml` (and related file or directory paths) several times. See
[Policy composition and authority](#policy-composition-and-authority)
before combining policies from different maintainers.

## TOML policy example

Here is an example of a [TOML policy](examples/micro-var.toml) that uses
variables, access right groups, and list of directory hierarchies for
conciseness.

```toml
abi = 6

[[variable]]
name = "tmp"
literal = ["/tmp", "/var/tmp"]

[[variable]]
name = "home"
literal = ["/root", "/home"]

[[variable]]
name = "config"
literal = ["/etc"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["abi.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "${config}"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["abi.read_write"]
parent = ["${tmp}", "${home}"]
```

We can get a view of the created Landlock rules:
```sh
landlock-exec --toml examples/micro-var.toml --debug date
```

## Migration from landlockconfig

`landlockconfig` was the previous name of this project and its public
interfaces. Because these interfaces have not been released from this
repository, they are replaced without compatibility aliases:

- The repository and Rust crate move from `landlockconfig` to
  `landlock-policy`; the FFI crate moves from `landlockconfig_ffi` to
  `landlock-policy-ffi`.
- The schema moves from `schema/landlockconfig.json` to
  `schema/landlock-policy.json`.
- The C library, pkg-config module, header, object type, and function prefix
  move from `liblandlockconfig`, `landlockconfig`, `landlockconfig.h`,
  `struct landlockconfig`, and `landlockconfig_*` to `liblandlock-policy`,
  `landlock-policy`, `landlock-policy.h`, `struct landlock_policy`, and
  `landlock_policy_*`.
- The former `llconfig schema` command is now `landlock-policy schema`;
  `llconfig run` is now `landlock-exec` with the same options and command
  arguments, but without the `run` subcommand.
- The Debian `liblandlockconfig0`, `liblandlockconfig-dev`, and `llconfig`
  packages are replaced by `liblandlock-policy0`, `liblandlock-policy-dev`,
  `landlock-policy`, and `landlock-exec`.
