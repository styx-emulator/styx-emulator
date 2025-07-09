# Styx Emulator

This is a monorepo that contains code for the `styx-core` library, its
pre-packaged components in the `styx-emulator` library, and the extensions built
on top of it under `extensions` and `incubation`.

When talking about "the Styx Emulator", we're generally talking about
the `styx-emulator` library, which contains all the in-tree processors, peripherals,
devices, machines, and cpu's etc. When discussing extensions, we usually
refer to them by name.

For advice about contributing and creating build environments, see [Contributing](./CONTRIBUTING.md)

For help around the codebase, see [Layout](./LAYOUT.md)

For repository conventions, see [Conventions](./CONVENTIONS.md)

For documentation, please see the docs site listed in the description -->

## Setup

For information on development within a preconfigured development container, see
the "Remote Development Containers" section in [Contributing](./CONTRIBUTING.md).

### Dependencies

- [direnv](https://direnv.net/)
- A working rust installation (cargo will automatically install the correct versions)
- python > 3.9
- python3-virtualenv
- python3-pip
- [protobuf-compiler](https://grpc.io/docs/protoc-installation/) >= 21.5 (anything recent)
- cmake

#### For Tests
- gdb-multiarch (gdb on RHEL systems)

### Project Setup

Make sure rust is installed with at least the following components:

```bash
rustup toolchain install nightly --component miri,rust-src,llvm-tools-preview
rustup component add llvm-tools-preview --toolchain stable
```

then install just

```bash
cargo install just
```

Then run:

```bash
just setup
```

This will install a virtualenv at `./venv`. This will also install `cargo`
tools needed for `CI`, linting and testing. (See [justfile](./justfile)).

## Documentation

After completing the setup steps, run the following to build the docs (these are hosted on git pages)

```bash
just docs
```

To build the Rust API docs (not hosted on git pages), run

```bash
just rust-docs
```

## License

The Styx Emulator Project is governed by the BSD-2 Clause License found in [`./LICENSE`](./LICENSE).

## Disclaimer

Part of this work was funded by DARPA; The views, opinions, and/or findings expressed are those of the author(s) and should not be interpreted as representing the official views or policies of the Department of Defense or the U.S. Government.
