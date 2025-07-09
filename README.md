# Styx Emulator

[![License](https://img.shields.io/github/license/styx-emulator/styx-emulator.svg)](https://github.com/styx-emulator/styx-emulator/blob/main/LICENSE)

The Styx Emulator is a composable emulation framework with the primary goal
of rapid emulator development for debugging target systems. The Styx Emulator
is primarily a Rust library with bindings in multiple languages and
extensions for multiple tools.

## Project Links

- Website: <https://styx-emulator.org>
- Documentation Site: <https://docs.styx-emulator.org>
- Github: <https://github.com/styx-emulator>
- Discord: <https://discord.gg/styx-emulator>
- Mastodon: <https://infosec.exchange/@styx_emulator>
- Twitter/X: <https://x.com/styx_emulator>

## Repository Information

- [**Contributing**](./CONTRIBUTING.md): advice about contributing and creating build environments, see
- [**Layout**](./LAYOUT.md): navigating the codebase
- [**Conventions**](./CONVENTIONS.md): repository conventions
- [**Documentation**](#documentation): how to locally build documentation

This is a monorepo that contains code for the `styx-core` library, its
pre-packaged components in the `styx-emulator` library, and the extensions built
on top of it under `extensions` and `incubation`. Styx also ships with a builtin
`tracebus` packaged in the `styx-tracebus` crate.

When talking about "the Styx Emulator", we're generally talking about
the `styx-emulator` library, which contains all the in-tree processors, peripherals,
devices, machines, and cpu's etc. When discussing extensions, we usually
refer to them by name.

## Development Environment

You have a few choices, none of which are too complicated

### devcontainer

Opening the repository in VSCode should prompt you to build + use the devcontainer,
it should "just work".

For more information on development within a pre-configured development container, see
the "Remote Development Containers" section in [Contributing](./CONTRIBUTING.md).

### guix

After installing `direnv`, the proper shell hooks, and adding the repo to the allowed `direnv` paths, simply run:

``` bash
enter-guix
```

### Docker container based

Build the `docker` container at `./utils/docker/ci.Dockerfile`

``` bash
# make sure to use the same rust version that is in the `.rust-version` file
docker build -t styx-dev -f ./utils/docker/ci.Dockerfile --build-arg RUST_VERSION=1.82.0 ./utils/docker/
```

### Host / Native development

To perform host development, you'll need somewhat recent versions of the following tools:
- [direnv](https://direnv.net/)
- A working rust installation (cargo will automatically install the correct versions)
- `python` > 3.9 + `python3-virtualenv` + `python3-pip`
- [protobuf-compiler](https://grpc.io/docs/protoc-installation/) >= 21.5
- `cmake`

#### For Tests + Local CI
- `pre-commit`
- `gdb-multiarch` (`gdb` on RHEL systems)

### Project Setup

Make sure rust is installed with at least the following components:

```bash
rustup component add llvm-tools-preview --toolchain stable
rustup component add rust-analyzer --toolchain stable
```

then install just and run the setup task

```bash
cargo install just && just setup
```

This will install a virtualenv at `./venv`. This will also install the `cargo`
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

## Disclaimer

<a href="https://kududyn.com">
  <img src="./data/assets/kudu-logo-black-white-bg.png" width="30%" description="Kudu Dynamics, LLC, a Leidos Company">
</a>

Copyright © 2025 Kudu Dynamics, LLC, a Leidos Company.
Licensed under the BSD-2 Clause license which may be obtained from [`./LICENSE`](./LICENSE).

Part of this work was funded by DARPA; The views, opinions, and/or findings expressed are those of the author(s) and should not be interpreted as representing the official views or policies of the Department of Defense or the U.S. Government.
