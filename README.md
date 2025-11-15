# Styx Emulator

<!--toc:start-->
- [Styx Emulator](#styx-emulator)
  - [Project Links](#project-links)
    - [Official](#official)
    - [Unofficial](#unofficial)
  - [Why Use Styx?](#why-use-styx)
  - [Repository Information](#repository-information)
  - [Development Roadmap](#development-roadmap)
  - [Development Environment](#development-environment)
    - [devcontainer](#devcontainer)
    - [guix](#guix)
    - [Docker container based](#docker-container-based)
    - [Host / Native development](#host-native-development)
      - [For Tests + Local CI](#for-tests-local-ci)
    - [Project Setup](#project-setup)
  - [Documentation](#documentation)
  - [Disclaimer](#disclaimer)
<!--toc:end-->

[![License](https://img.shields.io/github/license/styx-emulator/styx-emulator.svg)](https://github.com/styx-emulator/styx-emulator/blob/main/LICENSE)

The Styx Emulator is a composable emulation framework with the primary goal
of rapid emulator development for debugging target systems. The Styx Emulator
is primarily a Rust library with bindings in multiple languages and
extensions for multiple tools.

Contributions of code, issues, documentation, and showcases are always welcome. Look for issues [tagged with trivial](https://github.com/styx-emulator/styx-emulator/issues?q=is%3Aissue%20state%3Aopen%20label%3AD-Trivial) or submit an issue for how you would like to use Styx.

Do you use Styx to emulate an analyze a hard to reach target? Submit a [Pull Request](https://github.com/styx-emulator/styx-emulator/pulls) of part of or all of your Styx changes! PRs are encouraged for changes like but not limited to the following:

- ISA additions or changes
- New plugins
- Additional peripherals
- CPU Backend improvements
- Example code for running a new processor
- And so much more!

Thank you for giving back to the open source ecosystem.

Styx is under active development and does not currently follow Semantic Versioning. Beware of breaking changes!

## Project Links

### Official

- Documentation: <https://docs.styx-emulator.org>
- Github: <https://github.com/styx-emulator>
- Mastodon: <https://infosec.exchange/@styx_emulator>
- Twitter/X: <https://x.com/styx_emulator>

### Unofficial

**Note**: Unofficial communities are not moderated by nor affiliated with Kudu Dynamics, LLC.

- Discord: <https://discord.gg/styx-emulator>

## Why Use Styx?

- ✅ Emulation framework for non-standard targets (DSPs, CoProcessors, weird SoCs)
- ✅ Goal is to enable rapid development of custom built emulators
- ✅ Built-in bug finding tools (libAFL, memory error detection plugins)
- ✅ Built-in gdbserver with monitor commands
- ✅ High performance concurrent cross-emulator tracebus
- ✅ Programmatic I/O Access and Manipulation
- ✅ Library-first to provide first-class tailoring support
- ✅ (fledgling) Ghidra Interop

Styx is designed to be a foundational tool for building custom emulators, allowing you to focus on target specifics rather than the underlying emulation mechanics. It provides a powerful framework for creating tailored emulators that can be used in a variety of contexts, from debugging embedded systems to state of the art security research. Styx focuses on introspection and instrumentation over raw execution speed, meaning that in general Styx will sacrifice some execution speed in order to grant users the ability to get detailed information like cross-emulator interrupt tracking and data flow analysis. The best part? A lot of that instrumentation can be *compiled out* if you don't need it, so you can still get great performance when you don't need the introspection.

Whether you're working on embedded systems, DSPs, or just need a lightweight emulator for bug-finding, Styx has you covered. With built-in fuzzing support, plugins, external tool integrations and multi-processor capabilities, Styx exists to bring modern tools to long forgotten architectures and targets.

| **Feature**              | **STYX**                       | **QEMU**             | **UNICORN**           | **ICICLE-EMU**                   |
|--------------------------|--------------------------------|----------------------|-----------------------|----------------------------------|
| **License**              | BSD-2                          | GPL v2               | GPL v2                | MIT or Apache 2.0                |
| **Language**             | Rust                           | C                    | C                     | Rust                             |
| **Intended Use-Case**    | Embedded + DSP Bug-finding     | General OS Emulation | Lightweight Emulation | Linux Usermode bug finding       |
| **Architecture Porting** | Hours                          | Good Luck            | Good Luck             | Technically Possible             |
| **Multi-processor**      | ✅ Native                      | ❌                   | ❌                    | ❌                               |
| **Fuzzing**              | ✅ Customizable                | ❌ Old Fork          | ⚠ Work required       | ✅ Read their paper!             |
| **Pluggable Backends**   | ✅ Choose one in-tree or BYOB! | ❌ QEMU Tcg          | ❌ QEMU Tcg           | ❌ (Cool) Sleigh + Cranelift JIT |
| **Documentation**        | ✅ Extensive                   | ⚠ Sparse             | ⚠ Sparse              | ⚠ Sparse                         |
| **Commercial Use**       | ✅ Friendly                    | ⚠ GPL Risk           | ⚠ GPL Risk            | ✅ Friendly                      |

## Repository Information

- [**Contributing**](./CONTRIBUTING.md): advice about contributing and creating build environments
- [**Layout**](./LAYOUT.md): navigating the codebase
- [**Conventions**](./CONVENTIONS.md): repository conventions
- [**Documentation**](#documentation): how to locally build documentation
- [**Code of Conduct**](./CODE_OF_CONDUCT.md): ya'll please be kind to each other

This is a monorepo that contains code for the `styx-core` library, its
pre-packaged components in the `styx-emulator` library, and the extensions built
on top of it under `extensions` and `incubation`. Styx also ships with a builtin
`tracebus` packaged in the `styx-tracebus` crate.

When talking about "the Styx Emulator", we're generally talking about
the `styx-emulator` library, which contains all the in-tree processors, peripherals,
devices, machines, and cpu's etc. When discussing extensions, we usually
refer to them by name.

## Development Roadmap

Checkout out the [Styx Roadmap](https://github.com/orgs/styx-emulator/projects/7) to stay informed of where Styx is
heading next. The open tasks indicate where the Styx team is currently focused - but that doesn't mean all contributions
need to fit into those buckets! We welcome all offers of assistance, whether that's raising your hand to pick up an issue,
providing your two cents in an issue's comments, or submitting a [rfc](https://github.com/styx-emulator/rfcs) for a feature we haven't thought of yet!

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

You can pull the `docker` container used for devcontainers + CI from
`ghcr.io/styx-emulator/styx-emulator/styx-ci:main`, or you could build
build the `docker` container yourself at `./utils/docker/ci.Dockerfile`.

``` bash
# NOTE: the build context should be the root of the styx-emulator working directory
#       (the trailing `.`)
docker build -t styx-ci -f ./utils/docker/ci.Dockerfile --build-arg RUST_VERSION=$(cat .rust-version) .
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

*Distribution A: Approved for public release: Distribution is unlimited.*
