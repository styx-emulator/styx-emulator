# Repository Layout

This document provides a detailed overview of the recommended structure for the emulator project's repository. The layout is designed to promote ease of navigation, modularity, and clear separation of concerns, enabling both efficient project management and collaboration, if something
seem off or that it could be improved, file an issue!

In general, the repository layout should look roughly like:

```text
# non-code / extra files
./data

# utilities, maintenance and ci scripts
./util

# documentation
*.md
./docs

# examples + usages
./examples

# things built on top of, or in alpha quaility WIP/eval
./extensions
./incubation

# styx code
./styx

# utils, configs, and scripts for packaging styx
./dist
```

## Non-Code Directories and Auxiliary Files

**./data**: Contains essential data files that the emulator might need to run various software or to initialize certain states. This may include firmware, source, or extra static data.

## Documentation

**\*.md**: Markdown files located at the root level, including README, CONTRIBUTING etc., providing an introduction to the project, guidelines for contribution, and community standards.

**./docs**: This directory contains detailed documentation for the emulator, including setup instructions, architectural overviews, API references, and developer guides. This documentation is also automatically hosted on
a site in CI, so file an issue if something is incorrect or could be
improved!

## Examples

**./examples**: Includes sample code and projects demonstrating the use of the emulator's APIs and functionalities. This is also frequently used as
a testing ground of new features or for profiling.

## Development and Extensions

**./extensions**: This directory is dedicated to non-core crates, experimental features, and work-in-progress (WIP) modules that extend styx's capabilities beyond its essential functions.

**./incubation**: Serves as a staging area for experimental features and modules that are under consideration for integration into the main codebase. This facilitates isolated development and testing before their potential promotion to core components.

## styx

### Styx Components

**./core**: The internal types and core code that the greater styx library uses. ALl other crates depend on the library **styx-core** (**./core**) to integrate with each other and create the greater library ecosystem "styx".

**./event-controllers, ./peripherals, ./plugins, ./processors**: These directories contain the crates for respective components of the emulator. Each plays a specific role within the emulator's architecture, from managing peripheral interactions to processing emulator events.

**./src**: The top level library create which re-exports the core libraries (styx-core, from **./core**). This includes the fundamental building blocks upon which all other components are built. It is crucial that changes within this directory are made with caution, as they can impact the entire project.

**./idl**: Stores Interface Definition Language (IDL) files that define the interfaces between different components of the emulator. This is crucial for ensuring that components interact with each other in a well-defined manner. There are many crates, and multiple programming languages in the
project that all need a ground truth source of our `proto` etc. files, this is where they go.

**./bindings**: Hosts language-specific bindings for the styx's core functionalities, enabling styx to be used in different programming environments and ecosystems.

**./benches**: Contains benchmarking code and resources. These are essential for evaluating the performance of the emulator across various metrics, ensuring optimizations can be measured and regressions detected, and are usually stripped down versions of examples used to isolate a particular issue.

**./services**: Services that can be tacked onto or work with styx crates go here. Ideally these would be reusable by downstream people and extensions, generally created by graduating useful service from **../incubation**.

**./macrolib**: A library housing macros

**./integration-tests**: Houses some code useful for integration tests between components of styx.

**./tests**: Integration tests using the above integration test library.

### Crate Dependency Invariants

In order to prevent dependency loops and be able to maintain a well-structured rust workspace (that compiles in a reasonable amount of time), it is important to maintain the following import-level invariants:

```text
./generated
  - automatically generated code (bindgen, svd2rust etc)
./src
  - styx core libraries, can only depend on `src` + generated
./event-controllers
  - depend on everything above
./peripherals
  - depend on everything above
./processors
  - depend on everything above
./devices
  - depend on everything above
./extensions
  - depend on everything above
./plugins
  - depend on everything above
./machines
  - depend on everything above
```

The structure enforces a strict dependency hierarchy to maintain modularity and prevent circular dependencies. This section outlines the permissible dependencies for each component within the project:

**./generated**: Houses automatically generated code. Components in this directory should not have dependencies on the emulator's custom code to ensure that generated code remains standalone and reusable.

**Directories from ./src to ./machines**: Each of these components can depend on its predecessors in the list, adhering to a top-down dependency flow. This invariant ensures a clear separation of concerns and facilitates easier testing and maintenance.
