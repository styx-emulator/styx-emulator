# Changelog

All notable changes to this project will be documented in this file.
Note that each section is sorted *oldest* commit first.

## [1.2.0] - 2025-07-09

### Features

- Add arm big endian sla specs
- Add basic block hooks to pcode backend
- Gdb monitor for emulator introspection
- Add msp430 sla and isa
- Alphabetize enums
- Add execution constraints to bindings
- Add readmes to all examples
- Big endian arm in pcode backend
- Make ci tests and lints concurrent
- Exception behavior
- Pcode backend uses u128
- Dt-stats initial commit
- Fs walker
- Dts compilation
- Parallelize compilation
- Parsing via fdt
- Basic stats working!
- Bus-based stats
- Improved zephyr support
- JSON + data processing
- Data processing jq scripts
- Peripheral data
- Migrate to serde
- Add MemFaultData to styx-py-api
- Add macros to expedite architecture dev
- Build and deploy static docs site
- Lint docs
- Processor_start/stop and executor Delta
- Warn when elf file has zero loadable segments
- Backends report execution count
- Extensive fuzzer configuration improvements
- Add mips32 processor types
- FPU & ASE regs
- Basic pcode mips32 emulation
- Preliminary big endian ARM support

### Bug Fixes

- Prompt for user action instead of error
- Use keystone fork with gcc-15 fix
- Fix bootstrap-guix bugs
- Update guix sources
- Using-processor example
- Pcode backend benchmark hooks readding
- Spawn dtc in the correct dir for includes
- Do not let user set unicorn pc to 0

### Other

- Add cargo-home to path for weird setup ordering
- Remove non-styx from github linquist
- Dt-stats docs + ci + quickfixes
- Add blackfin binutils tests
- Fix readme rustup component install syntax
- Make bit banding address debug output hex
- Fix incorrect always-passing mips32 pcode test

### Refactor

- Different functions for compiling and parsing

### Testing

- Add walker test

### Miscellaneous Tasks

- Python examples test in ci
- Cleanup python stubs and update pyO3
- Replace tempdir dep with temp-dir
- Add dtc & workspace-hack
- Maybe fix merge conflict?
- Migrate blackfin to new macros
- Migrate arm to new macros
- Migrate mips64 to new macros
- Migrate msp430 to new macros
- Migrate superh to new macros
- Migrate ppc32 to new macros
- Update bindings
- Don't run big ci if only docs change

## [1.1.0] - 2025-05-30

### Features

- Check varnode sizes in pcode backend (#419)
- Add SyncProcessor and TaskQueuePlugin

### Miscellaneous Tasks

- Release uses cargo update and reminds to push tags
- Do not install cargo tools in ci

## [1.0.1] - 2025-05-23

### Bug Fixes

- Pcode backend doesn't panic on pc step

## [1.0.0] - 2025-05-22

### Features

- Gdb harness refactor to new architecture
- Remove Sync bounds Processor components
- Blackfin processor refactor
- PPC405 has functioning TLB
- Refactor Memory API
- Trace plugin refactor
- Processor tracing plugins refactor
- Styx-fuzzer reafactor
- Debug tools plugin refactor
- Mpc866m event controller refactor
- Nvic event controller refactor
- Add powerpc benchmark bins
- Gic event controller refactor
- Delegate common ops to ProcessorCore inner
- Styx supports register hooks
- Kinetis21 processor refactor
- Added mmu to processor core bundle
- Decouple peripheral reset from EventController
- Unicorn backend refactor
- Stm32f107 processor refactor
- Spi for stm32f107
- Stm32f405 processor refactor
- Convert ProcessorIntegrationTest runner
- Powerquicci processor refactor
- Ppc4xx refactor update
- Services are refactored
- Cyclone v refactor
- Fixed coproc registers on pcode backend
- Refactor examples
- Initial mvp codebase refactor and lint
- Refactor bindings to new architecture
- Initial migration guide

### Bug Fixes

- Update event controllers
- Format trinity refactor

### Other

- Fix sized value resize in read_hooked
- Fix off by 1 in UnmappedMemory calulcation

### Documentation

- Styx hooks refactor and how to use them
- Updated event controller api docs
- Processor and ProcessorBuilder API docs
- Memory API docs
- Plugins API docs
- Add doc comments for ProcessorBuilder
- Doc comments for the Processor
- Site now includes migration guides

### Miscellaneous Tasks

- Initial holy trinity refactor scaffolding
- Remove OBE crates
- Remove dead tests
- Remove log prefixed items from unicorn backend
- Clean kinetis21 tests
- Remove e2e-ppc405 tests
- Remove stm32f107 e2e tests
- Fixup docs site link rendering

## [1.0.0-rc1] - 2025-05-15

### Features

- Gdb harness refactor to new architecture
- Remove Sync bounds Processor components
- Blackfin processor refactor
- PPC405 has functioning TLB
- Refactor Memory API
- Trace plugin refactor
- Processor tracing plugins refactor
- Styx-fuzzer reafactor
- Debug tools plugin refactor
- Mpc866m event controller refactor
- Nvic event controller refactor
- Add powerpc benchmark bins
- Gic event controller refactor
- Delegate common ops to ProcessorCore inner
- Styx supports register hooks
- Kinetis21 processor refactor
- Added mmu to processor core bundle
- Decouple peripheral reset from EventController
- Unicorn backend refactor
- Stm32f107 processor refactor
- Spi for stm32f107
- Stm32f405 processor refactor
- Convert ProcessorIntegrationTest runner
- Powerquicci processor refactor
- Ppc4xx refactor update
- Services are refactored
- Cyclone v refactor
- Fixed coproc registers on pcode backend
- Refactor examples
- Initial mvp codebase refactor and lint
- Refactor bindings to new architecture
- Initial migration guide

### Bug Fixes

- Update event controllers
- Format trinity refactor

### Other

- Fix sized value resize in read_hooked
- Fix off by 1 in UnmappedMemory calulcation

### Documentation

- Styx hooks refactor and how to use them
- Updated event controller api docs
- Processor and ProcessorBuilder API docs
- Memory API docs
- Plugins API docs
- Add doc comments for ProcessorBuilder
- Doc comments for the Processor

### Miscellaneous Tasks

- Initial holy trinity refactor scaffolding
- Remove OBE crates
- Remove dead tests
- Remove log prefixed items from unicorn backend
- Clean kinetis21 tests
- Remove e2e-ppc405 tests
- Remove stm32f107 e2e tests

## [0.53.0] - 2025-04-15

### Features

- Automatic release management
- Release automation for core + bindings
- Styx is styx_emulator

### Bug Fixes

- Release-plz works on dirty repo contents
- Ci: no longer attempt to reinstall docker on the CI vm's
- Trailing whitespace

### Other

- Helpers for release automation

### Documentation

- Add DARPA disclaimer

### Miscellaneous Tasks

- Remove all crate naming collisions
- Update rustup cli args to new format

## [0.52.0] - 2025-02-25

### Features

- Xtask now updates devcontainer rust-version
- Initial superh floating point support
- Minimal superh2a processor
- Add mips gdb xml specifications
- Add mips64 isa support
- Add stub_gen to generate python types
- Update bindings to include mips64 isa

### Bug Fixes

- Devcontainer improvements
- Properly ignore miri for e2e tests

### Other

- Fix ppc_embedded.sinc `mtmsr`
- Implement try_into from ArchVariant
- Update unicorn ref

### Documentation

- Update name of "pkg" to "dist"

## [0.51.0] - 2025-02-07

### Bug Fixes

- *(docs)* Fixup visual formatting in concepts

### Documentation

- Document xtask usage
- Omit generated crates to save space
- Add minimal faq
- Add installing directions
- Add custom pip install help url
- Do no build rust docs, have the user build them
- Update README
- Add quickstart

### Miscellaneous Tasks

- Update rust-miri configuration
- Bypass failing coverage job
- Fix python container lifecycle
- Use correct python image variable

## [0.50.0] - 2025-01-24

### Features

- Added conventional commit check to pre-commit
- Create separate styx-hooks crate.
- Create styx-mmu-engine-trait crate.
- Move memory validation into MmuEngine trait.
- Use compression in context_save/context_restore.
- Add new MmuEngine functions.
- Move common memory_map/memory_unmap to MmuEngine trait.
- Move memory access validation to MmuEngine trait.
- Consolidate reads/writes into MmuEngine trait.
- Build python pip whl's in (gitlab) CI
- Upgrade to LibAFL version 0.13.2.
- Upgrade to Unicorn 2.1.1
- Provide ProcessorPlugin structs runtime access.
- Add standalone Executor/default implementation.
- Benchmark executors.
- Add timeout functionality to step function.
- Add integration tests for step functionality.
- Add context save/restore API to processor.
- Benchmark processor context saving/restoring.
- Add xtask to programatically update crate features.
- Switch the Kinetis K21 example to the new executor.
- Styx can handle most multi-target versions of gdb
- Add guix channel
- Poc guix shell integration
- Add rust app deps
- Initial development environment with guix
- Guix build support for styx
- Guix packaging is resilient to custom substitute-urls
- New architecture docs
- Add gdb xml for SH family
- (initial) pcode backend support for SH architecture
- RawProcessor poc
- Basic raw processor example
- Added ppc405 freertos source and build tools
- Bindings support superh
- Python bindings are built in CI
- C bindings are build in ci
- C examples tested in CI
- Created generic uart controller/interface, updated k21 to use this
- Updated cyclone proc to use new generic uart
- Updated stm32f405 uart impl to use the new stuff

### Bug Fixes

- MemoryBank::context_restore no longer requires READ perms.
- *(gitlab-ci)* Publish-python-wheels ignores default before_script
- *(fuzzer-example)* Remove custom interrupt handling.
- *(styx-cpu-unicorn-backend)* Remove translation cache clearing from set_pc.
- Update guix shell symlink
- Make the bootstrap guix process more reliable
- Fix superh docs link broken
- RawPRocessor now sets up a mninimnally valid address space
- Void event controller is always active
- Gitlab ci no longer references non-existent code
- Install just for c-bindings-examples
- Nextest update config changes
- *(docs)* Fixup visual formatting in concepts

### Other

- Pkg is now dist
- Add type hints (#240)
- `styx_executor` -> `executor`
- Make set_backend a setter
- Add kinetis21 example (#209)
- Move Loader type stubs to correct module
- Define Hook type stub
- Catch ctrl-c in `Processor::start()` (#226)
- Document usage of python library (#215)
- Initial structure stub
- Update hakari message
- Add `Use of RFCs and ADRs`
- Document overall RFC process
- Utility to update rust version
- Ensure all commands have a cli docstring
- Add ADR generator
- Add RFC generator
- Add note about adding generated files to index

### Documentation

- Styx lib rustdoc update
- Update CONVENTIONS.md
- Fixup markdown include rules
- Have examples use in-tree README
- Add stub workflows docs
- New documentation structure
- Use .rust-version as RUST_TOOLCHAIN

### Miscellaneous Tasks

- Update Dependencies to migrate from unnecessary git refs
- Update dependencies
- Remove unused slaspec
- Remove OBE rust docs
- Convert unnecesary mutex's to atomics
- Update lints
- NullProcessor is now VoidProcessor
- Do not run python ci until bindings are stable
- Update c bindings to modern styx
- Update py bindings to modern styx
- Update to 1.82.0
- Update styx-bindings workspace lock
- Update docs build process
- Remove obe docs
- Lock the cargo installs for just-setup
- Just setup installs manifests for all workspaces

<!-- generated by git-cliff -->
