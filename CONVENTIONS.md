# Conventions

There are only a few different types of conventions we're concerned about

- coding conventions
- repository organization conventions
- generic styx conventions

## Generic Styx Conventions

### Target Program

"Target Program" is the _thing_ being emulated, there are many possible overloaded terms we could choose,
at one point we just called it "firmware," but it is now "target program." This name allows us to accurately
reference the emulated **thing**, while still being able to talk about extra emulated libraries, peripherals,
etc. and not get immediately confused

### Addresses

Speaking of the target program, even if it is a 32 bit program `styx` will always think of any address as 64 bit.
This helps when designing more portables systems and API's, since the only type of address `styx` needs to deal with
is a 64-bit one.

This doesn't mean anything about the target program or depend on any compilation settings, this is just ensuring
that when referencing an address or setting the program counter during emulation that the address is 64 bits wide.

## Programming Conventions

Right now we only stress the Rust conventions, which we attempt to have
a uniform standard by using clippy, rustfmt, and some other uniform rules.

## Rust Code Style Guidelines

The rust styling is enforced by `rustfmt`. The linting by `clippy`, the remainder are a best effort from the
following points:

### Import paths inside the codebase

There are a few different tricks we use in order to keep developer sanity and consistency throughout the codebase. As always with a repository
convention, the important things is keeping it consistent. As long as it is consistent the codebase can all be upgraded together.

The imports are really only different rules for three cases:

- writing styx's core library code (code in `./styx/core`)
- writing styx's non-core library code (code in `./styx` but not in `./styx/core`)
- writing application code that _uses_ styx (code outside `./styx`)

#### Core Library Code

**NOTE**: also see further documentation in `./styx/core/README.md` for other core-specific import invariants that must be followed.

If you are writing code inside of `./styx/core`, you need to import your other `styx_core` counterparts directly by path.

eg.

**Cargo.toml**:

```toml
styx-cpu = { path = "../styx-cpu" }
styx-memory = { path = "../styx-memory" }
styx-loader = { path = "../styx-loader" }
```

which would result in possible import like:

```rust
use styx_cpu::Arch;
use styx_memory::MemoryRegion;
use styx_loader::Loader;
```

#### Non-core Library Code

**NOTE**: also see further documentation in `./styx/README.md` or `Repository Layout` for import invariants that must be followed.

If you are inside of `./styx` (but not inside `./styx/core`), then you are in one of the styx "non-core"
libraries. The TLDR is that nothing in core can depend on anything outside of core, and that the
dependency cycles should be easily avoided as long as you don't import one processor crate inside
of another processor crate.

The main rules to follow are:

- don't directly import any crate from `core`, instead import `styx-core` and `use` the pieces you need
- if you are adding a new folder under `./styx`, add a new path dependency to the workspace `Cargo.toml`
  - look for the other entries that are similar to: `styx-processors = { path = "./styx/processors" }`
- if you're adding a multi-processor crate, that belongs under the `./styx/machines` sub-directory

An example of importing other libraries when making non-core library modifications:
**Cargo.toml**

```toml
# this is basically always needed
styx-core = { workspace = true }

# other non-core libraries you depend on:
styx-plugins = { workspace = true }
```

So now your import paths could look like:

```rust
use styx_core::prelude::*;
use styx_core::cpu::arch::ArchEndian;
use styx_plugins::tracing::StyxTracePlugin;
```

#### Application Code

Writing code outside of `./styx` is by far the easiest convention to follow, simply add (if still in the `styx` cargo workspace):

**Cargo.toml**

```toml
styx-emulator = { workspace = true }
```

```rust
use styx_emulator::Thing::You::Want::To::Import;

// ~or~
use styx_emulator::prelude::*; // sane default
```

If you are outside the cargo workspace (eg. making your own in-house definitions / library) then you could do the following instead:

**Cargo.toml**

```toml
# get the public `crates.io` version
styx-emulator = { version = "<crates-io version>", features = [ "list", "of", "features" ] }

# ~or~ a specific git version
styx-emulator = { git = "<git repo url>", rev = "<specific git commit, branch, or tag>" }
```

See the [Cargo dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) documentation for more.

### Code Formatting and Linting

We employ automatic tools to keep our codebase clean and stylistically consistent:

#### Pre-commit Hooks

Make sure to set up the pre-commit hooks that run rustfmt, cargo check, and cargo clippy. This step is crucial for ensuring that your contributions adhere to our coding standards, `pre-commit` is your friend, not your enemy. Nothing gets merged without passing `pre-commit`.

#### Linting

We use cargo clippy for our rust linting and enforce its use in CI where missed lints will fail the pipeline. cargo clippy is also included as a pre-commit hook for your convenience.

If you want to lint your code into oblivion here's a fun command to run:

```shell
cargo clippy --all-targets --workspace -- -W clippy::all -W clippy::pedantic -W clippy::restriction -W clippy::nursery -D warnings
```

Note: This configuration is an excellent way to familiarize yourself with potential code improvements, and find many of the false positives and frankly arbitrary rules that clippy has.

### Alphabetized Enums

We try to alphabetize all enums to make it easier to find the desired variant. There are no automated checks here but you can run `cargo xtask alphabetize` to alphabetize the enums of the whole (rust) codebase.

If your enum is not alphabetized but should not be reordered by the `alphabetize` tool then there are number of exclusion criteria that implies enum ordering matters and alphabetize ignores these enums.

Exclusion of `alphabetize`:

- `PartialOrd` or `Ord` derive
- `repr()` of any kind
- `serde` derive
- `bitsize()`
- if there is any `VariantName = <integer>` indicating that the integer representation is relevant
- all generated code in `target` is omitted

### Safety Practices

Safety is an important part of programming any rust project interfacing with low-level features or external libraries:

- **ASAN**: We run ASAN tests in CI, there should be a good reason if you annotate your test with `#[cfg(asan, ignore)]`, a "good reason" can be "blocked on upstream," and then we can add it to the list of upstream blocked issues.

- **Unsafe Code**: The use of `unsafe` blocks is permitted only with a clear and present justification. Accompany any `unsafe` code with a `# Safety` comment explaining why the operation is considered safe. Example:

    ```rust
    fn call_something_unsafe() -> u64 {
        // # Safety
        // This operation is safe because [provide justification here].
        // It is marked `unsafe` due to [reason], but in our specific use case, it is safe because [reason].
        let result = unsafe { 2 + 3 };
    }
    ```

- **MIRI**: We also run tests under miri in CI. While it's nice to run everything through MIRI, it can take way too long, and is pretty limited in what it can do (as far as syscalls + ffi etc. go), so annotate your tests with `#[cfg_attr(miri, ignore)]` to disable miri, ideally with a comment as to why it's getting disabled.

## Error Handling

Our approach to error handling is evolving, particularly as we balance the needs of library development with application robustness.

As a library, Styx should **never** panic and all errors, expected or unexpected, should bubble to the top where caller can handle it appropriately.

To strike a balance between developer ergonomics and user error introspection we define two broad error types, **expected** and **unexpected**.

1. **Expected Error**: The operation failed in an expected manner that the caller could understand and operate in response to
    - Example: `ProcessorBuilder::build()` called without first specifying an endianness of the processor (note that most all Processors already have a default endianness)
2. **Unexpected Error**: The operation failed in an unexpected manner that is internal to the operation and the caller would not handle in any other way than to propagate
    - Example: `ProcessorBuilder::build()` called and the tokio runtime failed to start
    - Example: `ProcessorBuilder::build()` called and a hook could not be added

Good error design is predicated by the distinction between these categories of errors and is scaffolded by the supporting error types. Notably, the caller in these definitions is different for each function. Additionally, the caller should not care about all operations deep in the system, rather the caller is interested in errors directly relating to the function at hand.

### The Expected Failure (type 1)

The expected failure is the rarer of the two and requires that the user of the API matches on its variants and not propagating.

In internal APIs this is simple, if nothing matches the Err then it should be removed.

In public APIs it is harder to decide if an error state should be caught and included in the API or just lumped into an UnknownError. When in doubt, ere on the side of simpler error types with less states. If a use case needs an error variant then it can be added later.

Expected error types should be avoided in most cases and kept simple when required to be included because they add overhead to development but have unproven user upside.

### The Unexpected Failure (type 2)

The unexpected failure is preferred because it is simpler. Unexpected errors that occur should be passed up where they will eventually be handled by the calling code. They are lumped together using `anyhow::Error`, called **UnknownError** in the Styx codebase. See the `styx-errors` documentation for an example using UnknownError and additional documentation.

Even some "expected" errors should be classified as unexpected failures. For example, a Loader could classify a file not found error as an unexpected failure by specifying that files paths passed to the Loader must be valid files.

Because unexpected errors are almost always present, all expected failure enums should include and `Unknown` variant that wraps an UnknownError.

### Deconstructing Complex Errors

First, evaluate if some of the error variants could be removed and lumped into the Unknown variant.

If none of the error types should be removed, consider moving different pieces of the validation API into separate structs. For example, if a processor builder takes a loader and the processor builder's build function can fail because the loaders regions overlap then consider processing/validating the loader on its creation so the processor builder can assume that the loader has no overlapping regions.

### Tools

- **Defining Error Type**: We utilize `thiserror` to define errors at the crate and major module levels. All custom errors have an Unknown variant wrapping `UnknownError` where appropriate to allow `.into()` and the `?` operator.

- **UnknownError**: `anyhow::Error` aliased as `UnknownError`is used to propagate and backtrace fatal errors without panicking.

- **Guidance on `unwrap` and `expect`**: The use of `unwrap()` should be limited to scenarios where failure should be impossible, and continuing would lead to undefined behavior. Scenarios include locking a mutex or unrwapping a . If `unwrap()` is deemed necessary, prefer `expect()` with a clear message explaining why the operation cannot fail. In general, aim to handle errors gracefully or propagate them using `?`.

## Logging

Consistent logging practices are crucial for debugging and monitoring:

- **Library Crates**: Except for designated "frontend crates", all library crates should use the `log` crate for logging purposes.

- **Frontend Crates and Services**: Frontend crates may choose between `log` and `tracing` based on their specific requirements. For services, especially those involving gRPC or HTTP communication, `tracing` is recommended to provide more context-rich logs.

## Adding Rust Dependencies

At this stage in the project we are not concerned with trimming the number of dependencies, here's the rough process for adding new dependencies:

### Identification

Before adding a new dependency, consider its impact:

- **Necessity**: Is the dependency essential for the functionality you're implementing? Could the functionality be reasonably implemented without adding an external dependency?
- **Quality and Maintenance**: Assess the quality, documentation, and maintenance status of the dependency. Prefer dependencies that are actively maintained and widely used in the Rust ecosystem.
- **License Compatibility**: Ensure the dependency's license is compatible with our project's license and does not impose any unwanted restrictions.

### Adding the Dependency

Once you've determined that a new dependency is necessary and beneficial, follow these steps to add it:

1. **Root Cargo.toml**: Add the dependency to the `[dependencies]` section of the root `Cargo.toml`. This centralizes the management of version numbers and makes updating dependencies across the workspace more straightforward.

2. **Workspace Integration**: In the specific package where you need the dependency, add a reference to it in the package's `Cargo.toml` file. Instead of specifying a version number, use the following syntax to indicate that this package is part of our workspace:

    ```toml
    [dependencies]
    "package-name" = { workspace = true }
    ```

    This approach ensures that we use a consistent version of the dependency across our workspace, minimizing conflicts and duplications. If you need different features than what is present in the root `Cargo.toml`, then add a `features = []` tag after the `workspace = true` portion of the dependency listing.

**Note**: CI will also require you to update the workspace hack configuration, follow the prompts in CI to do this

### Documentation

After the new dependency has been approved:

- **Update Documentation**: Include information about the new dependency in a separate commit for the changelog.
