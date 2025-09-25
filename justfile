#!/usr/bin/env -S just --justfile

# use bash
set shell := ["bash", "-c"]

alias test := full-cargo-test
alias t := cargo-test
alias b := build
alias miri := cargo-miri
alias loom := cargo-loom
alias valgrind := valgrind-test
alias asan := asan-test
alias bench := cargo-bench
alias rs-doctest := cargo-doc-test

# hardcode path to the python interpreter
py-path := "./venv/bin/python3"

# List of crates, checks if the sub-directory contains Cargo.toml
GENERATED_CRATES := `find ./styx/generated -mindepth 1 -maxdepth 1 -type d -name "styx*" -exec test -e "{}/Cargo.toml" \; -print -prune | xargs -n1 basename`
EXAMPLE_CRATES := `find ./examples -mindepth 1 -maxdepth 1 -type d -exec test -e "{}/Cargo.toml" \; -print -prune | xargs -n1 basename`
INCUBATION_CRATES := `find ./incubation -mindepth 1 -maxdepth 1 -type d -exec test -e "{}/Cargo.toml" \; -print -prune | xargs -n1 basename`
DB_CONTAINER_CRATES := `echo "styx-dbutil styx-dbmodel styx-migration"`
# useful to exclude from tests which cause errors when run
MACRO_CRATES := `echo "styx-macros styx-macros-args typhunix-macros"`
SRC_CRATES := `find ./styx/core -mindepth 1 -maxdepth 1 -type d -exec test -e "{}/Cargo.toml" \; -print -prune | xargs -n1 basename`

# crates to ignore for tests
__IGNORE_CRATES := EXAMPLE_CRATES + " " + INCUBATION_CRATES + " " + GENERATED_CRATES

test-ignore-crates-value:
    #!/bin/bash -e
    IGNORE_CRATES=`a=({{ __IGNORE_CRATES }}); echo "${a[@]/#/--exclude }"`
    echo "Ignoring $IGNORE_CRATES"

c-bindings:
    #!/bin/bash -e
    cd styx/bindings/styx-c-api
    cargo build --release

python-bindings:
    #!/bin/bash -e
    cd styx/bindings/styx-py-api
    maturin build

license-check: nogpl-check
    cargo xtask license -c

# checks if the no-default-features build has no gpl code
nogpl-check:
    ./util/etc/gpl/nogpl-check

full-cargo-test: cargo-test cargo-doc-test cargo-test-bindings
cargo-test: cargo-test-deps
    #!/bin/bash -e
    IGNORE_CRATES=`a=({{ DB_CONTAINER_CRATES }} {{ MACRO_CRATES }}); echo "${a[@]/#/--exclude }"`
    cargo nextest run --workspace --lib --bins --tests $IGNORE_CRATES # no benches

cargo-test-bindings:
    #!/bin/bash -e
    pushd styx/bindings/
    cargo nextest run

cargo-doc-test:
    #!/bin/bash -e
    cargo test --doc --workspace --no-fail-fast

llvm-coverage-test:
    #!/bin/bash -e
    IGNORE_CRATES=`a=({{ __IGNORE_CRATES }}); echo "${a[@]/#/--exclude }"`
    export RUSTFLAGS="${RUSTFLAGS} -Zlinker-features=-lld"
    export RUSTDOCFLAGS="${RUSTDOCFLAGS} -Zlinker-features=-lld"
    source <(cargo +nightly llvm-cov show-env --export-prefix --doctests)
    cargo +nightly llvm-cov clean --workspace
    cargo +nightly test --doc --workspace --all-features --no-fail-fast $IGNORE_CRATES
    cargo +nightly nextest run --workspace --all-features --all-targets $IGNORE_CRATES || true # XXX: broken as of rust 1.86
    cargo +nightly llvm-cov report --html --output-dir ./target/llvm-cov/ --doctests

coverage: llvm-coverage-test
    @echo "The Rust API Coverage information is located at ./target/llvm-cov/html/index.html"

valgrind-test:
    RUSTFLAGS="${RUSTFLAGS} --cfg asan" cargo valgrind nextest run --release

cargo-miri:
    MIRIFLAGS="-Zmiri-disable-isolation -Zmiri-strict-provenance -Zmiri-retag-fields" cargo +nightly miri nextest run --workspace --release

cargo-bench:
    cargo bench

cargo-loom:
    #!/bin/bash -e
    export RUSTFLAGS="${RUSTFLAGS} --cfg loom --cfg tokio_unstable -C debug-assertions" # -Dwarnings
    export LOOM_MAX_PREEMPTIONS=2
    export LOOM_MAX_BRANCHES=10000
    cargo test --release --all-features --no-fail-fast loom -- --nocapture

shuttle:
    #!/bin/bash -e
    export RUSTFLAGS="${RUSTFLAGS} --cfg shuttle"
    # only tests with `shuttle` in the name will be executed
    cargo test --all-features --no-fail-fast shuttle -- --nocapture

build:
    cargo build --locked --workspace --all-targets

asan-test:
    #!/bin/bash -e
    IGNORE_CRATES=`a=({{ __IGNORE_CRATES }}); echo "${a[@]/#/--exclude }"`
    export RUSTFLAGS="${RUSTFLAGS} -Z sanitizer=address -Z linker-features=-lld --cfg asan "
    cargo +nightly nextest run --target x86_64-unknown-linux-gnu --workspace $IGNORE_CRATES

clean-target:
    find ./target/debug -maxdepth 1 -type f -delete
    rm -f ./target/debug/deps/*styx_*
    du -sh target/

lint-docs:
    #!/bin/bash -e
    set -eou pipefail

    RUSTDOCFLAGS='--deny warnings' cargo doc --no-deps --all-features --workspace --bins --lib --examples --keep-going --document-private-items

rust-docs-inner:
    #!/bin/bash -e
    IGNORE_CRATES=`a=({{ __IGNORE_CRATES }}); echo "${a[@]/#/--exclude }"`
    cargo doc --all-features --workspace --lib --bins --no-deps --document-private-items $IGNORE_CRATES
    cp -f ./data/misc/redirect.html ./target/doc/index.html

rust-docs: rust-docs-inner
    @echo "The Rust API docs are located at ./target/doc/index.html"

docs:
    @echo  "Making docs"
    #!/bin/bash -e
    . venv/bin/activate && sphinx-build -b html -jauto docs/source/ docs/build/

cargo-test-deps:
    cargo build -p workspace-service

docs-deps: python-deps llvm-coverage-test docs

mk-venv:
    python3 -m virtualenv -h > /dev/null || (echo "Please install python-virtualenv"; exit 1)
    [ -d venv ] || python3 -m virtualenv venv

python-deps: mk-venv
    {{ py-path }} -m pip install -r requirements.txt

rust-deps:
    cargo install --force --locked cargo-nextest@0.9.35 cargo-llvm-cov@0.6.16 cargo-valgrind@2.2.1 taplo-cli@0.9.3 cargo-hakari@0.9.35 just@1.38.0 git-cliff@2.7.0

container-setup: mk-venv rust-fetch

rust-fetch:
    cargo fetch --manifest-path ./Cargo.toml
    cargo fetch --manifest-path ./styx/bindings/Cargo.toml

setup: python-deps rust-deps rust-fetch

# Build the Docker container for development (takes docker platform as arg)
build-docker platform="linux/amd64":
    #!/bin/bash -e
    RUST_VERSION=$(cat .rust-version)
    docker build -t styx-ci -f ./util/docker/ci.Dockerfile --platform {{platform}} --build-arg RUST_VERSION=$RUST_VERSION .

# Run just commands inside the Docker container
docker *ARGS:
    docker run --rm -it -v "$(pwd):/workspace" -w /workspace -e PATH="/root/.cargo/bin:$PATH" localhost/styx-ci just {{ARGS}}

# Pass all arguments to cargo
cargo *ARGS:
    cargo {{ARGS}}
