FROM python:3.11

ENV DEBIAN_FRONTEND=noninteractive

ARG RUST_VERSION

ENV RUST_VERSION=${RUST_VERSION}

RUN apt update -yqq \
    && apt install -yqq --no-install-recommends \
    curl \
    direnv \
    build-essential \
    cmake \
    wget \
    clang \
    libclang-dev \
    valgrind \
    python3-pip \
    python3-virtualenv \
    gdb-multiarch \
    protobuf-compiler \
    libprotobuf-dev \
    device-tree-compiler \
    && curl -fsSL https://get.docker.com | sh \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VERSION} \
    && . ~/.cargo/env \
    && rustup toolchain install nightly --component miri,rust-src,llvm-tools-preview \
    && rustup component add llvm-tools-preview \
    && cargo install --force --locked \
    cargo-llvm-cov@0.6.16 \
    cargo-valgrind@2.2.1 \
    cargo-nextest@0.9.88 \
    cargo-hakari@0.9.35 \
    cargo-udeps@0.1.54 \
    taplo-cli@0.9.3 \
    maturin@1.8.3 \
    just@1.38.0
