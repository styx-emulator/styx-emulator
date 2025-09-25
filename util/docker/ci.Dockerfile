FROM python:3.11@sha256:c1239cb82bf08176c4c90421ab425a1696257b098d9ce21e68de9319c255a47d

LABEL org.opencontainers.image.source=https://github.com/styx-emulator/styx-emulator
LABEL org.opencontainers.image.description="CI container for the Styx Emulator"
LABEL org.opencontainers.image.licenses=BSD-2-Clause

ENV DEBIAN_FRONTEND=noninteractive

ARG RUST_VERSION
ENV RUST_VERSION=${RUST_VERSION}

ADD ./requirements.txt /tmp/requirements.txt

RUN apt update -yqq \
    && apt install -yqq --no-install-recommends \
    curl \
    ninja-build \
    direnv \
    build-essential \
    cmake \
    wget \
    clang \
    libclang-dev \
    valgrind \
    gdb-multiarch \
    protobuf-compiler \
    libprotobuf-dev \
    device-tree-compiler \
    && python3 -m pip install -U \
    virtualenv \
    pip \
    && python3 -m pip install -r /tmp/requirements.txt \
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
    cargo-udeps@0.1.57 \
    taplo-cli@0.9.3 \
    maturin@1.8.3 \
    just@1.38.0 \
    # purge all the caches
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip cache purge \
    && rm -rf ~/.cache/pip \
    && rm -rf ~/.cargo/{.crates*,*cache*,registry}
