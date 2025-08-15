## This file is from tests/docker/dockerfiles/debian-hexagon-cross.docker of the qemu repository.
## This file is licensed under GPL-2.0-or-later.
##
## This file has modifications.
##
## Modifications:
## - Lennon Anderson - 2025-08-20

# Containerfile to build QEMU's hexagon tcg tests.
#
# Steps:
# 1. Grab Linaro hexagon toolchain
#   - I think this could also use quic's if they're not the same
#   - https://github.com/quic/toolchain_for_hexagon
# 2. Shallow clone QEMU repo and grab tests
# 3. Build tests via toolchain
#
# TODO add the mutiarch tcg tests

FROM docker.io/library/debian:11-slim AS base

ARG jobs=4

# Duplicate deb line as deb-src
RUN cat /etc/apt/sources.list | sed "s/^deb\ /deb-src /" >> /etc/apt/sources.list
# Pull toolchain deps
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt install -yy eatmydata && \
    DEBIAN_FRONTEND=noninteractive eatmydata \
# Install common build utilities
    apt-get install -y --no-install-recommends \
        curl \
        xz-utils \
        ca-certificates

ENV TOOLCHAIN_INSTALL /opt
ENV TOOLCHAIN_RELEASE 12.Dec.2023
ENV TOOLCHAIN_BASENAME "clang+llvm-${TOOLCHAIN_RELEASE}-cross-hexagon-unknown-linux-musl"
ENV TOOLCHAIN_URL https://codelinaro.jfrog.io/artifactory/codelinaro-toolchain-for-hexagon/${TOOLCHAIN_RELEASE}/${TOOLCHAIN_BASENAME}.tar.xz

RUN curl -#SL "$TOOLCHAIN_URL" | tar -xJC "$TOOLCHAIN_INSTALL"
ENV TOOLCHAIN_BIN "${TOOLCHAIN_INSTALL}/${TOOLCHAIN_BASENAME}/x86_64-linux-gnu/bin"
ENV PATH $PATH:$TOOLCHAIN_BIN
ENV MAKE /usr/bin/make
ENV CC ${TOOLCHAIN_BIN}/hexagon-unknown-linux-musl-clang

FROM base AS build
# fetch/build deps
RUN DEBIAN_FRONTEND=noninteractive eatmydata \
    apt-get install -y --no-install-recommends \
        make \
        git \
        # why need this
        libxml2
RUN mkdir /src
WORKDIR /src
# single commit shallow clone QEMU repo
RUN mkdir -p qemu && cd qemu && \
    git init && \
    git remote add origin https://gitlab.com/qemu-project/qemu.git && \
    # August 13th, 2025
    git fetch --depth 1 origin 5836af0783213b9355a6bbf85d9e6bc4c9c9363f && \
    git checkout FETCH_HEAD

# copy and build tests
RUN mkdir -p tests/
WORKDIR tests/
RUN mkdir -p src/ && \
    cp ../qemu/tests/tcg/hexagon/* src/
COPY data/Makefile .
RUN mkdir -p build/ && make -j $jobs all

FROM build AS release
RUN mkdir -p /testdata/bin
WORKDIR /testdata
COPY --from=build /src/tests/build/* bin/

# test artifacts are in /testdata/bin

# container will exit (then rm) after 100 seconds
ENTRYPOINT [ "sh", "-c", "sleep 100" ]
