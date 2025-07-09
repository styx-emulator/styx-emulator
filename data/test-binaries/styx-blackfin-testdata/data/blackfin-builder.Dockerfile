FROM ubuntu:22.04@sha256:bace9fb0d5923a675c894d5c815da75ffe35e24970166a48a4460a48ae6e0d19 AS base

ARG jobs=4
ENV LC_CTYPE=C.UTF-8

# get gdb deps
RUN DEBIAN_FRONTEND=noninteractive apt update && \
    apt install -y \
    git \
    build-essential \
    texinfo \
    bison \
    flex \
    libgmp-dev \
    python3-dev \
    python3 \
    python3-pip \
    libmpfr-dev \
    g++ \
    gcc \
    libpython3-dev \
    gawk \
    file \
    zip \
    curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS build

# grab binutils-gdb sources
RUN mkdir /src
WORKDIR /src
# single commit shallow clone
RUN git init && \
    git remote add origin https://github.com/bminor/binutils-gdb.git && \
    git fetch --depth 1 origin d65111ff0a4bf2a7bcc37c4580089bf4ff161b0c && \
    git checkout FETCH_HEAD

WORKDIR /src

# do the actual configure and build of gdb
RUN ./configure --enable-sim \
        --target=bfin-elf \
        --prefix=/usr \
        --with-python=python3 && \
    make -j $jobs all-sim && \
    make -j $jobs && \
    make install

FROM base AS release

# copy output
COPY --from=build /usr/bin/bfin-elf-* /usr/bin/
COPY --from=build /usr/share/gdb /usr/share/gdb


FROM release AS build-tests

RUN mkdir /testdata && mkdir /testdata/bin
WORKDIR /testdata
COPY --from=build /src/sim/testsuite/bfin/* src/
COPY data/Makefile .
COPY data/testutils.inc src/
RUN make

# files are in /testdata/bin

# container will exit (then rm) after 100 seconds
ENTRYPOINT [ "sh", "-c", "sleep 100" ]
