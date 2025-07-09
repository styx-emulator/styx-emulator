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
    wget \
    && dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install libc6:i386 zlib1g:i386 -y \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://releases.linaro.org/archive/14.04/components/toolchain/binaries/gcc-linaro-armeb-none-eabi-4.8-2014.04_linux.tar.bz2
RUN tar -xjf gcc-linaro-armeb-none-eabi-4.8-2014.04_linux.tar.bz2 -C /usr/bin
RUN ln -s /usr/bin/gcc-linaro-armeb-none-eabi-4.8-2014.04_linux/bin/armeb-none-eabi-as /usr/bin/armeb-none-eabi-as && \
    ln -s /usr/bin/gcc-linaro-armeb-none-eabi-4.8-2014.04_linux/bin/armeb-none-eabi-ld /usr/bin/armeb-none-eabi-ld && \
    ln -s /usr/bin/gcc-linaro-armeb-none-eabi-4.8-2014.04_linux/bin/armeb-none-eabi-objcopy /usr/bin/armeb-none-eabi-objcopy

RUN mkdir /testdata && mkdir /testdata/elf && mkdir /testdata/src
WORKDIR /testdata

COPY  ./test-src/* src/
COPY Makefile .
COPY testutils.inc src/
RUN make

# files are in /testdata/bin

# container will exit (then rm) after 100 seconds
ENTRYPOINT [ "sh", "-c", "sleep 100"]
