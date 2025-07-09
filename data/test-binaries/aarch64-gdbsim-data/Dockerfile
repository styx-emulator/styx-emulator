FROM alpine:3.21 AS build

# install pre-requisites and aarch64 toolchain, add some links
RUN apk add --no-cache git libc6-compat make wget && \
    wget https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz && \
    tar -xJf arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz -C /usr/bin && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-as /usr/bin/aarch64-none-elf-as && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-ld /usr/bin/aarch64-none-elf-ld && \
    ln -s /usr/bin/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-objcopy /usr/bin/aarch64-none-elf-objcopy

# grab binutils-gdb sources
# single commit shallow clone of binutils
RUN mkdir /src && cd /src && \
    git init && \
    git remote add origin https://github.com/bminor/binutils-gdb.git && \
    git fetch --depth 1 origin dbd830f14f791fa8d27afa08b258347b95608e57 && \
    git checkout FETCH_HEAD

# build bins
RUN mkdir /testdata && mkdir /testdata/bin &&\
    cp -r /src/sim/testsuite/aarch64/ /testdata/src

# copy header and makefile into image
COPY testutils.inc ldnr.s xtl.s stn_single.s stn_multiple.s /testdata/src/
COPY Makefile /testdata/

# run make
RUN cd /testdata && make

FROM scratch AS export
COPY --from=build /testdata/bin/*.bin /
