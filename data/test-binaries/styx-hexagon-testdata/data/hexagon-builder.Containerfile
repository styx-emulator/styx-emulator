## This file is from tests/docker/dockerfiles/debian-hexagon-cross.docker of the qemu repository.
## This file is licensed under GPL-2.0-or-later.
##
## This file has modifications.
##
## Modifications:
## - Lennon Anderson - 2025-08-20
## - Ramesh Balaji   - 2026-05-22

# Containerfile to build QEMU's hexagon tcg tests.
#
# Steps:
# 1. Grab Qualcomm's hexagon Community SDK toolchain.
#    This used to grab the linaro hexagon toolchain, but linaro's toolchain lacks
#    certain features required to build qemu-hexagon-testing.
# 3. Copy and run build_ci.sh for qemu-hexagon-testing (clones qualcomm/qemu-hexagon-testing and builds it)
# 4. Delete scratch files that are unneeded for testing.
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
        wget \
        xz-utils \
	unzip \
        ca-certificates

ENV TOOLCHAIN_INSTALL   /opt
ENV TOOLCHAIN_VERSION  "6.5.0.0"
ENV TOOLCHAIN_TOOLSVER "19.0.07"
ENV TOOLCHAIN_BASENAME "Hexagon_SDK_Linux.zip"
ENV TOOLCHAIN_URL https://softwarecenter.qualcomm.com/api/download/software/sdks/Hexagon_SDK/Linux/Debian/${TOOLCHAIN_VERSION}/Hexagon_SDK_Linux.zip

# https://serverfault.com/questions/735882/unzip-from-stdin-to-stdout-funzip-python
RUN wget "$TOOLCHAIN_URL" -O /tmp/${TOOLCHAIN_BASENAME}
RUN unzip /tmp/${TOOLCHAIN_BASENAME} \
      -d "$TOOLCHAIN_INSTALL" \
      -x "*.qik" \
      "Hexagon_SDK/${TOOLCHAIN_VERSION}/tools/HEXAGON_Tools/${TOOLCHAIN_TOOLSVER}" && \
    rm /tmp/${TOOLCHAIN_BASENAME}


ENV TOOLCHAIN_BIN "${TOOLCHAIN_INSTALL}/Hexagon_SDK/${TOOLCHAIN_VERSION}/tools/HEXAGON_Tools/${TOOLCHAIN_TOOLSVER}/Tools/bin"
ENV HEXAGON_SDK_ROOT "${TOOLCHAIN_INSTALL}/Hexagon_SDK/${TOOLCHAIN_VERSION}"

FROM base AS build
# fetch/build deps
RUN DEBIAN_FRONTEND=noninteractive eatmydata \
    apt-get install -y --no-install-recommends \
        make \
	build-essential \
        git \
        cmake \
        ninja-build
RUN mkdir /src
WORKDIR /src

# copy and build qemu hexagon testing
WORKDIR /src
COPY /data/build_ci.sh /src
RUN /src/build_ci.sh

# test artifacts are in /testdata/bin
FROM build AS release
RUN mkdir -p /testdata/bin/
WORKDIR /testdata
COPY --from=build /src/qemu-hexagon-testing/build-systests/bin/* bin/

# container will exit (then rm) after 100 seconds
ENTRYPOINT [ "sh", "-c", "sleep 100" ]
