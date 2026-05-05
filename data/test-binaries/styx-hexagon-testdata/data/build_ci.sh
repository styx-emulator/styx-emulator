#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# This script downloads Qualcomm's qemu-hexagon-testing, which are a useful set of tests for
# system-level Hexagon support and various Hexagon peripherals. It then compiles these tests
# using the instructions in qemu-hexagon-testing's repository. Compilation of qemu-hexagon-testing
# requires a recent Hexagon SDK.
#
# The script requiers the environment variable HEXAGON_SDK_ROOT to be set. The root looks like
# /path/to/Hexagon_SDK/VERSION. For example, /opt/Hexagon_SDK/6.5.0.0 would be a valid HEXAGON_SDK_ROOT.
#
# styx-hexagon-testdata uses a Dockerfile to build a Docker image with test binaries available at /testdata.
# The test binaries are extracted from Docker and are later available for use in other styx crates.
# During the Docker image build, this script is run to build the test binaries.

# Gets aboslute path to directory containing this script.
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ ! -d "$SCRIPT_DIR"/qemu-hexagon-testing ]; then
	git clone https://github.com/qualcomm/qemu-hexagon-testing "$SCRIPT_DIR"/qemu-hexagon-testing

	cd "$SCRIPT_DIR"/qemu-hexagon-testing || exit 1
	git checkout d447953254f7f13e66db2a68bed322f084dbbfdf

	cmake -S standalone_systests -B build-systests \
	  -G Ninja \
	  -DCMAKE_TOOLCHAIN_FILE="${PWD}"/cmake/hexagon-standalone.cmake \
	  -DHEXAGON_SDK_ROOT="$HEXAGON_SDK_ROOT" \
	  -DHEXAGON_ARCH=v71
	cmake --build build-systests
else
	echo "Skipping build qemu-hexagon-testing for CI since it was already cloned."
fi
