#!/bin/bash

export CI_PROJECT_DIR=${CI_PROJECT_DIR:-$(pwd)}
# shellcheck disable=SC1091
source "${CI_PROJECT_DIR}"/extensions/typhunix/scripts/common.sh

DEFAULT_GHIDRA=${GHIDRA_RELEASE_DIR}/$(
    echo "$LATEST_GHIDRA_RELEASE" | cut -d'|' -f1
)
export GHIDRA_INSTALL_DIR=${DEFAULT_GHIDRA}
MAKE_DIR=${CI_PROJECT_DIR}/extensions/typhunix

set -e
header "DOWNLOAD GHIDRA RELEASE(S)"
make download-ghidra
mapfile -t GHIDRA_RELS < <(/bin/ls -d "${GHIDRA_RELEASE_DIR}"/* | grep -Ev "\.zip$")
header "java lint ${DEFAULT_GHIDRA}"
make -C "${MAKE_DIR}" quality-check-java

num=${#GHIDRA_RELS[@]}
i=0
header "Build ${num} plugins..."
for GR in "${GHIDRA_RELS[@]}"; do
    i=$((i + 1))
    header "Build plugin [${i} of ${num}] [${GR}]"
    GHIDRA_INSTALL_DIR=$GR make -C "${MAKE_DIR}" typhunix-plugin-build-ext
done

header "TEST - $GHIDRA_INSTALL_DIR"
GHIDRA_INSTALL_DIR=${DEFAULT_GHIDRA} make -C "${MAKE_DIR}" build test

header "BUILD RELEASE/PYTHON WHEELS"
# python bindings and release bins
export VIRTUAL_ENV
DEFAULT_VIRTUAL_ENV=${VIRTUAL_ENV:-"/opt/python3.10-venv"}
VENVS=("${DEFAULT_VIRTUAL_ENV}")
[[ ${CI_COMMIT_BRANCH} == "main" ]] &&  {
    VENVS+=(
        /opt/python3.8-venv
        /opt/python3.9-venv
        /opt/python3.11-venv
        /opt/python3.12-venv
    )
}

num=${#VENVS[@]}
i=0
for venv in "${VENVS[@]}"; do
    i=$((i + 1))
    header "Build [$i of $num] release pyhon bindings: ($venv)"
    VIRTUAL_ENV=$venv
    PATH=$venv/bin:$PATH
    GHIDRA_INSTALL_DIR=${DEFAULT_GHIDRA} make -C "${MAKE_DIR}" wheel-release
    echo "Ok ($i of $num)"
done

header "Ok($?) - $0"
