#!/bin/bash

RED="\u001b[31m"
CYN="\u001b[36m"
RST="\u001b[0m"

WORKDIR=/build

CARGO_HOME=${CARGO_HOME:-"${WORKDIR}/.cargo_1.77.2"}
GRADLE_USER_HOME=${GRADLE_USER_HOME:-"${WORKDIR}/.gradle_v7.5"}
VERSION=${VERSION:-Typhunix-$("$CI_PROJECT_DIR"/extensions/typhunix/scripts/version.sh)}

[[  -d "${GHIDRA_INSTALL_DIR}" ]] || {
    printf "${RED}Must set and export GHIDRA_INSTALL_DIR\n${RST}" 1>&2
    exit 1
}

ARGS=(
    # un-comment to force all ghidra releases and python bindings
    #  -e CI_COMMIT_BRANCH=main
    -e CARGO_HOME="${CARGO_HOME}"
    -e GRADLE_USER_HOME="${GRADLE_USER_HOME}"
    -e DISPLAY=:99
    -e GHIDRA_INSTALL_DIR=/opt/ghidra
    -e VERSION="${VERSION}"
	-e MINIO_ALIAS="${MINIO_ALIAS}"
	-e MINIO_HOST="${MINIO_HOST}"
	-e MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY}"
	-e MINIO_SECRET_KEY="${MINIO_SECRET_KEY}"
    # MOUNT
    -v "${CI_PROJECT_DIR}":"${WORKDIR}"
    -v "${GHIDRA_INSTALL_DIR}":/opt/ghidra
    -v "${CARGO_HOME}":"${CARGO_HOME}"
    -v "${GRADLE_USER_HOME}":"${GRADLE_USER_HOME}"
    # WORKDIR
    -w "${WORKDIR}"
    # IMAGE
    "${CI_REGISTRY_IMAGE}"
)

CMD=(docker run -it "${ARGS[@]}" $@ )
echo "${CMD[@]}"

# "${CMD[@]}"
# exit $?
