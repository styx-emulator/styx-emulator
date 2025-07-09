#!/bin/bash

#-------------------------------------------------------------------------------
CI_PROJECT_DIR=${CI_PROJECT_DIR:-$(pwd)}
GHIDRA_RELEASE_DIR=${GHIDRA_RELEASE_DIR:-${CI_PROJECT_DIR}}/ghidra-releases
CI_COMMIT_BRANCH=${CI_COMMIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
GHIDRA_DOWNLOADS=https://github.com/NationalSecurityAgency/ghidra/releases/download
#-------------------------------------------------------------------------------


#-------------------------------------------------------------------------------
export ALL_GHIDRA_URLS=(
    # GHIDRA list: ~a couple years
    # Available list
    "ghidra_10.1.2_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
    "ghidra_10.1.3_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.1.3_build/ghidra_10.1.3_PUBLIC_20220421.zip"
    "ghidra_10.1.4_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip"
    "ghidra_10.1.5_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip"
    "ghidra_10.2.2_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip"
    "ghidra_10.2.3_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip"
    "ghidra_10.3.1_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.3.1_build/ghidra_10.3.1_PUBLIC_20230614.zip"
    "ghidra_10.4_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip"
    "ghidra_11.0_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip"
    "ghidra_11.0.1_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip"
    "ghidra_11.0.2_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip"
    "ghidra_11.0.3_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip"
    "ghidra_11.1_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip"
    "ghidra_11.1.1_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.1.1_build/ghidra_11.1.1_PUBLIC_20240614.zip"
    "ghidra_11.1.2_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip"
)
#-------------------------------------------------------------------------------
export SUPPORTED_GHIDRA=(
    # SUPPORTED_GHIDRA list: 10.1.5 (required support for large math), latest 10.x and latest
    "ghidra_10.1.5_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip"
    "ghidra_10.4_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip"
    "ghidra_11.0.3_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip"
    "ghidra_11.1_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip"
    "ghidra_11.1.2_PUBLIC|${GHIDRA_DOWNLOADS}/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip"
)
#-------------------------------------------------------------------------------
export LATEST_GHIDRA_RELEASE=$(echo ${ALL_GHIDRA_URLS[-1]})
header() {
    local n=80
    for _ in $(seq ${n}); do echo -n "-";done;echo
    echo "$*"
    for _ in $(seq ${n}); do echo -n "-";done;echo
}
