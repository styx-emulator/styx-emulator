#!/bin/bash

# Script assumes typhunx plugin and server have already been built
export EXIT_CODE=0
export EXIT_STATUS="OK"
export CI_PROJECT_DIR=${CI_PROJECT_DIR:-$(pwd)}
export TEST_ARTIFACTS_DIR=${TEST_ARTIFACTS_DIR:-${CI_PROJECT_DIR}/extensions/typhunix/test-artifacts}

[[ -d "${TEST_ARTIFACTS_DIR}" ]] || mkdir -p  "${TEST_ARTIFACTS_DIR}"

export DISPLAY=${DISPLAY:-":99"} # needed for Xvfb
export VIRTX11
typeset -l VIRTX11=${VIRTX11:-xvfb}

show_header() {
    local n=80
    for _ in $(seq ${n}); do echo -n "-";done;echo
    echo "$*"
    for _ in $(seq ${n}); do echo -n "-";done;echo
}

# Env for logs
show_header "BUILD VARS: $(basename $GHIDRA_INSTALL_DIR)"
env | tee $TEST_ARTIFACTS_DIR/env.txt
show_header "Check build: $(basename $GHIDRA_INSTALL_DIR)"

# from here down, exit if we encounter an error
set -e

# we've already built typhunix - go to the built root dir
if [[ "${VIRTX11}" == xvfb ]] ;then
    # start virtual x server and GRPC server, in the background
    Xvfb ${DISPLAY} -screen 0 1280x1024x24 -nolisten tcp \
        > ${TEST_ARTIFACTS_DIR}/Xvfb.log  2>&1 &
    sleep 2
fi

rust/target/debug/typhunix-server 2>&1 \
    > ${TEST_ARTIFACTS_DIR}/typhunix-server.log 2>&1 &

# RUN the test
show_header "Run test: $(basename $GHIDRA_INSTALL_DIR)"
make gitlab-test 2>&1 | tee ${TEST_ARTIFACTS_DIR}/make_gitlab_test.log 2>&1

# Cleanup and collect anything we want to save
show_header "Cleanup and check: $(basename $GHIDRA_INSTALL_DIR)"
echo "Killing Xvfb, GRPC Server ... "
/bin/ps -f --no-headers -o pid,cmd  | \
    egrep "rust/target/debug/typhunix-server|Xvfb" | \
    grep -v grep | \
    awk '{print $1}' | \
    while read pid; do kill ${pid} || true;done

show_header "Gather Test Artifacts: $(basename $GHIDRA_INSTALL_DIR)"
echo TEST_ARTIFACTS_DIR=${TEST_ARTIFACTS_DIR}
(cd ${CI_PROJECT_DIR}/extensions/typhunix/TyphunixPlugin/build/reports; tar zcf - tests ) | \
    (cd $TEST_ARTIFACTS_DIR;tar vzxf -)

echo "Check tests: scripts/check_tests.sh ${TEST_ARTIFACTS_DIR} ..."
# Summarize/evaluate pass/fail
scripts/check_tests.sh ${TEST_ARTIFACTS_DIR}
exit $?
