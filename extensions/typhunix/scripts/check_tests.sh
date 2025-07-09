#!/bin/bash
export TEST_ARTIFACTS_DIR=$1
export EXIT_CODE=0
export EXIT_STATUS=OK

set -e

show_header() {
    local n=80
    for _ in $(seq ${n}); do echo -n "-";done;echo
    echo "$*"
    for _ in $(seq ${n}); do echo -n "-";done;echo
}

RUST_LOG=${TEST_ARTIFACTS_DIR}/rust_tests_summary.txt
JAVA_LOG=${TEST_ARTIFACTS_DIR}/java_tests_summary.txt

# consolidate
find $TEST_ARTIFACTS_DIR/tests -name '*.html' | xargs cat  | \
    egrep "(PASSED|FAILED) Test:" | sed -e "s/.*DEBUG..//" 2>&1 > \
    ${JAVA_LOG}
grep "^test " ${TEST_ARTIFACTS_DIR}/make_gitlab_test.log > \
     ${RUST_LOG}

# Count
RUST_PASSFAIL=(
    $(cat ${TEST_ARTIFACTS_DIR}/rust_tests_summary.txt | egrep "^test result:" |
    awk '{pass+=$4;fail+=$6} END {printf("%d %d", pass, fail)}')
)
typeset -i javaPass=$(grep PASSED ${JAVA_LOG} | wc -l)
typeset -i javaFail=$(grep FAILED ${JAVA_LOG} | wc -l)
typeset -i rustPass=${RUST_PASSFAIL[0]}
typeset -i rustFail=${RUST_PASSFAIL[1]}
typeset -i totalPass=$((rustPass + javaPass))
typeset -i totalFail=$((rustFail + javaFail))


show_header "Test Results ($(basename $GHIDRA_INSTALL_DIR))"
echo  "> Rust/GRPC"
grep "^test " ${RUST_LOG} | egrep -v "^test result:"

echo
echo "> Java/Plugin"
cat ${JAVA_LOG}

show_header "Pass / Fail Counts ($(basename $GHIDRA_INSTALL_DIR))"
echo
printf "  %-12s %4s %4s\n" "Component" "PASS" "FAIL"
printf "  %-12s %4s %4s\n" "------------"  "----" "----"
printf "  %-12s %4d %4d\n" "Rust/GRPC"  ${rustPass} ${rustFail}
printf "  %-12s %4d %4d\n" "Java/Plugin" ${javaPass} $javaFail
printf "  %-12s %4s %4s\n" "------------"  "----" "----"
printf "  %-12s %4d %4d\n" "TOTAL" ${totalPass} ${totalFail}
printf "\n"

# make sure we ran at least one test too
(( totalPass > 0 && totalFail == 0 && javaPass > 0 && rustPass > 0)) || {
    EXIT_CODE=1
    EXIT_STATUS="FAILED"
}

# Exit non-zero if anything failed
show_header "+ Exit: ${EXIT_STATUS} [${EXIT_CODE}]  ($(basename $GHIDRA_INSTALL_DIR))"
exit $EXIT_CODE
