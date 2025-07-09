// testing branches for loop completeness
 .include "testutils.inc"

    start
    bl test_conditional_branch
    bl test_loop_branch

    pass




@ -------------------------------
test_conditional_branch:
    mov r0, #5
    mov r1, #5
    cmp r0, r1
    bne .Lfailure     @ should not branch (equal)
    bx lr

@ -------------------------------
test_loop_branch:
    mov r2, #3        @ loop counter
    mov r3, #0        @ accumulator

.Lloop:
    add r3, r3, #1
    subs r2, r2, #1
    bne .Lloop        @ loop 3 times

    cmp r3, #3        @ confirm loop ran 3 times
    bne .Lfailure
    bx lr

.Lfailure:
	fail
