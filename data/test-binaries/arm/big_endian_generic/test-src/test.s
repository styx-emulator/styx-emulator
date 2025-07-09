.include "testutils.inc"

    start
    mov r0, #1       // Put 1 into r0
    mov r1, #2       // Put 2 into r1
    add r2, r0, r1   // r2 = r0 + r1 = 3
    cmp r2, #3
    bne .Lfailure
    pass

.Lfailure:
    fail
