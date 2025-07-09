# Check the non-widening multiply vector instruction: mul.

.include "testutils.inc"

	start
	mov r0, #8
    mul r1, r0, r0 //should be 64
    mov r2, #64
    cmp r1, r2
    bne .Lfailure

    mov r0,#1
	mov r1,#-1
	muls r1, r0, r1
	bpl .Lfailure

	pass

.Lfailure:
	fail
