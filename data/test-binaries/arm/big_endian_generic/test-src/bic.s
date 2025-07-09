# Check that bit clear, xor/eor work

.include "testutils.inc"

	start
	mov  R0, #0b1111     //; R0 = 0b1111
    mov  R1, #0b0101     //; R1 = 0b0101
    bic  R2, R0, R1      //; R2 = R0 & ~(R1) = 0b1111 & 0b1010 = 0b1010
    str  r5, [r0]
    cmp  r2, #0b1010
    bne .Lfailure

    //check eor now
    eor r3, r1, r2
    mov r4, #0xf
    cmp r3, r4
    bne .Lfailure


    //we can test writing to the program counter if we dare
    //depricated in v6T2 & above.... so we are still valid :)

    //also use sp for setting thumb mode..... not a good idea for now
	pass

.Lfailure:
	fail
