# Check that store and load work

.include "testutils.inc"

	.data
	.align 4

	start
	mov r0, #0xDE
	mov r1, #0x2000
	str r0,[r1]
	ldr r3,[r1] //load data stored @ address r1
	cmp r0, r3 //they should be same
    bne .Lfailure


    //we can test writing to the program counter if we dare
    //depricated in v6T2 & above.... so we are still valid :)

    //also use sp for setting thumb mode..... not a good idea for now
	pass

.Lfailure:
	fail
