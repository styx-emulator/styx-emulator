# arm testcase for b $offset11
# mach: unfinished

.include "testutils.inc"

	start
//testing addition
	mov r0,#1
	mov r1,#-1
	adds r2, r0, r1
	bne .Lfailure
	mov r0, #-1
	mov r1, #-1
	adds r2, r0, r1
	bpl .Lfailure
	mov r0, #2
	mov r1, #-1
	adds r2, r0, r1
	bcc .Lfailure
	mov r0, #0x80000000
	mov r1, #-1
	adds r2, r0, r1
	bvc .Lfailure
	mov r0, #-2
	mov r1, #1
	adds r2, r0, r1
	bcs .Lfailure

	mov r0, #1
	mov r1, #-1
	adds r2, r0, r1
	bne .Lfailure
	mov r0, #-1
	mov r1, #-1
	adds r2, r0, r1
	bpl .Lfailure
	mov r0, #2
	mov r1, #-1
	adds r2, r0, r1
	bcc .Lfailure
	mov r0, #0x80000000
	mov r1, #-1
	adds r2, r0, r1
	bvc .Lfailure
	mov r0, #-2
	mov r1, #1
	adds r2, r0, r1
	bcs .Lfailure

//subtraction
	mov r0, #1
	mov r1, #1
	subs r2, r0, r1
	bne .Lfailure
	mov r0, #-1
	mov r1, #1
	subs r2, r0, r1
	bpl .Lfailure
	mov r0, #2
	mov r1, #1
	subs r2, r0, r1
	bcc .Lfailure
	mov r0, #0x80000000
	mov r1, #1
	subs r2, r0, r1
	bvc .Lfailure
	mov r0, #-2
	mov r1, #-1
	subs r2, r0, r1
	bcs .Lfailure

	mov r0, #1
	mov r1, #1
	subs r2, r0, r1
	bne .Lfailure
	mov r0, #-1
	mov r1, #1
	subs r2, r0, r1
	bpl .Lfailure
	mov r0, #2
	mov r1, #1
	subs r2, r0, r1
	bcc .Lfailure
	mov r0, #0x80000000
	mov r1, #1
	subs r2, r0, r1
	bvc .Lfailure
	mov r0, #-2
	mov r1, #-1
	subs r2, r0, r1
	bcs .Lfailure
	pass

.Lfailure:
	fail
