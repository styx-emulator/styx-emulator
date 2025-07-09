# MACRO: exit
# Terminates execution.
	.macro exit nr

	stp	x29, x30, [sp,#-32]!
	mov	x4, #0x26
	mov	x7, #\nr
	mov	x29, sp
	movk	x4, #0x2, lsl #16
	add	x1, x29, #0x10
	str	x4, [x29,#16]
	str	x7, [x29,#24]
	mov	w0, #0x18
	hlt	#0xf000

	.endm

# MACRO: pass
# Write 'pass' to stdout and quit
	.macro pass

	mov x1, #0x0
	br x1
	.endm

# MACRO: fail
# Write 'fail' to stdout and quit
	.macro fail

	mov x1, #0x10
	br x1
	.endm

# MACRO: start
# All assembler tests should start with a call to "start"
	.macro start
	.data
.Lpass:
	.asciz "pass\n"
.Lfail:
	.asciz "fail\n"

	.text
.global _start
_start:
	.endm
