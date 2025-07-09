
# MACRO: exit
# unused - may need to remove
# rc is exit state
	.macro exit rc
	mov r0, rc
	swi #2 //'User' will see as swi #2
	// intentional punt/crash
	stc 0,cr0,[r0]
	.endm

# MACRO: pass
# Write 'pass' to stdout and quit
# Related code hook will watch for
.macro pass
	mov r0, #4
	mov r1, #7
	bx r1
	.endm

# MACRO: fail
# Write 'fail' to stdout and quit
	.macro fail

	mov r0, #1
	mov r1, #8
	bx r1
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
