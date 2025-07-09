#ifdef __GNUC__
/* $Id: xvectors.S,v 1.2.2.2 2006/04/12 22:23:14 vasanth Exp $ */
/*****************************************************************************
*
* Copyright (c) 2004 Xilinx, Inc.  All rights reserved.
*
* Xilinx, Inc.
* XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS" AS A
* COURTESY TO YOU.  BY PROVIDING THIS DESIGN, CODE, OR INFORMATION AS
* ONE POSSIBLE   IMPLEMENTATION OF THIS FEATURE, APPLICATION OR
* STANDARD, XILINX IS MAKING NO REPRESENTATION THAT THIS IMPLEMENTATION
* IS FREE FROM ANY CLAIMS OF INFRINGEMENT, AND YOU ARE RESPONSIBLE
* FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE FOR YOUR IMPLEMENTATION.
* XILINX EXPRESSLY DISCLAIMS ANY WARRANTY WHATSOEVER WITH RESPECT TO
* THE ADEQUACY OF THE IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO
* ANY WARRANTIES OR REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE
* FROM CLAIMS OF INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY
* AND FITNESS FOR A PARTICULAR PURPOSE.
*
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xvectors.S
*
* This file contains low-level functions for the PowerPC exception handler.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ch   06/18/02 First release
* </pre>
*
*****************************************************************************/

/*-----------------------------------------------------------------------------
//
// Documentation:
//
//    This is the structure of the PPC 405 interrupt stack frame that is
//    pushed onto the stack during an exception.
//
//    This interrupt frame only saves the User Model register sets that
//    could be used/genterated by compiler generated code. Any usage of
//    registers in an ISR beyond this set must be save/restored by the
//    ISR routine.
//
//    In general, this interrupt frame conforms to a standard PPC EABI
//    Stack Call Frame. The entire frame is 160 bytes (40 words) in size,
//    which is an exact multible of 8 bytes as required the PPC EABI.
//    And by using the standard EABI frame header, debuggers should still
//    be able to display the Stack Call Chain even for break points in an
//    exception handler function.
//
//    However, there are a few exceptions to EABI conventions :
//
//        1. The frame saves ALL registers instead of just registers that
//           will be modified. Exceptions can occur at any point instead
//           of just at function call branch points. Hence, saving the entire
//           context means an exception will never disturb the interrupted
//           code's register usage.
//
//        2. The current LR register contents is NOT save in the previous
//           Stack Frame as in standard EABI conventions. Rather, it is
//           saved in the local frame. This done to avoid corrupting the
//           previous Stack Frame's LR field, when the exception occurs
//           during an interrupted function's entry prologue process.
//
//        3. Unlike standard EABI frames, the interrupted PC location, and
//           MSR state is also saved to the frame. This may seem unnecessary
//           since registers SRR0 - SRR3 in the 405 are used exclusively to
//           save the PC and MSR during exceptions. However, always saving
//           the PC and MSR prepares this code for use in a multi-threaded
//           environment.
//
//        4. The USPRG0 register is also saved even though compilers will
//           never generate code to use it. Once again, this prepares the
//           way for use in a multi-threaded environment. This register
//           would be used to contain a pointer to the TCB (Task Control
//           Block) for the current task that is being interrupted.
//           Subsequent system code could then switch the memory map/context
//           from the TCB; such as the PID register.
//
//    +------------+
//    |     r31    | +156
//    |      .     |
//    |      .     |
//    |      .     |
//    |     r3     | +44
//    +------------+
//    |     r2     | +40
//    +------------+
//    |     r0     | +36
//    +------------+
//    |   USPRG0   | +32
//    +------------+
//    |     CR     | +28
//    +------------+
//    |     XER    | +24
//    +------------+
//    |     CTR    | +20
//    +------------+
//    |     LR     | +16
//    +------------+
//    |     PC     | +12
//    +------------+
//    |     MSR    | +8
//    +------------+
//    |   Next LR  | +4
//    +------------+
//    | Back Chain | +0
//    +------------+
//
//---------------------------------------------------------------------------*/

#endif

#include "xreg405.h"

	.file "xvectors.S"

	.section ".vectors","ax"

#ifdef __DCC__
#define // ;
#define MACRO0(name)name:	.macro
#define MACRO1(name, param1)name:	.macro	param1
#define MACRO2(name, param1, param2)name:	.macro	param1, param2
#define CONCAT(left, right) left##&&##right
#define CONCAT3(left, parammiddle, right) left##&&##parammiddle##right
#define PARAM(param) param
#else
#include <ppc-asm.h>
#define r1 1
#define r2 2
#define MACRO0(name) .macro	name
#define MACRO1(name, param1) .macro	name	param1
#define MACRO2(name, param1, param2) .macro	name	param1 param2
#define CONCAT(left,right) left##right
#define PARAM(param) param
#endif

	//---------------------------------------------------------------------
	//
	// Define interrupt frame structure offsets.
	//
	//---------------------------------------------------------------------

	.set	BChainField, 0
	.set	NextLRField, BChainField + 4
	.set	MSRField,    NextLRField + 4
	.set	PCField,     MSRField    + 4
	.set	LRField,     PCField     + 4
	.set	CTRField,    LRField     + 4
	.set	XERField,    CTRField    + 4
	.set	CRField,     XERField    + 4
	.set	USPRG0Field, CRField     + 4
	.set	r0Field,     USPRG0Field + 4
	.set	r2Field,     r0Field     + 4
	.set	r3r31Field,  r2Field     + 4
	.set	IFrameSize,  r3r31Field  + ( ( 31 - 3 ) + 1 ) * 4


	//---------------------------------------------------------------------
	//
	// Macro for the interrupt frame prologue.
	//
	//---------------------------------------------------------------------

	MACRO1(int_prologue, base)

	.org	_vectorbase + CONCAT(0x,\base)
	.globl	CONCAT(_vector,\base)
#ifdef __DCC__
CONCAT3(_vector, base, :)
#else
_vector\base:
#endif
	stwu	XREG_GPR1,-IFrameSize(XREG_GPR1)	// Save Back chain and move SP

	// Save r0 and r2.
	stw	XREG_GPR0, r0Field(XREG_GPR1)
	stw	XREG_GPR2, r2Field(XREG_GPR1)

	stmw	XREG_GPR3, r3r31Field(XREG_GPR1)	// Save the remaining GPR registers r3-r31

	// Save current Link register
	mflr	XREG_GPR0
	stw	XREG_GPR0, LRField(XREG_GPR1)

	// Save Counter register
	mfctr	XREG_GPR0
	stw	XREG_GPR0,CTRField(XREG_GPR1)

	// Save Fixed Point Exception register
	mfxer	XREG_GPR0
	stw	XREG_GPR0,XERField(XREG_GPR1)

	// Save Condition register
	mfcr	XREG_GPR0
	stw	XREG_GPR0,CRField(XREG_GPR1)

	// Save USPRG0 register
	mfspr	XREG_GPR0,0x100
	stw	XREG_GPR0,USPRG0Field(XREG_GPR1)

	.endm


	//---------------------------------------------------------------------
	//
	// Macro for the interrupt frame epilogue.
	//
	//---------------------------------------------------------------------

	MACRO0(int_epilogue)

	// Save USPRG0 register
	lwz	XREG_GPR0,USPRG0Field(XREG_GPR1)
	mtspr	0x100,XREG_GPR0

	// Restore Condition register
	lwz	XREG_GPR0,CRField(XREG_GPR1)
	mtcr	XREG_GPR0

	// Restore Fixed Point Exception register
	lwz	XREG_GPR0,XERField(XREG_GPR1)
	mtxer	XREG_GPR0

	// Restore Counter register
	lwz	XREG_GPR0,CTRField(XREG_GPR1)
	mtctr	XREG_GPR0

	// Restore Link register
	lwz	XREG_GPR0,LRField(XREG_GPR1)
	mtlr	XREG_GPR0

	// Restore remaining GPR registers.
	lmw	XREG_GPR3,r3r31Field(XREG_GPR1)

	// Restore r0 and r2.
	lwz	XREG_GPR0,r0Field(XREG_GPR1)
	lwz	XREG_GPR2,r2Field(XREG_GPR1)

	// Remove frame from stack
	addi	XREG_GPR1,XREG_GPR1,IFrameSize

	.endm


	//---------------------------------------------------------------------
	//
	// Macro for vector handler calling.
	//
	//---------------------------------------------------------------------

	MACRO1(call_vector_hander, int_num)

	// Pass the exception ordinal for this exception.
	li	XREG_GPR3, PARAM(\int_num)

  	// Get address of the vector table in r9.
	lis	XREG_GPR9,XExc_VectorTable@ha
	la	XREG_GPR9,XExc_VectorTable@l(XREG_GPR9)

	// Multiply vectorNumber (from r3) by 16 into r0.
	mr	XREG_GPR11,XREG_GPR3
	slwi	XREG_GPR0,XREG_GPR11,4
	//mulli	r0,r11,12

  	// Get the Nth vector element at r9 + r0 into r9.
	add	XREG_GPR9,XREG_GPR9,XREG_GPR0

  	// Get the vector address into r11.
	lwz	XREG_GPR11,0(XREG_GPR9)

  	// Get the user data value into r4.
	lwz	XREG_GPR3,4(XREG_GPR9)

  	// Get the read only small data area pointer into r2.
	lwz	XREG_GPR2,8(XREG_GPR9)

  	// Get the read/write small data area pointer into r13.
	lwz	XREG_GPR13,12(XREG_GPR9)

	// NOT! Pass exception ordinal parameter in r3.
	// Pass user data value parameter in r4.

  	// Move the vector address to the LR and call it.
	mtlr	XREG_GPR11
	blrl

	.endm


	//---------------------------------------------------------------------
	//
	// Macro for critical interrupts vector code.
	//
	//---------------------------------------------------------------------

	MACRO2(critical_interrupt, base, int_num)

	int_prologue PARAM(\base)

	// Save MSR register from SRR3.
	mfsrr3	XREG_GPR0
	stw	XREG_GPR0,MSRField(XREG_GPR1)

	// Save current PC location from SRR2.
	mfsrr2	XREG_GPR0
	stw	XREG_GPR0,PCField(XREG_GPR1)

	// Call the vector handler for this exception.
	call_vector_hander PARAM(\int_num)

	// Restore MSR register to SRR3.
	lwz	XREG_GPR0,MSRField(XREG_GPR1)
#ifdef PPC405_RESET_WE_ON_RFI
        rlwinm  XREG_GPR0,XREG_GPR0,0,(XREG_MSR_WAIT_STATE_ENABLE_BIT_POS + 1), (XREG_MSR_WAIT_STATE_ENABLE_BIT_POS - 1)
#endif
        mtsrr3	XREG_GPR0

	// Restore current PC location to SRR2.
	lwz	XREG_GPR0,PCField(XREG_GPR1)
	mtsrr2	XREG_GPR0

	int_epilogue

	// Return to the interrupted code
	rfci

	.endm


	//---------------------------------------------------------------------
	//
	// Macro for non-critical interrupts vector code.
	//
	//---------------------------------------------------------------------

	MACRO2(non_critical_interrupt, base, int_num)

	int_prologue PARAM(\base)

	// Save MSR register from SRR1.
	mfsrr1	XREG_GPR0
	stw	XREG_GPR0,MSRField(XREG_GPR1)

	// Save current PC location from SRR0.
	mfsrr0	XREG_GPR0
	stw	XREG_GPR0,PCField(XREG_GPR1)

	// Call the vector handler for this exception.
	call_vector_hander PARAM(\int_num)

	// Restore MSR register to SRR1.
	lwz	XREG_GPR0,MSRField(XREG_GPR1)
#ifdef PPC405_RESET_WE_ON_RFI
        rlwinm  XREG_GPR0,XREG_GPR0,0,(XREG_MSR_WAIT_STATE_ENABLE_BIT_POS + 1), (XREG_MSR_WAIT_STATE_ENABLE_BIT_POS - 1)
#endif
        mtsrr1	XREG_GPR0

	// Restore current PC location to SRR0.
	lwz	XREG_GPR0,PCField(XREG_GPR1)
	mtsrr0	XREG_GPR0

	int_epilogue

	// Return to the interrupted code
	rfi

	.endm


	//---------------------------------------------------------------------
	//
	// Vector table.
	//
	// Define the vector table for all exceptions. The code for each
	// exception is assembled inline at each vector entry point. Most
	// PPC exceptions are 0x100 bytes apart, so there is 256 bytes of
	// code space to handle an exception. The current exception code
	// spans about 160 bytes, this code size fits.
	//
	// NOTE:
	//
	// Vectors 0x1010 (fixed interval timer) and 0x1020 (watchdog timer)
	// are only 16 bytes apart and don't have enough room for the exception
	// handling code to fit between them. Fortunately, there is a hole in
	// the exception location sequence. Vectors 0x1100 through 0x1F00 are
	// not used in the 405. So as a work-around, relocate the exception
	// code for vectors 0x1010 and 0x1020 (where there isn't space) to
	// the unused locations 0x1300 and 0x1400 (where the is room).
	// Locations 0x1010 and 0x1020 merely contain a branch to the proper
	// reloacated exception code; which fits within the 16 bytes of space
	// of these "special" vector locations.
	//
	// If in the future this code is used for a different PPC processor,
	// this vector table may need to be changed.
	//
	//---------------------------------------------------------------------

	.globl	_vectorbase

_vectorbase:

	// Vector 0x0000, Jump to zero.
	critical_interrupt 0000, 0

	// Vector 0x0100, Critical interrupt.
	critical_interrupt 0100, 1

	// Vector 0x0200, Machine Check interrupt.
	critical_interrupt 0200, 2

	// Vector 0x0300, Data Storage interrupt.
	non_critical_interrupt 0300, 3

	// Vector 0x0400, Instruction Storage interrupt.
	non_critical_interrupt 0400, 4

	// Vector 0x0500, External interrupt.
	non_critical_interrupt 0500, 5

	// Vector 0x0600, Alignment interrupt.
	non_critical_interrupt 0600, 6

	// Vector 0x0700, Program interrupt.
	non_critical_interrupt 0700, 7

	// Vector 0x0800, FPU Unavailable interrupt.
	non_critical_interrupt 0800, 8

	// Vector 0x0C00, System Call interrupt.
	non_critical_interrupt 0C00, 9

	// Vector 0x0F20, APU Available interrupt.
	non_critical_interrupt 0F20, 10

	// Vector 0x1000, PIT interrupt.
	// This vector need the workaround described above
	.org _vectorbase + 0x1000
	b _vector1300


	// Vector 0x1010, FIT interrupt.
	// This vector need the workaround described above
	.org _vectorbase + 0x1010
	b _vector1400

	// Vector 0x1020, Watchdog Timer interrupt.
	.org _vectorbase + 0x1020
	critical_interrupt 1020, 13

	// Vector 0x1100, Data TLB Miss interrupt.
	non_critical_interrupt 1100, 14

	// Vector 0x1200, Instruction TLB Miss interrupt.
	non_critical_interrupt 1200, 15

	// Work-around!!! Real vector 0x1000, PIT
	// interrupt exception code. This gets around
	// the vector space/span problem. See title
	// block above.
	non_critical_interrupt 1300, 11

	// Work-around!!! Real vector 0x1010, FIT
	// interrupt exception code. This gets
	// around the vector space/span problem. See
	// title block above.
	non_critical_interrupt 1400, 12

	// Vector 0x2000, Debug interrupt.
	critical_interrupt 2000, 16
