/************************************************************************
 *
 * macros.h
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Defines various assembly macros. */

#ifndef _MACROS_H
#define _MACROS_H

#ifdef _MISRA_RULES
#pragma diag(push)
/* Due to asm syntax disable following rule for this header */
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_10)
#endif /* _MISRA_RULES */


#ifdef __ADSPBLACKFIN__

/*
 * Save all user registers except USP,SP, and FP
 * Can be used in either Supervisor or user mode
 */

#define save_user_regs\
		[--SP] = (R7:0,P5:0);\
		[--SP] = I3;\
		[--SP] = I2;\
		[--SP] = I1;\
		[--SP] = I0;\
		[--SP] = M3;\
		[--SP] = M2;\
		[--SP] = M1;\
		[--SP] = M0;\
		[--SP] = B3;\
		[--SP] = B2;\
		[--SP] = B1;\
		[--SP] = B0;\
		[--SP] = L3;\
		[--SP] = L2;\
		[--SP] = L1;\
		[--SP] = L0;\
		[--SP] = A0.x;\
		[--SP] = A0.w;\
		[--SP] = A1.x;\
		[--SP] = A1.w;\
		[--SP] = LC1;\
		[--SP] = LC0;\
		[--SP] = LT1;\
		[--SP] = LT0;\
		[--SP] = LB1;\
		[--SP] = LB0

/*
 * Restore all user registers except USP,SP, and FP
 * Can be used in either Supervisor or user mode
 */
#define restore_user_regs\
		LB0 = [SP++];\
		LB1 = [SP++];\
		LT0 = [SP++];\
		LT1 = [SP++];\
		LC0 = [SP++];\
		LC1 = [SP++];\
		A1.w = [SP++];\
		A1.x = [SP++];\
		A0.w = [SP++];\
		A0.x = [SP++];\
		L0 = [SP++];\
		L1 = [SP++];\
		L2 = [SP++];\
		L3 = [SP++];\
		B0 = [SP++];\
		B1 = [SP++];\
		B2 = [SP++];\
		B3 = [SP++];\
		M0 = [SP++];\
		M1 = [SP++];\
		M2 = [SP++];\
		M3 = [SP++];\
		I0 = [SP++];\
		I1 = [SP++];\
		I2 = [SP++];\
		I3 = [SP++];\
		(R7:0,P5:0) = [SP++]

/*
 * Save all supervisor only registers except USP,SP, and FP
 * Can only be used in Supervisor mode
 */
#define save_super_regs\
		[--SP] = RETS;\
		[--SP] = RETI;\
		[--SP] = RETX;\
		[--SP] = RETN;\
		[--SP] = RETE;\
		[--SP] = ASTAT;\
		[--SP] = SEQSTAT;\
		[--SP] = SYSCFG

/*
 * Restore all supervisor only registers except USP,SP, and FP
 * Can only be used in Supervisor mode
 */
#define restore_super_regs\
		SYSCFG = [SP++];\
		SEQSTAT = [SP++];\
		ASTAT = [SP++];\
		RETE = [SP++];\
		RETN = [SP++];\
		RETX = [SP++];\
		RETI = [SP++];\
		RETS = [SP++]


/*
 * Set the corresponding bits in a System Register (SR);
 * All bits set in "mask" will be set in the system register
 * specified by "sys_reg" bitset_SR(sys_reg, mask), where
 * sys_reg is the system register and mask are the bits to be set.
 */
#define bitset_SR(sys_reg, mask)\
		[--SP] = (R7:6);\
		r7 = sys_reg;\
		r6.l = (mask) & 0xffff;\
		r6.h = (mask) >> 16;\
		r7 = r7 | r6;\
		sys_reg = r7;\
		csync;\
		(R7:6) = [SP++]

/*
 * Clear the corresponding bits in a System Register (SR);
 * All bits set in "mask" will be cleared in the SR
 * specified by "sys_reg" bitclr_SR(sys_reg, mask), where
 * sys_reg is the SR and mask are the bits to be cleared.
 */
#define bitclr_SR(sys_reg, mask)\
		[--SP] = (R7:6);\
		r7 = sys_reg;\
		r7 =~ r7;\
		r6.l = (mask) & 0xffff;\
		r6.h = (mask) >> 16;\
		r7 = r7 | r6;\
		r7 =~ r7;\
		sys_reg = r7;\
		csync;\
		(R7:6) = [SP++]

/*
 * Set the corresponding bits in a Memory Mapped Register (MMR);
 * All bits set in "mask" will be set in the MMR specified by "mmr_reg"
 * bitset_MMR(mmr_reg, mask), where mmr_reg is the MMR and mask are
 * the bits to be set.
 */
#define bitset_MMR(mmr_reg, mask)\
		[--SP] = (R7:6);\
		[--SP] = P5;\
		p5.l = mmr_reg & 0xffff;\
		p5.h = mmr_reg >> 16;\
		r7 = [p5];\
		r6.l = (mask) & 0xffff;\
		r6.h = (mask) >> 16;\
		r7 = r7 | r6;\
		[p5] = r7;\
		csync;\
		p5 = [SP++];\
		(R7:6) = [SP++]

/*
 * Clear the corresponding bits in a Memory Mapped Register (MMR);
 * All bits set in "mask" will be cleared in the MMR specified by "mmr_reg"
 * bitclr_MMRreg(mmr_reg, mask), where sys_reg is the MMR and mask are
 * the bits to be cleared.
 */
#define bitclr_MMR(mmr_reg, mask)\
		[--SP] = (R7:6);\
		[--SP] = P5;\
		p5.l = mmr_reg & 0xffff;\
		p5.h = mmr_reg >> 16;\
		r7 = [p5];\
		r7 =~ r7;\
		r6.l = (mask) & 0xffff;\
		r6.h = (mask) >> 16;\
		r7 = r7 | r6;\
		r7 =~ r7;\
		[p5] = r7;\
		csync;\
		p5 = [SP++];\
		(R7:6) = [SP++]

#endif /* __ADSPBLACKFIN */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _MACROS_H */
