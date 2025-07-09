/************************************************************************
 *
 * libetsi.h
 *
 * (c) Copyright 2001-2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _LIBETSI_H
#define _LIBETSI_H

#ifndef ETSI_SOURCE
# define ETSI_SOURCE
#endif

#ifdef ETSI_SOURCE
#include <fract.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4:"ADI Header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI Header Function-like macros used")
#endif /* _MISRA_RULES */

#ifndef __SET_ETSI_FLAGS
#define __SET_ETSI_FLAGS 0
#endif

#define MAX_32	(fract32)0x7fffffffL
#define MIN_32	(fract32)0x80000000L
#define MAX_16	(fract16)0x7fff
#define MIN_16	(fract16)0x8000

#ifdef __cplusplus
	extern "C" {
#endif
		fract16 div_l (fract32 _num, fract16 _den);

		/* Oper32 Routines */
		fract32 Div_32(fract32 _L_num, fract16 _denom_hi, fract16 _denom_lo);
		/* 32 Bit returning routines */

		fract32 L_add_c(fract32 _a, fract32 _b);
		fract32 L_mls(fract32 _a, fract16 _b);
		fract32 L_sub_c(fract32 _a, fract32 _b);
		fract32 L_sat(fract32 _a);
#ifdef NO_ETSI_BUILTINS
		fract32 L_Comp(fract16 _hi,fract16 _lo);
		void    L_Extract(fract32 _L_32,fract16 * _hi,fract16 *_lo);
		fract32 L_negate (fract32 _a);
		fract32 Mpy_32(fract16 _hi1, fract16 _lo1, fract16 _hi2, fract16 _lo2);
		fract32 Mpy_32_16(fract16 _hi,fract16 _lo, fract16 _n);
		fract32 L_sub(fract32 _a, fract32 _b);
		fract32 L_abs(fract32 _a);
		fract32 L_add(fract32 _a, fract32 _b);
#ifdef RENAME_ETSI_NEGATE
#pragma linkage_name _negate
		fract16 etsi_negate(fract16 _a);
#else
		fract16 negate(fract16 _a);
#endif
		fract32 L_mult(fract16 _a, fract16 _b);
		fract32 L_deposit_l(fract16 _lo);
		fract32 L_deposit_h(fract16 _hi);
		fract32 L_mac(fract32 _a, fract16 _b, fract16 _c);
		fract32 L_msu(fract32 _a, fract16 _b, fract16 _c);
		fract32 L_shl(fract32 _a, fract16 _b);
		fract32 L_shr(fract32 _a, fract16 _b);
#endif
		fract32 L_macNs(fract32 _a, fract16 _b, fract16 _c);
		fract32 L_msuNs(fract32 _a, fract16 _b, fract16 _c);
		fract32 L_shr_r(fract32 _a, fract16 _b);
#ifndef L_shift_r
#define L_shift_r(a,b) (L_shr_r((a),negate(b)))
#endif

#define i_mult(X,Y)  (((int)(X))*((int)(Y)))   /* integer multiply */

		/* 16 bit returning routines */
#ifdef NO_ETSI_BUILTINS
		fract16 abs_s(fract16 _a);
		fract16 add(fract16 _a, fract16 _b);
		fract16 sub(fract16 _a, fract16 _b);
		fract16 div_s(fract16 _a, fract16 _b);
		fract16 mult(fract16 _a, fract16 _b);
		fract16 mult_r(fract16 _a, fract16 _b);
		fract16 round(fract32 _a);
		fract16 saturate(fract32 _a);
		fract16 extract_l(fract32 _a);
		fract16 extract_h(fract32 _a);
		int norm_l(fract32 _a);
		int norm_s(fract32 _a);
		fract16 shl(fract16 _a, fract16 _b);
		fract16 shr(fract16 _a, fract16 _b);
#endif
		fract16 mac_r(fract32 _a, fract16 _b, fract16 _c);
		fract16 msu_r(fract32 _a, fract16 _b, fract16 _c);
		fract16 shr_r(fract16 _a, fract16 _b);
#ifndef shift_r
#define shift_r(a,b) (shr_r((a),negate(b)))
#endif

#if __SET_ETSI_FLAGS
		extern int Overflow;
		extern int Carry;
#endif
#ifdef __cplusplus
		}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* ETSI_SOURCE */

#endif
