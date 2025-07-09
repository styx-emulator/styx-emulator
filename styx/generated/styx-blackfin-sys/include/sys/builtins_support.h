/*
** builtins_support.h : manual modifications for generate builtins.h
**
** Copyright (C) 2007-2008 Analog Devices Inc. All Rights Reserved.
*/

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_15)
#endif

#ifndef __DISABLED_SUPPORT_H
#define __DISABLED_SUPPORT_H

#define __DISABLE_ABS
#define __DISABLE_LABS
#define __DISABLE_ABORT
#define __DISABLE_COMPOSE_2X16
#define __DISABLE_ASSERT

/* disable complex.h defined builtins */
#define __DISABLE_REAL_FR16
#define __DISABLE_REAL_FX_FR16
#define __DISABLE_IMAG_FR16
#define __DISABLE_IMAG_FX_FR16
#define __DISABLE_CCOMPOSE_FR16
#define __DISABLE_CCOMPOSE_FX_FR16
#define __DISABLE_REAL_FR32
#define __DISABLE_REAL_FX_FR32
#define __DISABLE_IMAG_FR32
#define __DISABLE_IMAG_FX_FR32
#define __DISABLE_CADD_FR32
#define __DISABLE_CSUB_FR32
#define __DISABLE_CONJ_FR32
#define __DISABLE_CSQU_FR16

/* disable i2x16_base.h builtins */
#define __DISABLE_ADD_I2X16
#define __DISABLE_SUB_I2X16
#define __DISABLE_MULT_I2X16
#define __DISABLE_SUM_I2X16

/* disable i2x16_math.h builtins */
#define __DISABLE_MIN_I2X16
#define __DISABLE_ABS_I2X16
#define __DISABLE_MAX_I2X16

/* disable string.h defined builtins */
#define __DISABLE_MEMCPY
#define __DISABLE_MEMMOVE
#define __DISABLE_STRCPY
#define __DISABLE_STRLEN

/* stdarg.h builtins disabled */
#define __DISABLE_VA_START

/* video.h builtins disabled */
#define __DISABLE_BYTEUNPACK
#define __DISABLE_BYTEUNPACKR
#define __DISABLE_ADD_I4X8
#define __DISABLE_ADD_I4X8_R
#define __DISABLE_SUB_I4X8
#define __DISABLE_SUB_I4X8_R
#define __DISABLE_EXTRACT_AND_ADD
#define __DISABLE_SAA
#define __DISABLE_SAA_R

#endif /* __DISABLED_SUPPORT_H */

#if !defined(__NO_BUILTIN)

#if defined(__AVOID_CLI_ANOMALY__) || defined(__WORKAROUND_IMASK_CHECK)
  /* alternative definition of cli required for anomaly 05-00-071
  ** __AVOID_CLI_ANOMALY__ is obsolete, superceded by
  ** __WORKAROUND_IMASK_CHECK
  */
#if (!defined(__DEFINED_CLI) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_CLI)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_CLI))))

#define __DEFINED_CLI



#pragma inline
#pragma always_inline
#pragma source_position_from_call_site
static unsigned int cli(void) {
  unsigned int r;
  __asm volatile(
    "%1 = RETI;\t// avoid 05-00-0071\n"   /* To prevent interrupts being */
    "\tRETI = [SP++];\n"                  /* taken while CLI is committing, */
    "\tCLI %0;\n"                         /* pop something into RETI, and */
    "\t[--SP] = RETI;\n"                  /* restore afterwards. Stay in */
    "\tRETI = %1;\n" :                    /* asm for CLI, so that compiler */
    "=d" (r) :                            /* does not see altered stack. */
    "?d" (0) :
    /* no mention of clobbers */);
   return r;
}
#endif /* __DEFINED_CLI */
#endif /* defined(__AVOID_CLI_ANOMALY__) || defined(__WORKAROUND_IMASK_CHECK) */

/* define MISRA compliant expected_true and expected_false macros */
#if (!defined(__DEFINED_EXPECTED_TRUE) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_EXPECTED_TRUE)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_EXPECTED_TRUE))))

#define __DEFINED_EXPECTED_TRUE
#define expected_true(__A) (__builtin_expected_true((__A)) != 0)

#endif /* __DEFINED_EXPECTED_TRUE */

#if (!defined(__DEFINED_EXPECTED_FALSE) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_EXPECTED_FALSE)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_EXPECTED_FALSE))))

#define __DEFINED_EXPECTED_FALSE
#define expected_false(__A) (__builtin_expected_false((__A)) != 0)

#endif /* __DEFINED_EXPECTED_FALSE */

/* Define divq so that one needs not pass in the same variable twice */
#if (!defined(__DEFINED_DIVQ) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_DIVQ)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_DIVQ))))

#define __DEFINED_DIVQ

#pragma inline
#pragma always_inline
#pragma source_position_from_call_site
static int  divq(int  __a, int  __b, int  *__r2) {
  int  __rval = __builtin_divq_r1(__a, __b, *__r2);
  *__r2 = __builtin_divq_r2(__rval);
  return __rval;
}

#endif /* __DEFINED_DIVQ */

/* Define bitmux_shr and bitmux_shl as they were in 4.5 */
#if (!defined(__DEFINED_BITMUX_SHL) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_BITMUX_SHL)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_BITMUX_SHL))))

#define __DEFINED_BITMUX_SHL

#define bitmux_shl(X,Y,A) do { \
        int _x = (X), _y = (Y); \
        long long _a = (A); \
        _a = __builtin_bitmux_shl_r1(_a,_x,_y); \
        _x = __builtin_bitmux_shl_r2(_a); \
        _y = __builtin_bitmux_shl_r3(_a); \
        (X) = _x ; \
        (Y) = _y ; \
        (A) = _a ; \
        } while(0)
#endif /* __DEFINED_BITMUX_SHL */

#if (!defined(__DEFINED_BITMUX_SHR) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_BITMUX_SHR)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_BITMUX_SHR))))

#define __DEFINED_BITMUX_SHR

#define bitmux_shr(X,Y,A) do { \
        int _x = (X), _y = (Y); \
        long long _a = (A); \
        _a = __builtin_bitmux_shr_r1(_a,_x,_y); \
        _x = __builtin_bitmux_shr_r2(_a); \
        _y = __builtin_bitmux_shr_r3(_a); \
        (X) = _x ; \
        (Y) = _y ; \
        (A) = _a ; \
        } while(0)
#endif /* __DEFINED_BITMUX_SHL */

#if !defined(__NO_SHORTNAMES)

#if (!defined(__DEFINED_ALIGNED) && \
     ((defined(__SPECIFIC_NAMES) && defined(__ENABLE_ALIGNED)) || \
       (!defined(__SPECIFIC_NAMES) && !defined(__DISABLE_ALIGNED))))

#define __DEFINED_ALIGNED

#pragma inline
#pragma always_inline
#pragma source_position_from_call_site
static void aligned(const void * __a, int  __b) {
  __builtin_aligned(__a, __b);
}

#endif /* __DEFINED_ALIGNED */

#endif /* __NO_SHORTNAMES */

#endif /* __NO_BUILTIN */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif
