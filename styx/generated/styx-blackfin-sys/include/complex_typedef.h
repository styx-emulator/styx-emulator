/************************************************************************
 *
 * complex_typedef.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* complex_typedef.h */
#endif

/* Define complex data types (fractional and float) */

#ifndef _COMPLEX_TYPEDEF_H
#define _COMPLEX_TYPEDEF_H

#include <fract_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_18_4:"ADI header allows unions")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#endif /* _MISRA_RULES */

typedef struct complex_float {
    float re;
    float im;
} complex_float;

typedef struct complex_long_double {
    long double re;
    long double im;
} complex_long_double;

#ifdef __DOUBLES_ARE_FLOATS__          /* 32-bit doubles */
  typedef complex_float          complex_double;
#else                                  /* 64-bit doubles */
  typedef complex_long_double    complex_double;
#endif


typedef struct complex_fract16 {
#pragma align 4
    fract16 re;
    fract16 im;
} complex_fract16;

typedef struct complex_fract32 {
    fract32 re;
    fract32 im;
} complex_fract32;


/* Composite type used by builtins */
typedef union _composite_complex_fract16 {
    struct complex_fract16 a;
    long raw;
} _composite_complex_fract16;

typedef union _composite_complex_fract32 {
    struct complex_fract32  a;
    long long raw;
} _composite_complex_fract32;

#define _CCFR16_RE(_CCX)   (_CCX).a.re
#define _CCFR16_IM(_CCX)   (_CCX).a.im
#define _CCFR16_CPLX(_CCX) (_CCX).a
#define _CCFR16_RAW(_CCX)  (_CCX).raw

#define _CCFR32_RE(_CCX)   (_CCX).a.re
#define _CCFR32_IM(_CCX)   (_CCX).a.im
#define _CCFR32_CPLX(_CCX) (_CCX).a
#define _CCFR32_RAW(_CCX)  (_CCX).raw

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */
#endif /* _COMPLEX_TYPEDEF_H */
