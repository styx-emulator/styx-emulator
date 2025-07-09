/************************************************************************
 *
 * float.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* float.h */
#endif

/* float.h standard header -- IEEE 754 version */
#ifndef _FLOAT
#define _FLOAT
#ifndef _YVALS
 #include <yvals.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */

_C_STD_BEGIN

                /* COMMON PROPERTIES */
#define FLT_RADIX            2
 #ifdef _FRND
  #define FLT_ROUNDS         _FRND
 #else
  #define FLT_ROUNDS         (-1)   /* indeterminable */
 #endif

                /* float properties */
#define FLT_EPSILON          1.1920928955078125E-07F
#define FLT_MAX              3.4028234663852886E+38F
#define FLT_MIN              1.1754943508222875E-38F

#define FLT_DIG              6
#define FLT_MANT_DIG         24
#define FLT_MAX_10_EXP       38
#define FLT_MAX_EXP          128
#define FLT_MIN_10_EXP       (-37)
#define FLT_MIN_EXP          (-125)

                /* long double properties */
#define LDBL_EPSILON         2.2204460492503131E-16L
#define LDBL_MAX             1.797693134862315708E+308L
#define LDBL_MIN             2.2250738585072014E-308L
#define LDBL_DIG             15
#define LDBL_MANT_DIG        53
#define LDBL_MAX_10_EXP      308
#define LDBL_MAX_EXP         1024
#define LDBL_MIN_10_EXP      (-307)
#define LDBL_MIN_EXP         (-1021)

                /* double properties */
#if defined(__DOUBLES_ARE_FLOATS__)
#define DBL_EPSILON          FLT_EPSILON
#define DBL_MAX              FLT_MAX
#define DBL_MIN              FLT_MIN
#define DBL_DIG              FLT_DIG
#define DBL_MANT_DIG         FLT_MANT_DIG
#define DBL_MAX_10_EXP       FLT_MAX_10_EXP
#define DBL_MAX_EXP          FLT_MAX_EXP
#define DBL_MIN_10_EXP       FLT_MIN_10_EXP
#define DBL_MIN_EXP          FLT_MIN_EXP
#else
#define DBL_EPSILON          LDBL_EPSILON
#define DBL_MAX              LDBL_MAX
#define DBL_MIN              LDBL_MIN
#define DBL_DIG              LDBL_DIG
#define DBL_MANT_DIG         LDBL_MANT_DIG
#define DBL_MAX_10_EXP       LDBL_MAX_10_EXP
#define DBL_MAX_EXP          LDBL_MAX_EXP
#define DBL_MIN_10_EXP       LDBL_MIN_10_EXP
#define DBL_MIN_EXP          LDBL_MIN_EXP
#endif

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FLOAT */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
