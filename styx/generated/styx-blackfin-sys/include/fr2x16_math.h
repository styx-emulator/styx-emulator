#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fr2x16_math.h */
#endif
/************************************************************************
 *
 * fr2x16_math.h
 *
 * (c) Copyright 2000-2006 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Standard library functions for two packed fractional values. */

#ifndef _FR2x16_MATH_H
#define _FR2x16_MATH_H

#include <fract_typedef.h>  /* get definitions for fract16 and fract32 */
#include <fr2x16_base.h>
#include <fr2x16_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#if 0
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#endif
#pragma diag(suppress:misra_rule_2_4:"ADI header has example code in comments")
#pragma diag(suppress:misra_rule_8_1:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_8_5:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_12_2:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_19_6:"ADI header requires use of #undef")
#endif /* _MISRA_RULES */


/*
 * Standard functions:
 * abs({a,b})		=> {abs(a), abs(b)}
 * min({a,b},{c,d})	=> {min(a,c),min(b,d)}
 * max({a,b},{c,d})	=> {max(a,c),max(b,d)}
 */

#define __SPECIFIC_NAMES
#define __ENABLE_ABS_FR2X16
#define __ENABLE_MIN_FR2X16
#define __ENABLE_MAX_FR2X16
#define __ENABLE_ADD_AS_FR2X16
#define __ENABLE_ADD_SA_FR2X16
#define __ENABLE_DIFF_HL_FR2X16
#define __ENABLE_DIFF_LH_FR2X16
#include <builtins.h>
#undef __SPECIFIC_NAMES

/*
 * Cross-over multiplication:
 * ll({a,b}, {c,d})	=> a*c
 * lh({a,b}, {c,d})	=> a*d
 * hl({a,b}, {c,d})	=> b*c
 * hh({a,b}, {c,d})	=> b*d
 */

#ifdef __cplusplus
extern "C" {
#endif

#pragma inline
#pragma always_inline
static fract32 mult_ll_fr2x16(fract2x16 _x, fract2x16 _y) {
  return (fract32)low_of_fr2x16(_x)*(fract32)low_of_fr2x16(_y);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract mult_ll_fx_fr2x16(fract2x16 _x, fract2x16 _y) {
  fract32 result = low_of_fr2x16(_x)*(fract32)low_of_fr2x16(_y);
  return *(long _Fract *)&result;
}
#endif
#pragma inline
#pragma always_inline
static fract32 mult_hl_fr2x16(fract2x16 _x, fract2x16 _y) {
  return (fract32)high_of_fr2x16(_x)*(fract32)low_of_fr2x16(_y);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract mult_hl_fx_fr2x16(fract2x16 _x, fract2x16 _y) {
  fract32 result = high_of_fr2x16(_x)*(fract32)low_of_fr2x16(_y);
  return *(long _Fract *)&result;
}
#endif
#pragma inline
#pragma always_inline
static fract32 mult_lh_fr2x16(fract2x16 _x, fract2x16 _y) {
  return (fract32)low_of_fr2x16(_x)*(fract32)high_of_fr2x16(_y);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract mult_lh_fx_fr2x16(fract2x16 _x, fract2x16 _y) {
  fract32 result = low_of_fr2x16(_x)*(fract32)high_of_fr2x16(_y);
  return *(long _Fract *)&result;
}
#endif
#pragma inline
#pragma always_inline
static fract32 mult_hh_fr2x16(fract2x16 _x, fract2x16 _y) {
  return (fract32)high_of_fr2x16(_x)*(fract32)high_of_fr2x16(_y);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract mult_hh_fx_fr2x16(fract2x16 _x, fract2x16 _y) {
  fract32 result = high_of_fr2x16(_x)*(fract32)high_of_fr2x16(_y);
  return *(long _Fract *)&result;
}
#endif

#ifdef __cplusplus
}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FR2x16_MATH_H */
