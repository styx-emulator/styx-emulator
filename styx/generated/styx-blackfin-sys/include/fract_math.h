/************************************************************************
 *
 * fract_math.h
 *
 * (c) Copyright 2000-2011 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Definitions of math.h-style functions for fractional types. */

#ifndef _FRACT_MATH_H
#define _FRACT_MATH_H

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fract_math.h */
#endif

#include <fract_typedef.h>
#include <ccblkfn.h>
#include <fr2x16_math.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_8_8)
#pragma diag(suppress:misra_rule_10_1_a)
#pragma diag(suppress:misra_rule_10_1_d)
#pragma diag(suppress:misra_rule_12_7)
#pragma diag(suppress:misra_rule_18_4)
#pragma diag(suppress:misra_rule_19_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_6)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_20_1)
#endif /* _MISRA_RULES */


#if !defined(__NO_BUILTIN)
#ifdef __cplusplus
extern "C" {
#endif

/****************************************/
/*                                      */
/*   fract16 and fract2x16 arithmetic   */
/*                                      */
/****************************************/

#define __SPECIFIC_NAMES
#define __ENABLE_ADD_FR2X16
#define __ENABLE_ADD_FR1X16
#define __ENABLE_SUB_FR2X16
#define __ENABLE_MULT_FR2X16
#define __ENABLE_MULT_FR1X16
#define __ENABLE_MULTR_FR2X16
#define __ENABLE_MULTR_FR1X16
#define __ENABLE_NEGATE_FR2X16
#define __ENABLE_SHL_FR2X16
#define __ENABLE_SHL_FR2X16_CLIP
#define __ENABLE_SHL_FR1X16
#define __ENABLE_SHR_FR2X16
#define __ENABLE_SHR_FR2X16_CLIP
#define __ENABLE_SHR_FR1X16
#define __ENABLE_SHRL_FR2X16
#define __ENABLE_SHRL_FR2X16_CLIP
#include <builtins.h>

/* Returns the 16-bit result of the negation of the input parameter (-_x).  If
 * the input is 0x8000, saturation occurs and 0x7fff is returned. */
#pragma inline
#pragma always_inline
static fract16 negate_fr1x16(fract16 _x)
  { return (fract16)__builtin_negate_fr2x16((int)_x); }
#ifdef __FIXED_POINT_ALLOWED
/* for completeness only. You can use the unary negate operator instead. */
#pragma inline
#pragma always_inline
static _Fract negate_fx1x16(_Fract _x)
  { return -_x; }
#endif

/* Arithmetically shifts the src variable left by _y places.  The empty bits
 * are zero filled. If shft is negative, the shift is to the right by abs(shft)
 * places with sign extension.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represented in 5 bits.
 */
#pragma inline
#pragma always_inline
static fract16 shl_fr1x16_clip(fract16 _x, short _y)
  { return __builtin_shl_fr1x16(_x,(short)__builtin_max(__builtin_min((int)_y,15),-16)); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract shl_fx1x16_clip(_Fract _x, short _y)
  { return __builtin_shl_fx1x16(_x,(short)__builtin_max(__builtin_min((int)_y,15),-16)); }
#endif

/* Arithmetically shifts the src variable right by shft places with sign
 * extension.  If shft is negative, the shift is to the left by abs(_y) places,
 * and the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represented in 5 bits.
 */
#pragma inline
#pragma always_inline
static fract16 shr_fr1x16_clip(fract16 _x, short _y)
  { return __builtin_shr_fr1x16(_x,(short)__builtin_max(__builtin_min((int)_y,16),-15)); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract shr_fx1x16_clip(_Fract _x, short _y)
  { return __builtin_shr_fx1x16(_x,(short)__builtin_max(__builtin_min((int)_y,16),-15)); }
#endif

/* Logically shifts a fract16 right by shft places.  There is no sign extension
 * and no saturation - the empty bits are zero filled.
 *
 * WARNING: All the bits except for the lowest 5 bits of
 * _y are ignored.  If you want to shift by numbers larger than 5 bit signed ints,
 * you should use shrl_fr1x16_clip.
 */
#pragma inline
#pragma always_inline
static fract16 shrl_fr1x16(fract16 _x, short _y)
	{ return (fract16)__builtin_shrl_fr2x16((int)_x,_y); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract shrl_fx1x16(_Fract _x, short _y)
	{ fract2x16 result = __builtin_shrl_fr2x16((int)(*(fract16 *)&_x),_y); return *(_Fract *)&result; }
#endif

/* Logically shifts a fract16 right by _x places.  There is no sign extension
 * and no saturation - the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represented in 5 bits.
 */
#pragma inline
#pragma always_inline
static fract16 shrl_fr1x16_clip(fract16 _x, short _y)
	{ return (fract16)__builtin_shrl_fr2x16((int)_x,(short)__builtin_max(__builtin_min((int)_y,16),-15)); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract shrl_fx1x16_clip(_Fract _x, short _y)
	{ fract2x16 result = __builtin_shrl_fr2x16((int)(*(fract16 *)&_x),(short)__builtin_max(__builtin_min((int)_y,16),-15)); return *(_Fract *)&result; }
#endif



/**************************/
/*                        */
/*   fract32 arithmetic   */
/*                        */
/**************************/

#define __ENABLE_ADD_FR1X32
#define __ENABLE_ADD_FR1X16
#define __ENABLE_SUB_FR1X32
#define __ENABLE_SUB_FR1X16
#define __ENABLE_MULT_FR1X32X32
#define __ENABLE_MULT_FR1X32X32NS
#define __ENABLE_ABS_FR1X32
#define __ENABLE_NEGATE_FR1X32
#define __ENABLE_MIN_FR1X32
#define __ENABLE_MAX_FR1X32
#define __ENABLE_SHL_FR1X32
#define __ENABLE_SHL_FR1X32_CLIP
#define __ENABLE_SHR_FR1X32
#define __ENABLE_SHR_FR1X32_CLIP
#define __ENABLE_MULT_FR1X32
#include <builtins.h>

/*****************************/
/*                           */
/*   Conversion operations   */
/*                           */
/*****************************/

#define __ENABLE_SAT_FR1X32
#define __ENABLE_ROUND_FR1X32
#define __ENABLE_NORM_FR1X32
#define __ENABLE_NORM_FR1X16
#define __ENABLE_MAX_FR1X16
#define __ENABLE_MIN_FR1X16
#include <builtins.h>
#undef __SPECIFIC_NAMES

/* This function returns the top 16 bits of _x, i.e. it truncates _x to 16
 * bits.  */
#pragma inline
#pragma always_inline
static fract16 trunc_fr1x32(fract32 _x)
  { unsigned int res = (unsigned int)_x>>16;
    return (fract16)res; }
#ifdef __FIXED_POINT_ALLOWED
/* this function is provided for completeness only. You can use a cast to
** _Fract.  */
#pragma inline
#pragma always_inline
static _Fract trunc_fx1x32(long _Fract _x)
  {
#pragma FX_ROUNDING_MODE TRUNCATION
    return (_Fract)_x;
  }
#endif

/* Returns the 16-bit value that is the absolute value of the input parameter.
 * Where the input is 0x8000, saturation occurs and 0x7fff is returned. */
#pragma inline
#pragma always_inline
static fract16 abs_fr16 (fract16 _x)
  { return (fract16)__builtin_abs_fr2x16 ((int)_x); }
#ifdef __FIXED_POINT_ALLOWED
/* for completeness only. You can use absr() from stdfix.h instead. */
#pragma inline
#pragma always_inline
static _Fract abs_fx16 (_Fract _x)
  { fract2x16 result = __builtin_abs_fr2x16 ((int)(*(fract16 *)&_x)); return *(_Fract *)&result; }
#endif

#pragma inline
#pragma always_inline
static fract32 abs_fr32 (fract32 _x)
  { return (fract32)__builtin_abs_fr1x32 (_x); }
#ifdef __FIXED_POINT_ALLOWED
/* for completeness only. You can use abslr() from stdfix.h instead. */
#pragma inline
#pragma always_inline
static long _Fract abs_fx32 (long _Fract _x)
  { return __builtin_abs_fx1x32 (_x); }
#endif

/* Returns the 16-bit value that is the absolute value of the input parameter.
 * Where the input is 0x8000, saturation occurs and 0x7fff is returned. */
#pragma inline
#pragma always_inline
static fract16 abs_fr1x16 (fract16 _x)
  { return (fract16)__builtin_abs_fr2x16((int)_x); }
#ifdef __FIXED_POINT_ALLOWED
/* for completeness only. You can use absr() from stdfix.h instead. */
#pragma inline
#pragma always_inline
static _Fract abs_fx1x16 (_Fract _x)
  { fract2x16 result = __builtin_abs_fr2x16 ((int)(*(fract16 *)&_x)); return *(_Fract *)&result; }
#endif

/* Returns the maximum of the two input parameters. */
#pragma inline
#pragma always_inline
static fract16 max_fr16 (fract16 _x, fract16 _y)
  { return (fract16)__builtin_max_fr2x16 ((int)_x,(int)_y); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract max_fx16 (_Fract _x, _Fract _y)
  { fract2x16 result = __builtin_max_fr2x16 ((int)(*(fract16 *)&_x),(int)(*(fract16 *)&_y)); return *(_Fract *)&result; }
#endif

#pragma inline
#pragma always_inline
static fract32 max_fr32 (fract32 _x, fract32 _y)
  { return (fract32)__builtin_max_fr1x32 (_x, _y); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract max_fx32 (long _Fract _x, long _Fract _y)
  { return __builtin_max_fx1x32 (_x, _y); }
#endif

/* Returns the minimum of the two input parameters. */
#pragma inline
#pragma always_inline
static fract16 min_fr16 (fract16 _x, fract16 _y)
  { return (fract16)__builtin_min_fr2x16 ((int)_x, (int)_y); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract min_fx16 (_Fract _x, _Fract _y)
  { fract2x16 result = __builtin_min_fr2x16 ((int)(*(fract16 *)&_x),(int)(*(fract16 *)&_y)); return *(_Fract *)&result; }
#endif

#pragma inline
#pragma always_inline
static fract32 min_fr32 (fract32 _x, fract32 _y)
  { return (fract32)__builtin_min_fr1x32 (_x, _y); }
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static long _Fract min_fx32 (long _Fract _x, long _Fract _y)
  { return __builtin_min_fx1x32 (_x, _y); }
#endif

/*********************/
/*                   */
/*   ETSI Builtins   */
/*                   */
/*********************/

#ifdef ETSI_SOURCE /* { */
#ifndef NO_ETSI_BUILTINS /* { */
#pragma inline
#pragma always_inline
static fract16 add(fract16 _x, fract16 _y) { return (fract16)add_fr1x16(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 sub(fract16 _x, fract16 _y) { return (fract16)sub_fr1x16(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 abs_s(fract16 _x) { return (fract16)abs_fr1x16(_x); }
#if defined(_ADI_FAST_ETSI)
/* These are fast, but see the shift fr1x16 documentation for their limitations */
#pragma inline
#pragma always_inline
static fract16 shl(fract16 _x, short _y) { return (fract16)shl_fr1x16(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 shr(fract16 _x, short _y) { return (fract16)shr_fr1x16(_x, _y); }
#else /* _ADI_FAST_ETSI */
/* These are conformant, but not so fast */
#pragma inline
#pragma always_inline
static fract16 shl(fract16 _x, short _y) { return (fract16)shl_fr1x16_clip(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 shr(fract16 _x, short _y) { return (fract16)shr_fr1x16_clip(_x, _y); }
#endif /* _ADI_FAST_ETSi */
#pragma inline
#pragma always_inline
static fract16 mult(fract16 _x, fract16 _y) { return mult_fr1x16(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 mult_r(fract16 _x, fract16 _y) { return multr_fr1x16(_x, _y); }
#ifndef RENAME_ETSI_NEGATE
#pragma inline
#pragma always_inline
static fract16 negate(fract16 _x) { return (fract16)negate_fr1x16(_x); }
#else
/* The ETSI negate function conflicts with the C++ standard declaration of
   the template negate.
 */
#pragma inline
#pragma always_inline
static fract16 etsi_negate(fract16 _x) { return (fract16)negate_fr1x16(_x); }
#endif
#pragma inline
#pragma always_inline
static fract16 round(fract32 _x) { return (fract16)round_fr1x32(_x); }
#pragma inline
#pragma always_inline
static fract32 L_add(fract32 _x, fract32 _y) { return add_fr1x32(_x, _y); }
#pragma inline
#pragma always_inline
static fract32 L_sub(fract32 _x, fract32 _y) { return sub_fr1x32(_x, _y); }
#pragma inline
#pragma always_inline
static fract32 L_abs(fract32 _x) { return abs_fr1x32(_x); }
#pragma inline
#pragma always_inline
static fract32 L_negate(fract32 _x) { return negate_fr1x32(_x); }
#if defined(_ADI_FAST_ETSI)
/* These are fast, but see the shift fr1x32 documentation for their limitations */
#pragma inline
#pragma always_inline
static fract32 L_shl(fract32 _x, short _y) { return shl_fr1x32(_x, _y); }
#pragma inline
#pragma always_inline
static fract32 L_shr(fract32 _x, short _y) { return shr_fr1x32(_x, _y); }
#else /* _ADI_FAST_ETSI */
/* These are conformant, but not so fast */
#pragma inline
#pragma always_inline
static fract32 L_shl(fract32 _x, short _y) { return shl_fr1x32_clip(_x, _y); }
#pragma inline
#pragma always_inline
static fract32 L_shr(fract32 _x, short _y) { return shr_fr1x32_clip(_x, _y); }
#endif /* _ADI_FAST_ETSI */
#pragma inline
#pragma always_inline
static fract32 L_mult(fract16 _x, fract16 _y) { return mult_fr1x32(_x, _y); }
#pragma inline
#pragma always_inline
static fract16 saturate(fract32 _x) { return sat_fr1x32(_x); }
#pragma inline
#pragma always_inline
static fract32 L_mac(fract32 _a,fract16 _x, fract16 _y) { return (L_add(_a,L_mult(_x, _y))); }
#pragma inline
#pragma always_inline
static fract32 L_msu(fract32 _a,fract16 _x, fract16 _y) { return (L_sub(_a,L_mult(_x, _y))); }
#pragma inline
#pragma always_inline
static fract16 extract_h(fract32 _x) {
  unsigned int u = (unsigned int)_x;
  u >>= 16;
  return (fract16)u;
}
#pragma inline
#pragma always_inline
static fract16 extract_l(fract32 _x) { return (fract16)(_x); }
#pragma inline
#pragma always_inline
static fract32 L_deposit_h(fract16 _x) {
  unsigned int u = (unsigned int)_x;
  u <<= 16;
  return (fract32)u;
}
#pragma inline
#pragma always_inline
static fract32 L_deposit_l(fract16 _x) { return _x; }
#pragma inline
#pragma always_inline
static fract32 L_Comp(fract16 _x, fract16 _y) { return L_add(L_deposit_h(_x), L_shl((fract32)_y,1))  ; }

#pragma inline
#pragma always_inline
static int norm_l(fract32 _x) {
  return ((_x==0) ? 0 : ((int)norm_fr1x32(_x)));
}

#pragma inline
#pragma always_inline
static int norm_s(fract32 _x) {
  return ((_x==0) ? 0 : ((int)norm_fr1x16((fract16)_x)));
}

/* Multiplies a fract32 (decomposed to hi and lo) by a fract16, and returns the
 * result as a fract32. */
#pragma inline
#pragma always_inline
static fract32 Mpy_32_16(short _a, short _b, short _c) {
  return L_mac(L_mult(_a,_c), mult(_b,_c),1);
}

/* Decomposes a 32-bit fract into two 16-bit fracts. */
#pragma inline
#pragma always_inline
static void L_Extract(fract32 _a, fract16 *_b, fract16 *_c) {
  *_b=extract_h(_a);
  *_c=(fract16)L_msu(L_shr(_a,1), *_b, 16384);
}

/* Multiplies two fract32 numbers, and returns the result as a fract32.  The
 * input fracts have both been split up into two shorts. */
#pragma inline
#pragma always_inline
static fract32 Mpy_32(short _a, short _b, short _c, short _d) {
  int x = L_mult(_a, _c);
  x = L_mac(x, mult(_a, _d), 1);
  return L_mac(x, mult(_b, _c), 1);
}

/* Produces a result which is the fractional division of f1 by f2. Not a builtin
 * as written in C code. */
#pragma inline
#pragma always_inline
static fract16 div_s(fract16 _a, fract16 _b) {
  int x = (int)_a;
  int y = (int)_b;
  fract16 rtn;
  int i;
  int aq;
  if (x==0) {
    rtn = 0;
  }
  else if (x>=y) {
    rtn = 0x7fff;
  }
  else {
    x <<= 16;
    x = divs(x, y, &aq);
    for (i=0; i<15; i++) {
      x = divq(x, y, &aq);
    }
    rtn = (fract16) x;
  }
  return rtn;
}

#endif /*  } NO_ETSI_BUILTINS */
#include <libetsi.h>
#endif /* } ETSI_SOURCE */

#undef __OP1RT
#undef __BOP1RT
#undef __OP2RT
#undef __BOP2RT
#undef __OP1
#undef __BOP1
#undef __OP2
#undef __BOP2

#ifdef __cplusplus
}
#endif

#else

#pragma linkage_name __fmax_fr16
  fract16 max_fr16 (fract16 _x, fract16 _y);

#pragma linkage_name __fmin_fr16
  fract16 min_fr16 (fract16 _x, fract16 _y);

#pragma	linkage_name __abs_fr16
  fract16 abs_fr16 (fract16 _x);

#pragma linkage_name __max_fr32
  fract32 max_fr32 (fract32 _x, fract32 _y);

#pragma linkage_name __min_fr32
  fract32 min_fr32 (fract32 _x, fract32 _y);

#pragma linkage_name __abs_fr32
  fract32 abs_fr32 (fract32 _x);

#ifdef __FIXED_POINT_ALLOWED

_Fract max_fx16 (_Fract _x, _Fract _y);
#pragma inline
#pragma always_inline
static _Fract max_fx16(_Fract _x, _Fract _y) {
    fract16 result = max_fr16(*(fract16 *)&_x, *(fract16 *)&_y);
    return *(_Fract *)&result;
}

_Fract min_fx16 (_Fract _x, _Fract _y);
#pragma inline
#pragma always_inline
static _Fract min_fx16(_Fract _x, _Fract _y) {
    fract16 result = min_fr16(*(fract16 *)&_x, *(fract16 *)&_y);
    return *(_Fract *)&result;
}

_Fract abs_fx16 (_Fract _x);
#pragma inline
#pragma always_inline
static _Fract abs_fx16(_Fract _x) {
    fract16 result = abs_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#endif

#include <math_bf.h>

#endif /* __ADSPBLACKFIN__  && !__NO_BUILTIN */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FRACT_MATH_H */
