/************************************************************************
 *
 * math_bf.h
 *
 * (c) Copyright 2002-2011 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* math_bf.h */
#endif

/*
   This header file contains all ADSP Blackfin specific
   Analog extensions to the ANSI header file math.h.

   The header file is included by math.h by default.
   To disable the extensions, compile with the option:
        -D__NO_ANSI_EXTENSIONS__
 */

#ifndef  _MATH_BF_H
#define  _MATH_BF_H

#include <yvals.h>

#include <fract_typedef.h>
#include <fract_math.h>
#include <ccblkfn.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_1:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_8_5:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_10_1_d:"ADI header use of inline function")
#pragma diag(suppress:misra_rule_12_12:"ADI header use of float within a union")
#pragma diag(suppress:misra_rule_18_4:"ADI header requires union")
#pragma diag(suppress:misra_rule_19_1:"ADI header requires later include")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_6:"ADI header requires use of #undef")
#endif /* _MISRA_RULES */


_C_STD_BEGIN
_C_LIB_DECL

/* * * *        acos     * * * *
 *    Arc cosine
 */
#pragma linkage_name __acos_fr16
        fract16 acos_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
static _Fract acos_fx16(_Fract _x);
#endif

#pragma linkage_name __acos_fr32
        fract32 acos_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __acos_fr32
        long _Fract acos_fx32 (long _Fract _x);
#endif


/* * * *        alog     * * * *
 *    Natural anti-log
 */
#pragma linkage_name __alogf
        float alogf (float _x);

#pragma linkage_name __alogd
        long double alogd (long double _x);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __alogf
        double alog (double _x);
#else
#pragma linkage_name __alogd
        double alog (double _x);
#endif


/* * * *        alog10   * * * *
 *    Base-10 anti-log
 */
#pragma linkage_name __alog10f
        float alog10f (float _x);

#pragma linkage_name __alog10d
        long double alog10d (long double _x);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __alog10f
        double alog10 (double _x);
#else
#pragma linkage_name __alog10d
        double alog10 (double _x);
#endif


/* * * *        asin     * * * *
 *    Arc sine
 */
#pragma linkage_name __asin_fr16
        fract16 asin_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract asin_fx16 (_Fract _x);
#endif

#pragma linkage_name __asin_fr32
        fract32 asin_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __asin_fr32
        long _Fract asin_fx32 (long _Fract _x);
#endif


/* * * *        atan     * * * *
 *    Arc tangent
 */
#pragma linkage_name __atan_fr16
        fract16 atan_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract atan_fx16 (_Fract _x);
#endif

#pragma linkage_name __atan_fr32
        fract32 atan_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __atan_fr32
        long _Fract atan_fx32 (long _Fract _x);
#endif


/* * * *        atan2    * * * *
 *    Arc tangent of quotient
 */
#pragma linkage_name __atan2_fr16
        fract16 atan2_fr16 (fract16 _y, fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract atan2_fx16 (_Fract _y, _Fract _x);
#endif

#pragma linkage_name __atan2_fr32
        fract32 atan2_fr32 (fract32 _y, fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __atan2_fr32
        long _Fract atan2_fx32 (long _Fract _y, long _Fract _x);
#endif


/* * * *        cos      * * * *
 *    Cosine
 */
#pragma linkage_name __cos_fr16
        fract16 cos_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract cos_fx16 (_Fract _x);
#endif

#pragma linkage_name __cos_fr32
        fract32 cos_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __cos_fr32
        long _Fract cos_fx32 (long _Fract _x);
#endif


/* * * *        rsqrt    * * * *
 *    Inverse Square Root
 */
#pragma linkage_name __rsqrtf
        float rsqrtf (float _x);

#pragma linkage_name __rsqrtd
        long double rsqrtd (long double _x);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __rsqrtf
        double rsqrt (double _x);
#else
#pragma linkage_name __rsqrtd
        double rsqrt (double _x);
#endif


/* * * *        sin      * * * *
 *    Sine
 */
#pragma linkage_name __sin_fr16
        fract16 sin_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract sin_fx16 (_Fract _x);
#endif

#pragma linkage_name __sin_fr32
        fract32 sin_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __sin_fr32
        long _Fract sin_fx32 (long _Fract _x);
#endif


/* * * *        sqrt     * * * *
 *    Square Root
 */
#pragma linkage_name __sqrt_fr16
        fract16 sqrt_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract sqrt_fx16 (_Fract _x);
#endif

#pragma linkage_name __sqrt_fr32
        fract32 sqrt_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __sqrt_fr32
        long _Fract sqrt_fx32 (long _Fract _x);
#endif


/* * * *        tan      * * * *
 *    Tangent
 */
#pragma linkage_name __tan_fr16
        fract16 tan_fr16 (fract16 _x);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract tan_fx16 (_Fract _x);
#endif

#pragma linkage_name __tan_fr32
        fract32 tan_fr32 (fract32 _x);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __tan_fr32
        long _Fract tan_fx32 (long _Fract _x);
#endif


/* * * *        max      * * * *
 *    Maximum value
 */

#if !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static float fmaxf(float _x, float _y)
                { float res;
                  if (_x > _y) {
                   res = _x;
                  } else {
                   res = _y;
                  }
                  return res;
                }

#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static double fmax(double _x, double _y)
                { double res;
                  if (_x > _y) {
                   res = _x;
                  } else {
                   res = _y;
                  }
                  return res;
                }
#endif
#else
#pragma linkage_name __fmaxf
        float fmaxf(float _x, float _y);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __fmaxf
        double fmax(double _x, double _y);
#endif
#endif

#pragma linkage_name __fmaxd
        long double fmaxd(long double _x, long double _y);

#if !defined( __DOUBLES_ARE_FLOATS__)
#pragma linkage_name __fmaxd
        double fmax(double _x, double _y);
#endif


#if !defined(__NO_BUILTIN)

#define __SPECIFIC_NAMES
#define __ENABLE_MAX
#define __ENABLE_LMAX
#include <builtins.h>
#undef __SPECIFIC_NAMES

#else
#pragma linkage_name __max
        int max (int _x, int _y);

#pragma linkage_name __max
        long lmax (long _x, long _y);

#endif /* NO_BUILTIN */

#pragma linkage_name __llmax
        long long  llmax (long long  _x, long long  _y);


/* * * *        min      * * * *
 *    Minimum value
 */

#if !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static float fminf(float _x, float _y)
                { float res;
                  if (_x < _y) {
                   res = _x;
                  } else {
                   res = _y;
                  }
                  return res;
                }

#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static double fmin(double _x, double _y)
                { double res;
                  if (_x < _y) {
                   res = _x;
                  } else {
                   res = _y;
                  }
                  return res;
                }
#endif
#else
#pragma linkage_name __fminf
        float fminf(float _x, float _y);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __fminf
        double fmin(double _x, double _y);
#endif
#endif

#pragma linkage_name __fmind
        long double fmind(long double _x, long double _y);

#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __fmind
        double fmin(double _x, double _y);
#endif


#if !defined(__NO_BUILTIN)

#define __SPECIFIC_NAMES
#define __ENABLE_MIN
#define __ENABLE_LMIN
#include <builtins.h>
#undef __SPECIFIC_NAMES

#else
#pragma linkage_name __min
        int min (int _x, int _y);

#pragma linkage_name __min
        long lmin (long _x, long _y);
#endif

#pragma linkage_name __llmin
        long long  llmin (long long  _x, long long  _y);


/* * * *        clip     * * * *
 *    Clip value to limit
 *
 */
#pragma linkage_name __fclipf
        float fclipf (float _value, float _limit);

#pragma linkage_name __fclipd
        long double fclipd (long double _value, long double _limit);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __fclipf
#else
#pragma linkage_name __fclipd
#endif
        double fclip (double _value, double _limit);


#pragma linkage_name __clip_fr16
        fract16 clip_fr16 (fract16 _value, fract16 _limit);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract clip_fx16 (_Fract _value, _Fract _limit);
#endif

#pragma linkage_name __clip
        fract32 clip_fr32 (fract32 _value, fract32 _limit);

#pragma linkage_name __clip
        int clip (int _value, int _limit);

#pragma linkage_name __clip
        long lclip (long _value, long _limit);

#pragma linkage_name __llclip
        long long  llclip (long long  _value, long long  _limit);


/* * * *        copysign   * * * *
 *    Copy Sign of y (=reference) to x (=value)
 */
#pragma linkage_name __copysignf
        float copysignf (float _x, float _y);

#pragma linkage_name __copysignd
        long double copysignd (long double _x, long double _y);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __copysignf
        double copysign (double _x, double _y);
#else
#pragma linkage_name __copysignd
        double copysign (double _x, double _y);
#endif


#pragma linkage_name __copysign_fr16
        fract16 copysign_fr16 (fract16 _x, fract16 _y);
#ifdef __FIXED_POINT_ALLOWED
        static _Fract copysign_fx16 (_Fract _x, _Fract _y);
#endif

#pragma linkage_name __copysign_fr32
        fract32 copysign_fr32 (fract32 _x, fract32 _y);
#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __copysign_fr32
        long _Fract copysign_fx32 (long _Fract _x, long _Fract _y);
#endif


/* * * *        countones  * * * *
 *    Count number of 1 bits (parity)
 */
#if !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static int countones (int _x)
                { return (int)__builtin_ones(_x); }
#pragma inline
#pragma always_inline
        static int lcountones (long _x)
                { return (int)__builtin_ones((int)_x); }
#else
#pragma linkage_name __countones
        int countones (int _x);

#pragma linkage_name __lcountones
        int lcountones (long _x);
#endif /* __NO_BUILTIN */

#pragma linkage_name __llcountones
        int  llcountones (long long  _x);


/* * * *        isinf      * * * *
 *      Is number +/- Infinity?
 */
#if !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static int isinff(float _x) {
                union { float _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffffu) == 0x7f800000u;
        }

#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static int isinf(double _x) {
                union { double _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffffu) == 0x7f800000u;
        }
#endif
#else
#pragma linkage_name _isinf
        int isinff(float _x);

#ifdef __DOUBLES_ARE_FLOATS__
        int isinf(double _x);
#endif
#endif /* !__NO_BUILTIN */


#pragma linkage_name _isinfd
        int isinfd(long double _x);

#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name _isinfd
        int isinf(double _x);
#endif


/* * * *        isnan           * * * *
 *      Is number Not A Number?
 */
#if !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static int isnanf(float _x) {
                union { float _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffffu) > 0x7f800000uL;
        }

#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static int isnan(double _x) {
                union { double _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffffu) > 0x7f800000uL;
        }
#endif
#else
#pragma linkage_name _isnan
        int isnanf(float _x);

#ifdef __DOUBLES_ARE_FLOATS__
        int isnan(double _x);
#endif
#endif /* !__NO_BUILTIN */


#pragma linkage_name _isnand
        int isnand(long double _x);

#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name _isnand
        int isnan(double _x);
#endif

#ifdef __FIXED_POINT_ALLOWED

#pragma inline
#pragma always_inline
static _Fract acos_fx16(_Fract _x) {
    fract16 result = acos_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract asin_fx16(_Fract _x) {
    fract16 result = asin_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract atan_fx16(_Fract _x) {
    fract16 result = atan_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract atan2_fx16(_Fract _y, _Fract _x) {
    fract16 result = atan2_fr16(*(fract16 *)&_y, *(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract cos_fx16(_Fract _x) {
    fract16 result = cos_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract sin_fx16(_Fract _x) {
    fract16 result = sin_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract sqrt_fx16(_Fract _x) {
    fract16 result = sqrt_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract tan_fx16(_Fract _x) {
    fract16 result = tan_fr16(*(fract16 *)&_x);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract clip_fx16(_Fract _value, _Fract _limit) {
    fract16 result = clip_fr16(*(fract16 *)&_value, *(fract16 *)&_limit);
    return *(_Fract *)&result;
}

#pragma inline
#pragma always_inline
static _Fract copysign_fx16(_Fract _x, _Fract _y) {
    fract16 result = copysign_fr16(*(fract16 *)&_x, *(fract16 *)&_y);
    return *(_Fract *)&result;
}

#endif /* __FIXED_POINT_ALLOWED */

_END_C_LIB_DECL
_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* _MATH_BF_H */
