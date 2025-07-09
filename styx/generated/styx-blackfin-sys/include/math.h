/************************************************************************
 *
 * math.h
 *
 * (c) Copyright 2001-2010 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* math.h */
#endif

/* math.h standard header */

#ifndef _MATH
#define _MATH

#include <yvals.h>
#ifndef _YMATH
#include <ymath.h>
#endif


#if !defined( __NO_ANSI_EXTENSIONS__ )
#include <math_bf.h>
#endif  /* __NO_ANSI_EXTENSIONS__ */

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
#pragma diag(suppress:misra_rule_8_8:"some prototypes defined twice")
#pragma diag(suppress:misra_rule_12_12:"ADI header use of union with float")
#pragma diag(suppress:misra_rule_18_4)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_20_2)
#endif /* _MISRA_RULES */

_C_STD_BEGIN

/* MACROS */
#if defined(__DOUBLES_ARE_FLOATS__)
#define HUGE_VAL    _CSTD _FHugeval._Double
#else
#define HUGE_VAL    _CSTD _LHugeval._Double
#endif

_C_LIB_DECL

/* Map ANSI standard & Dinkum entry point
   names to Blackfin entry point names
*/
#define acosl    acosd
#define asinl    asind
#define atanl    atand
#define atan2l   atan2d
#define ceill    ceild
#define cosl     cosd
#define coshl    coshd
#define expl     expd
#define fabsl    fabsd
#define floorl   floord
#define fmodl    fmodd
#define frexpl   frexpd
#define ldexpl   ldexpd
#define logl     logd
#define log10l   log10d
#define modfl    modfd
#define powl     powd
#define sinl     sind
#define sinhl    sinhd
#define sqrtl    sqrtd
#define tanl     tand
#define tanhl    tanhd


/* * * *        acos      * * * *
 *    Arc cosine
 */
#pragma linkage_name __acosf
        float acosf (float _x);

#pragma linkage_name __acosd
        long double acosd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __acosf
        double acos (double _x);
#else
#pragma linkage_name __acosd
        double acos (double _x);
#endif


/* * * *        asin      * * * *
 *    Arc sine
 */
#pragma linkage_name __asinf
        float asinf (float _x);

#pragma linkage_name __asind
        long double asind (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __asinf
        double asin (double _x);
#else
#pragma linkage_name __asind
        double asin (double _x);
#endif


/* * * *        atan      * * * *
 *    Arc tangent
 */
#pragma linkage_name __atanf
        float atanf (float _x);

#pragma linkage_name __atand
        long double atand (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __atanf
        double atan (double _x);
#else
#pragma linkage_name __atand
        double atan (double _x);
#endif


/* * * *        atan2      * * * *
 *    Arc tangent of quotient
 */
#pragma linkage_name __atan2f
        float atan2f (float _y, float _x);

#pragma linkage_name __atan2d
        long double atan2d (long double _y, long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __atan2f
#else
#pragma linkage_name __atan2d
#endif
        double atan2 (double _y, double _x);


/* * * *        ceil      * * * *
 *    Ceiling
 */
#pragma linkage_name __ceilf
        float ceilf (float _x);

#pragma linkage_name __ceild
        long double ceild (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __ceilf
        double ceil (double _x);
#else
#pragma linkage_name __ceild
        double ceil (double _x);
#endif


/* * * *        cos      * * * *
 *    Cosine - dinkum version used for 32-bit function
 */
#pragma linkage_name __cosf
        float cosf (float _x);

#pragma linkage_name __cosd
        long double cosd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __cosf
        double cos (double _x);
#else
#pragma linkage_name __cosd
        double cos (double _x);
#endif


/* * * *        cosh      * * * *
 *    Hyperbolic Cosine - dinkum version used for 32-bit function
 */
#pragma linkage_name __coshf
        float coshf (float _x);

#pragma linkage_name __coshd
        long double coshd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __coshf
        double cosh (double _x);
#else
#pragma linkage_name __coshd
        double cosh (double _x);
#endif


/* * * *        cot      * * * *
 *    Cotangent
 */
#pragma linkage_name __cotf
        float cotf (float _x);

#pragma linkage_name __cotd
        long double cotd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __cotf
        double cot (double _x);
#else
#pragma linkage_name __cotd
        double cot (double _x);
#endif


/* * * *        exp      * * * *
 *    Exponential
 */
#pragma linkage_name __expf
        float expf (float _x);

#pragma linkage_name __expd
        long double expd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __expf
        double exp (double _x);
#else
#pragma linkage_name __expd
        double exp (double _x);
#endif


/* * * *        floor      * * * *
 *    Floor
 */
#pragma linkage_name __floorf
        float floorf (float _x);

#pragma linkage_name __floord
        long double floord (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __floorf
        double floor (double _x);
#else
#pragma linkage_name __floord
        double floor (double _x);
#endif


/* * * *        fmod      * * * *
 *    Floating point mod
 *    Using Dinkum for 64-bit floating point
 */
#pragma linkage_name __fmodf
        float fmodf (float _x, float _y);

#pragma linkage_name _fmodl
        long double fmodd (long double _x, long double _y);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __fmodf
        double fmod (double _x, double _y);
#else
#pragma linkage_name _fmodl
        double fmod (double _x, double _y);
#endif


/* * * *        frexp      * * * *
 *    Get mantissa and exponent
 */
#pragma linkage_name __frexpf
        float frexpf (float _x, int * _power_of_2);

#pragma linkage_name __frexpd
        long double frexpd (long double _x, int * _power_of_2);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __frexpf
        double frexp (double _x, int * _power_of_2);
#else
#pragma linkage_name __frexpd
        double frexp (double _x, int * _power_of_2);
#endif


/* * * *        ldexp      * * * *
 *    Set mantissa and exponent - dinkum version used for 32-bit function
 */
        float  ldexpf (float  _x, int _power_of_2);

#pragma linkage_name __ldexpd
        long double ldexpd (long double _x, int _power_of_2);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name  _ldexpf
        double ldexp (double _x, int _power_of_2);
#else
#pragma linkage_name __ldexpd
        double ldexp (double _x, int _power_of_2);
#endif


/* * * *        log      * * * *
 *    Natural Log
 */
#pragma linkage_name __logf
        float logf (float _x);

#pragma linkage_name __logd
        long double logd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __logf
        double log (double _x);
#else
#pragma linkage_name __logd
        double log (double _x);
#endif


/* * * *        log10      * * * *
 *    Log base 10
 */
#pragma linkage_name __log10f
        float log10f (float _x);

#pragma linkage_name __log10d
        long double log10d (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __log10f
        double log10 (double _x);
#else
#pragma linkage_name __log10d
        double log10 (double _x);
#endif


/* * * *        modf      * * * *
 *    Get fraction and integer parts of floating point
 */
#pragma linkage_name __modff
        float modff (float _x, float * _integral);

#pragma linkage_name __modfd
        long double modfd (long double _x, long double * _integral);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __modff
        double modf (double _x, double * _integral);
#else
#pragma linkage_name __modfd
        double modf (double _x, double * _integral);
#endif


/* * * *        pow      * * * *
 *    Power
 */
#pragma linkage_name __powf
        float powf (float _x, float _power_of_x);

#pragma linkage_name __powd
        long double powd (long double _x, long double _power_of_x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __powf
        double pow (double _x, double _power_of_x);
#else
#pragma linkage_name __powd
        double pow (double _x, double _power_of_x);
#endif


/* * * *        sin      * * * *
 *    Sine
 */
#pragma linkage_name __sinf
        float sinf (float _x);

#pragma linkage_name __sind
        long double sind (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __sinf
        double sin (double _x);
#else
#pragma linkage_name __sind
        double sin (double _x);
#endif


/* * * *        sinh      * * * *
 *    Hyperbolic Sine - dinkum version used for 32-bit function
 */
#pragma linkage_name __sinhf
        float sinhf (float _x);

#pragma linkage_name __sinhd
        long double sinhd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __sinhf
        double sinh (double _x);
#else
#pragma linkage_name __sinhd
        double sinh (double _x);
#endif


/* * * *        sqrt      * * * *
 *    Square Root
 */
#pragma linkage_name __sqrtf
        float sqrtf (float _x);

#pragma linkage_name __sqrtd
        long double sqrtd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __sqrtf
        double sqrt (double _x);
#else
#pragma linkage_name __sqrtd
        double sqrt (double _x);
#endif


/* * * *        tan      * * * *
 *    Tangent
 */
#pragma linkage_name __tanf
        float tanf (float _x);

#pragma linkage_name __tand
        long double tand (long double _x);

#if  defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __tanf
        double tan (double _x);
#else
#pragma linkage_name __tand
        double tan (double _x);
#endif


/* * * *        tanh      * * * *
 *    Hyperbolic Tangent
 */
#pragma linkage_name __tanhf
        float tanhf (float _x);

#pragma linkage_name __tanhd
        long double tanhd (long double _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __tanhf
        double tanh (double _x);
#else
#pragma linkage_name __tanhd
        double tanh (double _x);
#endif


/* * * *        fabs      * * * *
 *    Float Absolute Value
 */
#if !defined(__NO_BUILTIN)

#pragma inline
#pragma always_inline
        static float fabsf(float _x) {
            union { float _d; unsigned long _l; } _v;
            _v._d = _x;
            _v._l &= 0x7fffffffUL;
            return _v._d;
        }

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma inline
#pragma always_inline
        static double fabs(double _x) {
            union { double _d; unsigned long _l; } _v;
            _v._d = _x;
            _v._l &= 0x7fffffffUL;
            return _v._d;
        }
#endif
#else
        float fabsf (float _x);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name _fabsf
        double fabs (double _x);
#else
#pragma linkage_name __fabsd
        double fabs (double _x);
#endif
#endif  /* !__NO_BUILTIN */

#pragma linkage_name __fabsd
        long double fabsd (long double _x);

#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __fabsd
        double fabs (double _x);
#endif


_END_C_LIB_DECL


#if defined(__cplusplus)

  #if !_IS_EMBEDDED
		// TEMPLATE FUNCTION _Pow_int
template<class _Ty> inline
	_Ty _Pow_int(_Ty _Left, int _Right)
	{	// raise to integer power
	unsigned int _Num = _Right;
	if (_Right < 0)
		_Num = 0 - _Num;

	for (_Ty _Ans = 1; ; _Left *= _Left)
		{	// scale and fold in factors
		if ((_Num & 1) != 0)
			_Ans *= _Left;
		if ((_Num >>= 1) == 0)
			return ((_Ty)(0 <= _Right ? _Ans
				: _Ans == _Ty(0) ? HUGE_VAL : _Ty(1) / _Ans));
		}
	}
  #endif /* _IS_EMBEDDED */


 #if !_IS_EMBEDDED
#pragma always_inline
inline long double pow(long double _Left, int _Right)
	{	/* raise to integer power */
	return (_Pow_int(_Left, _Right));
	}
#pragma always_inline
inline double pow(double _Left, int _Right)
	{	/* raise to integer power */
	return (_Pow_int(_Left, _Right));
	}
#pragma always_inline
inline float pow(float _Left, int _Right)
	{	/* raise to integer power */
	return (_Pow_int(_Left, _Right));
	}
 #endif /* _IS_EMBEDDED */

    /* float inlines for C++ */

#pragma always_inline
inline double abs(double _Left)	// OVERLOADS
	{	/* return absolute value */
	return (fabs(_Left));
	}

#pragma always_inline
inline float abs(float _Left)	// OVERLOADS
	{	/* return absolute value */
	return (fabsf(_Left));
	}

#pragma always_inline
inline float acos(float _Left)
	{	/* return arccosine */
	return (acosf(_Left));
	}

#pragma always_inline
inline float asin(float _Left)
	{	/* return arcsine */
	return (asinf(_Left));
	}

#pragma always_inline
inline float atan(float _Left)
	{	/* return arctangent */
	return (atanf(_Left));
	}

#pragma always_inline
inline float atan2(float _Left, float _Right)
	{	/* return arctangent */
	return (atan2f(_Left, _Right));
	}

#pragma always_inline
inline float ceil(float _Left)
	{	/* return ceiling */
	return (ceilf(_Left));
	}

#pragma always_inline
inline float cos(float _Left)
	{	/* return cosine */
	return (cosf(_Left));
	}

#pragma always_inline
inline float cosh(float _Left)
	{	/* return hyperbolic cosine */
	return (coshf(_Left));
	}

#pragma always_inline
inline float exp(float _Left)
	{	/* return exponential */
	return (expf(_Left));
	}

#pragma always_inline
inline float fabs(float _Left)
	{	/* return absolute value */
	return (fabsf(_Left));
	}

#pragma always_inline
inline float floor(float _Left)
	{	/* return floor */
	return (floorf(_Left));
	}

#pragma always_inline
inline float fmod(float _Left, float _Right)
	{	/* return modulus */
	return (fmodf(_Left, _Right));
	}

#pragma always_inline
inline float frexp(float _Left, int *_Right)
	{	/* unpack exponent */
	return (frexpf(_Left, _Right));
	}

#pragma always_inline
inline float ldexp(float _Left, int _Right)
	{	/* pack exponent */
	return (ldexpf(_Left, _Right));
	}

#pragma always_inline
inline float log(float _Left)
	{	/* return natural logarithm */
	return (logf(_Left));
	}

#pragma always_inline
inline float log10(float _Left)
	{	/* return base-10 logarithm */
	return (log10f(_Left));
	}

#pragma always_inline
inline float modf(float _Left, float *_Right)
	{	/* unpack fraction */
	return (modff(_Left, _Right));
	}

#pragma always_inline
inline float pow(float _Left, float _Right)
	{	/* raise to power */
	return (powf(_Left, _Right));
	}

#pragma always_inline
inline float sin(float _Left)
	{	/* return sine */
	return (sinf(_Left));
	}

#pragma always_inline
inline float sinh(float _Left)
	{	/* return hyperbolic sine */
	return (sinhf(_Left));
	}

#pragma always_inline
inline float sqrt(float _Left)
	{	/* return square root */
	return (sqrtf(_Left));
	}

#pragma always_inline
inline float tan(float _Left)
	{	/* return tangent */
	return (tanf(_Left));
	}

#pragma always_inline
inline float tanh(float _Left)
	{	/* return hyperbolic tangent */
	return (tanhf(_Left));
	}


    /* Overload long double */


#pragma always_inline
inline long double abs(long double _Left)	/* OVERLOADS */
	{	/* return absolute value */
	return (fabsl(_Left));
	}

#pragma always_inline
inline long double acos(long double _Left)
	{	/* return arccosine */
	return (acosl(_Left));
	}

#pragma always_inline
inline long double asin(long double _Left)
	{	/* return arcsine */
	return (asinl(_Left));
	}

#pragma always_inline
inline long double atan(long double _Left)
	{	/* return arctangent */
	return (atanl(_Left));
	}

#pragma always_inline
inline long double atan2(long double _Left, long double _Right)
	{	/* return arctangent */
	return (atan2l(_Left, _Right));
	}

#pragma always_inline
inline long double ceil(long double _Left)
	{	/* return ceiling */
	return (ceill(_Left));
	}

#pragma always_inline
inline long double cos(long double _Left)
	{	/* return cosine */
	return (cosl(_Left));
	}

#pragma always_inline
inline long double cosh(long double _Left)
	{	/* return hyperbolic cosine */
	return (coshl(_Left));
	}

#pragma always_inline
inline long double exp(long double _Left)
	{	/* return exponential */
	return (expl(_Left));
	}

#pragma always_inline
inline long double fabs(long double _Left)
	{	/* return absolute value */
	return (fabsl(_Left));
	}

#pragma always_inline
inline long double floor(long double _Left)
	{	/* return floor */
	return (floorl(_Left));
	}

#pragma always_inline
inline long double fmod(long double _Left, long double _Right)
	{	/* return modulus */
	return (fmodl(_Left, _Right));
	}

#pragma always_inline
inline long double frexp(long double _Left, int *_Right)
	{	/* unpack exponent */
	return (frexpl(_Left, _Right));
	}

#pragma always_inline
inline long double ldexp(long double _Left, int _Right)
	{	/* pack exponent */
	return (ldexpl(_Left, _Right));
	}

#pragma always_inline
inline long double log(long double _Left)
	{	/* return natural logarithm */
	return (logl(_Left));
	}

#pragma always_inline
inline long double log10(long double _Left)
	{	/* return base-10 logarithm */
	return (log10l(_Left));
	}

#pragma always_inline
inline long double modf(long double _Left, long double *_Right)
	{	/* unpack fraction */
	return (modfl(_Left, _Right));
	}

#pragma always_inline
inline long double pow(long double _Left, long double _Right)
	{	/* raise to power */
	return (powl(_Left, _Right));
	}


#pragma always_inline
inline long double sin(long double _Left)
	{	/* return sine */
	return (sinl(_Left));
	}

#pragma always_inline
inline long double sinh(long double _Left)
	{	/* return hyperbolic sine */
	return (sinhl(_Left));
	}

#pragma always_inline
inline long double sqrt(long double _Left)
	{	/* return square root */
	return (sqrtl(_Left));
	}

#pragma always_inline
inline long double tan(long double _Left)
	{	/* return tangent */
	return (tanl(_Left));
	}

#pragma always_inline
inline long double tanh(long double _Left)
	{	/* return hyperbolic tangent */
	return (tanhl(_Left));
	}


#endif /* __cplusplus */

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _MATH */


#ifdef _STD_USING
using std::abs; using std::acos; using std::asin;
using std::atan; using std::atan2; using std::ceil;
using std::cos; using std::cosh; using std::exp;
using std::fabs; using std::floor; using std::fmod;
using std::frexp; using std::ldexp; using std::log;
using std::log10; using std::modf; using std::pow;
using std::sin; using std::sinh; using std::sqrt;
using std::tan; using std::tanh;

using std::acosf; using std::asinf;
using std::atanf; using std::atan2f; using std::ceilf;
using std::cosf; using std::coshf; using std::expf;
using std::fabsf; using std::floorf; using std::fmodf;
using std::frexpf; using std::ldexpf; using std::logf;
using std::log10f; using std::modff; using std::powf;
using std::sinf; using std::sinhf; using std::sqrtf;
using std::tanf; using std::tanhf;

#if defined(_ADI_SUPPORT_LONG_DOUBLE)
using std::acosd; using std::asind;
using std::atand; using std::atan2d; using std::ceild;
using std::cosd; using std::coshd; using std::expd;
using std::fabsd; using std::floord; using std::fmodd;
using std::frexpd; using std::ldexpd; using std::logd;
using std::log10d; using std::modfd; using std::powd;
using std::sind; using std::sinhd; using std::sqrtd;
using std::tand; using std::tanhd;
#endif /* _ADI_SUPPORT_LONG_DOUBLE */

#endif /* _STD_USING */

/*
* Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V3.10:1134 */
