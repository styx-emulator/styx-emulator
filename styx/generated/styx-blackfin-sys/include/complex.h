/************************************************************************
 *
 * complex.h
 *
 * (c) Copyright 1996-2010 Analog Devices, Inc.  All rights reserved.
 * $Revision: 14738 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* complex.h */
#endif

#ifndef __COMPLEX_DEFINED
#define __COMPLEX_DEFINED

#include <complex_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_19_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_6)
#pragma diag(suppress:misra_rule_19_7)
#endif /* _MISRA_RULES */


#ifdef __cplusplus
  extern "C" {
#endif

/* * * *        cabs      * * * *
 *
 *    Complex absolute value
 *
 */

#pragma linkage_name __cabsf
        float cabsf (complex_float _a);

#pragma linkage_name __cabsd
        long double cabsd (complex_long_double _a);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cabsf
#else
#pragma linkage_name __cabsd
#endif
        double cabs (complex_double _a);


#pragma linkage_name __cabs_fr16
        fract16 cabs_fr16 (complex_fract16 _a);

#pragma linkage_name __cabs_fr32
        fract32 cabs_fr32 (complex_fract32 _a);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __cabs_fr16
        _Fract cabs_fx_fr16 (complex_fract16 _a);

#pragma linkage_name __cabs_fr32
        long _Fract cabs_fx_fr32 (complex_fract32 _a);
#endif



/* * * *        conj      * * * *
 *
 *    Complex conjugate
 *
 */

#pragma inline
#pragma always_inline
        static complex_float conjf (complex_float _a)
        {
           complex_float _c;
           _c.re = _a.re;
           _c.im = -_a.im;
           return _c;
        }

#pragma linkage_name __conjd
        complex_long_double conjd (complex_long_double _a);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static complex_double conj (complex_double _a)
        {
           complex_double _c;
           _c.re =  _a.re;
           _c.im = -_a.im;
           return _c;
        }
#else
#pragma linkage_name __conjd
        complex_double conj (complex_double _a);
#endif


#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract16 conj_fr16 (complex_fract16 _a)
        {
           complex_fract16 _c = _a;
           int _negate_a = __builtin_negate_fr2x16(
                                     __builtin_ccompose_fr16(_a.re, _a.im)
                                                  );
           _c.im = __builtin_imag_fr16( _negate_a );
           return _c;
        }
#else
#pragma linkage_name __conj_fr16
        complex_fract16 conj_fr16 (complex_fract16 _a);
#endif


#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract32 conj_fr32 (complex_fract32 _a)
        {
           _composite_complex_fract32 _c;
           _CCFR32_CPLX(_c) = _a;
           _CCFR32_RAW(_c) = __builtin_conj_fr32(_CCFR32_RAW(_c));
           return _CCFR32_CPLX(_c);
        }
#else
#pragma linkage_name __conj_fr32
        complex_fract32 conj_fr32 (complex_fract32 _a);
#endif



/* * * *        cadd      * * * *
 *
 *    Complex addition
 *
 */

#pragma inline
#pragma always_inline
        static complex_float caddf (complex_float _a,
                                    complex_float _b)
        {
           complex_float _c;
           _c.re = _a.re + _b.re;
           _c.im = _a.im + _b.im;
           return _c;
        }

#pragma linkage_name __caddd
        complex_long_double caddd (complex_long_double _a,
                                   complex_long_double _b);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static complex_double cadd (complex_double _a,
                                    complex_double _b)
        {
           complex_double _c;
           _c.re = _a.re + _b.re;
           _c.im = _a.im + _b.im;
           return _c;
        }
#else
#pragma linkage_name __caddd
        complex_double cadd (complex_double _a, complex_double _b);
#endif


#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract16 cadd_fr16 (complex_fract16 _a,
                                          complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_add(
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                       );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }
#else
#pragma linkage_name __cadd_fr16
        complex_fract16 cadd_fr16 (complex_fract16 _a, complex_fract16 _b);
#endif

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract32 cadd_fr32 (complex_fract32 _a,
                                          complex_fract32 _b)
        {
           _composite_complex_fract32 _c, _d;
           _CCFR32_CPLX(_c) = _a;
           _CCFR32_CPLX(_d) = _b;
           _CCFR32_RAW(_c) = __builtin_cadd_fr32(_CCFR32_RAW(_c),
                                                 _CCFR32_RAW(_d));
           return _CCFR32_CPLX(_c);
        }
#else
#pragma linkage_name __cadd_fr32
        complex_fract32 cadd_fr32 (complex_fract32 _a, complex_fract32 _b);
#endif



/* * * *        csub      * * * *
 *
 *    Complex subtraction
 *
 */

#pragma inline
#pragma always_inline
        static complex_float csubf (complex_float _a,
                                    complex_float _b)
        {
           complex_float _c;
           _c.re = _a.re - _b.re;
           _c.im = _a.im - _b.im;
           return _c;
        }

#pragma linkage_name __csubd
        complex_long_double csubd (complex_long_double _a,
                                   complex_long_double _b);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static complex_double csub (complex_double _a,
                                    complex_double _b)
        {
           complex_double _c;
           _c.re = _a.re - _b.re;
           _c.im = _a.im - _b.im;
           return _c;
        }
#else
#pragma linkage_name __csubd
        complex_double csub (complex_double _a, complex_double _b);
#endif

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract16 csub_fr16 (complex_fract16 _a,
                                          complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_sub(
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                       );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }
#else
#pragma linkage_name __csub_fr16
        complex_fract16 csub_fr16 (complex_fract16 _a, complex_fract16 _b);
#endif

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract32 csub_fr32 (complex_fract32 _a,
                                          complex_fract32 _b)
        {
           _composite_complex_fract32 _c, _d;
           _CCFR32_CPLX(_c) = _a;
           _CCFR32_CPLX(_d) = _b;
           _CCFR32_RAW(_c) = __builtin_csub_fr32(_CCFR32_RAW(_c),
                                                 _CCFR32_RAW(_d));
           return _CCFR32_CPLX(_c);
        }
#else
#pragma linkage_name __csub_fr32
        complex_fract32 csub_fr32 (complex_fract32 _a, complex_fract32 _b);
#endif



/* * * *        cmlt      * * * *
 *
 *    Complex multiplication
 *
 */

#pragma inline
#pragma always_inline
        static complex_float cmltf (complex_float _a,
                                    complex_float _b)
        {
           complex_float _c;
           _c.re = (_a.re * _b.re) - (_a.im* + _b.im);
           _c.im = (_a.re * _b.im) + (_a.im* + _b.re);
           return _c;
        }

#pragma linkage_name __cmltd
        complex_long_double cmltd (complex_long_double _a,
                                   complex_long_double _b);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma inline
#pragma always_inline
        static complex_double cmlt (complex_double _a,
                                    complex_double _b)
        {
           complex_double _c;
           _c.re = (_a.re * _b.re) - (_a.im* + _b.im);
           _c.im = (_a.re * _b.im) + (_a.im* + _b.re);
           return _c;
        }
#else
#pragma linkage_name __cmltd
        complex_double cmlt (complex_double _a,
                             complex_double _b);
#endif


#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma inline
#pragma always_inline
        static complex_fract16 cmlt_fr16 (complex_fract16 _a,
                                          complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_mul(
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                       );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }
#else
#pragma linkage_name __cmlt_fr16
        complex_fract16 cmlt_fr16 (complex_fract16 _a, complex_fract16 _b);

#endif


#pragma linkage_name __cmlt_fr32
    complex_fract32 cmlt_fr32 (complex_fract32 _a, complex_fract32 _b);



/* * * *        cdiv      * * * *
 *
 *    Complex division
 *
 */

#pragma linkage_name __cdivf
        complex_float cdivf (complex_float _a, complex_float _b);

#pragma linkage_name __cdivd
        complex_long_double cdivd (complex_long_double _a,
                                   complex_long_double _b);

#ifdef __DOUBLES_ARE_FLOATS__

#pragma linkage_name __cdivf
#else
#pragma linkage_name __cdivd
#endif
        complex_double cdiv (complex_double _a, complex_double _b);


#pragma linkage_name __cdiv_fr16
        complex_fract16 cdiv_fr16 (complex_fract16 _a, complex_fract16 _b);


#pragma linkage_name __cdiv_fr32
        complex_fract32 cdiv_fr32 (complex_fract32 _a, complex_fract32 _b);



/* * * *        norm      * * * *
 *
 *    Normalize complex number
 *
 */

#pragma linkage_name __normf
        complex_float normf (complex_float _a);

#pragma linkage_name __normd
        complex_long_double normd (complex_long_double _a);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __normf
#else
#pragma linkage_name __normd
#endif
        complex_double norm (complex_double _a);



/* * * *        cexp      * * * *
 *
 *    Complex exponential e^x, where x is a real number
 *
 */

#pragma linkage_name __cexpf
        complex_float cexpf (float _x);

#pragma linkage_name __cexpd
        complex_long_double cexpd (long double _x);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cexpf
#else
#pragma linkage_name __cexpd
#endif
        complex_double cexp (double _x);



/* * * *        arg      * * * *
 *
 *    Get phase of complex number
 *
 */

#pragma linkage_name __argf
        float argf (complex_float _a);

#pragma linkage_name __argd
        long double argd (complex_long_double _a);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __argf
#else
#pragma linkage_name __argd
#endif
        double arg (complex_double _a);


#pragma linkage_name __arg_fr16
        fract16 arg_fr16 (complex_fract16 _a);

#pragma linkage_name __arg_fr32
        fract32 arg_fr32 (complex_fract32 _a);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __arg_fr16
        _Fract arg_fx_fr16 (complex_fract16 _a);

#pragma linkage_name __arg_fr32
        long _Fract arg_fx_fr32 (complex_fract32 _a);
#endif



/* * * *        polar      * * * *
 *
 *    Convert polar coordinates to cartesian notation
 *
 */

#pragma linkage_name __polarf
        complex_float polarf (float _magnitude, float _phase);

#pragma linkage_name __polard
        complex_long_double polard (long double _magnitude,
                                    long double _phase);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __polarf
#else
#pragma linkage_name __polard
#endif
        complex_double polar (double _magnitude, double _phase);


#pragma linkage_name __polar_fr16
        complex_fract16 polar_fr16 (fract16 _magnitude, fract16 _phase);

#pragma linkage_name __polar_fr32
        complex_fract32 polar_fr32 (fract32 _magnitude, fract32 _phase);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __polar_fr16
        complex_fract16 polar_fx_fr16 (_Fract _magnitude, _Fract _phase);

#pragma linkage_name __polar_fr32
        complex_fract32 polar_fx_fr32 (long _Fract _magnitude,
                                       long _Fract _phase);
#endif



/* * * *        cartesian  * * * *
 *
 *    Convert cartesian coordinates to polar notation
 *    (Return value == magnitude)
 *
 */

#pragma linkage_name __cartesianf
        float cartesianf (complex_float _a, float* _phase);

#pragma linkage_name __cartesiand
        long double cartesiand (complex_long_double _a, long double* _phase);


#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cartesianf
#else
#pragma linkage_name __cartesiand
#endif
        double cartesian (complex_double _a, double* _phase);


#pragma linkage_name __cartesian_fr16
        fract16 cartesian_fr16 (complex_fract16 _a, fract16* _phase);

#pragma linkage_name __cartesian_fr32
        fract32 cartesian_fr32 (complex_fract32 _a, fract32* _phase);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __cartesian_fr16
        _Fract cartesian_fx_fr16 (complex_fract16 _a, _Fract* _phase);

#pragma linkage_name __cartesian_fr32
        long _Fract cartesian_fx_fr32 (complex_fract32 _a,
                                       long _Fract* _phase);
#endif



#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)

/* * * * complex built-ins * * * *
 *
 */

#pragma inline
#pragma always_inline
        static complex_fract16 csqu_fr16 (complex_fract16 _a)
        {
           _composite_complex_fract16 _c;
           _CCFR16_CPLX(_c) = _a;
           _CCFR16_RAW(_c) = __builtin_csqu_fr16(_CCFR16_RAW(_c));
           return _CCFR16_CPLX(_c);
        }

#pragma inline
#pragma always_inline
        /*  Complex fract16 multiply accumulate operation with 32-bit internal
        **  saturation.
        */
        static complex_fract16 cmac_fr16 (complex_fract16 _sum,
                                          complex_fract16 _a,
                                          complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_mac(
                                 __builtin_ccompose_fr16(_sum.re, _sum.im),
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                       );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }

#pragma inline
#pragma always_inline
        /*  Complex fract16 multiply subtract operation with 32-bit internal
        **  saturation.
        */
        static complex_fract16 cmsu_fr16 (complex_fract16 _sum,
                                          complex_fract16 _a,
                                          complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_msu(
                                 __builtin_ccompose_fr16(_sum.re, _sum.im),
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                       );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }

#pragma inline
#pragma always_inline
        /*  Complex fract16 multiply accumulate operation with 40-bit internal
        **  saturation.
        */
        static complex_fract16 cmac_fr16_s40 (complex_fract16 _sum,
                                              complex_fract16 _a,
                                              complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_mac_s40(
                                 __builtin_ccompose_fr16(_sum.re, _sum.im),
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                           );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }

#pragma inline
#pragma always_inline
        /*  Complex fract16 multiply subtract operation with 40-bit internal
        **  saturation.
        */
        static complex_fract16 cmsu_fr16_s40 (complex_fract16 _sum,
                                              complex_fract16 _a,
                                              complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x = __builtin_cmplx_msu_s40(
                                 __builtin_ccompose_fr16(_sum.re, _sum.im),
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                           );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);
           return _c;
        }

#pragma inline
#pragma always_inline
        /* Calculate the square of the distance between
        ** the complex numbers _a and _b
        */
        static fract16 cdst_fr16 (complex_fract16 _a,
                                  complex_fract16 _b)
        {
           complex_fract16 _c;
           int _x;

           _x = __builtin_cmplx_sub(
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                   );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);

           _x = __builtin_mult_fr2x16(
                                 __builtin_ccompose_fr16(_c.re, _c.im),
                                 __builtin_ccompose_fr16(_c.re, _c.im)
                                     );
           _c.re = __builtin_real_fr16(_x);
           _c.im = __builtin_imag_fr16(_x);

           return __builtin_add_fr1x16( _c.im, _c.re );
        }

#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        /* Calculate the square of the distance between
        ** the complex numbers _a and _b
        */
        static _Fract cdst_fx_fr16 (complex_fract16 _a,
                                    complex_fract16 _b)
        {
           fract16 result = cdst_fr16(_a, _b);
           return *(_Fract *)&result;
        }
#endif

#pragma inline
#pragma always_inline
        /* Calculate the square of the distance between
        ** the complex numbers _a and _b
        */
        static fract32 cdst_fr32 (complex_fract16 _a,
                                  complex_fract16 _b)
        {
           fract32 _v, _w;
           int _x;

           _x = __builtin_cmplx_sub(
                                 __builtin_ccompose_fr16(_a.re, _a.im),
                                 __builtin_ccompose_fr16(_b.re, _b.im)
                                   );
           _v = __builtin_mult_fr1x32(
                                 __builtin_extract_lo(_x),
                                 __builtin_extract_lo(_x)
                                     );
           _w = __builtin_mult_fr1x32(
                                 __builtin_extract_hi(_x),
                                 __builtin_extract_hi(_x)
                                     );
           return __builtin_add_fr1x32(_v, _w);
        }

#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        /* Calculate the square of the distance between
        ** the complex numbers _a and _b
        */
        static long _Fract cdst_fx_fr32 (complex_fract16 _a,
                                         complex_fract16 _b)
        {
           fract32 result = cdst_fr32(_a, _b);
           return *(long _Fract *)&result;
        }
#endif

#define __NO_SHORTNAMES
/*
   note: __NO_SHORTNAMES is defined here, so any changes made which
   use builtins used should be enabled manually, e.g. to include min():
   you should remove the define of __NO_SHORTNAMES and use
     #define __SPECIFIC_NAMES
     #define __ENABLE_MIN 1
*/

#include <builtins.h>
#undef __NO_SHORTNAMES

#pragma inline
#pragma always_inline
        static complex_fract16 ccompose_fr16 (fract16 _a_real, fract16 _a_imag)
        {
           _composite_complex_fract16 _c;
           _CCFR16_RAW(_c) = __builtin_ccompose_fr16(_a_real, _a_imag);
           return _CCFR16_CPLX(_c);
        }

#pragma inline
#pragma always_inline
        static fract16 real_fr16 (complex_fract16 _a)
        {
           _composite_complex_fract16 _c;
           _CCFR16_CPLX(_c) = _a;
           return __builtin_real_fr16(_CCFR16_RAW(_c));
        }

#pragma inline
#pragma always_inline
        static fract16 imag_fr16 (complex_fract16 _a)
        {
           _composite_complex_fract16 _c;
           _CCFR16_CPLX(_c) = _a;
           return __builtin_imag_fr16(_CCFR16_RAW(_c));
        }

#ifdef __FIXED_POINT_ALLOWED

#pragma inline
#pragma always_inline
        static complex_fract16 ccompose_fx_fr16 (_Fract _a_real,
                                                 _Fract _a_imag)
        {
           _composite_complex_fract16 _c;
           _CCFR16_RAW(_c) = __builtin_ccompose_fx_fr16(_a_real, _a_imag);
           return _CCFR16_CPLX(_c);
        }

#pragma inline
#pragma always_inline
        static _Fract real_fx_fr16 (complex_fract16 _a)
        {
           _composite_complex_fract16 _c;
           _CCFR16_CPLX(_c) = _a;
           return __builtin_real_fx_fr16(_CCFR16_RAW(_c));
        }

#pragma inline
#pragma always_inline
        static _Fract imag_fx_fr16 (complex_fract16 _a)
        {
           _composite_complex_fract16 _c;
           _CCFR16_CPLX(_c) = _a;
           return __builtin_imag_fx_fr16(_CCFR16_RAW(_c));
        }

#endif /* __FIXED_POINT_ALLOWED */

#pragma inline
#pragma always_inline
        static complex_fract32 ccompose_fr32 (fract32 _a_real, fract32 _a_imag)
        {
           _composite_complex_fract32 _c;
           _CCFR32_RAW(_c) = __builtin_compose_i64(_a_real, _a_imag);
           return _CCFR32_CPLX(_c);
        }

#pragma inline
#pragma always_inline
        static fract32 real_fr32 (complex_fract32 _a)
        {
           _composite_complex_fract32 _c;
           _CCFR32_CPLX(_c) = _a;
           return __builtin_real_fr32(_CCFR32_RAW(_c));
        }

#pragma inline
#pragma always_inline
        static fract32 imag_fr32 (complex_fract32 _a)
        {
           _composite_complex_fract32 _c;
           _CCFR32_CPLX(_c) = _a;
           return __builtin_imag_fr32(_CCFR32_RAW(_c));
        }

#ifdef __FIXED_POINT_ALLOWED

#pragma inline
#pragma always_inline
        static complex_fract32 ccompose_fx_fr32 (long _Fract _a_real,
                                                 long _Fract _a_imag)
        {
           _composite_complex_fract32 _c;
           _CCFR32_RAW(_c) = __builtin_compose_i64(*(fract32 *)&_a_real,
                                                   *(fract32 *)&_a_imag);
           return _CCFR32_CPLX(_c);
        }

#pragma inline
#pragma always_inline
        static long _Fract real_fx_fr32 (complex_fract32 _a)
        {
           _composite_complex_fract32 _c;
           _CCFR32_CPLX(_c) = _a;
           return __builtin_real_fx_fr32(_CCFR32_RAW(_c));
        }

#pragma inline
#pragma always_inline
        static long _Fract imag_fx_fr32 (complex_fract32 _a)
        {
           _composite_complex_fract32 _c;
           _CCFR32_CPLX(_c) = _a;
           return __builtin_imag_fx_fr32(_CCFR32_RAW(_c));
        }

#endif /* __FIXED_POINT_ALLOWED */

#endif /* !__NO_BUILTIN */

        /* Legacy interface */
#pragma linkage_name __cmlt_fr32
        complex_fract32 cmul_fr32 (complex_fract32 _a, complex_fract32 _b);

#ifdef __cplusplus
}       /* end extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* __COMPLEX_DEFINED  (include guard) */
