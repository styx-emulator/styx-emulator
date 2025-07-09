/************************************************************************
 *
 * fract2float_conv.h
 *
 * (c) Copyright 2000-2009 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fract2float_conv.h */
#endif

#ifndef _FRACT2FLOAT_CONV_H
#define _FRACT2FLOAT_CONV_H

/* Conversions between fract16 or fract32 and float and long double */

#include <fract_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_5)
#endif /* _MISRA_RULES */

#ifdef __cplusplus
extern "C" {
#endif

    static fract32 fr16_to_fr32(fract16 _x);
#pragma inline
#pragma always_inline
    static fract32 fr16_to_fr32(fract16 _x) {
       /* convert a fract16 to a fract32 */
       unsigned int val = ((unsigned int)(_x)) << 16;
       return (fract32)val;
    }

    static fract16 fr32_to_fr16(fract32 _x);
#pragma inline
#pragma always_inline
    static fract16 fr32_to_fr16(fract32 _x) {
       /* Convert a fract32 to a fract16 */
       unsigned int val = (unsigned int)_x >> 16;
       return (fract16)val;
    }

#pragma inline
#pragma always_inline
    fract32 float_to_fr32 (float _x) {
       /* convert a float to a fract32 */
       return __builtin_float_to_fr32(_x);
    }
#pragma inline
#pragma always_inline
    fract16 float_to_fr16 (float _x) {
       /* convert a float to a fract16 */
       return __builtin_float_to_fr16(_x);
    }

#pragma linkage_name ___fr32_to_float
    float   fr32_to_float (fract32 _x);
#pragma linkage_name ___fr16_to_float
    float   fr16_to_float (fract16 _x);

#pragma linkage_name ___long_double_to_fr32
    fract32 long_double_to_fr32 (long double _x);

    fract16 long_double_to_fr16 (long double _x);
#pragma inline
#pragma always_inline
    fract16 long_double_to_fr16 (long double _x) {
       /* convert a long double to a fract16 */
       return fr32_to_fr16 (long_double_to_fr32(_x));
    }

#pragma linkage_name ___fr32_to_long_double
    long double fr32_to_long_double (fract32 _x);

    long double fr16_to_long_double (fract16 _x);
#pragma inline
#pragma always_inline
    long double fr16_to_long_double (fract16 _x) {
       /* convert a fract16 to a long double */
       return fr32_to_long_double (fr16_to_fr32(_x));
    }

#ifdef __FIXED_POINT_ALLOWED

/* Embedded C supports casts between these types. It is better to use these
** casts than to use the functions declared below. They are provided for
** completeness only.
*/

/* Convert between _Fract and long _Fract */

    static long _Fract fx16_to_fx32(_Fract _x);
#pragma inline
#pragma always_inline
    static long _Fract fx16_to_fx32(_Fract _x) {
       /* convert a _Fract to a long _Fract */
       return (long _Fract)_x;
    }

    static _Fract fx32_to_fx16(long _Fract _x);
#pragma inline
#pragma always_inline
    static _Fract fx32_to_fx16(long _Fract _x) {
       /* Convert a long _Fract to a _Fract */
#pragma FX_ROUNDING_MODE TRUNCATION
       return (_Fract)_x;
    }

/* Convert between float and _Fract/long _Fract */

#pragma linkage_name ___float_to_fr32
    long _Fract float_to_fx32 (float _x);
#pragma linkage_name ___float_to_fr16
    _Fract float_to_fx16 (float _x);

#pragma linkage_name ___fr32_to_float
    float   fx32_to_float (long _Fract _x);

    static float fx16_to_float (_Fract _x);
#pragma inline
#pragma always_inline
    static float fx16_to_float (_Fract _x) {
       /* Convert a long _Fract to a float */
       return fr16_to_float(*(fract16 *)&_x);
    }

/* Convert between long double and _Fract/long _Fract */

#pragma linkage_name ___long_double_to_fr32
    long _Fract long_double_to_fx32 (long double _x);

    _Fract long_double_to_fx16 (long double _x);
#pragma inline
#pragma always_inline
    _Fract long_double_to_fx16 (long double _x) {
       /* convert a long double to a _Fract */
       return fx32_to_fx16 (long_double_to_fx32(_x));
    }

#pragma linkage_name ___fr32_to_long_double
    long double fx32_to_long_double (long _Fract _x);

    long double fx16_to_long_double (_Fract _x);
#pragma inline
#pragma always_inline
    long double fx16_to_long_double (_Fract _x) {
       /* convert a _Fract to a long double */
       return fx32_to_long_double (fx16_to_fx32(_x));
    }

#endif

#ifdef __cplusplus
}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FRACT2FLOAT_CONV_H */
