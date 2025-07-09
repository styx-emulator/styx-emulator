#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* i2x16_math.h */
#endif
/************************************************************************
 *
 * i2x16_math.h
 *
 * (c) Copyright 2000-2006 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Additional operations on packed 16-bit integers */

#ifndef _I2x16_MATH_H
#define _I2x16_MATH_H

#include <i2x16_typedef.h>
#include <i2x16_base.h>
#include <stdlib.h>
#include <math.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4:"ADI header has example code in comments")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_1:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_8_5:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_12_2:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#endif /* _MISRA_RULES */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Standard functions
 * abs({a,b})		=> { abs(a), abs(b) }
 * min({a,b},{c,d})	=> { min(a,c), min(b,d) }
 * max({a,b},{c,d})	=> { max(a,c), max(b,d) }
 */

#pragma inline
#pragma always_inline
static int2x16 abs_i2x16(int2x16 _x) {
	return compose_2x16((short)abs((int)high_of_i2x16(_x)), (short)abs((int)low_of_i2x16(_x)));
}
#pragma inline
#pragma always_inline
static int2x16 min_i2x16(int2x16 _x, int2x16 _y) {
	return compose_2x16((short)min((int)high_of_i2x16(_x), (int)high_of_i2x16(_y)),
                       (short)min((int)low_of_i2x16(_x), (int)low_of_i2x16(_y)));
}
#pragma inline
#pragma always_inline
static int2x16 max_i2x16(int2x16 _x, int2x16 _y) {
	return compose_2x16((short)max((int)high_of_i2x16(_x), (int)high_of_i2x16(_y)),
                       (short)max((int)low_of_i2x16(_x), (int)low_of_i2x16(_y)));
}

/*
 * Cross-wise multiplication
 * ll({a,b},{c,d})	=> a*c
 * lh({a,b},{c,d})	=> a*d
 * hl({a,b},{c,d})	=> b*c
 * hh({a,b},{c,d})	=> b*d
 */

#pragma inline
#pragma always_inline
static long int mult_ll_i2x16(int2x16 _x, int2x16 _y) {
	return (long int)low_of_i2x16(_x)*(long int)low_of_i2x16(_y);
}
#pragma inline
#pragma always_inline
static long int mult_hl_i2x16(int2x16 _x, int2x16 _y) {
	return (long int)high_of_i2x16(_x)*(long int)low_of_i2x16(_y);
}
#pragma inline
#pragma always_inline
static long int mult_lh_i2x16(int2x16 _x, int2x16 _y) {
	return (long int)low_of_i2x16(_x)*(long int)high_of_i2x16(_y);
}
#pragma inline
#pragma always_inline
static long int mult_hh_i2x16(int2x16 _x, int2x16 _y) {
	return (long int)high_of_i2x16(_x)*(long int)high_of_i2x16(_y);
}

#ifdef __cplusplus
  } /* extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _I2x16_MATH_H */
