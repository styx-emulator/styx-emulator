#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* int_math.h */
#endif
/************************************************************************
 *
 * int_math.h
 *
 * (c) Copyright 2000-2006 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Defines builtin functions for the int type.  */

#ifndef _INT_MATH_H
#define _INT_MATH_H

#ifdef __ADSPBLACKFIN__

#include <ccblkfn.h>


#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#endif /* _MISRA_RULES */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Abs/Min/Max _short all use the same underlying ops as
 * the _fr1x16 intrinsics, but the builtin name comes from the
 * fract version
 */
#pragma inline
#pragma always_inline
static short abs_short(short _x) {
	return (short)__builtin_abs_fr2x16((int)_x);
}
#pragma inline
#pragma always_inline
static short min_short(short _x, short _y) {
	return (short)__builtin_min_fr2x16((int)_x, (int)_y);
}
#pragma inline
#pragma always_inline
static short max_short(short _x, short _y) {
	return (short)__builtin_max_fr2x16((int)_x, (int)_y);
}

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#else

#pragma inline
#pragma always_inline
static short abs_short(short _x) {
	return abs(_x);
}
#pragma inline
#pragma always_inline
static short min_short(short _x, short _y) {
	return _x > _y ? _y : _x;
}
#pragma inline
#pragma always_inline
static short max_short(short _x, short _y) {
	return _x > _y ? _x : _y;
}


#endif /* __ADSPBLACKFIN__ */

#ifdef __cplusplus
  }    /*   extern "C"     */
#endif


#endif /* __INT_MATH_H */
