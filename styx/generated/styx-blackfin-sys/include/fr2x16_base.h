#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fr2x16_base.h */
#endif

/************************************************************************
 *
 * fr2x16_base.h
 *
 * (c) Copyright 2000-2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Basic operations on packed fractional types, including composition and
 * extraction
 */

#ifndef _FR2x16_BASE_H
#define _FR2x16_BASE_H

#include <fr2x16_typedef.h>
#include <fract_typedef.h>
#include <r2x16_base.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_5_6)
#pragma diag(suppress:misra_rule_5_7)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_16_1)
#pragma diag(suppress:misra_rule_19_6)
#endif /* _MISRA_RULES */

#ifdef __cplusplus
extern "C" {
#endif

#define __SPECIFIC_NAMES
#define __ENABLE_SUM_FR2X16
#include <builtins.h>
#undef __SPECIFIC_NAMES

/*
 * Composition and extraction
 */

/* Takes two fract16 values, and returns a fract2x16 value.
 * Input: two fract16 values
 * Returns: {_x,_y} */
#pragma inline
#pragma always_inline
static fract2x16 compose_fr2x16(fract16 _x, fract16 _y) {
	return compose_2x16(_x,_y);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static fract2x16 compose_fx_fr2x16(_Fract _x, _Fract _y) {
  return compose_2x16(*(fract16 *)&_x,*(fract16 *)&_y);
}
#endif

/* Takes a fract2x16 and returns the 'high half' fract16.
 * Input: _x{a,b}
 * Returns: a.
 */

#pragma inline
#pragma always_inline
static fract16 high_of_fr2x16(fract2x16 _x) {
  return high_of_2x16(_x);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract high_of_fx_fr2x16(fract2x16 _x) {
  fract16 result = high_of_2x16(_x);
  return *(_Fract *)&result;
}
#endif

/* Takes a fract2x16 and returns the 'low half' fract16
 * Input: _x{a,b}
 * Returns: b
 */

#pragma inline
#pragma always_inline
static fract16 low_of_fr2x16(fract2x16 _x) {
  return low_of_2x16(_x);
}
#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
static _Fract low_of_fx_fr2x16(fract2x16 _x) {
  fract16 result = low_of_2x16(_x);
  return *(_Fract *)&result;
}
#endif

#ifdef __cplusplus
 }
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FR2x16_BASE_H */
