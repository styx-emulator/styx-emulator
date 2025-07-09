/* stdint.h standard header */
#if defined (_ADI_COMPILER)
#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdint.h */
#endif
/************************************************************************
 *
 * stdint.h
 *
 * (c) Copyright 2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/
#endif /* _ADI_COMPILER */
#ifndef _STDINT
#define _STDINT
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_19_4:"Macros cannot be simplified")
#pragma diag(suppress:misra_rule_19_7:"Macros function-like")
#endif /* _ADI_COMPILER && _MISRA_RULES */

 #if _BITS_BYTE != 8 && _BITS_BYTE != 32
  #error <stdint.h> assumes 8 bits or 32 bits per byte
 #endif /* _BITS_BYTE != 8 */

/* NB: also assumes
	long is 32 bits
	pointer can convert to and from long long
	long long is longest type
 */

 #if __STDC_WANT_LIB_EXT1__
  #define RSIZE_MAX	_RSIZE_MAX
 #endif /* __STDC_WANT_LIB_EXT1__ */

_C_STD_BEGIN

		/* TYPE DEFINITIONS */
 #ifndef _SYS_INT_TYPES_H
  #define _STD_USING_INT_TYPES

  #if !defined(__BIT_TYPES_DEFINED__) && !defined(_MACHTYPES_H_) \
	&& !defined(__int8_t_defined)
   #define _STD_USING_BIT_TYPES
   #define __int8_t_defined

#if _BITS_BYTE == 8
typedef signed char int8_t;
typedef short int16_t;
#endif
typedef _Int32t int32_t;
  #endif /* !defined(__BIT_TYPES_DEFINED__) etc. */

#if !(defined(_ADI_COMPILER) && defined(_ADI_INT_TYPES_DEFINED))
#if _BITS_BYTE == 8
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
#endif
typedef _Uint32t uint32_t;
#endif

#if _BITS_BYTE == 8
typedef signed char int_least8_t;
typedef short int_least16_t;
typedef unsigned char uint_least8_t;
typedef unsigned short uint_least16_t;
#else
typedef _Int32t int_least8_t;
typedef _Int32t int_least16_t;
typedef _Uint32t uint_least8_t;
typedef _Uint32t uint_least16_t;
#endif /*_BITS_BYTE*/
typedef _Int32t int_least32_t;
typedef _Uint32t uint_least32_t;
 #endif /* _SYS_INT_TYPES_H */

#if defined (_ADI_COMPILER)
/* Removed _DNK_SunOS_5_10 and __SunOS_5_10 specific settings. */
#endif /* _ADI_COMPILER */
#if _BITS_BYTE == 8
typedef signed char int_fast8_t;
typedef short int_fast16_t;
typedef unsigned char uint_fast8_t;
typedef unsigned short uint_fast16_t;
#else
typedef _Int32t int_fast8_t;
typedef _Int32t int_fast16_t;
typedef _Uint32t uint_fast8_t;
typedef _Uint32t uint_fast16_t;
#endif  /* _BITS_BYTE == 8 */
typedef _Int32t int_fast32_t;
typedef _Uint32t uint_fast32_t;

 #ifndef _INTPTR
  #define _INTPTR	0	/* 0 => int, 1 => long, 2 => long long */
 #endif /* _INTPTR */

 #ifndef _SYS_INT_TYPES_H

  #if !defined(_MACHTYPES_H_)

   #if !defined(_UINTPTR_T_DEFINED)
    #define _UINTPTR_T_DEFINED
    #define _STD_USING_UINTPTR_T

    #if _INTPTR == 0
typedef unsigned int uintptr_t;

    #elif _INTPTR == 1
typedef unsigned long uintptr_t;

    #elif _INTPTR == 2
typedef _ULonglong uintptr_t;

    #else /* _INTPTR */
     #error bad _INTPTR value
    #endif /* _INTPTR */

   #endif /* _UNITPTR_T_DEFINED */

   #if !defined(__int_ptr_t_defined) && !defined(_INTPTR_T_DEFINED)
    #define _INTPTR_T_DEFINED
    #define _STD_USING_INTPTR_T

    #if _INTPTR == 0
typedef int intptr_t;

    #elif _INTPTR == 1
typedef long intptr_t;

    #elif _INTPTR == 2
typedef _Longlong intptr_t;

    #else /* _INTPTR */
     #error bad _INTPTR value
    #endif /* _INTPTR */

    #endif /* __int_ptr_t_defined etc. */

   #ifndef __BIT_TYPES_DEFINED__
#if !(defined(_ADI_COMPILER) && defined(_ADI_INT_TYPES_DEFINED))
typedef _Longlong int64_t;
#endif
   #endif /* __BIT_TYPES_DEFINED__ */

  #endif /* !defined(_MACHTYPES_H_) */
#if !(defined(_ADI_COMPILER) && defined(_ADI_INT_TYPES_DEFINED))
typedef _ULonglong uint64_t;
#endif

typedef _Longlong int_least64_t;
typedef _ULonglong uint_least64_t;
 #endif /* _SYS_INT_TYPES_H */

#if defined(_ADI_COMPILER)
/* Removed _DNK_SunOS_5_10 and __SunOS_5_10 specific settings. */
#endif /* _ADI_COMPILER */

typedef _Longlong int_fast64_t;
typedef _ULonglong uint_fast64_t;

 #if !defined(_SYS_INT_TYPES_H) && !defined(_INTMAXT)
  #define _INTMAXT
typedef _Longlong intmax_t;
typedef _ULonglong uintmax_t;
 #endif /* !defined(_SYS_INT_TYPES_H) etc. */

#if defined(_ADI_COMPILER) && !defined(_ADI_INT_TYPES_DEFINED)
#define _ADI_INT_TYPES_DEFINED 1
#endif
		/* LIMIT MACROS */
#if _BITS_BYTE == 8
#define INT8_MIN	(-0x7f - _C2)
#define INT16_MIN	(-0x7fff - _C2)
#endif /*_BITS_BYTE*/
#define INT32_MIN	(-0x7fffffff - _C2)

#if _BITS_BYTE == 8
#define INT8_MAX	0x7f
#define INT16_MAX	0x7fff
#endif /*_BITS_BYTE*/
#define INT32_MAX	0x7fffffff
#if _BITS_BYTE == 8
#define UINT8_MAX	0xff
#define UINT16_MAX	0xffff
#endif /*_BITS_BYTE*/
#define UINT32_MAX	0xffffffff

#if _BITS_BYTE == 8
#define INT_LEAST8_MIN		(-0x7f - _C2)
#define INT_LEAST16_MIN		(-0x7fff - _C2)
#else
#define INT_LEAST8_MIN          (-0x7fffffff - _C2)
#define INT_LEAST16_MIN         (-0x7fffffff - _C2)
#endif /*_BITS_BYTE*/
#define INT_LEAST32_MIN		(-0x7fffffff - _C2)

#if _BITS_BYTE == 8
#define INT_LEAST8_MAX		0x7f
#define INT_LEAST16_MAX		0x7fff
#else
#define INT_LEAST8_MAX		0x7fffffff
#define INT_LEAST16_MAX		0x7fffffff
#endif /*_BITS_BYTE*/
#define INT_LEAST32_MAX		0x7fffffff
#if _BITS_BYTE == 8
#define UINT_LEAST8_MAX		0xff
#define UINT_LEAST16_MAX	0xffff
#else
#define UINT_LEAST8_MAX		0xffffffff
#define UINT_LEAST16_MAX	0xffffffff
#endif /*_BITS_BYTE*/
#define UINT_LEAST32_MAX	0xffffffff

#if _BITS_BYTE == 8
#define INT_FAST8_MIN		(-0x7f - _C2)
#define INT_FAST16_MIN		(-0x7fff - _C2)
#else
#define INT_FAST8_MIN		(-0x7fffffff - _C2)
#define INT_FAST16_MIN		(-0x7fffffff - _C2)
#endif /*_BITS_BYTE*/
#define INT_FAST32_MIN		(-0x7fffffff - _C2)

#if _BITS_BYTE == 8
#define INT_FAST8_MAX		0x7f
#define INT_FAST16_MAX		0x7fff
#else
#define INT_FAST8_MAX		0x7fffffff
#define INT_FAST16_MAX		0x7fffffff
#endif /*_BITS_BYTE*/
#define INT_FAST32_MAX		0x7fffffff
#if _BITS_BYTE == 8
#define UINT_FAST8_MAX		0xff
#define UINT_FAST16_MAX		0xffff
#else
#define UINT_FAST8_MAX		0xffffffff
#define UINT_FAST16_MAX		0xffffffff
#endif /*_BITS_BYTE*/
#define UINT_FAST32_MAX		0xffffffff

 #if _INTPTR == 0 && !_ILONG
#define INTPTR_MAX			0x7fff
#define INTPTR_MIN			(-INTPTR_MAX - _C2)
#define UINTPTR_MAX			0xffff

 #elif _INTPTR == 1 || _INTPTR == 0 && _ILONG
#define INTPTR_MAX			0x7fffffff
#define INTPTR_MIN			(-INTPTR_MAX - _C2)
#define UINTPTR_MAX			0xffffffff

 #else /* _INTPTR == 2 */
#define INTPTR_MIN			(-_LLONG_MAX - _C2)
#define INTPTR_MAX			_LLONG_MAX
#define UINTPTR_MAX			_ULLONG_MAX
#endif /* _INTPTR */

#define INT8_C(x)	(x)
#define INT16_C(x)	(x)
#define INT32_C(x)	((x) + (INT32_MAX - INT32_MAX))

#define UINT8_C(x)	(x)
#define UINT16_C(x)	(x)
#define UINT32_C(x)	((x) + (UINT32_MAX - UINT32_MAX))

 #if _ILONG
  #define PTRDIFF_MIN		INT32_MIN
  #define PTRDIFF_MAX		INT32_MAX

  #define SIG_ATOMIC_MIN	INT32_MIN
  #define SIG_ATOMIC_MAX	INT32_MAX

  #define SIZE_MAX			UINT32_MAX

 #else /* _ILONG */
  #define PTRDIFF_MIN		INT16_MIN
  #define PTRDIFF_MAX		INT16_MAX

  #define SIG_ATOMIC_MIN	INT16_MIN
  #define SIG_ATOMIC_MAX	INT16_MAX

  #define SIZE_MAX			UINT16_MAX
 #endif /* _ILONG */

#define WCHAR_MIN	_WCMIN
#define WCHAR_MAX	_WCMAX

#define WINT_MIN	_WCMIN
#define WINT_MAX	_WCMAX

 #define INT64_MIN	(-0x7fffffffffffffffLL - _C2)
 #define INT64_MAX	0x7fffffffffffffffLL
 #define UINT64_MAX	0xffffffffffffffffULL

 #define INT_LEAST64_MIN	(-0x7fffffffffffffffLL - _C2)
 #define INT_LEAST64_MAX	0x7fffffffffffffffLL
 #define UINT_LEAST64_MAX	0xffffffffffffffffULL

 #define INT_FAST64_MIN		(-0x7fffffffffffffffLL - _C2)
 #define INT_FAST64_MAX		0x7fffffffffffffffLL
 #define UINT_FAST64_MAX	0xffffffffffffffffULL

 #define INTMAX_MIN		(-0x7fffffffffffffffLL - _C2)
 #define INTMAX_MAX		0x7fffffffffffffffLL
 #define UINTMAX_MAX	0xffffffffffffffffULL

#define INT64_C(x)		((x) + (INT64_MAX - INT64_MAX))
#define UINT64_C(x)		((x) + (UINT64_MAX - UINT64_MAX))
#define INTMAX_C(x)		INT64_C(x)
#define UINTMAX_C(x)	UINT64_C(x)
_C_STD_END

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
/* Also removed Apple specific setting here. */
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _STDINT */

 #if defined(_STD_USING)

  #ifdef _STD_USING_BIT_TYPES
using _CSTD int8_t; using _CSTD int16_t;
using _CSTD int32_t; using _CSTD int64_t;
  #endif /* _STD_USING_BIT_TYPES */

  #ifdef _STD_USING_INT_TYPES
#if _BITS_BYTE == 8
using _CSTD uint8_t; using _CSTD uint16_t;
#endif
using _CSTD uint32_t; using _CSTD uint64_t;

using _CSTD int_least8_t; using _CSTD int_least16_t;
using _CSTD int_least32_t;  using _CSTD int_least64_t;
using _CSTD uint_least8_t; using _CSTD uint_least16_t;
using _CSTD uint_least32_t; using _CSTD uint_least64_t;

using _CSTD intmax_t; using _CSTD uintmax_t;
  #endif /* _STD_USING_INT_TYPES */

  #ifdef _STD_USING_UINTPTR_T
using _CSTD uintptr_t;
  #endif /* _STD_USING_UINTPTR_T */

  #ifdef _STD_USING_INTPTR_T
using _CSTD intptr_t;
  #endif /* _STD_USING_INTPTR_T */

using _CSTD int_fast8_t; using _CSTD int_fast16_t;
using _CSTD int_fast32_t; using _CSTD int_fast64_t;
using _CSTD uint_fast8_t; using _CSTD uint_fast16_t;
using _CSTD uint_fast32_t; using _CSTD uint_fast64_t;
 #endif /* defined(_STD_USING) */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
