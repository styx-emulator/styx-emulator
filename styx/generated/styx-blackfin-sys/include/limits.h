/************************************************************************
 *
 * limits.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

/* limits.h standard header -- 8-bit version */
#ifndef _LIMITS
#define _LIMITS
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4:"macro definition violates rule")
#endif /* _ADI_COMPILER && _MISRA_RULES */

#if (_BITS_BYTE != 8) &&  (defined(_ADI_COMPILER) && !defined(__ADSP21000__))
  #error <limits.h> assumes 8 bits per byte
#endif

 #if defined(_LIMITS_H___)
  #undef MB_LEN_MAX
  #define MB_LEN_MAX	_MBMAX

 #else /* defined(_LIMITS_H___) */
  #define _LIMITS_H___
		/* CHAR PROPERTIES */
  #define CHAR_BIT	_BITS_BYTE

  #if _CSIGN
   #define CHAR_MAX	SCHAR_MAX
   #define CHAR_MIN	SCHAR_MIN

  #else /* _CSIGN */
   #define CHAR_MAX	0xFF
   #define CHAR_MIN	0
  #endif /* _CSIGN */

		/* INT PROPERTIES */

  #ifdef _ILONG
   #define INT_MAX		LONG_MAX
   #define INT_MIN		LONG_MIN
   #define UINT_MAX	ULONG_MAX

  #else /* _ILONG */
   #define INT_MAX		SHRT_MAX
   #define INT_MIN		SHRT_MIN
   #define UINT_MAX	USHRT_MAX
  #endif /* _ILONG */

		/* MULTIBYTE PROPERTIES */
  #define MB_LEN_MAX	_MBMAX

		/* SIGNED CHAR PROPERTIES */
  #define SCHAR_MAX	0x7f
  #define SCHAR_MIN	(-SCHAR_MAX - _C2)

		/* SHORT PROPERTIES */
  #define SHRT_MAX	0x7fff
  #define SHRT_MIN	(-SHRT_MAX - _C2)

		/* LONG PROPERTIES */
  #define LONG_MAX	0x7fffffff
  #define LONG_MIN	(-LONG_MAX - _C2)

		/* UNSIGNED PROPERTIES */
#ifdef _MISRA_RULES
  #define UCHAR_MAX	0xffu
  #define USHRT_MAX	0xffffu
#else
  #define UCHAR_MAX	0xff
  #define USHRT_MAX	0xffff
#endif /* _MISRA_RULES */
  #define ULONG_MAX	0xffffffffU


 #endif /* defined(_LIMITS_H___) */

#if !defined(_NO_LONGLONG) || _HAS_C9X
# define LLONG_MAX	_LLONG_MAX
# define LLONG_MIN	(-_LLONG_MAX - _C2)
# define ULLONG_MAX	_ULLONG_MAX
#endif /* _IS_C9X */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _LIMITS */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
