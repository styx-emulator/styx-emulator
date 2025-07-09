/* stddef.h standard header */
#if defined (_ADI_COMPILER)
#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stddef.h */
#endif/* stddef.h standard header */
#endif /* _ADI_COMPILER */

#ifndef _STDDEF
#define _STDDEF
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#pragma diag(suppress:misra_rule_19_10)
#pragma diag(suppress:misra_rule_19_11)
#pragma diag(suppress:misra_rule_20_1)
#endif /* _ADI_COMPILER && _MISRA_RULES */

_C_STD_BEGIN

		/* macros */
#ifndef NULL
 #define NULL	_NULL
#endif /* NULL */

#ifndef offsetof

 #if __EDG__
  #define offsetof(T, member) ((_Sizet)__INTADDR__(&(((T *)0)->member)))

 #elif defined(__cplusplus) && ((__GNUC__ == 3) && (3 < __GNUC_MINOR__))
  #define offsetof(T, member) \
	(__offsetof__ (reinterpret_cast<_CSTD size_t> \
	(&reinterpret_cast<char &> \
	(static_cast<T *>(0)->member))))

 #else /* __EDG__ */
  #define offsetof(T, member)	((_CSTD size_t)&(((T *)0)->member))
 #endif /* __EDG__ */

#endif /* offsetof */

		/* type definitions */

 #if !defined(_PTRDIFF_T) && !defined(_PTRDIFFT) \
	&& !defined(_PTRDIFF_T_DEFINED)
  #define _PTRDIFF_T
  #define _PTRDIFFT
  #define _PTRDIFF_T_DEFINED
  #define _STD_USING_PTRDIFF_T
typedef _Ptrdifft ptrdiff_t;
 #endif /* !defined(_PTRDIFF_T) etc. */

 #if !defined(_SIZE_T) && !defined(_SIZET) && !defined(_SIZE_T_DEFINED) \
	&& !defined(_BSD_SIZE_T_DEFINED_)
  #define _SIZE_T
  #define _SIZET
  #define _BSD_SIZE_T_DEFINED_
  #define _SIZE_T_DEFINED
  #define _STD_USING_SIZE_T
typedef _Sizet size_t;
 #endif /* !defined(_SIZE_T) etc. */

 #if !defined(_WCHART) && !defined(_WCHAR_T_DEFINED)
  #define _WCHART
  #define _WCHAR_T_DEFINED
typedef _Wchart wchar_t;
 #endif /* _WCHART etc. */

 #if __STDC_WANT_LIB_EXT1__

  #if !defined(_RSIZE_T_DEFINED)
   #define _RSIZE_T_DEFINED
typedef size_t rsize_t;
  #endif /* _RSIZE_T_DEFINED */

 #endif /* __STDC_WANT_LIB_EXT1__ */
_C_STD_END
#endif /* _STDDEF */

 #if defined(_STD_USING)

  #ifdef _STD_USING_PTRDIFF_T
using _CSTD ptrdiff_t;
  #endif /* _STD_USING_PTRDIFF_T */

  #ifdef _STD_USING_SIZE_T
using _CSTD size_t;
  #endif /* _STD_USING_SIZE_T */

 #if __STDC_WANT_LIB_EXT1__
using _CSTD rsize_t;
 #endif /* __STDC_WANT_LIB_EXT1__ */

 #endif /* defined(_STD_USING) */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
