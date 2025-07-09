/* wctype.h standard header */
#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * wctype.h
 *
 * (c) Copyright 2002-2009 Analog Devices, Inc.  All rights reserved.
 * (c) Copyright 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * $Revision: 3524 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* wctype.h */
#endif
#endif /* _ADI_COMPILER */

#ifndef _WCTYPE
#define _WCTYPE
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_16_3:"ADI header allows use of unnamed parameters in prototype")
#pragma diag(suppress:misra_rule_19_1:"ADI standard header includes files\
 after statements")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#endif /* _ADI_COMPILER && _MISRA_RULES */


_C_STD_BEGIN

		/* MACROS */
#define WEOF	((_CSTD wint_t)(-1))

		/* TYPE DEFINITIONS */
typedef _Sizet wctrans_t;

 #if !defined(__BORLANDC__)
typedef _Sizet wctype_t;

 #elif !defined(_WCTYPE_T_DEFINED)
  #define _WCTYPE_T_DEFINED
typedef _Wchart wctype_t;
 #endif /* !defined(__BORLANDC__) */

 #ifndef _WINTT
  #define _WINTT
typedef _Wintt wint_t;
 #endif /* _WINTT */

		/* ctype DECLARATIONS */
 #include <xwcc.h>

_C_LIB_DECL
wctrans_t wctrans(const char *);
wctype_t wctype(const char *);
_END_C_LIB_DECL

 #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
		/* INLINES, FOR C++ */
_C_LIB_DECL
#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline wint_t (towctrans)(wint_t _Wc, wctrans_t _Off)
	{	// translate by category
	return (_Towctrans(_Wc, _Off));
	}
_END_C_LIB_DECL

 #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
	/* DECLARATIONS AND MACRO OVERRIDES, FOR C */
_C_LIB_DECL
wint_t (towctrans)(wint_t, wctrans_t);
_END_C_LIB_DECL
 #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

_C_STD_END
#endif /* _WCTYPE */

#ifdef _STD_USING
using _CSTD wctrans_t; using _CSTD wctype_t; using _CSTD wint_t;

using _CSTD iswalnum; using _CSTD iswalpha; using _CSTD iswcntrl;
using _CSTD iswctype; using _CSTD iswdigit; using _CSTD iswgraph;
using _CSTD iswlower; using _CSTD iswprint; using _CSTD iswpunct;
using _CSTD iswspace; using _CSTD iswupper; using _CSTD iswxdigit;
using _CSTD towctrans; using _CSTD towlower; using _CSTD towupper;
using _CSTD wctrans; using _CSTD wctype;

 #if _HAS_C9X
using _CSTD iswblank;
 #endif /* _IS_C9X */

#endif /* _STD_USING */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
