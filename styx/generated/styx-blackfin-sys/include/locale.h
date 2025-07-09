/* locale.h standard header */
#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * locale.h: $Revision: 3522 $
 *
 * (c) Copyright 2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* locale.h */
#endif
#endif /* _ADI_COMPILER */

#ifndef _LOCALE
#define _LOCALE
 #ifndef _YVALS
  #include <yvals.h>
 #endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_8:"Declaration _Locale in xmtloc.h")
#pragma diag(suppress:misra_rule_16_3:"ADI header, identifiers not needed on all parameters")
#pragma diag(suppress:misra_rule_18_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_20_1)
#endif /* _ADI_COMPILER && _MISRA_RULES */


_C_STD_BEGIN

		/* MACROS */
#ifndef NULL
 #define NULL	_NULL
#endif /* NULL */

		/* LOCALE CATEGORY INDEXES */
#define _LC_COLLATE		1
#define _LC_CTYPE		2
#define _LC_MONETARY	3
#define _LC_NUMERIC		4
#define _LC_TIME		5
#define _LC_MESSAGES	6
	/* ADD YOURS HERE, THEN UPDATE _NCAT */
#define _NCAT			7	/* one more than last index */

		/* LOCALE CATEGORY MASKS */
#define _CATMASK(n)	((1 << (n)) >> 1)
#define _M_COLLATE	_CATMASK(_LC_COLLATE)
#define _M_CTYPE	_CATMASK(_LC_CTYPE)
#define _M_MONETARY	_CATMASK(_LC_MONETARY)
#define _M_NUMERIC	_CATMASK(_LC_NUMERIC)
#define _M_TIME		_CATMASK(_LC_TIME)
#define _M_MESSAGES	_CATMASK(_LC_MESSAGES)
#define _M_ALL		(_CATMASK(_NCAT) - 1)

		/* LOCALE CATEGORY HANDLES */
#define LC_COLLATE	_CATMASK(_LC_COLLATE)
#define LC_CTYPE	_CATMASK(_LC_CTYPE)
#define LC_MONETARY	_CATMASK(_LC_MONETARY)
#define LC_NUMERIC	_CATMASK(_LC_NUMERIC)
#define LC_TIME		_CATMASK(_LC_TIME)
#define LC_MESSAGE	_CATMASK(_LC_MESSAGES)	/* retained */
#define LC_MESSAGES	_CATMASK(_LC_MESSAGES)
#define LC_ALL		(_CATMASK(_NCAT) - 1)

#if defined (_ADI_COMPILER)
/* Removed thread-local locale support as we only support the "C" locale. */
#endif /* _ADI_COMPILER */

		/* TYPE DEFINITIONS */
struct lconv
	{	/* locale-specific information */
		/* controlled by LC_MONETARY */
	char *currency_symbol;
	char *int_curr_symbol;
	char *mon_decimal_point;
	char *mon_grouping;
	char *mon_thousands_sep;
	char *negative_sign;
	char *positive_sign;

	char frac_digits;
	char n_cs_precedes;
	char n_sep_by_space;
	char n_sign_posn;
	char p_cs_precedes;
	char p_sep_by_space;
	char p_sign_posn;

	char int_frac_digits;
/* vv added with C99 vv */
	char int_n_cs_precedes;
	char int_n_sep_by_space;
	char int_n_sign_posn;
	char int_p_cs_precedes;
	char int_p_sep_by_space;
	char int_p_sign_posn;
/* ^^ added with C99 ^^ */

		/* controlled by LC_NUMERIC */
	char *decimal_point;
	char *grouping;
	char *thousands_sep;
	char *_Frac_grouping;
	char *_Frac_sep;
	char *_False;
	char *_True;

		/* controlled by LC_MESSAGES */
	char *_No;
	char *_Yes;
	};

struct _Linfo;

		/* DECLARATIONS */
_C_LIB_DECL
#pragma misra_func(io)
struct lconv *localeconv(void);
#pragma misra_func(io)
char *setlocale(int, const char *);
#if defined (_ADI_COMPILER)
 extern const struct lconv _Locale;
#endif
_END_C_LIB_DECL

#if defined (_ADI_COMPILER)
#  ifdef __cplusplus
              /* INLINES, FOR C++ */
#pragma always_inline
inline struct lconv *localeconv(void)
      {       /* return pointer to current locale */
      return (const_cast<struct lconv *>(&_Locale)); }
#  else /* __cplusplus */
              /* MACRO OVERRIDES, FOR C */
   #define localeconv()       ((struct lconv *)&_Locale)
#  endif /* __cplusplus */
#endif  /* _ADI_COMPILER */
_C_STD_END

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _LOCALE */

#ifdef _STD_USING
using _CSTD lconv; using _CSTD localeconv; using _CSTD setlocale;
#endif /* _STD_USING */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
