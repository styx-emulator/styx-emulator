/* ctype.h standard header */

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* ctype.h */
#endif
/************************************************************************
 *
 * ctype.h : $Revision: 14738 $
 *
 * (c) Copyright 2001-2013 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#ifndef _CTYPE
#define _CTYPE
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"Basic types required by standard.")
#pragma diag(suppress:misra_rule_19_7:"Allow function-like macros.")
#pragma diag(suppress:misra_rule_20_2:"Allow standard library names.")
#endif /* _MISRA_RULES */

#ifdef __cplusplus
  extern "C" {
#endif
#ifdef __ANALOG_EXTENSIONS__
  int isascii(int c);
  int toascii(int c);

  #define isascii(c) (!((c)&(~0x7f)))
  #define toascii(c) ((c)&0x7f)
#endif
#ifdef __cplusplus
  }
#endif

_C_STD_BEGIN

		/* _Ctype code bits */
#define _XB		0x400 /* extra blank */
#define _XA		0x200 /* extra alphabetic */
#define _XS		0x100 /* extra space */
#define _BB		0x80 /* BEL, BS, etc. */
#define _CN		0x40 /* CR, FF, HT, NL, VT */
#define _DI		0x20 /* '0'-'9' */
#define _LO		0x10 /* 'a'-'z' */
#define _PU		0x08 /* punctuation */
#define _SP		0x04 /* space */
#define _UP		0x02 /* 'A'-'Z' */
#define _XD		0x01 /* '0'-'9', 'A'-'F', 'a'-'f' */

_C_LIB_DECL

typedef const short *_Ctype_t;

#if defined(_ADI_COMPILER)
/* No locales support, hence const tables and direct access */
extern const short _Ctype1[257];
extern const short _Tolotab1[257];
extern const short _Touptab1[257];

/* Offset 1 accounts for EOF entry at index 0 */
#define _Getpctype()	(_Ctype1 + 1)
#define _Getptolower()	(_Tolotab1 + 1)
#define _Getptoupper()	(_Touptab1 + 1)

#define _Getchrtype(x)	(_Getpctype()[(unsigned char)(x)])
#define _CTolower(x)    ((((int)(x)>=0)&&((int)(x)<=255))?(_Getptolower()[(int)(x)]):(x))
#define _CToupper(x)    ((((int)(x)>=0)&&((int)(x)<=255))?(_Getptoupper()[(int)(x)]):(x))

#else /* _ADI_COMPILER */
_Ctype_t _Getpctype(void);
_Ctype_t _Getptolower(void);
_Ctype_t _Getptoupper(void);

 #if !_MULTI_THREAD || _COMPILER_TLS && !_GLOBAL_LOCALE
extern _Ctype_t _TLS_QUAL _Ctype;
extern _Ctype_t _TLS_QUAL _Tolotab;
extern _Ctype_t _TLS_QUAL _Touptab;

  #define _Getpctype()		_Ctype
  #define _Getptolower()	_Tolotab
  #define _Getptoupper()	_Touptab
 #endif /* !_MULTI_THREAD || _COMPILER_TLS && !_GLOBAL_LOCALE */

#define _Getchrtype(x)	(_Getpctype()[(int)(x)])
#define _CTolower(x)	(_Getptolower()[(int)(x)])
#define _CToupper(x)	(_Getptoupper()[(int)(x)])

#endif /* _ADI_COMPILER */

_END_C_LIB_DECL

 #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
		// INLINES, for C++
_C_LIB_DECL

#pragma always_inline
inline int isalnum(int _Ch)
	{	// check alnum bits
	return (_Getchrtype(_Ch) & (_DI|_LO|_UP|_XA));
	}

#pragma always_inline
inline int isalpha(int _Ch)
	{	// check alpha bits
	return (_Getchrtype(_Ch) & (_LO|_UP|_XA));
	}

#pragma always_inline
inline int iscntrl(int _Ch)
	{	// check cntrl bits
	return (_Getchrtype(_Ch) & _BB);
	}

#pragma always_inline
inline int isdigit(int _Ch)
	{	// check digit bits
	return (_Getchrtype(_Ch) & _DI);
	}

#pragma always_inline
inline int isgraph(int _Ch)
	{	// check graph bits
	return (_Getchrtype(_Ch) & (_DI|_LO|_PU|_UP|_XA));
	}

#pragma always_inline
inline int islower(int _Ch)
	{	// check alnum bits
	return (_Getchrtype(_Ch) & _LO);
	}

#pragma always_inline
inline int isprint(int _Ch)
	{	// check print bits
	return (_Getchrtype(_Ch) & (_DI|_LO|_PU|_SP|_UP|_XA));
	}

#pragma always_inline
inline int ispunct(int _Ch)
	{	// check punct bits
	return (_Getchrtype(_Ch) & _PU);
	}

#if !defined(_ADI_COMPILER)
#pragma always_inline
inline int _Isspace(int _Ch)
	{	// check space bits
	return (_Getchrtype(_Ch) & (_CN|_SP|_XS));
	}
#endif /* _ADI_COMPILER */

#pragma always_inline
inline int isspace(int _Ch)
	{	// check space bits
	return (_Getchrtype(_Ch) & (_CN|_SP|_XS));
	}

#pragma always_inline
inline int isupper(int _Ch)
	{	// check upper bits
	return (_Getchrtype(_Ch) & _UP);
	}

#pragma always_inline
inline int isxdigit(int _Ch)
	{	// check xdigit bits
	return (_Getchrtype(_Ch) & _XD);
	}

 #if _HAS_C9X
#pragma always_inline
inline int isblank(int _Ch)
	{	// check blank bits
	return (_Getchrtype(_Ch) & (_SP|_XB));
	}
 #endif /* _IS_C9X */

#pragma always_inline
inline int tolower(int _Ch)
	{	// convert to lower case
	return (_CTolower(_Ch));
	}

#pragma always_inline
inline int toupper(int _Ch)
	{	// convert to upper case
	return (_CToupper(_Ch));
	}
_END_C_LIB_DECL

 #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
		/* declarations and macro overrides, for C */
_C_LIB_DECL
int isalnum(int c);
int isalpha(int c);
int iscntrl(int c);
int isdigit(int c);
int isgraph(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int isspace(int c);
int isupper(int c);
int isxdigit(int c);
int tolower(int c);
int toupper(int c);

 #if _HAS_C9X
int isblank(int c);
 #endif /* _IS_C9X */

_END_C_LIB_DECL

 #ifndef _MISRA_RULES
  /* Use library versions of these functions if MISRA support is enabled,
   * because the macro versions can not be made fully MISRA-compliant.
   */

  #define isalnum(c)		(_Getchrtype(c) & (_DI|_LO|_UP|_XA))

  #ifdef isalpha
   #define _dnk_isalpha(c)	(_Getchrtype(c) & (_LO|_UP|_XA))

  #else /* _dnk_isalpha */
   #define isalpha(c)		(_Getchrtype(c) & (_LO|_UP|_XA))
  #endif /* _dnk_isalpha */

  #define iscntrl(c)		(_Getchrtype(c) & _BB)
  #define isdigit(c)		(_Getchrtype(c) & _DI)
  #define isgraph(c)		(_Getchrtype(c) & (_DI|_LO|_PU|_UP|_XA))

  #ifdef islower
   #define _dnk_islower(c)	(_Getchrtype(c) & _LO)

  #else /* _dnk_islower */
   #define islower(c)		(_Getchrtype(c) & _LO)
  #endif /* _dnk_islower */

  #define isprint(c)		(_Getchrtype(c) & (_DI|_LO|_PU|_SP|_UP|_XA))
  #define ispunct(c)		(_Getchrtype(c) & _PU)
  #define isspace(c)		(_Getchrtype(c) & (_CN|_SP|_XS))
  #define isupper(c)		(_Getchrtype(c) & _UP)
  #define isxdigit(c	)	(_Getchrtype(c) & _XD)

 #if _HAS_C9X
  #define isblank(c)		(_Getchrtype(c) & (_SP|_XB))
 #endif /* _IS_C9X */

 #ifndef _DNK_RENAME

#if !defined(__DEFINE_TOLOWER_FUNC)
#pragma always_inline
__inline int tolower(int _Ch)
	{	// convert to lower case
	return (_CTolower(_Ch));
	}
#endif

#if !defined(__DEFINE_TOUPPER_FUNC)
#pragma always_inline
__inline int toupper(int _Ch)
	{	// convert to upper case
	return (_CToupper(_Ch));
	}
#endif

 #endif /* _DNK_RENAME */
 #endif /* _MISRA_RULES */

 #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */
#endif /* _CTYPE */

#ifdef _STD_USING
using _CSTD isalnum; using _CSTD isalpha; using _CSTD iscntrl;
using _CSTD isdigit; using _CSTD isgraph; using _CSTD islower;
using _CSTD isprint; using _CSTD ispunct; using _CSTD isspace;
using _CSTD isupper; using _CSTD isxdigit; using _CSTD tolower;
using _CSTD toupper; using _CSTD _Isspace;

 #if _HAS_C9X
using _CSTD isblank;
 #endif /* _IS_C9X */

#endif /* _STD_USING */


/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
