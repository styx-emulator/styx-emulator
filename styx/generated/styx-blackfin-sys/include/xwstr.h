/* xwstr.h internal header */
#ifndef _WSTR
#define _WSTR

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_2:"ADI header allows C++ style comments")
#pragma diag(suppress:misra_rule_5_6:"ADI header re-uses identifier")
#pragma diag(suppress:misra_rule_5_7:"ADI header re-uses identifier")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_16_3:"ADI header allows unnamed parameters in prototypes")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows non-MISRA compliant text in macro definitions")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function-like macros")
#pragma diag(suppress:misra_rule_19_10:"ADI header allows macro parameters to be used without parentheses")
#endif /* _ADI_COMPILER && _MISRA_RULES */

  #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
		/* INLINES AND OVERLOADS, FOR C++ */
_C_LIB_DECL
const wchar_t *wcschr(const wchar_t *, wchar_t);
const wchar_t *wcspbrk(const wchar_t *, const wchar_t *);
const wchar_t *wcsrchr(const wchar_t *, wchar_t);
const wchar_t *wcsstr(const wchar_t *, const wchar_t *);
_END_C_LIB_DECL

#pragma always_inline
inline wchar_t *wcschr(wchar_t *_Str, wchar_t _Ch)
	{return ((wchar_t *)wcschr((const wchar_t *)_Str, _Ch));
	}

#pragma always_inline
inline wchar_t *wcspbrk(wchar_t *_Str1, const wchar_t *_Str2)
	{return ((wchar_t *)wcspbrk((const wchar_t *)_Str1, _Str2));
	}

#pragma always_inline
inline wchar_t *wcsrchr(wchar_t *_Str, wchar_t _Ch)
	{return ((wchar_t *)wcsrchr((const wchar_t *)_Str, _Ch));
	}

#pragma always_inline
inline wchar_t *wcsstr(wchar_t *_Str1, const wchar_t *_Str2)
	{return ((wchar_t *)wcsstr((const wchar_t *)_Str1, _Str2));
	}

_C_LIB_DECL
#if !defined(_ADI_LIBIO)
#pragma always_inline
inline wint_t btowc(int _By)
	{	// convert single byte to wide character
	return (_Btowc(_By));
	}

#pragma always_inline
inline int wctob(wint_t _Wc)
	{	// convert wide character to single byte
	return (_Wctob(_Wc));
	}
#endif  /* !defined(_ADI_LIBIO) */
 #if _HAS_C9X
#pragma always_inline
inline float wcstof(const wchar_t *_Restrict _Str,
	wchar_t **_Restrict _Endptr)
	{	// convert wide string to float
	return (_WStof(_Str, _Endptr, 0));
	}

#pragma always_inline
inline long double wcstold(const wchar_t *_Restrict _Str,
	wchar_t **_Restrict _Endptr)
	{	// convert wide string to double
	return (_WStold(_Str, _Endptr, 0));
	}
 #endif /* _IS_C9X */

_END_C_LIB_DECL

  #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
   #define _WConst_return

_C_LIB_DECL
wchar_t *wcschr(const wchar_t *, wchar_t);
wchar_t *wcspbrk(const wchar_t *, const wchar_t *);
wchar_t *wcsrchr(const wchar_t *, wchar_t);
wchar_t *wcsstr(const wchar_t *, const wchar_t *);
wint_t btowc(int);
int wctob(wint_t);

 #if _HAS_C9X
float wcstof(const wchar_t *_Restrict,
	wchar_t **_Restrict);
long double wcstold(const wchar_t *_Restrict,
	wchar_t **_Restrict);
 #endif /* _IS_C9X */

_END_C_LIB_DECL

   #define btowc(by)	_Btowc(by)
   #define wcstof(str, endptr)	_WStof(str, endptr, 0)
   #define wcstold(str, endptr)	_WStold(str, endptr, 0)
   #define wctob(wc)	_Wctob(wc)
  #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _WSTR */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
