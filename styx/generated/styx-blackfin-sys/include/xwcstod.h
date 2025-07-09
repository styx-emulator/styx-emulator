/* xwcstod.h internal header */
#ifndef _WCSTOD
#define _WCSTOD

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_6:"ADI Header re-uses identifier")
#pragma diag(suppress:misra_rule_6_3:"ADI Header allows basic types")
#pragma diag(suppress:misra_rule_16_3:"ADI Header allows unnamed parameters in prototype")
#pragma diag(suppress:misra_rule_19_4:"ADI Header allows any substitution text for a macro")
#pragma diag(suppress:misra_rule_19_7:"ADI Header allows function macros")
#pragma diag(suppress:misra_rule_19_10:"ADI Header does not require parenthesis around macro parameters")
#endif /* _ADI_COMPILER && _MISRA_RULES */

  #if defined(__cplusplus) && !defined(_NO_CPP_INLINES) && \
      !defined(_ADI_LIBIO)
		/* INLINES, FOR C++ */
_C_LIB_DECL
#pragma always_inline
inline double wcstod(const wchar_t *_Restrict _Str,
	wchar_t **_Restrict _Endptr)
	{
#if defined (_ADI_COMPILER)
#  if defined(__DOUBLES_ARE_FLOATS__)
        return (_WStof(_Str, _Endptr, 0));
#  else  /* __DOUBLES_ARE_FLOATS__ */
        return (_WStold(_Str, _Endptr, 0));
#  endif  /* __DOUBLES_ARE_FLOATS__ */
#else  /* _ADI_COMPILER */
        return (_WStod(_Str, _Endptr, 0));
#endif  /* _ADI_COMPILER */
	}

#pragma always_inline
inline unsigned long wcstoul(const wchar_t *_Restrict _Str,
	wchar_t **_Restrict _Endptr, int _Base)
	{return (_WStoul(_Str, _Endptr, _Base));
	}
_END_C_LIB_DECL

  #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
		/* MACROS AND DECLARATIONS, FOR C */
_C_LIB_DECL
double wcstod(const wchar_t *, wchar_t **);
unsigned long wcstoul(const wchar_t *, wchar_t **, int);
_END_C_LIB_DECL

#if defined (_ADI_COMPILER)
#  if defined(__DOUBLES_ARE_FLOATS__)
   #define wcstod(str, endptr)	_WStof(str, endptr, 0)
#  else  /* __DOUBLES_ARE_FLOATS__ */
   #define wcstod(str, endptr)	_WStold(str, endptr, 0)
#  endif  /* __DOUBLES_ARE_FLOATS__ */
#else  /* _ADI_COMPILER */
   #define wcstod(str, endptr)	_WStod(str, endptr, 0)
#endif  /* _ADI_COMPILER */
   #define wcstoul(str, endptr, base)	_WStoul(str, endptr, base)
  #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _WCSTOD */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
