/************************************************************************
 *
 * stdlib.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdlib.h */
#endif

/* stdlib.h standard header */
#ifndef _STDLIB
#define _STDLIB

#ifndef _YVALS
 #include <yvals.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_8_8:"_Exit defined in yfuns.h")
#pragma diag(suppress:misra_rule_8_10)
#pragma diag(suppress:misra_rule_16_4)
#pragma diag(suppress:misra_rule_19_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_20_1)
#pragma diag(suppress:misra_rule_20_2)
#endif /* _MISRA_RULES */

_C_STD_BEGIN

		/* MACROS */
#ifndef NULL
 #define NULL	_NULL
#endif

#define EXIT_FAILURE	_EXFAIL
#define EXIT_SUCCESS	0

#define MB_CUR_MAX	6

 #ifdef _ILONG
  #define RAND_MAX	0x3fffffff
 #else
  #define RAND_MAX	0x7fff
 #endif

		/* TYPE DEFINITIONS */
 #if !defined(_SIZE_T) && !defined(_SIZET)
  #define _SIZE_T
  #define _SIZET
typedef _Sizet size_t;
 #endif

#ifndef _WCHART
 #define _WCHART
typedef _Wchart wchar_t;
#endif

#if !defined( __NO_ANSI_EXTENSIONS__ )
#if defined(__ADSPBLACKFIN__)

/* Need to include header after size_t is defined */
#include <stdlib_bf.h>

#endif  /* __ADSPBLACKFIN__ */
#endif  /* __NO_ANSI_EXTENSIONS__ */

/*
 * Arithmetic builtins ... these macros redefine the primary function
 * names, both here (for the prototype declarations) and in the
 * user programs (where the functions are called)
 */

#ifndef __NO_BUILTIN
#if  defined(__ADSP21XX__) || defined(__ADSPBLACKFIN__)
#define abs __builtin_abs
#define labs __builtin_labs
#endif
#endif /* __NO_BUILTIN */

typedef struct
	{	/* result of int divide */
	int quot;
	int rem;
	} div_t;

typedef struct
	{	/* result of long divide */
	long quot;
	long rem;
	} ldiv_t;

typedef struct
        {       /* result of long long divide */
        _Longlong quot;
        _Longlong rem;
} _Lldiv_t;

typedef _Lldiv_t lldiv_t;

		/* DECLARATIONS */
_EXTERN_C /* low-level functions */
#ifdef  __ADSPBLACKFIN__
#pragma noreturn
void _Exit(void);
#else
#pragma noreturn
void _Exit(int);	/* added with C99 */
#endif
#pragma noreturn
#pragma misra_func(system)
void exit(int _status);
#pragma noreturn
#pragma misra_func(system)
void adi_fatal_error(int general_code, int specific_code, int value);
#pragma noreturn
#pragma misra_func(system)
void adi_fatal_exception(int general_code, int specific_code, int value);
#pragma misra_func(system)
char * getenv(const char *_name);
#pragma misra_func(system)
int system(const char *_s);
_END_EXTERN_C

_C_LIB_DECL
#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#pragma noreturn
void __builtin_abort(void);
#if !defined(sys_abort)
#define sys_abort() _Exit()
#endif
#endif
#pragma noreturn
#pragma misra_func(system)
void abort(void);
int abs(int _i);
#pragma misra_func(heap)
void * calloc(size_t _nelem, size_t _size);
div_t div(int _numer, int _denom);
#pragma misra_func(heap)
void free(void *_ptr);
long labs(long _i);
ldiv_t ldiv(long _numer, long _denom);
#pragma misra_func(heap)
void * malloc(size_t _size_arg);
int mblen(const char *_s, size_t _n);
size_t mbstowcs(wchar_t *_wcs, const char *_s, size_t _n);
int mbtowc(wchar_t *_pwc, const char *_s, size_t _n);
int rand(void);
void srand(unsigned int _seed);
#pragma misra_func(heap)
void * realloc(void *_ptr, size_t _size_arg);
long strtol(const char *_s, char **_endptr, int _base);
size_t wcstombs(char *_s, const wchar_t *_wcs, size_t _n);
int wctomb(char *_s, wchar_t _wchar);

 #ifdef _SOLARIS_C_LIB
int getopt(int, char * const *, const char *);
char *mktemp(char *);
int putenv(char *);
int rand_r(unsigned *);
char *tempnam(const char *, const char *);

extern char *optarg;
extern int optind, opterr, optopt;
 #endif /* _SOLARIS_C_LIB */

unsigned long _Stoul(const char *_s, char **_endptr, int _base);
float _Stof(const char *_s, char **_endptr, long _pten);

#if defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __Stof
#else
#pragma linkage_name __Stold
#endif
double _Stod(const char *_s, char **_endptr, long _pten);

long double _Stold(const char *_s, char **_endptr, long _pten);
_Longlong _Stoll(const char *_s, char **_endptr, int _base);
_ULonglong _Stoull(const char *_s, char **_endptr, int _base);

_Longlong llabs(_Longlong _i);
lldiv_t lldiv(_Longlong _numer, _Longlong _denom);

_END_C_LIB_DECL

 #ifdef __cplusplus
_EXTERN_C
typedef void _Atexfun(void);
typedef int _Cmpfun(const void *_ptr1, const void *_ptr2);

int atexit(void (*_func)(void));
void * bsearch(const void *_Key, const void *_Base, size_t _Nelem, size_t _Size, _Cmpfun *_Cmp);
void qsort(void *_base, size_t _n, size_t _size, _Cmpfun *_cmp);
#pragma misra_func(string_conv)
double atof(const char *_S);
#pragma misra_func(string_conv)
int atoi(const char *_S);
#pragma misra_func(string_conv)
long atol(const char *_S);
double strtod(const char *_S, char **_EndPtr);
unsigned long strtoul(const char *_S, char **_EndPtr, int _Base );
_Longlong atoll(const char *_S);
float strtof(const char *_Restrict _Str, char **_Restrict _EndPtr);
long double strtold(const char *_Restrict _Str, char **_Restrict _EndPtr);
_Longlong strtoll(const char *_Restrict _Str, char **_Restrict _EndPtr, int _Base);
_ULonglong strtoull(const char *_Restrict_S, char **_Restrict _EndPtr, int _Base);
_END_EXTERN_C
  #ifdef _HAS_STRICT_LINKAGE

typedef int _Cmpfun2(const void *_ptr1, const void *_ptr2);

#pragma inline
#pragma always_inline
int atexit(void (*_Pfn)(void))
	{	/* register a function to call at exit */
	return (atexit((_Atexfun *)_Pfn));
	}

#pragma inline
#pragma always_inline
void * bsearch(const void *_Key, const void *_Base,
	size_t _Nelem, size_t _Size, _Cmpfun2 *_Cmp)
	{	/* search by binary chop */
	return (bsearch(_Key, _Base, _Nelem, _Size, (_Cmpfun *)_Cmp));
	}

#pragma inline
#pragma always_inline
void qsort(void *_base,
	size_t _n, size_t _size, _Cmpfun2 *_cmp)
	{	/* sort */
	qsort(_base, _n, _size, (_Cmpfun *)_cmp);
	}
  #endif /* _HAS_STRICT_LINKAGE */
#else
typedef int _Cmpfun(const void *, const void *);

int atexit(void (*_func)(void));
void * bsearch(const void *_key, const void *_base, size_t _nelem, size_t _size, _Cmpfun *_cmp);
void qsort(void *_base, size_t _n, size_t _size, _Cmpfun *_cmp);
#endif
		/* INLINES, FOR C++ */
#pragma misra_func(string_conv)
#pragma inline
#pragma always_inline
double atof(const char *_S)
	{	/* convert string to double */
#if defined(__DOUBLES_ARE_FLOATS__)
        return (_Stof(_S, (char **)0, 0));
#else
        return (_Stold(_S, (char **)0, 0));
#endif
	}

#pragma misra_func(string_conv)
#pragma inline
#pragma always_inline
int atoi(const char *_S)
	{	/* convert string to int */
	return ((int)_Stoul(_S, (char **)0, 10));
	}

#pragma misra_func(string_conv)
#pragma inline
#pragma always_inline
long atol(const char *_S)
	{	/* convert string to long */
	return ((long)_Stoul(_S, (char **)0, 10));
	}

#pragma inline
#pragma always_inline
double strtod(const char *_S,
	char **_Endptr)
	{	/* convert string to double, with checking */
#if defined(__DOUBLES_ARE_FLOATS__)
	return (_Stof(_S, _Endptr, 0));
#else
        return (_Stold(_S, _Endptr, 0));
#endif
	}

#pragma inline
#pragma always_inline
unsigned long strtoul(const char *_S,
	char **_Endptr, int _Base)
	{	/* convert string to unsigned long, with checking */
	return (_Stoul(_S, _Endptr, _Base));
	}
#ifdef __cplusplus
extern "C++" {
#pragma always_inline
inline long abs(long _X)	/* OVERLOADS */
	{	/* compute abs */
	return (labs(_X));
	}

#pragma always_inline
inline ldiv_t div(long _X, long _Y)
	{	/* compute quotient and remainder */
	return (ldiv(_X, _Y));
	}

#pragma always_inline
inline _Longlong abs(_Longlong _Left)
        {       /* compute abs */
        return (llabs(_Left));
        }

#pragma always_inline
inline _Lldiv_t div(_Longlong _Left, _Longlong _Right)
	{       /* compute quotient and remainder */
        return (lldiv(_Left, _Right));
        }
}
#endif
#pragma inline
#pragma always_inline
_Longlong atoll(const char *_Str)
   {  /* convert string to long long */
   return ((_Longlong)_Stoull(_Str, (char **)0, 10));
   }

#pragma inline
#pragma always_inline
float strtof(const char *_Restrict _Str,
   char **_Restrict _Endptr)
   {  /* convert string to float, with checking */
   return (_Stof(_Str, _Endptr, 0));
   }

#pragma inline
#pragma always_inline
long double strtold(const char *_Restrict _Str,
   char **_Restrict _Endptr)
   {  /* convert string to long double, with checking */
   return (_Stold(_Str, _Endptr, 0));
   }

#pragma inline
#pragma always_inline
_Longlong strtoll(const char *_Restrict _Str,
   char **_Restrict _Endptr, int _Base)
   {  /* convert string to long long, with checking */
   return (_Stoll(_Str, _Endptr, _Base));
   }

#pragma inline
#pragma always_inline
_ULonglong strtoull(const char *_Restrict _Str,
   char **_Restrict _Endptr, int _Base)
   {  /* convert string to unsigned long long, with checking */
   return (_Stoull(_Str, _Endptr, _Base));
   }

   /* "int" versions */
#ifdef  __ADSP21XX__
int   abs  (int);       /* absolute value */
#endif

#ifndef _EXT1_FAIL
 #define _EXT1_FAIL(mesg)       (-1)
#endif /* _EXT1_FAIL */

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _STDLIB */

#ifdef _STD_USING
using std::size_t; using std::div_t; using std::ldiv_t;

using std::abort; using std::abs; using std::atexit;
using std::atof; using std::atoi; using std::atol;
using std::bsearch; using std::calloc; using std::div;
using std::exit; using std::free; using std::getenv;
using std::labs; using std::ldiv; using std::malloc;
using std::mblen; using std::mbstowcs; using std::mbtowc;
using std::qsort; using std::rand; using std::realloc;
using std::srand; using std::strtod; using std::strtol;
using std::strtoul; using std::system;
using std::wcstombs; using std::wctomb;

using std::lldiv_t;

using std::atoll; using std::llabs; using std::lldiv;
using std::strtof; using std::strtold;
using std::strtoll; using std::strtoull;
using std::_Exit;
#endif /* _STD_USING */


/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
