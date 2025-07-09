/* string.h standard header */
#if defined (_ADI_COMPILER)
#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* string.h */
#endif
/************************************************************************
 *
 * string.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/
#endif /* _ADI_COMPILER */

#ifndef _STRING
#define _STRING
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_2)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_16_3)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_20_1)
#pragma diag(suppress:misra_rule_20_2)
#endif /* _ADI_COMPILER && _MISRA_RULES */

_C_STD_BEGIN

		/* macros */
#ifndef NULL
 #define NULL	_NULL
#endif /* NULL */

		/* type definitions */

 #if !defined(_SIZE_T) && !defined(_SIZET) && !defined(_SIZE_T_DEFINED) \
	&& !defined(_BSD_SIZE_T_DEFINED_)
  #define _SIZE_T
  #define _SIZET
  #define _BSD_SIZE_T_DEFINED_
  #define _SIZE_T_DEFINED
  #define _STD_USING_SIZE_T
typedef _Sizet size_t;
 #endif /* !defined(_SIZE_T) etc. */

		/* declarations */
_C_LIB_DECL
int memcmp(const void *, const void *, size_t);
void *memcpy(void *_Restrict, const void *_Restrict, size_t);
void *memset(void *, int, size_t);
char *strcat(char *_Restrict, const char *_Restrict);
int strcmp(const char *, const char *);
char *strcpy(char *_Restrict, const char *_Restrict);
size_t strlen(const char *);

void *memmove(void *, const void *, size_t);
int strcoll(const char *, const char *);
size_t strcspn(const char *, const char *);
char *strerror(int);
char *strncat(char *_Restrict, const char *_Restrict, size_t);
int strncmp(const char *, const char *, size_t);
char *strncpy(char *_Restrict, const char *_Restrict, size_t);
size_t strspn(const char *, const char *);
char *strtok(char *_Restrict, const char *_Restrict);
size_t strxfrm(char *_Restrict, const char *_Restrict, size_t);

#if defined (_ADI_COMPILER)
 #if !defined(__NO_BUILTIN)
 #define strcpy  __builtin_strcpy
 #define strlen  __builtin_strlen
 #define memcpy  __builtin_memcpy
 #define memmove __builtin_memmove
 #endif
#else /* _ADI_COMPILER */
 #if _ADDED_C_LIB
char *strdup(const char *);
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, size_t);
char *strtok_r(char *, const char *, char **);
 #endif /* _ADDED_C_LIB */
#endif /* _ADI_COMPILER */

_END_C_LIB_DECL

 #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
		// INLINES AND OVERLOADS, for C++
 #define _Const_return const

_C_LIB_DECL
const char *strchr(const char *, int);
const char *strpbrk(const char *, const char *);
const char *strrchr(const char *, int);
const char *strstr(const char *, const char *);
_END_C_LIB_DECL

#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline char *strchr(char *_Str, int _Ch)
	{	// call with const first argument
	return ((char *)_CSTD strchr((const char *)_Str, _Ch));
	}

#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline char *strpbrk(char *_Str1, const char *_Str2)
	{	// call with const first argument
	return ((char *)_CSTD strpbrk((const char *)_Str1, _Str2));
	}

#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline char *strrchr(char *_Str, int _Ch)
	{	// call with const first argument
	return ((char *)_CSTD strrchr((const char *)_Str, _Ch));
	}

#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline char *strstr(char *_Str1, const char *_Str2)
	{	// call with const first argument
	return ((char *)_CSTD strstr((const char *)_Str1, _Str2));
	}

 #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES)*/
_C_LIB_DECL
 #define _Const_return

char *strchr(const char *, int);
char *strpbrk(const char *, const char *);
char *strrchr(const char *, int);
char *strstr(const char *, const char *);
_END_C_LIB_DECL
 #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

 #ifndef _MEMCHR
  #define _MEMCHR

  #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
_C_LIB_DECL
const void *memchr(const void *, int, size_t);
_END_C_LIB_DECL

#if defined (_ADI_COMPILER)
#pragma always_inline
#endif /* _ADI_COMPILER */
inline void *memchr(void *_Str, int _Ch, size_t _Num)
	{	// call with const first argument
	return ((void *)_CSTD memchr((const void *)_Str, _Ch, _Num));
	}

  #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
_C_LIB_DECL
void *memchr(const void *, int, size_t);
_END_C_LIB_DECL
  #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

 #endif /* _MEMCHR */

 #if __STDC_WANT_LIB_EXT1__
_C_LIB_DECL

  #if !defined(_ERRNO_T_DEFINED)
   #define _ERRNO_T_DEFINED
typedef int errno_t;
  #endif /* _ERRNO_T_DEFINED */

  #if !defined(_RSIZE_T_DEFINED)
   #define _RSIZE_T_DEFINED
typedef size_t rsize_t;
  #endif /* _RSIZE_T_DEFINED */

errno_t memcpy_s(void *_Restrict, rsize_t,
	const void *_Restrict, rsize_t);
errno_t memmove_s(void *, rsize_t,
	const void *, rsize_t);

errno_t strcpy_s(char *_Restrict, rsize_t,
	const char *_Restrict);
errno_t strncpy_s(char *_Restrict, rsize_t,
	const char *_Restrict, rsize_t);
errno_t strcat_s(char *_Restrict, rsize_t,
	const char *_Restrict);
errno_t strncat_s(char *_Restrict, rsize_t,
	const char *_Restrict, rsize_t);
char *strtok_s(char *_Restrict, rsize_t *_Restrict,
	const char *_Restrict, char **_Restrict);

errno_t strerror_s(char *, rsize_t, errno_t);
size_t strerrorlen_s(errno_t);

size_t strnlen_s(const char *_Restrict, size_t);
_END_C_LIB_DECL
 #endif /* __STDC_WANT_LIB_EXT1__ */

_C_STD_END
#endif /* _STRING */

 #if defined(_STD_USING)

  #ifdef _STD_USING_SIZE_T
using _CSTD size_t;
  #endif /* _STD_USING_SIZE_T */

using _CSTD memchr; using _CSTD memcmp;
using _CSTD memcpy; using _CSTD memmove; using _CSTD memset;
using _CSTD strcat; using _CSTD strchr; using _CSTD strcmp;
using _CSTD strcoll; using _CSTD strcpy; using _CSTD strcspn;
using _CSTD strerror; using _CSTD strlen; using _CSTD strncat;
using _CSTD strncmp; using _CSTD strncpy; using _CSTD strpbrk;
using _CSTD strrchr; using _CSTD strspn; using _CSTD strstr;
using _CSTD strtok; using _CSTD strxfrm;

 #if __STDC_WANT_LIB_EXT1__
using _CSTD errno_t;
using _CSTD rsize_t;

using _CSTD memcpy_s;
using _CSTD memmove_s;
using _CSTD strcpy_s;
using _CSTD strncpy_s;
using _CSTD strcat_s;
using _CSTD strncat_s;
using _CSTD strtok_s;
using _CSTD strerror_s;
using _CSTD strerrorlen_s;
using _CSTD strnlen_s;
 #endif /* __STDC_WANT_LIB_EXT1__ */

 #endif /* defined(_STD_USING) */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
