/************************************************************************
 *
 * stdio.h
 *
 * (c) Copyright 2003-2010 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdio.h */
#endif

/* stdio.h standard header */
#ifndef _STDIO
#define _STDIO
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_1:"Disable rule 5.1 which bars use of long identifiers (>31 chars). This header has many such long macros but they have been available for a long time so cannot be modified to be compliant.")
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_16_1:"ADI header allows variable number of arguments")
#pragma diag(suppress:misra_rule_19_1:"ADI header requires later include")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#pragma diag(suppress:misra_rule_19_11:"Dinkumware macros aren't MISRA-compliant")
#pragma diag(suppress:misra_rule_20_1:"Library file that defines library names")
#pragma diag(suppress:misra_rule_20_2:"Library file that defines library names")
#endif /* _MISRA_RULES */

_C_STD_BEGIN

 #ifndef _HAS_DINKUM_CLIB
  #define _HAS_DINKUM_CLIB	1
 #endif /* _HAS_DINKUM_CLIB */

		/* MACROS */
#ifndef NULL
 #define NULL	 	_NULL
#endif /* NULL */

#define _IOFBF		0
#define _IOLBF		1
#define _IONBF		2

#define BUFSIZ		512
#define EOF			(-1)
#define FILENAME_MAX	_FNAMAX
#define FOPEN_MAX		_FOPMAX
#define L_tmpnam		_TNAMAX
#define TMP_MAX			32

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2

#define stdin		(&_CSTD _Stdin)
#define stdout		(&_CSTD _Stdout)
#define stderr		(&_CSTD _Stderr)

		/* TYPE DEFINITIONS */
 #ifndef _MBSTATET
  #define _MBSTATET
typedef struct _Mbstatet
	{	/* state of a multibyte translation */
	unsigned long _Wchar;
	unsigned short _Byte, _State;
	} _Mbstatet;
 #endif /* _MBSTATET */

 #if !defined(_SIZE_T) && !defined(_SIZET) && !defined(_SIZE_T_DEFINED) \
	&& !defined(_BSD_SIZE_T_DEFINED_)
  #define _SIZE_T
  #define _SIZET
  #define _BSD_SIZE_T_DEFINED_
  #define _SIZE_T_DEFINED
  #define _STD_USING_SIZE_T
typedef _Sizet size_t;
 #endif /* !defined(_SIZE_T) etc. */

typedef struct fpos_t
	{	/* file position */
	_Longlong _Off;	/* can be system dependent */
	_Mbstatet _Wstate;
	} fpos_t;

 #define _FPOSOFF(fp)	((fp)._Off)

struct _Dnk_filet
	{	/* file control information */
	unsigned short _Mode;
 #if defined(_ADI_LIBIO)
	_FD_TYPE  fileID;
 #else
	_FD_TYPE _Handle;
 #endif
	unsigned char *_Next;
	unsigned char *_Rend;
	unsigned char *_Wend;
	unsigned char *_Buf;
	unsigned char *_Bend;
 #if defined(_ADI_LIBIO)
	unsigned char *bufadr;
	unsigned char *rsave;
	unsigned char  onechar;
	char           nback;
	unsigned char  _Back[2];
	/* Padding ensures that LIBIO and -full-io have the same FILE size. */
	void          *_Padding[9];
 #else
	unsigned char _Lockno;
	unsigned char *_Rback;
	_Wchart *_WRback;
	_Wchart _WBack[2];
	unsigned char *_Rsave;
	unsigned char *_WRend;
	unsigned char *_WWend;
	struct _Mbstatet _Wstate;
	char *_Tmpnam;
	unsigned char _Back[2];
	unsigned char _Cbuf;
 #endif
	};

 #ifndef _FILET
  #define _FILET
typedef struct _Dnk_filet _Filet;
 #endif /* _FILET */

typedef _Filet FILE;

		/* declarations */
_C_LIB_DECL
extern FILE _Stdin, _Stdout, _Stderr;

#pragma misra_func(io)
void clearerr(FILE *_str);
#pragma misra_func(io)
int fclose(FILE *_str);
#pragma misra_func(io)
int feof(FILE *_str);
#pragma misra_func(io)
int ferror(FILE *_str);
#pragma misra_func(io)
int fflush(FILE *_str);
#pragma misra_func(io)
int fgetc(FILE *_str);
#pragma misra_func(io)
int fgetpos(FILE *_Restrict _str, fpos_t *_Restrict _p);
#pragma misra_func(io)
char *fgets(char *_Restrict _buf, int _n, FILE *_Restrict _str);
#pragma misra_func(io)
FILE *fopen(const char *_Restrict _filename, const char *_Restrict _mods);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __fprintf64
#endif
#pragma misra_func(io)
int fprintf(FILE *_Restrict _str, const char *_Restrict _fmt, ...);

#pragma misra_func(io)
int fputc(int _c, FILE *_str);
#pragma misra_func(io)
int fputs(const char *_Restrict _s, FILE *_Restrict _str);
#pragma misra_func(io)
size_t fread(void *_Restrict _ptr, size_t _size, size_t _nelem, FILE *_Restrict _str);
#pragma misra_func(io)
FILE *freopen(const char *_Restrict _filename, const char *_Restrict _mods,
	FILE *_Restrict _str);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __fscanf64
#endif
#pragma misra_func(io)
int fscanf(FILE *_Restrict _str, const char *_Restrict _fmt, ...);

#pragma misra_func(io)
int fseek(FILE * _str, long _off, int _smode);
#pragma misra_func(io)
int fsetpos(FILE *_str, const fpos_t *_p);
#pragma misra_func(io)
long ftell(FILE *_str);
#pragma misra_func(io)
size_t fwrite(const void *_Restrict _ptr, size_t _size, size_t _nelem,
	FILE *_Restrict _str);
#pragma misra_func(io)
char *gets(char *_buf);
#pragma misra_func(io)
void perror(const char *_s);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __printf64
#endif
#pragma misra_func(io)
int printf(const char *_Restrict _fmt, ...);

#pragma misra_func(io)
int puts(const char *_s);
#pragma misra_func(io)
int remove(const char *_filename);
#pragma misra_func(io)
int rename(const char *_oldnm, const char *_newnm);
#pragma misra_func(io)
void rewind(FILE *_str);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __scanf64
#endif
#pragma misra_func(io)
int scanf(const char *_Restrict _fmt, ...);

#pragma misra_func(io)
void setbuf(FILE *_Restrict _str , char *_Restrict _buf);

#pragma misra_func(io)
int setvbuf(FILE *_Restrict _str , char *_Restrict _abuf, int _smode, size_t _size);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __sprintf64
#endif
#pragma misra_func(io)
int sprintf(char *_Restrict _s, const char *_Restrict _fmt, ...);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __sscanf64
#endif
#pragma misra_func(io)
int sscanf(const char *_Restrict _s, const char *_Restrict _fmt, ...);

#ifndef _ADI_LIBIO
#pragma misra_func(io)
FILE *tmpfile(void);
#pragma misra_func(io)
char *tmpnam(char *_s);
#endif

#pragma misra_func(io)
int ungetc(int _c, FILE *_str);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vfprintf64
#endif
#pragma misra_func(io)
int vfprintf(FILE *_Restrict _str, const char *_Restrict _fmt, _Va_list _ap);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vprintf64
#endif
#pragma misra_func(io)
int vprintf(const char *_Restrict _fmt, _Va_list _ap);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vsprintf64
#endif
#pragma misra_func(io)
int vsprintf(char *_Restrict _s, const char *_Restrict _fmt, _Va_list _ap);

 #if _ADDED_C_LIB
#pragma misra_func(io)
FILE *fdopen(_FD_TYPE _fd, const char *_mods);
#pragma misra_func(io)
int fileno(FILE *_str);
#pragma misra_func(io)
int getw(FILE *_str);
#pragma misra_func(io)
int putw(int _c, FILE *_str);
 #endif /* _ADDED_C_LIB */

extern FILE *_Files[FOPEN_MAX];

 #if defined(__ADSPBLACKFIN__) && !defined( __NO_ANSI_EXTENSIONS__ )

 #if _HAS_C9X

 #if __EDG__ /* compiler test */
  #pragma __printf_args
 #endif /* __EDG__ */

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __snprintf64
#endif
#pragma misra_func(io)
int snprintf(char *_Restrict _s, size_t _size,
	const char *_Restrict _fmt, ...);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vsnprintf64
#endif
#pragma misra_func(io)
int vsnprintf(char *_Restrict _s, size_t _size,
	const char *_Restrict _fmt, _Va_list _ap);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vfscanf64
#endif
#pragma misra_func(io)
int vfscanf(FILE *_Restrict _f,
	const char *_Restrict _fmt, _Va_list _ap);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vscanf64
#endif
#pragma misra_func(io)
int vscanf(const char *_Restrict _fmt, _Va_list _ap);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vsscanf64
#endif
#pragma misra_func(io)
int vsscanf(const char *_Restrict _s,
	const char *_Restrict _fmt, _Va_list _ap);

 #else /* _IS_C9X */

 #if _ADDED_C_LIB

  #if __EDG__ /* compiler test */
   #pragma __printf_args
  #endif /* __EDG__ */

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __snprintf64
#endif
#pragma misra_func(io)
int snprintf(char *_Restrict _s, size_t _size,
	const char *_Restrict _fmt, ...);

#if !defined(__DOUBLES_ARE_FLOATS__)
 #pragma linkage_name __vsnprintf64
#endif
#pragma misra_func(io)
int vsnprintf(char *_Restrict _s, size_t _size,
	const char *_Restrict _fmt, _Va_list _ap);

 #endif /* _ADDED_C_LIB */

 #endif /* _IS_C9X */

 #endif  /* defined(__ADSPBLACKFIN__) && !defined( __NO_ANSI_EXTENSIONS__ ) */

_END_C_LIB_DECL

 #if _MULTI_THREAD || defined(_ADI_LIBIO)
		/* declarations only */
_C_LIB_DECL
#pragma misra_func(io)
int getc(FILE *_str);
#pragma misra_func(io)
int getchar(void);
#pragma misra_func(io)
int putc(int _c, FILE *_str);
#pragma misra_func(io)
int putchar(int _c);
_END_C_LIB_DECL

 #else /* _MULTI_THREAD || defined(_ADI_LIBIO) */

  #if defined(__cplusplus) && !defined(_NO_CPP_INLINES)
		// INLINES, for C++

 #if !defined(__GNUC__)	/* compiler test */
_C_LIB_DECL
 #endif /* !defined(__GNUC__) */

#pragma always_inline
inline int getc(FILE *_Str)
	{	// get a character
	return ((_Str->_Next < _Str->_Rend
		? *_Str->_Next++ : fgetc(_Str)));
	}

#pragma always_inline
inline int getchar()
	{	// get a character from stdin
	return ((_Files[0]->_Next < _Files[0]->_Rend
	? *_Files[0]->_Next++ : fgetc(_Files[0])));
	}

#pragma always_inline
inline int putc(int _Ch, FILE *_Str)
	{	// put a character
	return ((_Str->_Next < _Str->_Wend
		? (*_Str->_Next++ = (char)_Ch) : fputc(_Ch, _Str)));
	}

#pragma always_inline
inline int putchar(int _Ch)
	{	// put a character to stdout
	return ((_Files[1]->_Next < _Files[1]->_Wend
	? (*_Files[1]->_Next++ = (char)_Ch) : fputc(_Ch, _Files[1])));
	}

 #if !defined(__GNUC__)	/* compiler test */
_END_C_LIB_DECL
 #endif /* !defined(__GNUC__) */

  #else /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */
		/* declarations and macro overrides, for C */
_C_LIB_DECL
#pragma misra_func(io)
int getc(FILE *_Str);
#pragma misra_func(io)
int getchar(void);
#pragma misra_func(io)
int putc(int _Ch, FILE *_Str);
#pragma misra_func(io)
int putchar(int _Ch);
_END_C_LIB_DECL

 #define getc(str)	((str)->_Next < (str)->_Rend \
	? *(str)->_Next++ : (fgetc)(str))

 #define getchar()	(_Files[0]->_Next < _Files[0]->_Rend \
	? *_Files[0]->_Next++ : (fgetc)(_Files[0]))

 #define putc(ch, str)	((str)->_Next < (str)->_Wend \
	? (*(str)->_Next++ = (ch)) : (fputc)((ch), (str)))

 #define putchar(ch)	(_Files[1]->_Next < _Files[1]->_Wend \
	? (*_Files[1]->_Next++ = (ch)) : (fputc)((ch), _Files[1]))
  #endif /* defined(__cplusplus) && !defined(_NO_CPP_INLINES) */

 #endif /* _MULTI_THREAD || defined(_ADI_LIBIO) */
_C_STD_END
#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */
#endif /* _STDIO */

 #if defined(_STD_USING)
using _CSTD _Filet; using _CSTD _Mbstatet;

  #ifdef _STD_USING_SIZE_T
using _CSTD size_t;
  #endif /* _STD_USING_SIZE_T */

using _CSTD fpos_t; using _CSTD FILE;
using _CSTD clearerr; using _CSTD fclose; using _CSTD feof;
using _CSTD ferror; using _CSTD fflush; using _CSTD fgetc;
using _CSTD fgetpos; using _CSTD fgets; using _CSTD fopen;
using _CSTD fprintf; using _CSTD fputc; using _CSTD fputs;
using _CSTD fread; using _CSTD freopen; using _CSTD fscanf;
using _CSTD fseek; using _CSTD fsetpos; using _CSTD ftell;
using _CSTD fwrite; using _CSTD getc; using _CSTD getchar;
using _CSTD gets; using _CSTD perror;
using _CSTD putc; using _CSTD putchar;
using _CSTD printf; using _CSTD puts; using _CSTD remove;
using _CSTD rename; using _CSTD rewind; using _CSTD scanf;
using _CSTD setbuf; using _CSTD setvbuf; using _CSTD sprintf;
using _CSTD sscanf; using _CSTD tmpfile; using _CSTD tmpnam;
using _CSTD ungetc; using _CSTD vfprintf; using _CSTD vprintf;
using _CSTD vsprintf;

 #if _HAS_C9X
using _CSTD snprintf; using _CSTD vsnprintf;
using _CSTD vfscanf; using _CSTD vscanf; using _CSTD vsscanf;

 #else /* _IS_C9X */

 #if _ADDED_C_LIB
using _CSTD snprintf; using _CSTD vsnprintf;
 #endif /* _ADDED_C_LIB */

 #endif /* _IS_C9X */

 #if _ADDED_C_LIB
using _CSTD fdopen; using _CSTD fileno; using _CSTD getw; using _CSTD putw;
 #endif /* _ADDED_C_LIB */

 #endif /* defined(_STD_USING) */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
