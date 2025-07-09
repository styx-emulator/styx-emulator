/* yvals.h values header for conforming compilers on various systems */

#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * yvals.h: $Revision: 3953 $
 *
 * (c) Copyright 2002-2010 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once

#if !defined(_IS_WRS)
#define _IS_WRS 0
#endif

#endif /* _ADI_COMPILER */

 #if _IS_WRS	/* compiler test */
 #ifndef _YVALS_WRS
  #define _YVALS_WRS

 #if (defined(__cplusplus) && defined(__GNUC__))	/* use GCC's yvals.h */
  #include_next <yvals.h>
  #define _YVALS
 #endif /* defined(__cplusplus) etc. */

 #endif /* _YVALS_WRS */
 #endif /* _IS_WRS */

#ifndef _YVALS
#define _YVALS

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_10)
#pragma diag(suppress:misra_rule_19_11)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#define _CPPLIB_VER	503

/* You can predefine (on the compile command line, for example):

_ADDED_C_LIB=0 -- to omit declarations for C extensions
_ALT_NS=1 -- to use namespace _Dinkum_std for C++
_ALT_NS=2 -- to use namespace _Dinkum_std for C++ and C
_ALT_NS=3 -- to use namespace _Dinkum_std for C++ and _Dinkum_std_c for C
_C_AS_CPP -- to compile C library as C++
_C_IN_NS -- to define C names in std/_Dinkum_std instead of global namespace
_C99 -- to turn ON C99 library support
_ABRCPP -- to turn ON Abridged C++ dialect (implies _ECPP)
_ECPP -- to turn ON Embedded C++ dialect
_HAS_FIXED_POINT=0 -- to turn OFF fixed-point extensions (if present)
_HAS_IMMUTABLE_SETS=1 -- to permit alterable set elements
_HAS_STRICT_CONFORMANCE=1 -- to to disable nonconforming extensions
_HAS_TRADITIONAL_IOSTREAMS=0 -- to omit old iostreams functions
_HAS_TRADITIONAL_ITERATORS=1 -- for vector/string pointer iterators
_HAS_TRADITIONAL_POS_TYPE=1 -- for streampos same as streamoff
_HAS_TRADITIONAL_STL=0 -- to turn OFF old STL functions
_HAS_TR1=0 -- to turn OFF TR1 extensions (if present)
_NO_EX -- to turn OFF use of try/throw
_NO_MT -- to turn OFF thread synchronization
_NO_NS -- to turn OFF use of namespace declarations
_STL_DB (or _STLP_DEBUG) -- to turn ON iterator/range debugging
_USE_EXISTING_SYSTEM_NAMES=0 -- to disable mappings (_Open to open)
__NO_LONG_LONG -- to define _Longlong as long, not long long

You can change (in this header AND ALL ITS COPIES):

_COMPILER_TLS -- from 0 to 1 if _TLS_QUAL is not nil
_EXFAIL -- from 1 to any nonzero value for EXIT_FAILURE
_FILE_OP_LOCKS -- from 0 to 1 for file atomic locks
_GLOBAL_LOCALE -- from 0 to 1 for shared locales instead of per-thread
_IOSTREAM_OP_LOCKS -- from 0 to 1 for iostream atomic locks
_TLS_QUAL -- from nil to compiler TLS qualifier, such as __declspec(thread)
__STDC_WANT_LIB_EXT1__ -- from 1 to 0 to disable C library extension 1

Include directories needed to compile with Dinkum C:

C -- include/c
C99 -- include/c (define _C99)
Embedded C++ -- include/c include/embedded (define _ECPP)
Abridged C++ -- include/c include/embedded include (define _ABRCPP)
Standard C++ -- include/c include
Standard C++ with export -- include/c include/export include
	(--export --template_dir=lib/export)

Include directories needed to compile with native C:

C -- none
C99 -- N/A
Embedded C++ -- include/embedded (define _ECPP)
Abridged C++ -- include/embedded include (define _ABRCPP)
Standard C++ -- include
Standard C++ with export -- include/export include
	(--export --template_dir=lib/export)
 */

 #ifndef __STDC_HOSTED__
  #define __STDC_HOSTED__	1
 #endif /* __STDC_HOSTED__ */

 #ifndef __STDC_IEC_559__
  #define __STDC_IEC_559__	1
 #endif /* __STDC_IEC_559__ */

 #ifndef __STDC_IEC_559_COMPLEX__
  #define __STDC_IEC_559_COMPLEX__	1
 #endif /* __STDC_IEC_559_COMPLEX__ */

 #ifndef __STDC_ISO_10646__
  #define __STDC_ISO_10646__	200009L	/* match glibc */
 #endif /* __STDC_ISO_10646__ */

 /* TR 24731 macros */
 #ifdef _ADI_COMPILER
  #define __STDC_WANT_LIB_EXT1__ 0
 #else
 #ifndef __STDC_LIB_EXT1__
  #define __STDC_LIB_EXT1__	200509L
 #endif /* __STDC_LIB_EXT1__ */

 #ifndef __STDC_WANT_LIB_EXT1__
  #define __STDC_WANT_LIB_EXT1__	1
 #endif /* __STDC_WANT_LIB_EXT1__ */
 #endif

		/* DETERMINE MACHINE TYPE */

 #if defined(i386) || defined(__i386) \
	|| defined(__i386__) || defined(_M_IX86)	/* Pentium */
  #define _D0		3	/* 0: big endian, 3: little endian floating-point */

  #if defined(__RTP__)
   #define _DLONG       1       /* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LBIAS       0x3ffe  /* 80/128 long double bits */
   #define _LOFF        15      /* 64 long double bits */

  #elif defined(__BORLANDC__) && !__EDG__
   #pragma warn -inl
   #define _DLONG	1	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LBIAS	0x3ffe	/* 80/128 long double bits */
   #define _LOFF	15	/* 64 long double bits */

  #elif defined(__MINGW32__)
   #define _DLONG	1	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LBIAS	0x3ffe	/* 80/128 long double bits */
   #define _LOFF	15	/* 64 long double bits */

  #elif defined(_M_IX86)
   #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LBIAS	0x3fe	/* 64 long double bits */
   #define _LOFF	4	/* 64 long double bits */

  #else /* unknown compilation environment, guess 80-bit long double */
   #define _DLONG	1	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LBIAS	0x3ffe	/* 80/128 long double bits */
   #define _LOFF	15	/* 80/128 long double bits */
  #endif /* defined(_M_IX86) */

  #define _FPP_TYPE	_FPP_X86	/* Pentium FPP */

 #elif defined(sparc) || defined(__sparc)	/* SPARC */

 #if _IS_WRS	/* compiler test */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _LBIAS	0x3ffe	/* 80/128 long double bits */
  #define _FPP_TYPE	_FPP_SPARC	/* SPARC FPP */

  #if defined(_NO_WINDRIVER_MODIFICATIONS)
   #define _DLONG	2	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LOFF		15	/* 80/128 long double bits */

  #else /* _NO_WINDRIVER_MODIFICATIONS */
   #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
   #define _LOFF		4	/* 80/128 long double bits */
  #endif /* _NO_WINDRIVER_MODIFICATIONS */

 #else /* _IS_WRS */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	2	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3ffe	/* 80/128 long double bits */
  #define _LOFF		15	/* 80/128 long double bits */
  #define _FPP_TYPE	_FPP_SPARC	/* SPARC FPP */

  #if defined(__arch64__)
   #define _MACH_PDT	long
   #define _MACH_SZT	unsigned long
  #endif /* defined(__arch64__) */

 #endif /* _IS_WRS */

 #elif defined(_MIPS) || defined(_MIPS_) \
	|| defined(__mips) || defined(_M_MRX000)		/* MIPS */

  #if defined(__LITTLE_ENDIAN__) || defined(__MIPSEL)
   #define _D0		3	/* 0: big endian, 3: little endian floating-point */

  #else /* __LITTLE_ENDIAN__ etc. */
   #define _D0		0
  #endif /* __LITTLE_ENDIAN__ etc. */

  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_MIPS	/* MIPS FPP */

 #if _IS_WRS	/* compiler test */

  #if defined(_NO_WINDRIVER_MODIFICATIONS)
   #define _MACH_PDT	long
   #define _MACH_SZT	unsigned long
  #endif /* _NO_WINDRIVER_MODIFICATIONS */

 #endif /* _IS_WRS */

 #if !defined(_MACH_PDT)
  #define _MACH_PDT	long
  #define _MACH_SZT	unsigned long
 #endif /* defined(_MACH_PDT) */

 #elif defined(__s390__)	/* IBM S/390 */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_S390	/* S/390 FPP */

  #define _MACH_PDT	long
  #define _MACH_SZT	unsigned long

 #elif defined(__ppc__) || defined(_POWER) || defined(_M_PPC)	/* PowerPC */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_PPC	/* PowerPC FPP */

  #if defined(__APPLE__)
   #define _MACH_I32	int
   #define _MACH_PDT	int
   #define _MACH_SZT	unsigned long
  #endif /* defined(__APPLE__) */

 #elif defined(__hppa)	/* HP PA-RISC */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	2	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3ffe	/* 80/128 long double bits */
  #define _LOFF		15	/* 80/128 long double bits */
  #define _FPP_TYPE	_FPP_HPPA	/* Hewlett-Packard PA-RISC FPP */

 #elif defined(_M_ALPHA)	/* Alpha */
  #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_ALPHA	/* Compaq Alpha */

 #elif defined(_ARM_) || defined(__arm)	/* ARM */

  #if defined(__BIG_ENDIAN__) || defined(__ARMEB__)
   #define _D0		0	/* 0: big endian, 3: little endian floating-point */

  #else /* __BIG_ENDIAN__ etc. */
   #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #endif /* __BIG_ENDIAN__ etc. */

  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_ARM	/* ARM ARM FPP */

 #elif defined(_M68K)	/* Motorola 68K */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	1	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3ffe	/* 80/128 long double bits */
  #define _LOFF		15	/* 80/128 long double bits */
  #define _FPP_TYPE	_FPP_M68K	/* Motorola 68xxx FPP */

 #elif defined(_SH4_) || defined(__sh) || defined(__sh__)	/* SH4 */

  #if defined(__BIG_ENDIAN__) || defined(_SH4)
   #define _D0		0	/* 0: big endian, 3: little endian floating-point */

  #else /* __BIG_ENDIAN__ etc. */
   #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #endif /* __BIG_ENDIAN__ etc. */

  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_SH4	/* Hitachi SH4 FPP */

 #elif defined(_M_IA64)	/* IA64 */
  #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_IA64	/* Intel IA64 FPP */

 #elif defined(__x86_64) /* 64-Bit GCC */
  #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	1	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3ffe	/* 80/128 long double bits */
  #define _LOFF		15	/* 80/128 long double bits */
  #define _FPP_TYPE	_FPP_X86	/* Pentium FPP */

 #elif defined(_M_X64) /* 64-Bit x86 VC++ */
  #define _D0		3	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
  #define _FPP_TYPE	_FPP_WIN	/* Pentium FPP under Windows */

 #else /* unknown compilation environment, guess big-endian */
# if !defined(_ADI_COMPILER)
  /* For the ADI targets we set these later on in this file once the target
  ** specific settings have been made.
  */
  #define _D0		0	/* 0: big endian, 3: little endian floating-point */
  #define _DLONG	0	/* 0: 64, 1: 80, 2: 128 long double bits */
  #define _LBIAS	0x3fe	/* 64 long double bits */
  #define _LOFF		4	/* 64 long double bits */
# endif
 #endif /* system detector */

		/* DETERMINE _Ptrdifft AND _Sizet FROM MACHINE TYPE */
# if defined(__ADSP21000__)
   /* configuration for Sharc and Hammerhead targets */

#define _IS_EMBEDDED	                1   /* 1 for Embedded C++ */
#define _ABRCPP                         1
#define _ECPP                         1
#define _HAS_TRADITIONAL_IOSTREAMS	0   /* disable old iostreams stuff */

#ifdef __EXCEPTIONS
#  define _HAS_EXCEPTIONS       1
#else
#  define _HAS_EXCEPTIONS       0
#endif
#  define _ADI_FLOAT_ENDIAN                 0
#  define _ADI_SUPPORT_LONG_DOUBLE          1
#  define _ADI_ABRTNUM                      32
#  define _ADI_SIGMAX                       39
#  define _ADI_TARG_INT16                   0
#  define _ADI_TARG_MBMAX                   2
#  define _ADI_ALIGNA                       1U
#  define _ADI_BYTE_BITS                    32

#  define _HAS_DINKUM_CLIB 0

# elif defined(__ADSPBLACKFIN__)
   /* configuration for Blackfin targets */
#if defined(_ADI_COMPILER) && defined(_ADI_FULLCPPLIB)
#define _IS_EMBEDDED                    0   /* 1 for Embedded C++ */
#define _ABRCPP                         0
#define _ECPP                         0
#else
#define _IS_EMBEDDED                    1   /* 1 for Embedded C++ */
#define _ABRCPP                         1
#define _ECPP                         1
#endif /* defined(_ADI_COMPILER) && defined(_ADI_FULLCPPLIB) */
#ifdef __EXCEPTIONS
#  define _HAS_EXCEPTIONS       1
#else
#  define _HAS_EXCEPTIONS       0
#endif
#  define _USING_DINKUM_C_LIBRARY 1
#  define _HAS_DINKUM_CLIB 1

#if defined(__DOUBLES_ARE_FLOATS__)
#  /* Array index for MSB:  union {float;short[2];} */
#  define _ADI_FLOAT_ENDIAN                 1
#else
#  /* Array index for MSB:  union {long double;short[4];} */
#  define _ADI_FLOAT_ENDIAN                 3
#endif
#  define _ADI_SUPPORT_LONG_DOUBLE          1
#  define _ADI_WCHART_UNSIGNED              unsigned
#  define _ADI_ABRTNUM                      22
#  define _ADI_SIGMAX                       23
#  define _ADI_TARG_INT16                   0
#  define _ADI_TARG_MBMAX                   8
#  define _ADI_ALIGNA                       3U /* even-byte boundaries (2^^1) */
#  define _ADI_BYTE_BITS                    8

#  define _NSETJMP 39   /* size of jmpbuf */

# else
#  error Unknown target
# endif
   typedef long int _Ptrdifft;
   typedef long unsigned int _Sizet;


 #if defined(_MACH_I32)
typedef _MACH_I32 _Int32t;
typedef unsigned _MACH_I32 _Uint32t;

 #else /* defined(_MACH_I32) */
#if defined (_ADI_COMPILER)
/* Make _Int32t explicitly signed to address TAR35636 */
 typedef signed int _Int32t; /* Needs to be int for MISRA and
                                backwards compatibility */
 typedef unsigned int _Uint32t; /* backwards compatability */
#else /* _ADI_COMPILER */
 typedef long _Int32t;
 typedef unsigned long _Uint32t;
#endif /* _ADI_COMPILER */
 #endif /* defined(_MACH_I32) */

#if defined(_ADI_COMPILER)
#define _HAS_C9X 0 /* Even if compiler supports C99, the Library is a
                       freestanding implementation */
#define _ALT_NS 0
#define _HAS_TR1 0 /* Does not currently support TR1 extensions */
#endif /* defined(_ADI_COMPILER) */

#if !_ADI_COMPILER
 #if defined(_LP64) || defined(__x86_64)
typedef long _Ptrdifft;

 #elif defined(_M_X64)
typedef __int64 _Ptrdifft;

 #elif defined(_MACH_PDT)
typedef _MACH_PDT _Ptrdifft;

 #else /* defined(_MACH_PDT) */
typedef int _Ptrdifft;
 #endif /* defined(_LP64) */

 #if defined(_LP64) || defined(__x86_64)
typedef unsigned long _Sizet;

 #elif defined(_MACH_SZT)
typedef _MACH_SZT _Sizet;

 #else /* defined(_MACH_SZT) */
typedef unsigned int _Sizet;
 #endif /* defined(_LP64) */
#endif /* !_ADI_COMPILER */

 #if defined(__x86_64)
  #define _LLONG	1	/* 64-bit longs */
  #define _RSIZE_MAX	((unsigned int)(-1) >> 1)

 #else /* defined(__x86_64) */
  #define _LLONG	0	/* 32-bit longs */
  #define _RSIZE_MAX	((_Sizet)(-1) >> 1)	/* or sizeof largest object */
 #endif /* defined(__x86_64) */

 #if defined(__linux) || defined(__linux__)
  #define _LINUX_C_LIB	1	/* Linux-specific conventions */
 #endif /* defined(__linux) etc. */

 #if defined(_M_IX86) || defined(_M_MRX000) || defined(_M_PPC) \
	|| defined(_M_ALPHA) || defined(_M_IA64) || defined(_WIN32_WCE) \
	|| defined(_WIN64)
  #define _WIN32_C_LIB	1	/* use Windows32 conventions */

 #else /* defined(_M_*) */
  #if defined (_ADI_COMPILER)
  # define _HAS_POSIX_C_LIB	0
  #else
  # define _HAS_POSIX_C_LIB	1	/* use common Unix/Linux conventions */
  #endif
 #endif /* defined(_M_*) */

 #if !defined(_HAS_C9X) && defined(_C99)
  #define _HAS_C9X	1
 #endif /* !defined(_HAS_C9X) etc. */

 #if !defined(_ECPP) && defined(_ABRCPP)
  #define _ECPP
 #endif /* !defined(_ECPP) && defined(_ABRCPP) */

 #if _IS_WRS	/* compiler test */

 #if defined(_NO_WINDRIVER_MODIFICATIONS)

  #if _HAS_C9X && __EDG__ && !defined(__cplusplus)
   #define _HAS_C9X_IMAGINARY_TYPE	1

  #else /* _HAS_C9X etc. */
   #define _HAS_C9X_IMAGINARY_TYPE	0
  #endif /* _HAS_C9X etc. */

 #if !defined(_IS_EMBEDDED) && defined(_ECPP)
  #define _IS_EMBEDDED	1	/* 1 for Embedded C++ */
 #endif /* _IS_EMBEDDED etc. */

 #else /* _NO_WINDRIVER_MODIFICATIONS */
  #define _HAS_C9X_IMAGINARY_TYPE	0
  #define _IS_EMBEDDED	__CONFIGURE_EMBEDDED
 #endif /* _NO_WINDRIVER_MODIFICATIONS */

 #else /* _IS_WRS */

 #if _HAS_C9X && __EDG__ && !defined(__cplusplus)
  #define _HAS_C9X_IMAGINARY_TYPE	1

 #else /* _HAS_C9X etc. */
  #define _HAS_C9X_IMAGINARY_TYPE	0
 #endif /* _HAS_C9X etc. */

 #if !defined(_IS_EMBEDDED) && defined(_ECPP)
  #define _IS_EMBEDDED	1	/* 1 for Embedded C++ */
 #endif /* _IS_EMBEDDED etc. */

 #endif /* _IS_WRS */

 #ifndef __STDC_VERSION__

  #if _HAS_C9X
   #define __STDC_VERSION__	199901L

  #else /* _HAS_C9X */
    #define __STDC_VERSION__	199409L
  #endif /* _HAS_C9X */

 #endif /* __STDC_VERSION__ */

		/* EXCEPTION CONTROL */
 #ifndef _HAS_EXCEPTIONS
  #ifndef _NO_EX	/* don't simplify */
   #define _HAS_EXCEPTIONS	1	/* 1 for try/throw logic */

  #else	/* _NO_EX */
   #define _HAS_EXCEPTIONS	0
  #endif /* _NO_EX */

 #endif /* _HAS_EXCEPTIONS */

		/* NAMING PROPERTIES */
/* #define _STD_LINKAGE	define C names as extern "C++" */
/* #define _STD_USING	define C names in one of three namespaces */

 #ifndef _HAS_NAMESPACE
  #ifndef _NO_NS	/* don't simplify */
   #define _HAS_NAMESPACE	1	/* 1 for C++ names in std */

  #else	/* _NO_NS */
   #define _HAS_NAMESPACE	0
  #endif /* _NO_NS */

 #endif /* _HAS_NAMESPACE */

 #if !defined(_STD_USING) && defined(__cplusplus) \
	&& (defined(_C_IN_NS) || 1 < _ALT_NS)
  #define _STD_USING	/* *.h headers export C names to global */

 #elif defined(_STD_USING) && !defined(__cplusplus)
  #undef _STD_USING	/* define only for C++ */
 #endif /* !defined(_STD_USING) */

 #if !defined(_HAS_STRICT_LINKAGE) \
	&& ((defined(__SUNPRO_CC) && __SUNPRO_CC) || __EDG__)
#if defined(_ADI_COMPILER) || !defined(_WIN32_C_LIB)
  #define _HAS_STRICT_LINKAGE	1	/* extern "C" in function type */
#endif  /* _ADI_COMPILER || !_WIN32_C_LIB */
 #endif /* !defined(_HAS_STRICT_LINKAGE) */

		/* THREAD AND LOCALE CONTROL */

#if defined(_ADI_COMPILER)
#  if defined(_ADI_THREADS) || defined(__ADI_MULTICORE)
#    define _MULTI_THREAD 1
#  else
#    define _MULTI_THREAD 0
#  endif
#endif /* _ADI_COMPILER */

 #ifndef _MULTI_THREAD

  #ifdef __CYGWIN__
   #define _MULTI_THREAD	0	/* Cygwin has dummy thread library */

  #else /* __CYGWIN__ */
   #ifndef _NO_MT
    #define _MULTI_THREAD	1	/* 0 for no thread locks */

   #else
    #define _MULTI_THREAD	0
   #endif	/* _NO_MT */

  #endif /* __CYGWIN__ */
 #endif /* _MULTI_THREAD */

#if defined(_ADI_COMPILER)
#define _GLOBAL_LOCALE	1   /* 0 for per-thread locales, 1 for shared */
#define _FILE_OP_LOCKS	0   /* 0 for global lock, 1 for file-specific */
#define _IOSTREAM_OP_LOCKS	1   /* 0 for global lock, 1 for stream-specific */
#else /* defined(_ADI_COMPILER) */
#define _GLOBAL_LOCALE	0   /* 0 for per-thread locales, 1 for shared */
#define _FILE_OP_LOCKS	0   /* 0 for no FILE locks, 1 for atomic */
#define _IOSTREAM_OP_LOCKS	0   /* 0 for no iostream locks, 1 for atomic */
#endif /* defined(_ADI_COMPILER) */

		/* THREAD-LOCAL STORAGE */
#define _COMPILER_TLS	0	/* 1 if compiler supports TLS directly */
#define _TLS_QUAL	/* TLS qualifier, such as __declspec(thread), if any */

#if defined (_ADI_COMPILER)
/* Some of the macros just default to 0 as they are not defined. We will
 * explicitly set them instead.
 */
#define _USE_EXISTING_SYSTEM_NAMES 0
#define _HAS_ITERATOR_DEBUGGING	0	/* disable range checks, etc. */
#endif /* _ADI_COMPILER */

 #if !defined(_ADDED_C_LIB)
  #define _ADDED_C_LIB	1	/* include declarations for C extensions */
 #endif /* !defined(_ADDED_C_LIB) */

 #if !defined(_HAS_FIXED_POINT)
  #define _HAS_FIXED_POINT	1	/* enable fixed-point extensions */
 #endif /* !defined(_HAS_FIXED_POINT) */

 #if !defined(_HAS_IMMUTABLE_SETS)
  #define _HAS_IMMUTABLE_SETS	1	/* disallow alterable set elements */
 #endif /* !defined(_HAS_IMMUTABLE_SETS) */

 #if !defined(_HAS_ITERATOR_DEBUGGING) \
	&& (defined(_STL_DB) || defined(_STLP_DEBUG))
  #define _HAS_ITERATOR_DEBUGGING	1	/* enable range checks, etc. */
 #endif /* define _HAS_ITERATOR_DEBUGGING */

 #if !defined(_HAS_STRICT_CONFORMANCE)
  #define _HAS_STRICT_CONFORMANCE	0	/* enable nonconforming extensions */
 #endif /* !defined(_HAS_STRICT_CONFORMANCE) */

 #if !defined(_HAS_TRADITIONAL_IOSTREAMS)
  #define _HAS_TRADITIONAL_IOSTREAMS	1	/* enable old iostreams stuff */
 #endif /* !defined(_HAS_TRADITIONAL_IOSTREAMS) */

 #if !defined(_HAS_TRADITIONAL_ITERATORS)
  #define _HAS_TRADITIONAL_ITERATORS	0	/* don't use pointer iterators */
 #endif /* !defined(_HAS_TRADITIONAL_ITERATORS) */

 #if !defined(_HAS_TRADITIONAL_POS_TYPE)
  #define _HAS_TRADITIONAL_POS_TYPE	0	/* make streampos same as streamoff */
 #endif /* !defined(_HAS_TRADITIONAL_POS_TYPE) */

 #if !defined(_HAS_TRADITIONAL_STL)
  #define _HAS_TRADITIONAL_STL	1	/* enable older STL extensions */
 #endif /* !defined(_HAS_TRADITIONAL_STL) */

 #if !defined(_HAS_TR1)
  #define _HAS_TR1	(!_IS_EMBEDDED)	/* enable TR1 extensions */
 #endif /* !defined(_HAS_TR1) */

#define _HAS_TR1_DECLARATIONS	_HAS_TR1

 #if !defined(_USE_EXISTING_SYSTEM_NAMES)
  #define _USE_EXISTING_SYSTEM_NAMES	1	/* _Open => open, etc.  */
 #endif /* !defined(_USE_EXISTING_SYSTEM_NAMES) */

 #if defined(__STDC_WANT_SAFER_LIB__) && __STDC_WANT_SAFER_LIB__
  #define __STDC_SAFER_LIB__	200510L
 #endif /* __STDC_WANT_SAFER_LIB__ */

		/* NAMESPACE CONTROL */

 #if defined(__cplusplus)

 #if _HAS_NAMESPACE
namespace std {}

 #if defined(_C_AS_CPP)
  #define _NO_CPP_INLINES	/* just for compiling C library as C++ */
 #endif /* _C_AS_CPP */

 #if 0 < _ALT_NS

  #if defined(_C_AS_CPP)	/* define library in _Dinkum_std */
   #define _STD_BEGIN	namespace _Dinkum_std {_C_LIB_DECL
   #define _STD_END		_END_C_LIB_DECL }

  #else /* _C_AS_CPP */
   #define _STD_BEGIN	namespace _Dinkum_std {
   #define _STD_END		}
  #endif /* _C_AS_CPP */

  #if _ALT_NS == 1	/* define C library in global namespace */
    #define _C_STD_BEGIN
    #define _C_STD_END
    #define _CSTD		::
    #define _STD			::_Dinkum_std::

  #elif _ALT_NS == 2	/* define both C and C++ in namespace _Dinkum_std */
    #define _C_STD_BEGIN	namespace _Dinkum_std {
    #define _C_STD_END	}
    #define _CSTD		::_Dinkum_std::
    #define _STD			::_Dinkum_std::

  #else	/* define C in namespace _Dinkum_std_c and C++ in _Dinkum_std */
    #define _C_STD_BEGIN	namespace _Dinkum_std_c {
    #define _C_STD_END	}
    #define _CSTD		::_Dinkum_std_c::
    #define _STD			::_Dinkum_std::
  #endif /* _ALT_NS */

namespace _Dinkum_std {}
namespace _Dinkum_std_c {}
namespace std {
	using namespace _Dinkum_std;
	using namespace _Dinkum_std_c;
	}

 #elif defined(_STD_USING)

  #if defined(_C_AS_CPP)	/* define library in std */
   #define _STD_BEGIN	namespace std {_C_LIB_DECL
   #define _STD_END		_END_C_LIB_DECL }

  #else /* _C_AS_CPP */
   #define _STD_BEGIN	namespace std {
   #define _STD_END		}
  #endif /* _C_AS_CPP */

   #define _C_STD_BEGIN	namespace std {
   #define _C_STD_END	}
   #define _CSTD		::std::
   #define _STD			::std::

 #else /* _ALT_NS == 0 && !defined(_STD_USING) */

  #if defined(_C_AS_CPP)	/* define C++ library in std, C in global */
   #define _STD_BEGIN	_C_LIB_DECL
   #define _STD_END		_END_C_LIB_DECL

  #else /* _C_AS_CPP */
   #define _STD_BEGIN	namespace std {
   #define _STD_END		}
  #endif /* _C_AS_CPP */

   #define _C_STD_BEGIN
   #define _C_STD_END
   #define _CSTD		::
   #define _STD			::std::
 #endif /* _ALT_NS etc */

  #define _X_STD_BEGIN	namespace std {
  #define _X_STD_END	}
  #define _XSTD			::std::

  #if defined(_STD_USING) && _ALT_NS < 3
   #undef _GLOBAL_USING		/* C names in std namespace */

  #elif !defined(_MSC_VER) || 1300 <= _MSC_VER
   #define _GLOBAL_USING	1	/* c* headers import C names to std */
  #endif /* defined(_STD_USING) */

  #if defined(_STD_LINKAGE)
   #define _C_LIB_DECL		extern "C++" {	/* C has extern "C++" linkage */

  #else /* defined(_STD_LINKAGE) */
   #define _C_LIB_DECL		extern "C" {	/* C has extern "C" linkage */
  #endif /* defined(_STD_LINKAGE) */

  #define _END_C_LIB_DECL	}
  #define _EXTERN_C			extern "C" {
  #define _END_EXTERN_C		}

 #else /* _HAS_NAMESPACE */
  #define _STD_BEGIN
  #define _STD_END
  #define _STD	::

  #define _X_STD_BEGIN
  #define _X_STD_END
  #define _XSTD	::

  #define _C_STD_BEGIN
  #define _C_STD_END
  #define _CSTD	::

  #define _C_LIB_DECL		extern "C" {
  #define _END_C_LIB_DECL	}
  #define _EXTERN_C			extern "C" {
  #define _END_EXTERN_C		}
 #endif /* _HAS_NAMESPACE */

 #else /* __cplusplus */
  #define _STD_BEGIN
  #define _STD_END
  #define _STD

  #define _X_STD_BEGIN
  #define _X_STD_END
  #define _XSTD

  #define _C_STD_BEGIN
  #define _C_STD_END
  #define _CSTD

  #define _C_LIB_DECL
  #define _END_C_LIB_DECL
  #define _EXTERN_C
  #define _END_EXTERN_C
 #endif /* __cplusplus */

 #if 199901L <= __STDC_VERSION__

 #if defined(__GNUC__) || defined(__cplusplus)
  #define _Restrict

 #else /* defined(__GNUC__) || defined(__cplusplus) */
  #define _Restrict restrict
 #endif /* defined(__GNUC__) || defined(__cplusplus) */

 #else /* 199901L <= __STDC_VERSION__ */
 #define _Restrict
 #endif /* 199901L <= __STDC_VERSION__ */

 #ifdef __cplusplus
_STD_BEGIN
typedef bool _Bool;
_STD_END
 #endif /* __cplusplus */

#if !defined(_ADI_COMPILER)
/* no standard headers should be included from this file as yvals.h
** is included from every header!.
*/
#include <stdarg.h>
#endif

		/* VC++ COMPILER PARAMETERS */
 #define _CRTIMP
 #define _CDECL

 #if defined(_WIN32_C_LIB)
  #ifndef _VA_LIST_DEFINED

   #if defined(__BORLANDC__)

   #elif defined(_M_ALPHA)
typedef struct
	{	/* define va_list for Alpha */
	char *a0;
	int offset;
	} va_list;

   #else /* defined(_M_ALPHA) */
typedef char *va_list;
   #endif /* defined(_M_ALPHA) */

   #define _VA_LIST_DEFINED
  #endif /* _VA_LIST_DEFINED */

 #endif /* defined(_WIN32_C_LIB) */

 #ifdef __NO_LONG_LONG

 #elif defined(_MSC_VER)
  #define _LONGLONG	__int64
  #define _ULONGLONG	unsigned __int64
  #define _LLONG_MAX	0x7fffffffffffffff
  #define _ULLONG_MAX	0xffffffffffffffff

 #else /* defined(__NO_LONG_LONG) && !defined (_MSC_VER) */
  #define _LONGLONG	long long
  #define _ULONGLONG	unsigned long long
  #define _LLONG_MAX	0x7fffffffffffffffLL
  #define _ULLONG_MAX	0xffffffffffffffffULL
 #endif /* __NO_LONG_LONG */

		/* MAKE MINGW LOOK LIKE WIN32 HEREAFTER */

 #if defined(__MINGW32__)
  #define _WIN32_C_LIB	1
 #endif /* defined(__MINGW32__) */

 #if defined(_WIN32_C_LIB) && !defined(__BORLANDC__)
  #undef _HAS_POSIX_C_LIB

  #if !defined(_SIZE_T) && !defined(_SIZET) \
	&& !defined(_BSD_SIZE_T_DEFINED_) \
	&& !defined(_SIZE_T_DEFINED)
   #define _SIZE_T
   #define _SIZET
   #define _BSD_SIZE_T_DEFINED_
   #define _STD_USING_SIZE_T
   #define _SIZE_T_DEFINED

typedef _Sizet size_t;

   #ifdef __cplusplus
namespace _Dinkum_std {
	using ::size_t;
	}
namespace _Dinkum_std_c {
	using ::size_t;
		}
   #endif /* __cplusplus */

  #endif /* !defined(_SIZE_T) etc. */

  #if defined(_WCHAR_T_)
   #define _WCHAR_T_DEFINED
  #endif /* defined(_WCHAR_T_) */

  #if !defined(_WCHAR_T_DEFINED) ||
   #define _WCHAR_T_DEFINED
   #define _WCHAR_T_
   #undef __need_wchar_t

   #ifndef __cplusplus
typedef unsigned short wchar_t;
   #endif /* __cplusplus */

  #endif /* !defined(_WCHAR_T) etc. */
 #endif /* _WIN32_C_LIB */

		/* FLOATING-POINT PROPERTIES */
#if defined(_ADI_COMPILER)
# define _D0     _ADI_FLOAT_ENDIAN
# define _FBIAS  0x7e
# define _FOFF   7
# define _FRND   1
# if defined(__DOUBLES_ARE_FLOATS__)
#  define _DBIAS _FBIAS
#  define _DOFF  _FOFF
# else
#  define _DBIAS 0x3fe   /* IEEE format double and float */
#  if defined(__ADSP21000__) || defined(__ADSPTS__)
#   define _DOFF  20
#  else
#   define _DOFF  4
#  endif
# endif
# if defined(_ADI_SUPPORT_LONG_DOUBLE)
#  define _DLONG  0       /* 1 if 80-bit long double */
#  define _LBIAS  0x3fe   /* 0x3ffe if 80-bit long double */
#  if defined(__ADSP21000__)
#   define _LOFF  20
#  else
#   define _LOFF  4       /* 15 if 80-bit long double */
#  endif
# else
#  define _DLONG  0       /* 1 if 80-bit long double */
#  define _LBIAS  _FBIAS
#  define _LOFF   _FOFF
# endif
#else
# define _DBIAS	0x3fe	/* IEEE format double and float */
# define _DOFF	4
# define _FBIAS	0x7e
# define _FOFF	7
#endif

		/* INTEGER PROPERTIES */
#if defined (_ADI_COMPILER)
#define _BITS_BYTE      _ADI_BYTE_BITS
#else
#define _BITS_BYTE	8
#endif
#define _C2			1	/* 0 if not 2's complement */
#define _MBMAX		8	/* MB_LEN_MAX */
#define _ILONG		1	/* 0 if 16-bit int */

 #if defined(__s390__) || defined(__CHAR_UNSIGNED__)  \
	|| defined(_CHAR_UNSIGNED)
  #define _CSIGN	0	/* 0 if char is not signed */

 #else /* defined(__s390__) etc */
  #define _CSIGN	1
 #endif /* defined(__s390__) etc */

#define _MAX_EXP_DIG	8	/* for parsing numerics */
#define _MAX_INT_DIG	32
#define _MAX_SIG_DIG	48

 #if defined(_LONGLONG)
typedef _LONGLONG _Longlong;
typedef _ULONGLONG _ULonglong;

 #else /* defined(_LONGLONG) */
typedef long _Longlong;
typedef unsigned long _ULonglong;
 #define _LLONG_MAX		0x7fffffffL
 #define _ULLONG_MAX	0xffffffffUL
 #endif /* defined(_LONGLONG) */

		/* wchar_t AND wint_t PROPERTIES */

 #if defined(_WCHAR_T) || defined(_WCHAR_T_DEFINED) \
	|| defined (_MSL_WCHAR_T_TYPE)
  #define _WCHART
 #endif /* defined(_WCHAR_T) || defined(_WCHAR_T_DEFINED) */

 #if defined(_WINT_T)
  #define _WINTT
 #endif /* _WINT_T */

 #ifdef __cplusplus
#if !defined(_WCHART)
#define _WCHART
#endif /* !defined(_WCHART) */
typedef wchar_t _Wchart;
typedef wchar_t _Wintt;
 #endif /* __cplusplus */

 #if defined(_ADI_COMPILER)

   #if defined(__ADSPBLACKFIN__)
       #ifndef __cplusplus
           typedef unsigned int _Wintt;
           typedef unsigned int _Wchart;
       #endif /* __cplusplus */
       #define _WCMIN     0
       #define _WCMAX    0xffffffff
   #elif defined(__ADSP21000__)
       #ifndef __cplusplus
           typedef int _Wintt;
           typedef int _Wchart;
       #endif /* __cplusplus */
       #define _WCMAX    0x7fffffff
       #define _WCMIN     (-_WCMAX - _C2)
   #endif /* __ADSPBLACKFIN__ */

 #else /* _ADI_COMPILER */

 #if defined(_MSL_WCHAR_T_TYPE)
  #define _WCMIN	0
  #define _WCMAX	0xffff

  #ifndef __cplusplus
typedef wchar_t _Wchart;
typedef wint_t _Wintt;
  #endif /* __cplusplus */

  #define mbstate_t	_DNK_mbstate_t
  #define wctype_t	_DNK_wctype_t
  #define wint_t	_DNK_wint_t
  #define _MSC_VER	1

 #elif defined(_WIN32_C_LIB)
  #define _WCMIN	0
  #define _WCMAX	0xffff

  #ifndef __cplusplus
typedef unsigned short _Wchart;
typedef unsigned short _Wintt;
  #endif /* __cplusplus */

 #elif defined(__CYGWIN__)
  #define _WCMIN	(-_WCMAX - _C2)
  #define _WCMAX	0x7fff

  #ifndef __cplusplus
typedef short _Wchart;
typedef short _Wintt;
  #endif /* __cplusplus */

 #elif defined(__WCHAR_TYPE__)
  #define _WCMIN	(-_WCMAX - _C2)
  #define _WCMAX	0x7fffffff	/* assume signed 32-bit wchar_t */

  #ifndef __cplusplus
typedef __WCHAR_TYPE__ _Wchart;
typedef __WCHAR_TYPE__ _Wintt;
  #endif /* __cplusplus */

 #else /* default wchar_t/wint_t */
  #define _WCMIN	(-_WCMAX - _C2)
  #define _WCMAX	0x7fffffff

  #ifndef __cplusplus
typedef long _Wchart;
typedef long _Wintt;
  #endif /* __cplusplus */

 #endif /* compiler/library type */

 #endif /* _ADI_COMPILER */
		/* POINTER PROPERTIES */

#ifdef _MISRA_RULES
#define _NULL           ((void *)0)     /* MISRA requirement */
#else
#define _NULL           0       /* 0L if pointer same as long */
#endif /* _MISRA_RULES */

		/* signal PROPERTIES */

#if defined (_ADI_COMPILER)
#define _SIGABRT        _ADI_ABRTNUM
#define _SIGMAX         _ADI_SIGMAX
#else
 #if defined(_WIN32_C_LIB)
#define _SIGABRT	22
#define _SIGMAX		32

 #else /* defined(_WIN32_C_LIB) */
#define _SIGABRT	6
#define _SIGMAX		44
 #endif /* defined(_WIN32_C_LIB) */
#endif

		/* stdarg PROPERTIES */
# ifndef _VA_LIST_DEFINED
  typedef char *  va_list;
#  define _VA_LIST_DEFINED
# endif
typedef va_list _Va_list;

 #if _HAS_C9X

 #if __EDG__ && !defined(__x86_64)
  #undef va_copy
 #endif /* __EDG__ */

 #ifndef va_copy
_EXTERN_C
void _Vacopy(va_list *, va_list);
_END_EXTERN_C
  #define va_copy(apd, aps)	_Vacopy(&(apd), aps)
 #endif /* va_copy */

 #endif /* _IS_C9X */

_C_STD_BEGIN
		/* stdlib PROPERTIES */
#define _EXFAIL	1	/* EXIT_FAILURE */

#if !defined(_ADI_COMPILER)
_EXTERN_C
void _Atexit(void (*)(void));
_END_EXTERN_C
#else
#if  defined(__ADSP21000__)
/* required for various C++ headers */
typedef struct _Mbstatet {
   _Wchart _Wchar;
   char _State;
   } _Mbstatet;
#endif
#endif  /* !_ADI_COMPILER */

		/* stdio PROPERTIES */
#if defined(_ADI_COMPILER)
#define _FN_WIDE 0
#endif
#define _FNAMAX	260
#define _FOPMAX	20
#define _TNAMAX	16

 #define _FD_TYPE	signed char
  #define _FD_NO(str) ((str)->_Handle)
 #define _FD_VALID(fd)	(0 <= (fd))	/* fd is signed integer */
 #define _FD_INVALID	(-1)
 #define _SYSCH(x)	x
typedef char _Sysch_t;

		/* STORAGE ALIGNMENT PROPERTIES */

 #if defined(_LP64) || defined(__x86_64)	/* compiler test */
  #define _MEMBND	4U /* 16-byte boundaries (2^^4) */

 #elif _ADI_COMPILER
/* STORAGE ALIGNMENT PROPERTIES */
  #define _MEMBND _ADI_ALIGNA /* eight-byte boundaries (2^^3) */
  # define _AUPBND   _ADI_ALIGNA
  # define _ADNBND   _ADI_ALIGNA
 #else /* defined(_LP64) etc. */
  #define _MEMBND	3U /* eight-byte boundaries (2^^3) */
 #endif /* defined(_LP64) etc. */


		/* time PROPERTIES */
 #define _CPS	1

#define _TBIAS	((70 * 365LU + 17) * 86400)
_C_STD_END

		/* MULTITHREAD PROPERTIES */

#if !defined(_ADI_COMPILER)
/* The lock macros are defined in xsyslock.h, much more appropriate */
 #if _MULTI_THREAD
_EXTERN_C
void _Locksyslock(int);
void _Unlocksyslock(int);
_END_EXTERN_C

 #else /* _MULTI_THREAD */
  #define _Locksyslock(x)	(void)0
  #define _Unlocksyslock(x)	(void)0
 #endif /* _MULTI_THREAD */

		/* LOCK MACROS */
 #define _LOCK_LOCALE	0
 #define _LOCK_MALLOC	1
 #define _LOCK_STREAM	2
 #define _LOCK_DEBUG	3
 #define _MAX_LOCK		4	/* one more than highest lock number */
#endif

 #if _IOSTREAM_OP_LOCKS
  #define _MAYBE_LOCK

 #else /* _IOSTREAM_OP_LOCKS */
  #define _MAYBE_LOCK	\
	if (_Locktype == _LOCK_MALLOC || _Locktype == _LOCK_DEBUG)
 #endif /* _IOSTREAM_OP_LOCKS */

#if defined (_ADI_COMPILER)
/* We have removed all of the _Lockit class and related, all now placed
 * into xsyslock.h.
 */
#if !defined (_HAS_POSIX_C_LIB)
#  define _HAS_POSIX_C_LIB 0
#endif
#endif /* _ADI_COMPILER */

		/* MISCELLANEOUS MACROS */
#define _ATEXIT_T	void

#if defined (_ADI_COMPILER)
/* number of atexit slots; deprecated by later Dinkumware but we still use
 * it with our own somewhat different implementation.
 */
#define NATS 40
#endif

#ifndef _TEMPLATE_STAT
 #define _TEMPLATE_STAT
#endif /* */

 #if defined(__GNUC__) && (0 < __GNUC__)
  #define _NO_RETURN(fun)	void fun __attribute__((__noreturn__))

 #elif defined(_MSC_VER) && (1200 <= _MSC_VER)
  #define _NO_RETURN(fun)	__declspec(noreturn) void fun

 #else /* compiler selector */
  #define _NO_RETURN(fun)	void fun
 #endif /* compiler selector */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _YVALS */


/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
