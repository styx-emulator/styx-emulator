/************************************************************************
 *
 * time.h
 *
 * (c) Copyright 1996-2008 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3524 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* time.h */
#endif

#ifndef __TIME_DEFINED
#define __TIME_DEFINED

#ifndef _YVALS
 #include <yvals.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_1:"asm code required on clock_t macro expansion")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"Suppress checking basic types")
#pragma diag(suppress:misra_rule_8_1:"Body of clock function")
#pragma diag(suppress:misra_rule_8_5:"Body of clock function")
#pragma diag(suppress:misra_rule_10_1_a:"Body of clock function")
#pragma diag(suppress:misra_rule_19_1:"Do not fault Include after extern \"C\"")
#pragma diag(suppress:misra_rule_19_4:"Suppress checking macro expansions")
#pragma diag(suppress:misra_rule_19_7:"Suppress checking function macros")
#pragma diag(suppress:misra_rule_20_1:"Library file that defines library names")
#pragma diag(suppress:misra_rule_20_2:"Library file that defines library names")
#endif /* _MISRA_RULES */

#ifdef __cplusplus
  extern "C" {
#endif

#ifndef NULL
  #ifdef __cplusplus
    #define NULL	0
  #else
    #define NULL	((void *)0)
  #endif
#endif

#if !defined(__SIZE_T_DEFINED) && !defined(_SIZE_T)
  #define __SIZE_T_DEFINED
  #define _SIZET
  typedef _Sizet size_t;
#endif

/* Include generalized cycle count capability */
#include <xcycle_count.h>

/* By default set macro to processor speed */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC  (((clock_t)_Processor_cycles_per_sec!=-1) ? \
                         (clock_t)_Processor_cycles_per_sec : \
                         (clock_t) (__PROCESSOR_SPEED__))
#endif

#if defined(__ADSP21000__)
#if defined(__LONG_LONG_PROCESSOR_TIME__)
typedef long long clock_t;
#else
typedef long clock_t;
#endif
#endif

#if defined(__ADSPBLACKFIN__)
typedef long long clock_t;
#endif

#if defined(__ADSPTS__)
typedef long long clock_t;
#endif

typedef long time_t;

struct tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
};

#pragma misra_func(time)
#pragma inline
#pragma always_inline
static clock_t clock(void)
{
  _cycle_t _cnt;
  _GET_CYCLE_COUNT( _cnt );
  return  (clock_t) _cnt;
}

#pragma misra_func(time)
time_t mktime(struct tm *_t);
#pragma misra_func(time)
time_t time(time_t *_t);
#pragma misra_func(time)
struct tm *gmtime(const time_t *_secs);
#pragma misra_func(time)
struct tm *localtime(const time_t *_secs);
#pragma misra_func(time)
size_t strftime(char *_buf, size_t _buf_size, const char *_format, const struct tm *_t);


/* asctime() is special because it calls sprintf; and although the function
** itself is not sensitive to the size of double, it should reference the
** same version of printf as used by the application. The C run-time library
** therefore contains one version that references the version of printf
** that is compiled as if doubles and floats are equivalent, and the
** other version in which it calls the printf used when doubles are 64-bit
** double precision values.
*/
#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __asctimed
#elif !defined(__ADSPBLACKFIN__)
#pragma linkage_name __asctimef
#endif
#pragma misra_func(time)
char *asctime(const struct tm *_t);

/* Because ctime() is defined as calling asctime, two versions of ctime
** are provided to correspond to the two versions of asctime that are
** defined above.
*/
#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __ctimed
#elif !defined(__ADSPBLACKFIN__)
#pragma linkage_name __ctimef
#endif
#pragma misra_func(time)
char *ctime(const time_t *_t);

/* difftime() returns a double and so two binary versions of the function
** are provided. It is recommended that any application that calls the
** difftime function is compiled with the switch -double-size-64, but
** a version of the function is also available if the application is
** compiled with the (default) switch of -double-size-32 but this version
** can only operate correctly if the difference in calendar times is less
** than approximately 97 days.
*/
#if !defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __difftimed
#elif !defined(__ADSPBLACKFIN__)
#pragma linkage_name __difftimef
#endif
#pragma misra_func(time)
double difftime(time_t _t1, time_t _t0);

#ifdef __cplusplus
  }
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __TIME_DEFINED */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
