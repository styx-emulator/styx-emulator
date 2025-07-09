/************************************************************************
 *
 * xcycle_count.h
 *
 * (c) Copyright 2006-2008 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3524 $
 ************************************************************************/

/*
   Generic low level support to measure cycles counts
 */

#ifndef __XCYCLE_COUNT_DEFINED
#define __XCYCLE_COUNT_DEFINED

#if !defined(_LANGUAGE_ASM)

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* xcycle_count.h */
#endif

#include <limits.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_8_9)
#pragma diag(suppress:misra_rule_16_3)
#pragma diag(suppress:misra_rule_19_1)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_10)
#endif /* _MISRA_RULES */

/* Add a trailing semi-colon for legacy purposes if requested */
#if defined( __USE_CYCLE_MACRO_REL45__ )
  #define __TRAILING_SC__ ;
#else
  #define __TRAILING_SC__
#endif

/* Define type used for cycle counting */

#if   defined(__ADSP21000__)
#if   defined(__LONG_LONG_PROCESSOR_TIME__)
typedef  volatile unsigned long long  _cycle_t;
#define  _CYCLES_T_MAX                ULLONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s%llu\n", (_STRG), (_DAT)) __TRAILING_SC__
#else
typedef  volatile unsigned long       _cycle_t;
#define  _CYCLES_T_MAX                ULONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s%lu\n", (_STRG), (_DAT)) __TRAILING_SC__
#endif

#elif defined(__ADSPBLACKFIN__)
typedef  volatile unsigned long long  _cycle_t;
#define  _CYCLES_T_MAX                ULLONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s%llu\n", (_STRG), (_DAT)) __TRAILING_SC__

#elif defined(__ADSPTS__)
typedef  volatile unsigned long long  _cycle_t;
#define  _CYCLES_T_MAX                ULLONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s%llu\n", (_STRG), (_DAT)) __TRAILING_SC__

#endif


/* The following low level macros are defined, operating on type _cycle_t

      _START_CYCLE_COUNT( S )    - Set S to the current value
                                   in the cycle count register(s)

      _STOP_CYCLE_COUNT( X, S )  - Return in S the elapsed cycle count
                                   since start counting
                                   X = current count
                                       - S (=start count)
                                       - measurement overhead
 */


/* Include platform specific implementation */

#if   defined(__ADSP21000__)
#include <cycle_count_21xxx.h>
#elif defined(__ADSPBLACKFIN__)
#include <cycle_count_bf.h>
#elif defined(__ADSPTS__)
#include <cycle_count_ts.h>
#else
#error  ARCHITECTURE NOT SUPPORTED
#endif

/* Private Data from here (do not remove because it is used by time.h) */

extern volatile int _Processor_cycles_per_sec;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#else	/* _LANGUAGE_ASM */

#if defined(__ADSPBLACKFIN__)

/* Supply an Assembly Language declaration of _Processor_cycles_per_sec */

.extern  __Processor_cycles_per_sec;

#endif

#endif	/* _LANGUAGE_ASM */
#endif	/* __XCYCLE_COUNT_DEFINED */
