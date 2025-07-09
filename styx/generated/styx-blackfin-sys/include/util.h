/************************************************************************
 *
 * util.h
 *
 * (c) Copyright 2002-2013 Analog Devices, Inc.  All rights reserved.
 * $Revision: 14738 $
 ************************************************************************/

/* This file contains function declarations and  macros used in the
** standard C and DSP libraries.
*/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* util.h */
#endif

#ifndef _UTIL_H
#define _UTIL_H

#ifdef __ADSPTS__
#include "_divide.h"
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_12_12:"ADI header use of float in union")
#pragma diag(suppress:misra_rule_18_4:"ADI header requires unions")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows complex macro\
 substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#endif /* _MISRA_RULES */

#define DOUBLE  long double
#define FLOAT   float
#define INT     int
#define LONG    long int
#define ULONG   unsigned long int
#define LLONG   long long int
#define ULLONG  unsigned long long int

#define MPY(x, y)   ((float)(x) * (float)(y))
#define MPYD(x, y)  ((long double)(x) * (long double)(y))

#ifdef  __ADSPTS__
#define DIV(x, y)   (_divide40((float)(x),(float)(y)))
#else
#define DIV(x, y)   ((float)(x) / (float)(y))
#endif
#define DIVD(x, y)  ((long double)(x) / (long double)(y))

#define ADD(x, y)   ((float)(x) + (float)(y))
#define ADDD(x, y)  ((long double)(x) + (long double)(y))

#define SUB(x, y)   ((float)(x) - (float)(y))
#define SUBD(x, y)  ((long double)(x) - (long double)(y))

#define TO_FLOAT(x)    ((float)(x))
#define TO_DOUBLE(x)   ((long double)(x))
#define TO_LONG(x)     ((long)(x))

typedef union
{
   FLOAT f;
   LONG  i;
   ULONG ui;
} FLOAT_BIT_MANIPULATOR;

#if defined(__ADSP21000__)
  #define MSW 0
  #define LSW 1
#else
  #define MSW 1
  #define LSW 0
#endif

typedef union
{
   DOUBLE d;
   LONG   ia[2];
   LLONG  ll;
   ULONG  uia[2];
   ULLONG ull;
} DOUBLE_BIT_MANIPULATOR;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _UTIL_H */
