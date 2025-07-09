#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* heapinfo.h */
#endif
/************************************************************************
 *
 * heapinfo.h
 *
 * (c) Copyright 2002-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _HEAPINFO_H
#define _HEAPINFO_H
#include <stdlib.h>
#include "xalloc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_8:"ADI header _space unused re-declared")
#endif /* _MISRA_RULES */


typedef struct t_heapdata {
  char *base;
  size_t length;
  unsigned long userid;
  char *current;
  struct t_heapdata *next_heap;
#ifdef _FAST_MULTI_HEAPS
  _Altab _Aldata ;
#endif
} heapdata;

typedef struct {
  heapdata *first_heap;
} heapinfo;

extern volatile heapinfo __heaps;
extern volatile int __nheaps;
void _heap_initheaps(void);
int _space_unused(void);
int _heap_space_unused(int _idx);
int _peak_size(void);
int _heap_peak_size(int _idx);
extern void _heap_print(int _idx);
extern void _heap_print_heaps(void);
#ifdef __cplusplus
}
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _HEAPINFO_H */
